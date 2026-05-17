package proxybuild

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// tcpForwardDialTimeout bounds the per-connection dial to the upstream
// forward target. Aligned with connector.defaultDialTimeout.
const tcpForwardDialTimeout = 30 * time.Second

// TCPForwardParams configures StartTCPForwardsNamed and friends. Each map
// entry is a per-port forward: the key is the local port (e.g. "9999")
// and the value carries the upstream target host:port.
//
// Supported protocols (live data path):
//   - "" / "auto" — Peek the first inner byte; HTTP/1.x → http arm,
//     other bytes → raw fallback, h2c preface → rejected with USK-914
//     citation, TLS first byte → warn + raw fallback.
//   - "raw" — [bytechunk → bytechunk] stack; recorded as RawMessage
//     envelopes (USK-711).
//   - "http" — [http1 → http1] stack; per-exchange dispatch; supports
//     keep-alive AND the WS/SSE Upgrade swap via the Pipeline's
//     UpgradeStep (USK-913).
//   - "websocket" — same stack as "http", with an in-handler filter
//     that 502s the first exchange when it is not an RFC 6455 Upgrade
//     request (USK-913).
//   - "sse" — same stack as "http", with an in-handler filter that
//     502s the first exchange when the upstream response is not
//     text/event-stream (USK-913).
//
// TLS support:
//   - TLS=true (client-side terminate) — USK-915. Requires a configured CA
//     Issuer; listener start rejects fc.TLS=true without one.
//   - UpstreamTLS=true (upstream-side TLS dial) — USK-916. ALPN propagation:
//     explicit Protocol derives from declaration; "auto"+client-TLS
//     propagates the client-negotiated ALPN; "auto"+plaintext-client
//     advertises only http/1.1 (h2 upstream requires explicit
//     Protocol="http2"). Upstream cert verification uses the global
//     BuildConfig.InsecureSkipVerify flag — per-host / mTLS / uTLS is
//     deferred to a follow-up Issue.
type TCPForwardParams struct {
	// Forwards maps local port -> ForwardConfig (target, protocol, tls).
	Forwards map[string]*config.ForwardConfig
}

// tcpForwardEntry tracks a single per-port net.Listener and its lifecycle
// channels. Owned by listenerEntry.tcpForwards (one entry per parent listener).
type tcpForwardEntry struct {
	port     string
	target   string
	protocol string // USK-913: live-dispatch arm selector (raw/auto/http/websocket/sse)
	addr     string
	cancel   context.CancelFunc
	done     chan struct{}
	netLn    net.Listener
	wgConns  sync.WaitGroup // tracks per-connection handler goroutines

	// fc retains the originating ForwardConfig so per-conn dispatch can
	// route on Protocol / TLS / UpstreamTLS. Kept as a pointer to the
	// caller's value — TCPForwardParams.Forwards lifetime exceeds the
	// listener's, and the per-conn handler treats this as read-only.
	fc *config.ForwardConfig

	// activeConns and maxConns implement an atomic per-forward connection
	// cap. activeConns is incremented on accept and decremented when the
	// handler returns; if activeConns would exceed maxConns the new conn is
	// rejected (closed) and the counter is rolled back. maxConns is read
	// atomically so a runtime SetMaxConnections fan-out is observed without
	// taking m.mu in the accept loop. maxConns == 0 disables the cap.
	activeConns atomic.Int64
	maxConns    atomic.Int64

	// tlsServerCfg is the per-entry MITM *tls.Config used to terminate
	// client-side TLS when fc.TLS=true (USK-915). Built once at listener
	// start so crypto/tls's lazy session-ticket key persists across every
	// accepted conn on this forward entry; nil when fc.TLS=false.
	tlsServerCfg *tls.Config
}

// forwardConnOverride carries per-connection overrides that the TLS
// terminate handler (handleTCPForwardTLSConn) passes to the downstream H1
// / H2 dispatch arms (USK-915). It is intentionally a value type — the
// per-conn handler builds one on the stack so the listener-owned
// *tcpForwardEntry is never copied (which would copy its embedded
// sync.WaitGroup + atomic counters and trip go vet).
//
// Fields:
//
//   - protocol overrides entry.protocol so the downstream dispatch routes
//     by the negotiated ALPN rather than the declared TLS protocol.
//   - tlsTerminated marks that the clientConn handed to the downstream
//     handler is already wrapped in *tls.Conn — the connector builder
//     stamps envelope Scheme="https" and ClientTLSSnapshot accordingly.
//   - clientTLSSnapshot is the negotiated client-side TLS snapshot.
//
// nil overrideForwardConn means "no override; honor entry's configured
// values" — the cleartext forward path.
type forwardConnOverride struct {
	protocol          string
	tlsTerminated     bool
	clientTLSSnapshot *envelope.TLSSnapshot
}

// resolveProtocol returns the protocol the downstream dispatch should use
// for this connection: the override's protocol when non-empty, otherwise
// the entry's listener-configured protocol.
func (o *forwardConnOverride) resolveProtocol(entry *tcpForwardEntry) string {
	if o != nil && o.protocol != "" {
		return o.protocol
	}
	return entry.protocol
}

// startTCPForwardListener constructs and starts a per-port forward listener.
// net.Listen is synchronous, so on return the listener is bound (via
// entry.addr) and the accept goroutine is running.
//
// Lifecycle:
//   - The accept goroutine exits when ctx is cancelled or the underlying
//     net.Listener is closed.
//   - In-flight per-connection handler goroutines are awaited via wgConns
//     before the accept goroutine closes done.
func (m *Manager) startTCPForwardListener(
	ctx context.Context,
	parentListenerName, port string,
	fc *config.ForwardConfig,
) (*tcpForwardEntry, error) {
	if fc == nil {
		return nil, fmt.Errorf("tcp forward port %s: nil ForwardConfig", port)
	}
	if fc.Target == "" {
		return nil, fmt.Errorf("tcp forward port %s: empty Target", port)
	}

	// After the rebase of USK-913 onto main (USK-914 already landed), all
	// six L7 / raw selectors are wired: raw/auto via the bytechunk inline
	// path (USK-711), http/websocket/sse via the http1 arm of
	// connector.BuildConnectionStackWithTarget (USK-913), http2/grpc via
	// the h2c arm + per-stream proxybuild dispatch (USK-914,
	// tcp_forward_h2.go). USK-915 wires client-side TLS terminate before
	// the protocol dispatch in handleTCPForwardTLSConn. Unknown values
	// surface as a validation error.
	switch fc.Protocol {
	case "", "raw", "auto", "http", "websocket", "sse", "http2", "grpc":
		// supported
	default:
		return nil, fmt.Errorf("tcp forward port %s: protocol %q is not a valid forward protocol", port, fc.Protocol)
	}
	// USK-915: client-side TLS terminate requires a configured CA Issuer.
	// Reject at listener start with a clear error so an operator that
	// forgot to wire the CA gets immediate feedback instead of silent
	// per-conn handshake failures. The per-conn handler additionally
	// fails-soft for CA regen races.
	if fc.TLS {
		if m.buildCfg == nil || m.buildCfg.Issuer == nil {
			return nil, fmt.Errorf("tcp forward port %s: tls=true requires a configured CA Issuer", port)
		}
	}
	// USK-916: fc.UpstreamTLS=true is wired via proxybuild.dialForwardUpstream
	// (in tcp_forward_tls.go). No listener-start validation needed beyond
	// the existing Target / Protocol checks — the upstream cert verification
	// policy uses BuildConfig.InsecureSkipVerify (global) and tolerates a
	// missing Issuer (upstream TLS does not need the proxy's CA).

	bindAddr := fmt.Sprintf("127.0.0.1:%s", port)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp forward listen on %s: %w", bindAddr, err)
	}

	// Derive a child context for this listener so StopNamed can cancel it
	// independently of the parent listener.
	listenerCtx, cancel := context.WithCancel(ctx)
	entry := &tcpForwardEntry{
		port:     port,
		target:   fc.Target,
		protocol: fc.Protocol,
		addr:     ln.Addr().String(),
		cancel:   cancel,
		done:     make(chan struct{}),
		netLn:    ln,
		fc:       fc,
	}
	// Seed the per-forward connection cap from the manager-level setting so
	// SetMaxConnections fan-out reaches forward listeners. 0 = unlimited.
	if mc := m.MaxConnections(); mc > 0 {
		entry.maxConns.Store(int64(mc))
	}

	// USK-915: build the per-entry MITM tls.Config once so crypto/tls's
	// lazy session-ticket key persists across every accepted conn on this
	// forward entry. The cert LRU inside the Issuer is shared across all
	// listeners; only the *tls.Config wrapper is per-entry.
	if fc.TLS {
		if err := configureForwardTLS(entry, fc, m.buildCfg.Issuer); err != nil {
			_ = ln.Close()
			cancel()
			return nil, fmt.Errorf("tcp forward port %s: %w", port, err)
		}
	}

	go m.runTCPForwardAcceptLoop(listenerCtx, parentListenerName, entry)
	return entry, nil
}

// runTCPForwardAcceptLoop is the per-port accept loop. It mirrors
// connector.FullListener.Start's structure (ctx-cancel closes the listener,
// active conns drain before the goroutine returns) but stays simple — no
// peek-based protocol detection, no per-connection lifecycle hooks. Each
// accepted conn runs handleTCPForwardConn.
func (m *Manager) runTCPForwardAcceptLoop(
	ctx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
) {
	defer close(entry.done)
	defer entry.netLn.Close()

	// Close the listener when ctx is cancelled so Accept returns immediately.
	go func() {
		<-ctx.Done()
		_ = entry.netLn.Close()
	}()

	for {
		conn, err := entry.netLn.Accept()
		if err != nil {
			// On ctx-cancel or listener-close, drain handlers and exit.
			select {
			case <-ctx.Done():
				entry.wgConns.Wait()
				return
			default:
			}
			// Net listener closed by another path (e.g. cancel raced with
			// parent shutdown). Treat as a clean stop after draining.
			if errors.Is(err, net.ErrClosed) {
				entry.wgConns.Wait()
				return
			}
			m.logger.Warn("tcp forward accept failed",
				"name", parentListenerName,
				"port", entry.port,
				"error", err,
			)
			entry.wgConns.Wait()
			return
		}

		// Capacity check: reject if at or above the per-forward cap. The
		// counter is incremented atomically and rolled back on rejection;
		// the decrement on handler exit is symmetric (always paired with
		// the accept-time increment via the `counted` flag, so a runtime
		// SetMaxConnections from N→0 cannot strand the counter).
		counted := false
		if maxConns := entry.maxConns.Load(); maxConns > 0 {
			if entry.activeConns.Add(1) > maxConns {
				entry.activeConns.Add(-1)
				if m.logger.Enabled(ctx, slog.LevelWarn) {
					m.logger.Warn("tcp forward connection rejected: at capacity",
						"name", parentListenerName,
						"port", entry.port,
						"remote_addr", conn.RemoteAddr().String(),
						"max_connections", maxConns,
					)
				}
				_ = conn.Close()
				continue
			}
			counted = true
		}

		m.logger.Debug("tcp forward connection accepted",
			"name", parentListenerName,
			"port", entry.port,
			"remote_addr", conn.RemoteAddr().String(),
			"active_connections", entry.activeConns.Load(),
		)

		entry.wgConns.Add(1)
		go func(c net.Conn, counted bool) {
			defer entry.wgConns.Done()
			if counted {
				defer entry.activeConns.Add(-1)
			}
			// USK-915: when fc.TLS=true, terminate client-side TLS first
			// then dispatch by negotiated ALPN. handleTCPForwardTLSConn
			// owns the post-handshake routing — it picks the H2 or H1
			// arm based on what the client negotiated, not on
			// fc.Protocol alone.
			if entry.fc != nil && entry.fc.TLS {
				m.handleTCPForwardTLSConn(ctx, parentListenerName, entry, c)
				return
			}
			// USK-914: route http2 / grpc to the h2-aware handler. All
			// other supported values (raw / auto / "") stay on the raw
			// bytechunk path. The protocol gating happens at
			// startTCPForwardListener so the switch here is just a
			// dispatch — invalid values cannot reach this code.
			if entry.fc != nil {
				switch entry.fc.Protocol {
				case "http2", "grpc":
					m.handleTCPForwardH2Conn(ctx, parentListenerName, entry, entry.fc, c)
					return
				}
			}
			m.handleTCPForwardConn(ctx, parentListenerName, entry, c)
		}(conn, counted)
	}
}

// handleTCPForwardConn runs a single accepted connection through the
// configured forward dispatch. The protocol arm decides which Layer stack
// is built:
//
//   - "raw" — inline [bytechunk → bytechunk]; raw bytes recorded via
//     RawMessage envelopes (USK-711 happy path).
//   - "http" / "websocket" / "sse" — connector.BuildConnectionStackWithTarget
//     builds [http1 → http1]; per-exchange dispatch with the
//     Pipeline-mounted UpgradeStep handling WS / SSE Layer swap.
//   - "" / "auto" — Peek the inner byte stream; HTTP/1.x → http arm,
//     everything else → raw fallback (h2c rejected with USK-914 citation).
//
// Recording integrates with the parent Stack's existing Pipeline. The
// forward target is injected into the context so plugins reading
// connector.ForwardTargetFromContext can disambiguate forward-listener
// traffic from other paths. PluginV2Engine + StateReleaser wiring comes
// from tcpForwardSessionOpts (already in place for the raw path; reused
// verbatim by the http arm).
func (m *Manager) handleTCPForwardConn(
	ctx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
	clientConn net.Conn,
) {
	m.handleTCPForwardConnWithOverride(ctx, parentListenerName, entry, nil, clientConn)
}

// handleTCPForwardConnWithOverride is the override-aware extension of
// handleTCPForwardConn (USK-915). The TLS terminate handler calls this
// with a non-nil override carrying the negotiated protocol + TLS snapshot;
// every other caller passes nil and gets the listener-configured
// (entry.protocol, entry.fc) values verbatim.
func (m *Manager) handleTCPForwardConnWithOverride(
	ctx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
	override *forwardConnOverride,
	clientConn net.Conn,
) {
	defer clientConn.Close()

	protocol := override.resolveProtocol(entry)

	connID := connector.GenerateConnID()
	clientAddr := clientConn.RemoteAddr().String()
	connLogger := m.logger.With(
		"conn_id", connID,
		"remote_addr", clientAddr,
		"name", parentListenerName,
		"port", entry.port,
		"target", entry.target,
		"via", "tcp-forward",
		"protocol", protocol,
	)

	connCtx := connector.ContextWithConnID(ctx, connID)
	connCtx = connector.ContextWithClientAddr(connCtx, clientAddr)
	connCtx = connector.ContextWithListenerName(connCtx, parentListenerName)
	connCtx = connector.ContextWithLogger(connCtx, connLogger)
	connCtx = connector.ContextWithForwardTarget(connCtx, entry.target)

	// Look up the parent Stack from the manager. The forward listener piggy-
	// backs on the parent's Pipeline + FlowStore so the live data path
	// already records flows. If the parent has been torn down between
	// accept and dispatch, drop the connection cleanly.
	parentStack := m.Stack(parentListenerName)
	if parentStack == nil {
		connLogger.Debug("tcp forward parent listener no longer running; dropping connection")
		return
	}

	// Dial upstream with a bounded timeout. EffectiveUpstreamProxyForCtx
	// is consulted so a runtime proxy_start / configure switch reaches the
	// next forward dial (USK-734) AND the parent listener's per-listener
	// upstream-proxy override (USK-826) participates — connCtx carries the
	// parent listener name via ContextWithListenerName above.
	//
	// USK-916: dialForwardUpstream additionally performs an upstream TLS
	// handshake when entry.fc.UpstreamTLS=true, returning the TLS snapshot
	// for envelope stamping below.
	upstreamConn, upstreamSnap, derr := dialForwardUpstream(connCtx, entry, override, parentStack, connLogger)
	if derr != nil {
		connLogger.Debug("tcp forward upstream dial failed", "error", derr)
		// USK-916: TLS-dial failures (cert verify, handshake timeout, etc)
		// should produce a state="error" Stream so MCP query("flows",
		// filter:{state:"error"}) surfaces them. Plain TCP dial failures
		// stay silent (matches the pre-USK-916 raw forward behaviour where
		// the connection drops before any Layer is constructed).
		if entry.fc != nil && entry.fc.UpstreamTLS {
			if rec := buildTLSStackBuildErrorRecorder(parentStack.FlowStore, nil, parentListenerName, connLogger); rec != nil {
				rec(connCtx, entry.target, derr)
			}
		}
		return
	}

	// Branch on the operator-declared (or override-rewritten) protocol.
	// raw / auto-resolved-to-raw stays on the bytechunk inline path
	// (USK-711); http / websocket / sse / auto-resolved-to-http flow
	// through the connector L7 dispatch.
	switch protocol {
	case "", "raw", "auto", "http", "websocket", "sse":
		// supported below
	default:
		// startTCPForwardListener already rejected unsupported values;
		// defensive guard for the goroutine spawn path.
		connLogger.Debug("tcp forward unsupported protocol at dispatch", "protocol", protocol)
		_ = upstreamConn.Close()
		return
	}

	if protocol == "raw" {
		m.handleTCPForwardConnRaw(connCtx, parentStack, connID, connLogger, clientConn, upstreamConn)
		return
	}

	// L7 dispatch via connector.BuildConnectionStackWithTarget. The builder
	// owns the Layer assembly; this handler owns the per-exchange dispatch,
	// the ctx-cancel watcher, and the websocket/sse expectation filter.
	// upstreamSnap is non-nil when fc.UpstreamTLS=true (USK-916) and threads
	// through to the upstream Layer's EnvelopeContext.TLS via
	// TargetOverrideParams.UpstreamTLSSnapshot.
	m.handleTCPForwardConnL7(connCtx, parentStack, connID, connLogger, entry, override, protocol, clientConn, upstreamConn, upstreamSnap)
}

// handleTCPForwardConnRaw runs the USK-711 [bytechunk → bytechunk] path.
// Factored out of handleTCPForwardConn so the L7 arm reads against an
// equal-sibling structure — both call into the same session options
// wiring and the same ctx-cancel watcher idiom.
func (m *Manager) handleTCPForwardConnRaw(
	connCtx context.Context,
	parentStack *Stack,
	connID string,
	connLogger *slog.Logger,
	clientConn, upstreamConn net.Conn,
) {
	stack := connector.NewConnectionStack(connID)
	clientLayer := bytechunk.New(clientConn, connID+"/client", envelope.Send)
	stack.PushClient(clientLayer)
	upstreamLayer := bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive)
	stack.PushUpstream(upstreamLayer)

	defer stack.Close()

	// ctx-cancellation watcher: close the stack when ctx is cancelled so the
	// session goroutines parked in conn.Read are unblocked. Mirrors the
	// proven recipe in proxybuild.buildOnStack (see USK-710 ctx cleanup).
	doneCh := make(chan struct{})
	var watcherWG sync.WaitGroup
	watcherWG.Add(1)
	go func() {
		defer watcherWG.Done()
		select {
		case <-connCtx.Done():
			_ = stack.Close()
		case <-doneCh:
		}
	}()
	defer func() {
		close(doneCh)
		watcherWG.Wait()
	}()

	// Wire the per-stream session. The dial closure yields the upstream
	// channel from the bytechunk Layer (bytechunk yields exactly one
	// Channel). The session loop's clientToUpstream reads from the client
	// channel, runs Pipeline.Run on each RawMessage envelope, and forwards
	// bytes to upstream; upstreamToClient does the same in reverse.
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		ch, ok := <-stack.UpstreamTopmost().Channels()
		if !ok {
			return nil, fmt.Errorf("proxybuild: tcp forward upstream channel closed before yielding")
		}
		return ch, nil
	}

	if err := session.RunStackSession(connCtx, stack, dial, parentStack.Pipeline, m.tcpForwardSessionOpts(parentStack, connCtx)); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		connLogger.Debug("tcp forward session ended with error", "error", err)
	}
}

// handleTCPForwardConnL7 runs the http / websocket / sse / auto arms.
//
// Stack assembly is delegated to connector.BuildConnectionStackWithTarget;
// per-exchange dispatch goes through runTCPForwardHTTP1ExchangeLoop (the
// forward-side sibling of the MITM live data path's runHTTP1ExchangeLoop —
// identical loop shape, plus an optional per-exchange filter for the
// websocket/sse arms). The filter is selected by exchangeFilterFor so a
// websocket listener that sees a non-Upgrade request — or an sse listener
// that sees a non-SSE response — synthesises a 502 to the client and
// records the rejection as a Pipeline-Drop audit Stream.
func (m *Manager) handleTCPForwardConnL7(
	connCtx context.Context,
	parentStack *Stack,
	connID string,
	connLogger *slog.Logger,
	entry *tcpForwardEntry,
	override *forwardConnOverride,
	protocol string,
	clientConn, upstreamConn net.Conn,
	upstreamSnap *envelope.TLSSnapshot,
) {
	// Build the stack via the connector dispatcher. Protocol is a
	// non-h2 / non-grpc / non-TLS combination per the startTCPForwardListener
	// switch, so the only failure modes here are bad params (defensive) or
	// the Auto-h2c reject path (already cited USK-914).
	params := connector.TargetOverrideParams{
		Target:   entry.target,
		Protocol: connector.ForwardProtocol(protocol),
	}
	// USK-915: when TLS was terminated upstream of this handler, stamp the
	// envelope Scheme as "https" and forward the client TLS snapshot so
	// recordings and plugin payloads reflect wire reality.
	if override != nil && override.tlsTerminated {
		params.Scheme = "https"
		params.ClientTLSSnapshot = override.clientTLSSnapshot
	}
	// USK-916: when an upstream TLS handshake completed, thread the snapshot
	// into the upstream Layer's EnvelopeContext.TLS via the builder.
	if entry.fc != nil && entry.fc.UpstreamTLS && upstreamSnap != nil {
		params.UpstreamTLS = true
		params.UpstreamTLSSnapshot = upstreamSnap
	}
	stack, err := connector.BuildConnectionStackWithTarget(connCtx, clientConn, upstreamConn, params, parentStack.BuildConfig)
	if err != nil {
		connLogger.Debug("tcp forward L7 stack build failed", "error", err)
		_ = upstreamConn.Close()
		return
	}

	// Note: the connector builder mints its own ConnID for the assembled
	// stack; the handler's local connID is reserved for log correlation
	// only (connLogger already carries it). The Layer-level streamIDs
	// downstream are seeded from the builder's ConnID. Future Issues that
	// need a single ConnID across handler logs + stack identity can wire
	// the override through TargetOverrideParams (deferred — no current
	// consumer).
	_ = connID

	defer stack.Close()

	// ctx-cancellation watcher: close the stack when ctx is cancelled so
	// goroutines parked inside http1.Channel.Next (conn.Read) are unblocked.
	// Mirrors the proven recipe in buildOnStack.
	doneCh := make(chan struct{})
	var watcherWG sync.WaitGroup
	watcherWG.Add(1)
	go func() {
		defer watcherWG.Done()
		select {
		case <-connCtx.Done():
			_ = stack.Close()
		case <-doneCh:
		}
	}()
	defer func() {
		close(doneCh)
		watcherWG.Wait()
	}()

	// Verify the assembly produced http1 Layers on both sides. Auto may
	// have fallen through to Raw if peek did not see HTTP/1.x bytes — in
	// that case we hand off to the raw session loop and let the bytechunk
	// recording cover the connection (graceful degradation per CLAUDE.md
	// graceful-malformed-input principle).
	clientH1, clientOK := stack.ClientTopmost().(*http1.Layer)
	upstreamH1, upstreamOK := stack.UpstreamTopmost().(*http1.Layer)
	if !clientOK || !upstreamOK {
		// Raw fallback path — run the bytechunk session loop on the
		// assembled stack. Same shape as handleTCPForwardConnRaw but
		// without re-constructing the stack.
		connLogger.Debug("tcp forward L7 fell back to non-http1 stack",
			"client_topmost", fmt.Sprintf("%T", stack.ClientTopmost()),
			"upstream_topmost", fmt.Sprintf("%T", stack.UpstreamTopmost()))
		dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			ch, ok := <-stack.UpstreamTopmost().Channels()
			if !ok {
				return nil, fmt.Errorf("proxybuild: tcp forward L7-fallback upstream channel closed before yielding")
			}
			return ch, nil
		}
		if err := session.RunStackSession(connCtx, stack, dial, parentStack.Pipeline, m.tcpForwardSessionOpts(parentStack, connCtx)); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			connLogger.Debug("tcp forward L7-fallback session ended with error", "error", err)
		}
		return
	}

	// Per-exchange dispatch. The expectation filter (Protocol="websocket" /
	// Protocol="sse") wraps each clientCh so a mismatched first envelope
	// short-circuits the exchange with a synthetic 502 — recorded as a
	// state="error" Stream via the Pipeline-Drop audit hook.
	sessOpts := m.tcpForwardSessionOpts(parentStack, connCtx)
	filter := exchangeFilterFor(protocol, connLogger)
	runTCPForwardHTTP1ExchangeLoop(connCtx, stack, clientH1, upstreamH1, parentStack.Pipeline, sessOpts, entry.target, connLogger, filter)
}

// tcpForwardSessionOpts builds session.SessionOptions for a TCP forward
// session. Mirrors proxybuild.buildSessionOptions but resolves dependencies
// against the parent Stack (since the live path Deps are not stored on
// Manager — only the StackFactory closure carries them).
//
// PluginV2Engine threading and FlowStore-driven OnComplete are both copied
// from the parent so plugin lifecycle hooks and Stream state finalisation
// behave identically to a CONNECT-routed raw flow.
//
// connCtx is captured by the OnComplete closure so it can distinguish
// "listener-shutdown closed the stack" from "upstream/peer closed the
// socket". RunSession passes a context.WithoutCancel context to OnComplete,
// so we cannot ask the OnComplete-supplied ctx whether teardown was our
// doing — only connCtx.Err() answers that question.
func (m *Manager) tcpForwardSessionOpts(parent *Stack, connCtx context.Context) session.SessionOptions {
	opts := session.SessionOptions{}
	if parent == nil {
		return opts
	}
	if parent.PluginV2Engine != nil {
		opts.LifecycleEngine = parent.PluginV2Engine
		opts.StateReleaser = parent.PluginV2Engine
	}
	// Mirrors proxybuild.buildSessionOptions: when a FlowStore is wired,
	// finalise Stream state on session completion so recordings transition
	// active → complete (or active → error). Without this hook every Stream
	// recorded via the forward path stays at "active".
	if parent.FlowStore != nil {
		store := parent.FlowStore
		blocked := newBlockedStreamSet()
		opts.OnComplete = func(ctx context.Context, streamID string, err error) {
			if streamID == "" {
				return
			}
			if blocked.contains(streamID) {
				// USK-782: skip terminal-state finalisation for streams
				// already finalised by the audit recorder. Without this
				// the normal-EOF state="complete" overwrite would clobber
				// the BlockedBy attribution. Evict for consistency with
				// the live-path recorder (the per-connection set is
				// short-lived here, but keep the contract uniform).
				blocked.remove(streamID)
				return
			}
			// Raw TCP forwarding has no application-protocol "natural EOF"
			// signal apart from one peer closing its half. The session loop
			// returns nil on a clean EOF from clientToUpstream. If instead
			// the listener shuts down mid-exchange, the watcher in
			// runTCPForwardSession closes the stack, which races the
			// session's in-flight read/write: depending on which side wins,
			// the session can surface context.Canceled (read drained the
			// ctx-Done case first) or a wrapped "use of closed network
			// connection" from the underlying conn.Write. Both are
			// listener-shutdown artefacts, not wire-level failures.
			//
			// We only treat them as graceful when the connection's own
			// context (connCtx, captured at session start) is cancelled —
			// that is, the close was driven by our listener teardown, not
			// by an upstream peer closing its socket mid-flow. A malicious
			// or buggy upstream sending TCP RST would also surface as
			// net.ErrClosed via Go's net stack; gating on connCtx.Err()
			// keeps that case classified as "error" so MITM recordings
			// still flag the abort.
			state := "complete"
			if err != nil && !errors.Is(err, io.EOF) {
				if (errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)) && connCtx.Err() != nil {
					// Listener-shutdown path: keep state="complete".
				} else {
					state = "error"
				}
			}
			_ = store.UpdateStream(ctx, streamID, flow.StreamUpdate{
				State:         state,
				FailureReason: session.ClassifyError(err),
			})
		}
		// USK-782: persist Pipeline-Drop audit Streams for the forward
		// session as well — the parent Stack's Pipeline includes the
		// scope / safety / intercept Steps that may emit a BlockedBy
		// attribution against forwarded traffic.
		opts.OnPipelineDrop = buildPipelineDropRecorder(store, "", m.logger, blocked)
	}
	return opts
}

// stopTCPForwardEntry cancels and waits for a single forward listener.
// Bounded by shutdownTimeout so a stuck handler cannot block manager
// shutdown indefinitely.
func (m *Manager) stopTCPForwardEntry(parentListenerName, port string, fwd *tcpForwardEntry) {
	fwd.cancel()
	select {
	case <-fwd.done:
		m.logger.Info("tcp forward listener stopped",
			"name", parentListenerName,
			"port", port,
			"listen_addr", fwd.addr,
		)
	case <-time.After(shutdownTimeout):
		m.logger.Warn("tcp forward listener shutdown timed out",
			"name", parentListenerName,
			"port", port,
			"timeout", shutdownTimeout,
		)
	}
}

// validateForwardPortKey checks that the map key in TCPForwardParams.Forwards
// is a valid TCP port number (0-65535). Port 0 is allowed because tests bind
// to an OS-assigned ephemeral port via "127.0.0.1:0".
//
// This is defensive validation at the package boundary. The MCP layer
// (validatePortNumber in internal/mcp) already enforces the same rule for
// AI-agent input, but a direct programmatic caller would otherwise reach
// net.Listen with a confusing bind-address error.
func validateForwardPortKey(port string) error {
	if port == "" {
		return fmt.Errorf("tcp forward port key cannot be empty")
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("tcp forward port key %q must be a number", port)
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("tcp forward port key %q must be between 0 and 65535", port)
	}
	return nil
}
