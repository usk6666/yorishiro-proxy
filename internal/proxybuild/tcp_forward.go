package proxybuild

import (
	"context"
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
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// tcpForwardDialTimeout bounds the per-connection dial to the upstream
// forward target. Aligned with connector.defaultDialTimeout.
const tcpForwardDialTimeout = 30 * time.Second

// TCPForwardParams configures StartTCPForwardsNamed and friends. Each map
// entry is a per-port forward: the key is the local port (e.g. "9999")
// and the value carries the upstream target host:port.
//
// First-iteration scope (USK-711):
//   - Protocol "raw" (or empty / "auto") is supported and routes the
//     accepted connection through the bytechunk Layer so raw-bytes flow
//     recording works end-to-end via the existing Pipeline.
//   - Protocol "auto" without a peek-detector falls back to raw.
//   - TLS=true and protocol values "http"/"http2"/"grpc"/"websocket" are
//     accepted by config validation but NOT yet implemented at the live
//     data path; calls with those values return an error at start time.
//     Follow-up work (separate Linear issue) layers full L7 dispatch on
//     top of this base.
type TCPForwardParams struct {
	// Forwards maps local port -> ForwardConfig (target, protocol, tls).
	Forwards map[string]*config.ForwardConfig
}

// tcpForwardEntry tracks a single per-port net.Listener and its lifecycle
// channels. Owned by listenerEntry.tcpForwards (one entry per parent listener).
type tcpForwardEntry struct {
	port    string
	target  string
	addr    string
	cancel  context.CancelFunc
	done    chan struct{}
	netLn   net.Listener
	wgConns sync.WaitGroup // tracks per-connection handler goroutines

	// activeConns and maxConns implement an atomic per-forward connection
	// cap. activeConns is incremented on accept and decremented when the
	// handler returns; if activeConns would exceed maxConns the new conn is
	// rejected (closed) and the counter is rolled back. maxConns is read
	// atomically so a runtime SetMaxConnections fan-out is observed without
	// taking m.mu in the accept loop. maxConns == 0 disables the cap.
	activeConns atomic.Int64
	maxConns    atomic.Int64
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

	// First iteration: only "raw", "auto" (with no detector → raw fallback),
	// and "" are wired. Other modes return an explicit error so callers know
	// they have to wait for the L7-mode follow-up.
	switch fc.Protocol {
	case "", "raw", "auto":
		// supported
	default:
		return nil, fmt.Errorf("tcp forward port %s: protocol %q not yet supported (USK-711 implements raw/auto; L7 modes deferred)", port, fc.Protocol)
	}
	if fc.TLS {
		return nil, fmt.Errorf("tcp forward port %s: tls=true not yet supported (USK-711 implements raw forwarding only)", port)
	}

	bindAddr := fmt.Sprintf("127.0.0.1:%s", port)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp forward listen on %s: %w", bindAddr, err)
	}

	// Derive a child context for this listener so StopNamed can cancel it
	// independently of the parent listener.
	listenerCtx, cancel := context.WithCancel(ctx)
	entry := &tcpForwardEntry{
		port:   port,
		target: fc.Target,
		addr:   ln.Addr().String(),
		cancel: cancel,
		done:   make(chan struct{}),
		netLn:  ln,
	}
	// Seed the per-forward connection cap from the manager-level setting so
	// SetMaxConnections fan-out reaches forward listeners. 0 = unlimited.
	if mc := m.MaxConnections(); mc > 0 {
		entry.maxConns.Store(int64(mc))
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
			m.handleTCPForwardConn(ctx, parentListenerName, entry, c)
		}(conn, counted)
	}
}

// handleTCPForwardConn runs a single accepted connection through the raw
// TCP forward path: dial upstream → build [bytechunk → bytechunk] stack →
// run the parent listener's session loop → close on exit.
//
// Recording integrates with the parent Stack's existing Pipeline (RecordStep
// receives RawMessage envelopes from the bytechunk Layer). The forward
// target is also injected into the context so plugins reading
// connector.ForwardTargetFromContext can disambiguate forward-listener
// traffic from other paths.
func (m *Manager) handleTCPForwardConn(
	ctx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
	clientConn net.Conn,
) {
	defer clientConn.Close()

	connID := connector.GenerateConnID()
	clientAddr := clientConn.RemoteAddr().String()
	connLogger := m.logger.With(
		"conn_id", connID,
		"remote_addr", clientAddr,
		"name", parentListenerName,
		"port", entry.port,
		"target", entry.target,
		"via", "tcp-forward",
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

	// Dial upstream with a bounded timeout. EffectiveUpstreamProxy is
	// consulted (rather than the static UpstreamProxy field) so a runtime
	// proxy_start / configure switch reaches the next forward dial (USK-734).
	dialOpts := connector.DialRawOpts{
		DialTimeout: tcpForwardDialTimeout,
	}
	if parentStack.BuildConfig != nil {
		dialOpts.UpstreamProxy = parentStack.BuildConfig.EffectiveUpstreamProxy()
	}

	upstreamConn, _, derr := connector.DialUpstreamRaw(connCtx, entry.target, dialOpts)
	if derr != nil {
		connLogger.Debug("tcp forward upstream dial failed", "error", derr)
		return
	}

	// Build a [bytechunk client → bytechunk upstream] ConnectionStack. The
	// bytechunk Layer records RawMessage envelopes via the parent's
	// Pipeline; raw bytes flow recording is the L4-capable principle in
	// action (CLAUDE.md MITM principles).
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

	if err := session.RunStackSession(connCtx, stack, dial, parentStack.Pipeline, m.tcpForwardSessionOpts(parentStack)); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		connLogger.Debug("tcp forward session ended with error", "error", err)
	}
}

// tcpForwardSessionOpts builds session.SessionOptions for a TCP forward
// session. Mirrors proxybuild.buildSessionOptions but resolves dependencies
// against the parent Stack (since the live path Deps are not stored on
// Manager — only the StackFactory closure carries them).
//
// PluginV2Engine threading and FlowStore-driven OnComplete are both copied
// from the parent so plugin lifecycle hooks and Stream state finalisation
// behave identically to a CONNECT-routed raw flow.
func (m *Manager) tcpForwardSessionOpts(parent *Stack) session.SessionOptions {
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
		opts.OnComplete = func(ctx context.Context, streamID string, err error) {
			if streamID == "" {
				return
			}
			state := "complete"
			if err != nil && !errors.Is(err, io.EOF) {
				state = "error"
			}
			_ = store.UpdateStream(ctx, streamID, flow.StreamUpdate{
				State:         state,
				FailureReason: session.ClassifyError(err),
			})
		}
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
