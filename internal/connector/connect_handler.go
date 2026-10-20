package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// OnHTTP2StackFunc is the callback signature for when a ConnectionStack's h2
// route produces an upstream HTTP/2 Layer (the stack's client side is also
// http2.ServerRole). The callback owns the per-stream fan-out and session
// wiring for every new stream that appears on stack.ClientTopmost().Channels().
//
// The upstream Layer is pooled: its lifetime is independent of the client
// stack. The handler that invokes this callback is responsible for returning
// upstreamH2 to the pool (or evicting on failure) once the callback exits —
// callees do not call Pool.Put themselves.
//
// clientSnap is the synthetic MITM TLS snapshot presented to the client;
// upstreamSnap is the real upstream TLS snapshot observed at dial time.
// Both are per-Layer per RFC-001 §3.1.
type OnHTTP2StackFunc func(
	ctx context.Context,
	stack *ConnectionStack,
	upstreamH2 *http2.Layer,
	clientSnap, upstreamSnap *envelope.TLSSnapshot,
	target string,
)

// OnStackFunc is the callback signature for non-h2 ConnectionStack routes.
// It receives both TLS snapshots so that callers have access to client-
// facing MITM cert and real upstream cert (per-Layer per RFC-001 §3.1).
type OnStackFunc func(
	ctx context.Context,
	stack *ConnectionStack,
	clientSnap, upstreamSnap *envelope.TLSSnapshot,
	target string,
)

// OnUpstreamTLSErrorFunc is the callback signature invoked when the proxy
// has accepted a CONNECT/SOCKS5 tunnel but the subsequent
// BuildConnectionStack call fails inside the TLS MITM data path. Two wire
// directions can produce this callback (USK-858):
//
//   - upstream TLS handshake rejection (proxy → upstream) — most commonly
//     an expired / self-signed / untrusted-CA / hostname-mismatch cert
//     presented by the upstream server.
//   - client-side TLS MITM handshake rejection (browser → proxy) — the
//     client refused the proxy's MITM cert (Chromium pinning, missing CA
//     install, unknown_certificate / bad_certificate / unknown_ca TLS
//     alert). The connector wraps these with
//     ErrClientTLSMITMHandshake so proxybuild's recorder can branch
//     FailureReason between "client_tls_error" and "upstream_tls_error"
//     via errors.Is.
//
// The callback name is retained for backward compatibility with USK-784
// — despite the broadened scope, the wire shape (callback signature,
// firing site, recorded Stream shape) is unchanged. The CONNECT authority
// is preserved verbatim (CLAUDE.md MITM Principle #1 — do not normalize)
// and the underlying build error is passed through so the recorder can
// surface both diagnostic strings (Tags["error"]) and the canonical
// FailureReason taxonomy value to MCP query consumers.
//
// USK-784 brings the HTTP/1.x HTTPS path to parity with USK-188 (WebSocket).
// USK-858 extends the taxonomy to distinguish client-side from
// upstream-side TLS handshake failures.
type OnUpstreamTLSErrorFunc func(ctx context.Context, target string, err error)

// OnRequestHeadFailureFunc is the callback signature invoked when a
// connector-side handler closes a client connection while reading a request
// head, before any Layer or Envelope exists (USK-1189): the CONNECT request
// (CONNECTHandlerConfig) or the plain-forward target peek
// (HTTP1ForwardHandlerConfig). head carries what the wire showed — the
// received bytes, the armed deadline and, for the forward peek, the 400 the
// handler returned — in the same shape the HTTP/1 Layer reports for its own
// request heads (USK-1181), so one recorder serves both. target is the
// validated host:port the connection was bound for, empty when none could
// be determined. A connection that sent zero bytes never fires it.
type OnRequestHeadFailureFunc func(ctx context.Context, target string, head *http1.RequestHeadError)

// CONNECTHandlerConfig holds dependencies for the CONNECT handler factory.
type CONNECTHandlerConfig struct {
	// Negotiator parses the CONNECT request and, once the target is
	// admitted, sends 200 Connection Established.
	Negotiator *CONNECTNegotiator

	// BuildCfg configures ConnectionStack construction (TLS, proxy, host TLS).
	BuildCfg *BuildConfig

	// Scope validates the CONNECT target against policy rules. Nil disables.
	Scope *TargetScope

	// RateLimiter checks per-host rate limits. Nil disables.
	RateLimiter *RateLimiter

	// LiveConns, when non-nil, tracks every admitted tunnel so a policy
	// change that no longer admits its target closes it (USK-1160).
	LiveConns *LiveConns

	// PassthroughList, if non-nil, identifies hosts whose TLS traffic should
	// be relayed without MITM. Matching hosts bypass the ConnectionStack
	// entirely and use bidirectional io.Copy relay.
	PassthroughList *PassthroughList

	// PassthroughObserver, if non-nil, receives PassthroughObservation
	// callbacks around the relay so a meta-flow recorder can persist a
	// TLSHandshakeMessage audit flow per passthrough connection (USK-790).
	// Nil disables the observer hooks; the relay then runs as a plain
	// io.Copy without byte counters or SNI peek (matches the pre-USK-790
	// hot path).
	PassthroughObserver PassthroughObserver

	// OnStack is called when a non-h2 ConnectionStack is ready. The callback
	// owns the session lifecycle (RunSession wiring). This avoids an import
	// cycle between connector and pipeline/session. h2-routed stacks are
	// dispatched via OnHTTP2Stack instead.
	OnStack OnStackFunc

	// OnHTTP2Stack is called when the stack was built for the "h2" ALPN route.
	// See OnHTTP2StackFunc for the callback contract. When nil, h2 stacks are
	// closed immediately after Pool.Put.
	OnHTTP2Stack OnHTTP2StackFunc

	// OnUpstreamTLSError is invoked when BuildConnectionStack fails after
	// CONNECT was already accepted with a 200 response. The most common
	// trigger is upstream TLS handshake rejection (expired / self-signed /
	// untrusted CA cert). Nil disables — the failure is logged and dropped
	// silently, matching pre-USK-784 behaviour for stacks that opt out of
	// recording. See OnUpstreamTLSErrorFunc for the callback contract.
	OnUpstreamTLSError OnUpstreamTLSErrorFunc

	// OnRequestHeadFailure is invoked when the CONNECT request head is cut
	// off by the request_timeout_ms deadline after bytes arrived, or
	// exceeds the request-line / header-section parser limit (USK-1189).
	// Nil disables — the failure is only logged, as before.
	OnRequestHeadFailure OnRequestHeadFailureFunc

	// InnerPeekTimeout bounds how long the handler waits for the first
	// inner byte after CONNECT 200 (USK-762). Zero means
	// DefaultInnerPeekTimeout. Misbehaving clients that complete CONNECT
	// then send nothing release the goroutine after this deadline.
	InnerPeekTimeout time.Duration

	// InnerPeekTimeoutProvider, when non-nil, is consulted on every
	// inner-byte peek so a runtime SetRequestTimeout on the owning
	// FullListener (USK-844) takes effect on the next accepted CONNECT
	// without rebuilding the handler. Returning <=0 falls back to the
	// static InnerPeekTimeout / DefaultInnerPeekTimeout.
	InnerPeekTimeoutProvider func() time.Duration

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger
}

// passDialOpts builds DialRawOpts for TLS passthrough relay. It safely
// handles a nil BuildCfg (only UpstreamProxy is needed for passthrough).
// EffectiveUpstreamProxyForCtxErr is consulted so a runtime proxy_start /
// configure switch reaches the next passthrough dial (USK-734) AND a
// per-listener override (USK-826) + rotation (USK-959) take effect when
// the ctx carries the listener name. Returns an error on rotation
// resolver failure — caller must fail-closed (close client conn) rather
// than dial direct (privacy regression).
func passDialOpts(ctx context.Context, buildCfg *BuildConfig) (DialRawOpts, error) {
	var opts DialRawOpts
	if buildCfg != nil {
		u, err := buildCfg.EffectiveUpstreamProxyForCtxErr(ctx)
		if err != nil {
			return opts, err
		}
		opts.UpstreamProxy = u
	}
	return opts, nil
}

// NewCONNECTHandler returns a HandlerFunc that processes CONNECT tunnel
// connections: parse CONNECT → scope check → rate limit check (a denial
// is answered 403 / 429, USK-1246) → 200 Connection Established →
// build ConnectionStack → invoke OnStack callback.
//
// The handler does NOT close the underlying PeekConn — FullListener owns
// connection lifecycle. The OnStack callback receives ownership of the
// ConnectionStack and must defer stack.Close().
func NewCONNECTHandler(cfg CONNECTHandlerConfig) HandlerFunc {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, pc *PeekConn) error {
		connLogger := LoggerFromContext(ctx, logger)

		// Step 1: parse the CONNECT request (no reply yet — the 200 is
		// written only after the policy gates admit the target, USK-1246).
		// USK-1162: bound the CONNECT request head by request_timeout_ms
		// so a trickling client cannot hold the slot (nil-safe BuildCfg).
		armed := cfg.BuildCfg.EffectiveRequestHeaderTimeout()
		started := time.Now()
		_ = pc.SetReadDeadline(started.Add(armed))
		target, err := cfg.Negotiator.ReadRequest(ctx, pc)
		_ = pc.SetReadDeadline(time.Time{})
		if err != nil {
			if errors.Is(err, ErrNotCONNECT) {
				connLogger.Debug("not a CONNECT request", "error", err)
				return nil
			}
			connLogger.Debug("CONNECT negotiation failed", "error", err)
			reportCONNECTHeadFailure(ctx, cfg, err, armed, started)
			return nil
		}

		connLogger = connLogger.With("target", target)

		// Step 2-3: scope and rate-limit policy checks. A denial is
		// answered with 403 / 429 and the connection closes (USK-1246).
		if resp := connectPolicyReject(cfg, target, connLogger); resp != nil {
			writeForwardResponse(pc, resp)
			return nil
		}

		// USK-1160: track the admitted tunnel so a policy change that no
		// longer admits target cancels ctx — which every route below
		// (passthrough relay, inner dispatch, TLS MITM stack) watches.
		ctx, release, ok := trackAdmitted(ctx, cfg.LiveConns, "connect", target, func() (bool, string) {
			allowed, reason, _ := connectScopeCheck(cfg.Scope, target)
			return allowed, reason
		}, connLogger)
		defer release()
		if !ok {
			writeForwardErrorResponse(pc, 403, "Forbidden", connectScopeDenyDetail)
			return nil
		}

		// The target is admitted: open the tunnel.
		if err := cfg.Negotiator.WriteEstablished(pc); err != nil {
			connLogger.Debug("CONNECT 200 write failed", "error", err)
			return nil
		}

		// Step 4: TLS passthrough check.
		if connectPassthrough(ctx, cfg, pc, target, connLogger) {
			return nil
		}

		// Step 5: inner-byte peek + dispatch (USK-762). Returns true when
		// the peek classified the inner stream as TLS and the caller should
		// drive the existing BuildConnectionStack path.
		if !connectShouldRunTLSMITM(ctx, cfg, pc, target, connLogger) {
			return nil
		}

		// Step 6: TLS MITM path (existing behaviour).
		runTLSMITM(ctx, cfg.BuildCfg, pc, target, cfg.OnStack, cfg.OnHTTP2Stack, cfg.OnUpstreamTLSError, connLogger)
		return nil
	}
}

// reportCONNECTHeadFailure hands a CONNECT request the proxy itself cut
// off (deadline or parser limit, after bytes arrived) to
// cfg.OnRequestHeadFailure (USK-1189). The connection is still closed
// without a response, as before.
func reportCONNECTHeadFailure(ctx context.Context, cfg CONNECTHandlerConfig, err error, armed time.Duration, started time.Time) {
	if cfg.OnRequestHeadFailure == nil {
		return
	}
	var maxRaw int64
	if cfg.BuildCfg != nil {
		maxRaw = cfg.BuildCfg.MaxRawCaptureSize
	}
	if head, target := connectRequestHeadFailure(err, armed, started, maxRaw); head != nil {
		cfg.OnRequestHeadFailure(ctx, target, head)
	}
}

// Reject-response details for the CONNECT gate. They match the plain-HTTP
// forward gate so every connector-level gate answers in one shape.
const (
	connectScopeDenyDetail     = "yorishiro-proxy: target blocked by scope"
	connectRateLimitDenyDetail = "yorishiro-proxy: target blocked by rate limit"
)

// connectPolicyReject runs the scope and rate-limit gates. It returns nil
// when the target is admitted, otherwise the response the caller must send
// before closing — 403 for a scope denial, 429 for a rate-limit denial
// (USK-1246) — after emitting the denial log line. Scope runs first, so a
// scope-denied CONNECT consumes no rate-limit token.
func connectPolicyReject(cfg CONNECTHandlerConfig, target string, logger *slog.Logger) []byte {
	allowed, reason, splitErr := connectScopeCheck(cfg.Scope, target)
	if splitErr != nil {
		logger.Debug("invalid CONNECT target", "error", splitErr)
		return forwardErrorResponse(400, "Bad Request", "yorishiro-proxy: invalid CONNECT target")
	}
	if !allowed {
		logger.Info("CONNECT target blocked by scope", "reason", reason)
		return forwardErrorResponse(403, "Forbidden", connectScopeDenyDetail)
	}
	if cfg.RateLimiter != nil {
		host, _, _ := net.SplitHostPort(target)
		if denial := cfg.RateLimiter.Check(host); denial != nil {
			logger.Info("CONNECT target blocked by rate limit",
				"limit_type", denial.LimitType,
				"effective_rps", denial.EffectiveRPS)
			return forwardErrorResponse(429, "Too Many Requests", connectRateLimitDenyDetail)
		}
	}
	return nil
}

// connectScopeCheck is the CONNECT gate's scope check: scheme "https",
// the CONNECT authority's host and port, path "". It is both the admission
// check and the live-connection predicate (USK-1160), so a tunnel survives
// a policy change iff an identical new CONNECT would be admitted. A nil or
// rule-less scope allows everything. err is non-nil only for an authority
// that is not host:port (then allowed is false).
func connectScopeCheck(scope *TargetScope, target string) (allowed bool, reason string, err error) {
	if scope == nil || !scope.HasRules() {
		return true, "", nil
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return false, "invalid CONNECT target", err
	}
	port, _ := strconv.Atoi(portStr)
	allowed, reason = scope.CheckTarget("https", host, port, "")
	return allowed, reason, nil
}

// connectPassthrough handles the TLS passthrough relay. Returns true when
// the relay engaged (caller returns).
func connectPassthrough(ctx context.Context, cfg CONNECTHandlerConfig, pc *PeekConn, target string, logger *slog.Logger) bool {
	if cfg.PassthroughList == nil {
		return false
	}
	host, _, _ := net.SplitHostPort(target)
	if !cfg.PassthroughList.Contains(host) {
		return false
	}
	logger.Debug("TLS passthrough relay", "target", target)
	// USK-959: stamp the dial target on ctx so the per_target_host
	// rotation policy can scope state by upstream host.
	dialCtx := ContextWithDialTarget(ctx, target)
	opts, perr := passDialOpts(dialCtx, cfg.BuildCfg)
	if perr != nil {
		logger.Warn("TLS passthrough upstream proxy rotation failed; failing closed",
			"target", target, "error", perr)
		return true
	}
	relayErr := runPassthroughRelay(dialCtx, pc, target, opts, cfg.PassthroughObserver)
	logPassthroughEnd(logger, target, host, relayErr)
	return true
}

// logPassthroughEnd logs a passthrough relay's abnormal end. A relay cut by
// a policy change (USK-1160) was already logged at Info by
// LiveConns.Reconcile, so it is only a Debug line here.
func logPassthroughEnd(logger *slog.Logger, target, host string, relayErr error) {
	switch {
	case relayErr == nil:
	case errors.Is(relayErr, ErrTargetScopeRevoked):
		logger.Debug("TLS passthrough closed: target no longer in scope", "target", target, "error", relayErr)
	default:
		logger.Warn("TLS passthrough ended", "target", target, "sni_peek_target", host, "error", relayErr)
	}
}

// runPassthroughRelay dispatches to the observer-aware relay when an
// observer is configured and to the plain relay otherwise. Centralised so
// CONNECT and SOCKS5 paths share the same dispatch and the no-observer
// path stays close to a plain io.Copy.
func runPassthroughRelay(ctx context.Context, pc *PeekConn, target string, opts DialRawOpts, observer PassthroughObserver) error {
	if observer != nil {
		return RelayTLSPassthroughObserved(ctx, pc, target, opts, observer)
	}
	return RelayTLSPassthrough(ctx, pc, target, opts)
}

// connectShouldRunTLSMITM peeks the inner byte stream and returns true when
// the caller should run the TLS MITM path. Returns false on every other
// outcome (plain HTTP / h2c / bytechunk dispatched in-place, or peek
// failed and the connection was closed).
//
// Raw passthrough hosts (config-level) skip the inner peek entirely so the
// IsRawPassthrough override remains identical to its pre-USK-762 behaviour.
func connectShouldRunTLSMITM(ctx context.Context, cfg CONNECTHandlerConfig, pc *PeekConn, target string, logger *slog.Logger) bool {
	if cfg.BuildCfg != nil && cfg.BuildCfg.ProxyConfig != nil &&
		cfg.BuildCfg.ProxyConfig.IsRawPassthrough(target) {
		return true
	}
	return dispatchInnerProtocol(ctx, pc, target, innerDispatchConfig{
		PeekTimeout:         cfg.InnerPeekTimeout,
		PeekTimeoutProvider: cfg.InnerPeekTimeoutProvider,
		BuildCfg:            cfg.BuildCfg,
		OnStack:             cfg.OnStack,
		OnHTTP2Stack:        cfg.OnHTTP2Stack,
		Logger:              logger,
	})
}

// runTLSMITM drives the existing BuildConnectionStack TLS path and dispatches
// the resulting stack to OnStack / OnHTTP2Stack. Shared by CONNECT and SOCKS5
// handlers so the TLS branch behaves identically across tunnel entry points.
//
// USK-997: before delegating to BuildConnectionStack this function peeks
// the client's first TLS ClientHello (non-consuming, bounded by
// clientHelloPeekTimeout / clientHelloPeekSize) and extracts SNI + ALPN
// list. The result is threaded through BuildConnectionStack as
// ClientHelloPeek so the sniff-first MITM path can forward the client's
// ALPN list verbatim to upstream and advertise upstream's pick back to
// the client. Peek failures (timeout, non-TLS, > 4 KiB, ECH) fall through
// silently — BuildConnectionStack sees an empty ClientHelloPeek and
// routes through the legacy cache/miss/pool fallbacks.
//
// BuildConfig.DisableClientHelloPeek (test-only) skips the peek entirely
// so integration tests can exercise the fallback path.
//
// On stack-build failure, onUpstreamTLSError (when non-nil) is invoked with
// the CONNECT/SOCKS5 authority and the underlying error so callers
// (proxybuild) can persist a state="error" flow.Stream — the USK-784 parity
// fix for HTTP/1.x HTTPS upstream-TLS-handshake errors. Nil disables the
// callback path; the failure is then logged and dropped silently, matching
// pre-USK-784 behaviour for stacks that opt out of recording.
func runTLSMITM(
	ctx context.Context,
	buildCfg *BuildConfig,
	pc *PeekConn,
	target string,
	onStack OnStackFunc,
	onHTTP2Stack OnHTTP2StackFunc,
	onUpstreamTLSError OnUpstreamTLSErrorFunc,
	logger *slog.Logger,
) {
	// USK-997: sniff-first peek. Test-only DisableClientHelloPeek bypasses.
	var peeked ClientHelloPeek
	if buildCfg == nil || !buildCfg.DisableClientHelloPeek {
		peeked = peekClientHelloSNIAndALPN(pc)
	}

	stack, clientSnap, upstreamSnap, err := BuildConnectionStack(ctx, pc, target, buildCfg, peeked)
	if err != nil {
		// Upstream-side / stack-build failures land here. Clients see a
		// closed tunnel; without a recorded Stream the failure is invisible
		// to MITM diagnostic users. Surface it through the callback so the
		// flow store gets a state="error" entry tagged with the authority
		// and the error reason (USK-784 parity with USK-188).
		logger.Warn("stack build failed", "error", err)
		if onUpstreamTLSError != nil {
			onUpstreamTLSError(ctx, target, err)
		}
		return
	}
	// USK-959: wire the BuildConfig in so ConnectionStack.Close can
	// release per-connection rotation state when the client disconnects.
	stack.SetBuildConfig(buildCfg)
	logger.Debug("connection stack built")
	dispatchStack(ctx, stack, clientSnap, upstreamSnap, target, buildCfg, onStack, onHTTP2Stack)
}

// dispatchStack picks between OnHTTP2Stack (when the stack has a pooled
// upstream h2 Layer) and OnStack (all other routes). It also handles the
// Pool.Put lifecycle for h2 stacks — even if OnHTTP2Stack is nil, the
// upstream Layer is still returned to the pool so it can be reused by a
// later connection.
//
// This helper is shared by CONNECT and SOCKS5 handlers to keep the h2
// dispatch behaviour consistent across tunnel entry points.
func dispatchStack(
	ctx context.Context,
	stack *ConnectionStack,
	clientSnap, upstreamSnap *envelope.TLSSnapshot,
	target string,
	buildCfg *BuildConfig,
	onStack OnStackFunc,
	onHTTP2Stack OnHTTP2StackFunc,
) {
	if upstreamH2 := stack.UpstreamH2Layer(); upstreamH2 != nil {
		// h2 route: always return the Layer to the pool on exit (if one
		// exists). Pool.Put is a no-op when the pool is nil, but we must
		// still close the Layer in that case so no goroutines leak.
		//
		// USK-1160: a connection cut because its target is no longer
		// admitted retires the Layer instead, so no idle socket to the
		// denied host is parked in the pool. Retire only closes it once
		// no other borrower holds it: another connection sharing the
		// pooled Layer (same PoolKey, so same target) may have been
		// admitted by a gate whose check still passes — the SOCKS5 gate
		// checks a blank scheme where CONNECT checks "https" — and must
		// keep its streams. A sharer cut by the same Reconcile retires
		// too, and the last one out closes the Layer.
		poolKey := stack.PoolKey()
		defer func() {
			switch {
			case buildCfg == nil || buildCfg.HTTP2Pool == nil:
				_ = upstreamH2.Close()
			case errors.Is(context.Cause(ctx), ErrTargetScopeRevoked):
				buildCfg.HTTP2Pool.Retire(poolKey, upstreamH2)
			default:
				buildCfg.HTTP2Pool.Put(poolKey, upstreamH2)
			}
		}()

		if onHTTP2Stack != nil {
			onHTTP2Stack(ctx, stack, upstreamH2, clientSnap, upstreamSnap, target)
		}
		// Always close the client-side stack once the handler exits. Pool.Put
		// above handles upstreamH2 independently (stack.Close is a no-op for
		// it by design — see ConnectionStack.Close docstring).
		_ = stack.Close()
		return
	}

	if onStack != nil {
		onStack(ctx, stack, clientSnap, upstreamSnap, target)
	} else {
		_ = stack.Close()
	}
}
