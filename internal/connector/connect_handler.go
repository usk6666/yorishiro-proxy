package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
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
// has accepted a CONNECT/SOCKS5 tunnel and successfully negotiated client
// TLS MITM context, but the subsequent upstream stack build fails — most
// commonly because the upstream TLS handshake rejected the certificate
// (expired, self-signed, untrusted CA, hostname mismatch, etc.).
//
// The callback is the bridge from the connector layer to the flow recorder
// in proxybuild: it is fired with the CONNECT authority preserved verbatim
// (per CLAUDE.md MITM Principle #1 — do not normalize) and the underlying
// build error so the recorder can persist a state="error" Stream that
// surfaces the upstream-side failure to MITM diagnostic users.
//
// USK-784 brings the HTTP/1.x HTTPS path to parity with USK-188 (WebSocket).
type OnUpstreamTLSErrorFunc func(ctx context.Context, target string, err error)

// CONNECTHandlerConfig holds dependencies for the CONNECT handler factory.
type CONNECTHandlerConfig struct {
	// Negotiator parses the CONNECT request and sends 200 OK.
	Negotiator *CONNECTNegotiator

	// BuildCfg configures ConnectionStack construction (TLS, proxy, host TLS).
	BuildCfg *BuildConfig

	// Scope validates the CONNECT target against policy rules. Nil disables.
	Scope *TargetScope

	// RateLimiter checks per-host rate limits. Nil disables.
	RateLimiter *RateLimiter

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

	// InnerPeekTimeout bounds how long the handler waits for the first
	// inner byte after CONNECT 200 (USK-762). Zero means
	// DefaultInnerPeekTimeout. Misbehaving clients that complete CONNECT
	// then send nothing release the goroutine after this deadline.
	InnerPeekTimeout time.Duration

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger
}

// passDialOpts builds DialRawOpts for TLS passthrough relay. It safely
// handles a nil BuildCfg (only UpstreamProxy is needed for passthrough).
// EffectiveUpstreamProxyForCtx is consulted so a runtime proxy_start /
// configure switch reaches the next passthrough dial (USK-734) AND a
// per-listener override (USK-826) takes effect when the ctx carries the
// listener name.
func passDialOpts(ctx context.Context, buildCfg *BuildConfig) DialRawOpts {
	var opts DialRawOpts
	if buildCfg != nil {
		opts.UpstreamProxy = buildCfg.EffectiveUpstreamProxyForCtx(ctx)
	}
	return opts
}

// NewCONNECTHandler returns a HandlerFunc that processes CONNECT tunnel
// connections: negotiate → scope check → rate limit check →
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

		// Step 1: CONNECT negotiation (parses request, sends 200 OK).
		target, err := cfg.Negotiator.Negotiate(ctx, pc)
		if err != nil {
			if errors.Is(err, ErrNotCONNECT) {
				connLogger.Debug("not a CONNECT request", "error", err)
				return nil
			}
			connLogger.Debug("CONNECT negotiation failed", "error", err)
			return nil
		}

		connLogger = connLogger.With("target", target)

		// Step 2-3: scope and rate-limit policy checks.
		if !connectPolicyAllow(cfg, target, connLogger) {
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

// connectPolicyAllow runs the scope and rate-limit gates. Returns false when
// the connection has been rejected (a log line was emitted; caller returns).
func connectPolicyAllow(cfg CONNECTHandlerConfig, target string, logger *slog.Logger) bool {
	if cfg.Scope != nil && cfg.Scope.HasRules() {
		host, portStr, splitErr := net.SplitHostPort(target)
		if splitErr != nil {
			logger.Debug("invalid CONNECT target", "error", splitErr)
			return false
		}
		port, _ := strconv.Atoi(portStr)
		allowed, reason := cfg.Scope.CheckTarget("https", host, port, "")
		if !allowed {
			logger.Info("CONNECT target blocked by scope", "reason", reason)
			return false
		}
	}
	if cfg.RateLimiter != nil {
		host, _, _ := net.SplitHostPort(target)
		if denial := cfg.RateLimiter.Check(host); denial != nil {
			logger.Info("CONNECT target blocked by rate limit",
				"limit_type", denial.LimitType,
				"effective_rps", denial.EffectiveRPS)
			return false
		}
	}
	return true
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
	relayErr := runPassthroughRelay(ctx, pc, target, passDialOpts(ctx, cfg.BuildCfg), cfg.PassthroughObserver)
	if relayErr != nil {
		logger.Warn("TLS passthrough ended", "target", target, "sni_peek_target", host, "error", relayErr)
	}
	return true
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
		PeekTimeout:  cfg.InnerPeekTimeout,
		BuildCfg:     cfg.BuildCfg,
		OnStack:      cfg.OnStack,
		OnHTTP2Stack: cfg.OnHTTP2Stack,
		Logger:       logger,
	})
}

// runTLSMITM drives the existing BuildConnectionStack TLS path and dispatches
// the resulting stack to OnStack / OnHTTP2Stack. Shared by CONNECT and SOCKS5
// handlers so the TLS branch behaves identically across tunnel entry points.
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
	stack, clientSnap, upstreamSnap, err := BuildConnectionStack(ctx, pc, target, buildCfg)
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
		poolKey := stack.PoolKey()
		defer func() {
			if buildCfg != nil && buildCfg.HTTP2Pool != nil {
				buildCfg.HTTP2Pool.Put(poolKey, upstreamH2)
			} else {
				_ = upstreamH2.Close()
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
