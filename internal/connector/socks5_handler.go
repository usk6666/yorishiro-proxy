package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// SOCKS5HandlerConfig holds dependencies for the SOCKS5 handler factory.
type SOCKS5HandlerConfig struct {
	// Negotiator performs the SOCKS5 handshake (auth + CONNECT command).
	// Scope and RateLimit checks are built into the negotiator.
	Negotiator *SOCKS5Negotiator

	// BuildCfg configures ConnectionStack construction.
	BuildCfg *BuildConfig

	// LiveConns, when non-nil, tracks every admitted tunnel so a policy
	// change that no longer admits its target closes it (USK-1160).
	LiveConns *LiveConns

	// PassthroughList, if non-nil, identifies hosts whose TLS traffic should
	// be relayed without MITM. Matching hosts bypass the ConnectionStack.
	PassthroughList *PassthroughList

	// PassthroughObserver, if non-nil, receives PassthroughObservation
	// callbacks around the relay so a meta-flow recorder can persist a
	// TLSHandshakeMessage audit flow per passthrough connection (USK-790).
	// Nil disables the observer hooks.
	PassthroughObserver PassthroughObserver

	// OnStack is called when a non-h2 ConnectionStack is ready. The callback
	// owns the session lifecycle (RunSession wiring). h2-routed stacks are
	// dispatched via OnHTTP2Stack instead.
	OnStack OnStackFunc

	// OnHTTP2Stack is called when the stack was built for the "h2" ALPN route.
	// See OnHTTP2StackFunc for the callback contract. When nil, h2 stacks are
	// closed immediately after Pool.Put.
	OnHTTP2Stack OnHTTP2StackFunc

	// OnUpstreamTLSError is invoked when BuildConnectionStack fails after
	// SOCKS5 negotiated the tunnel. See CONNECTHandlerConfig.OnUpstreamTLSError
	// (USK-784) for the contract. Nil disables.
	OnUpstreamTLSError OnUpstreamTLSErrorFunc

	// InnerPeekTimeout bounds how long the handler waits for the first
	// inner byte after the SOCKS5 200 reply (USK-762). Zero means
	// DefaultInnerPeekTimeout. Misbehaving clients that complete SOCKS5
	// then send nothing release the goroutine after this deadline.
	InnerPeekTimeout time.Duration

	// InnerPeekTimeoutProvider, when non-nil, is consulted on every
	// inner-byte peek so a runtime SetRequestTimeout on the owning
	// FullListener (USK-844) takes effect on the next accepted SOCKS5
	// without rebuilding the handler. Returning <=0 falls back to the
	// static InnerPeekTimeout / DefaultInnerPeekTimeout. Mirrors
	// CONNECTHandlerConfig.InnerPeekTimeoutProvider.
	InnerPeekTimeoutProvider func() time.Duration

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger

	// PluginV2Engine is the optional pluginv2 Engine consulted for
	// (socks5, on_connect) lifecycle hooks (USK-683 / RFC §9.3
	// PhaseSupportNone). The hook fires after Negotiate returns and
	// BEFORE BuildConnectionStack, so a DROP-returning hook closes the
	// tunnel before any ConnectionStack is built. nil disables.
	PluginV2Engine *pluginv2.Engine
}

// NewSOCKS5Handler returns a HandlerFunc that processes SOCKS5 tunnel
// connections: negotiate (with built-in scope + ratelimit) →
// build ConnectionStack → invoke OnStack callback.
//
// The SOCKS5Negotiator already handles scope denial (REP=0x02), rate limit
// denial (REP=0x02), authentication failure, and unsupported commands by
// sending appropriate SOCKS5 reply codes before returning sentinel errors.
// This handler detects those sentinel errors and returns nil (not the error)
// to prevent FullListener from logging them at Error level.
func NewSOCKS5Handler(cfg SOCKS5HandlerConfig) HandlerFunc {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, pc *PeekConn) error {
		connLogger := LoggerFromContext(ctx, logger)

		// Step 1: SOCKS5 handshake (auth + CONNECT + scope + ratelimit).
		ctx, target, err := cfg.Negotiator.Negotiate(ctx, pc)
		if err != nil {
			handleSOCKS5NegotiateErr(ctx, err, connLogger)
			return nil
		}

		connLogger = connLogger.With("target", target, "via", "socks5")

		// USK-1130: classify the route once so the live-connection
		// predicate and the passthrough decision agree. An opaque route
		// (no HTTP path ever observed) is re-checked strictly here: the
		// negotiator only refuses it before the reply when its
		// OpaqueRoute is wired, and the passthrough list may have
		// changed since it ran.
		scope := cfg.Negotiator.Scope
		// A SOCKS5 destination is both the dial target and the TLS
		// authority (USK-1315).
		ut := SameUpstreamTarget(target)
		route := classifyTunnelRoute(cfg.PassthroughList, cfg.BuildCfg, ut)
		if route.opaque() {
			if allowed, reason := socks5ScopeCheck(scope, target, true); !allowed {
				connLogger.Info("socks5 target blocked by scope", "reason", reason)
				return nil
			}
		}

		// USK-1160: track the admitted tunnel with the negotiator's own
		// scope check (blank scheme) so a policy change that no longer
		// admits target cancels ctx for every route below.
		ctx, release, ok := trackAdmitted(ctx, cfg.LiveConns, "socks5", target, func() (bool, string) {
			return socks5ScopeCheck(scope, target, route.opaque())
		}, func() (bool, string) {
			return socks5ScopeCheck(scope, target, true)
		}, connLogger)
		defer release()
		if !ok {
			return nil
		}

		// pluginv2 (socks5, on_connect) lifecycle dispatch (USK-683).
		// DROP short-circuits before stack build / passthrough relay.
		if dispatchSOCKS5OnConnect(ctx, cfg.PluginV2Engine, target, connLogger) {
			return nil
		}

		// Step 2: TLS passthrough check.
		if socks5Passthrough(ctx, cfg, pc, target, route.passthrough, connLogger) {
			return nil
		}

		// Step 3: inner-byte peek + dispatch (USK-762).
		if !socks5ShouldRunTLSMITM(ctx, cfg, pc, ut, connLogger) {
			return nil
		}

		// Step 4-5: TLS MITM path (existing behaviour).
		runTLSMITM(ctx, cfg.BuildCfg, pc, ut, cfg.OnStack, cfg.OnHTTP2Stack, cfg.OnUpstreamTLSError, connLogger)
		return nil
	}
}

// handleSOCKS5NegotiateErr maps the SOCKS5 negotiator's sentinel errors to
// the appropriate log level so the handler's main loop stays small.
func handleSOCKS5NegotiateErr(ctx context.Context, err error, logger *slog.Logger) {
	switch {
	case errors.Is(err, ErrSOCKS5BlockedByScope):
		logger.Info("SOCKS5 target blocked by scope",
			"target", SOCKS5TargetFromContext(ctx))
	case errors.Is(err, ErrSOCKS5BlockedByRateLimit):
		logger.Info("SOCKS5 target blocked by rate limit",
			"target", SOCKS5TargetFromContext(ctx))
	case errors.Is(err, ErrSOCKS5AuthFailed):
		logger.Info("SOCKS5 authentication failed")
	case errors.Is(err, ErrSOCKS5NoAcceptableMethods):
		logger.Debug("SOCKS5 no acceptable auth methods")
	case errors.Is(err, ErrSOCKS5UnsupportedCommand):
		logger.Debug("SOCKS5 unsupported command")
	case errors.Is(err, ErrSOCKS5UnsupportedAddrType):
		logger.Debug("SOCKS5 unsupported address type")
	default:
		logger.Debug("SOCKS5 negotiation failed", "error", err)
	}
}

// socks5Passthrough engages the TLS passthrough relay when relay (the
// handler's classifyTunnelRoute result) says so. Returns true when the
// relay was used (caller returns).
func socks5Passthrough(ctx context.Context, cfg SOCKS5HandlerConfig, pc *PeekConn, target string, relay bool, logger *slog.Logger) bool {
	if !relay {
		return false
	}
	host, _, _ := net.SplitHostPort(target)
	logger.Debug("TLS passthrough relay", "target", target)
	// USK-959: stamp the dial target on ctx so the per_target_host
	// rotation policy can scope state by upstream host.
	dialCtx := ContextWithDialTarget(ctx, target)
	opts, perr := passDialOpts(dialCtx, cfg.BuildCfg)
	if perr != nil {
		logger.Warn("TLS passthrough upstream proxy rotation failed (socks5); failing closed",
			"target", target, "error", perr)
		return true
	}
	relayErr := runPassthroughRelay(dialCtx, pc, target, opts, cfg.PassthroughObserver)
	logPassthroughEnd(logger, target, host, relayErr)
	return true
}

// socks5ShouldRunTLSMITM peeks the inner byte stream and returns true when
// the caller should run the TLS MITM path. Plain HTTP / h2c / bytechunk
// branches are dispatched in-place; raw passthrough hosts skip the peek.
func socks5ShouldRunTLSMITM(ctx context.Context, cfg SOCKS5HandlerConfig, pc *PeekConn, ut UpstreamTarget, logger *slog.Logger) bool {
	if ut.isRawPassthrough(cfg.BuildCfg) {
		return true
	}
	return dispatchInnerProtocol(ctx, pc, ut.Dial, innerDispatchConfig{
		PeekTimeout:         cfg.InnerPeekTimeout,
		PeekTimeoutProvider: cfg.InnerPeekTimeoutProvider,
		BuildCfg:            cfg.BuildCfg,
		OnStack:             cfg.OnStack,
		OnHTTP2Stack:        cfg.OnHTTP2Stack,
		Logger:              logger,
	})
}

// dispatchSOCKS5OnConnect dispatches the (socks5, on_connect) lifecycle
// hook and returns true when the caller should abort (DROP outcome).
// Returns false when the engine is nil, no hooks are registered, all
// hooks returned CONTINUE, or FireLifecycle errored (fail-soft Warn).
func dispatchSOCKS5OnConnect(ctx context.Context, engine *pluginv2.Engine, target string, logger *slog.Logger) bool {
	if engine == nil {
		return false
	}
	hookCtx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()

	payload := pluginv2.BuildSOCKS5ConnectDict(ConnIDFromContext(ctx), ClientAddrFromContext(ctx), target)
	action, err := engine.FireLifecycle(hookCtx, pluginv2.ProtoSOCKS5, pluginv2.EventOnConnect, nil, payload)
	if err != nil {
		logger.Warn("pluginv2 socks5 on_connect hook error", "error", err)
	}
	if action == pluginv2.ActionDrop {
		logger.Info("SOCKS5 tunnel dropped by pluginv2 on_connect hook",
			"target", target, "hook", "socks5.on_connect")
		return true
	}
	return false
}
