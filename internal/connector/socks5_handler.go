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

		// pluginv2 (socks5, on_connect) lifecycle dispatch (USK-683).
		// DROP short-circuits before stack build / passthrough relay.
		if dispatchSOCKS5OnConnect(ctx, cfg.PluginV2Engine, target, connLogger) {
			return nil
		}

		// Step 2: TLS passthrough check.
		if socks5Passthrough(ctx, cfg, pc, target, connLogger) {
			return nil
		}

		// Step 3: inner-byte peek + dispatch (USK-762).
		if !socks5ShouldRunTLSMITM(ctx, cfg, pc, target, connLogger) {
			return nil
		}

		// Step 4-5: TLS MITM path (existing behaviour).
		runTLSMITM(ctx, cfg.BuildCfg, pc, target, cfg.OnStack, cfg.OnHTTP2Stack, cfg.OnUpstreamTLSError, connLogger)
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

// socks5Passthrough engages the TLS passthrough relay when the target
// matches. Returns true when the relay was used (caller returns).
func socks5Passthrough(ctx context.Context, cfg SOCKS5HandlerConfig, pc *PeekConn, target string, logger *slog.Logger) bool {
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

// socks5ShouldRunTLSMITM peeks the inner byte stream and returns true when
// the caller should run the TLS MITM path. Plain HTTP / h2c / bytechunk
// branches are dispatched in-place; raw passthrough hosts skip the peek.
func socks5ShouldRunTLSMITM(ctx context.Context, cfg SOCKS5HandlerConfig, pc *PeekConn, target string, logger *slog.Logger) bool {
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
