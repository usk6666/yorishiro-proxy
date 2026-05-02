package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"

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

	// OnStack is called when a non-h2 ConnectionStack is ready. The callback
	// owns the session lifecycle (RunSession wiring). h2-routed stacks are
	// dispatched via OnHTTP2Stack instead.
	OnStack OnStackFunc

	// OnHTTP2Stack is called when the stack was built for the "h2" ALPN route.
	// See OnHTTP2StackFunc for the callback contract. When nil, h2 stacks are
	// closed immediately after Pool.Put.
	OnHTTP2Stack OnHTTP2StackFunc

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
		// PeekConn embeds net.Conn so it satisfies the net.Conn interface.
		// The negotiator returns enriched context with SOCKS5 metadata.
		ctx, target, err := cfg.Negotiator.Negotiate(ctx, pc)
		if err != nil {
			// Sentinel errors: negotiator already sent the SOCKS5 reply.
			switch {
			case errors.Is(err, ErrSOCKS5BlockedByScope):
				connLogger.Info("SOCKS5 target blocked by scope",
					"target", SOCKS5TargetFromContext(ctx))
				return nil
			case errors.Is(err, ErrSOCKS5BlockedByRateLimit):
				connLogger.Info("SOCKS5 target blocked by rate limit",
					"target", SOCKS5TargetFromContext(ctx))
				return nil
			case errors.Is(err, ErrSOCKS5AuthFailed):
				connLogger.Info("SOCKS5 authentication failed")
				return nil
			case errors.Is(err, ErrSOCKS5NoAcceptableMethods):
				connLogger.Debug("SOCKS5 no acceptable auth methods")
				return nil
			case errors.Is(err, ErrSOCKS5UnsupportedCommand):
				connLogger.Debug("SOCKS5 unsupported command")
				return nil
			case errors.Is(err, ErrSOCKS5UnsupportedAddrType):
				connLogger.Debug("SOCKS5 unsupported address type")
				return nil
			default:
				connLogger.Debug("SOCKS5 negotiation failed", "error", err)
				return nil
			}
		}

		connLogger = connLogger.With("target", target, "via", "socks5")

		// pluginv2 (socks5, on_connect) lifecycle dispatch (USK-683).
		// DROP short-circuits before stack build / passthrough relay.
		if dispatchSOCKS5OnConnect(ctx, cfg.PluginV2Engine, target, connLogger) {
			return nil
		}

		// Step 2: TLS passthrough check.
		if cfg.PassthroughList != nil {
			host, _, _ := net.SplitHostPort(target)
			if cfg.PassthroughList.Contains(host) {
				connLogger.Debug("TLS passthrough relay", "target", target)
				if err := RelayTLSPassthrough(ctx, pc, target, passDialOpts(cfg.BuildCfg)); err != nil {
					connLogger.Debug("TLS passthrough ended", "error", err)
				}
				return nil
			}
		}

		// Step 3: Build ConnectionStack.
		stack, clientSnap, upstreamSnap, err := BuildConnectionStack(ctx, pc, target, cfg.BuildCfg)
		if err != nil {
			connLogger.Warn("stack build failed", "error", err)
			return nil
		}

		connLogger.Debug("connection stack built")

		// Step 4: Hand off to the appropriate callback based on ALPN route.
		dispatchStack(ctx, stack, clientSnap, upstreamSnap, target, cfg.BuildCfg, cfg.OnStack, cfg.OnHTTP2Stack)

		return nil
	}
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
