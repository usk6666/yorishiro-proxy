package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
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

	// OnStack is called when a ConnectionStack is ready. The callback owns
	// the session lifecycle (RunSession wiring). This avoids an import cycle
	// between connector and pipeline/session.
	OnStack func(ctx context.Context, stack *ConnectionStack, snap *envelope.TLSSnapshot, target string)

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger
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
		stack, snap, err := BuildConnectionStack(ctx, pc, target, cfg.BuildCfg)
		if err != nil {
			connLogger.Warn("stack build failed", "error", err)
			return nil
		}

		connLogger.Debug("connection stack built")

		// Step 4: Hand off to OnStack callback for session wiring.
		if cfg.OnStack != nil {
			cfg.OnStack(ctx, stack, snap, target)
		} else {
			stack.Close()
		}

		return nil
	}
}
