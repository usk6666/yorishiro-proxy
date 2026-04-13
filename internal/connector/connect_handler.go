package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

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

	// OnStack is called when a ConnectionStack is ready. The callback owns
	// the session lifecycle (RunSession wiring). This avoids an import cycle
	// between connector and pipeline/session.
	OnStack func(ctx context.Context, stack *ConnectionStack, snap *envelope.TLSSnapshot, target string)

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger
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

		// Step 2: TargetScope check.
		if cfg.Scope != nil && cfg.Scope.HasRules() {
			host, portStr, splitErr := net.SplitHostPort(target)
			if splitErr != nil {
				connLogger.Debug("invalid CONNECT target", "error", splitErr)
				return nil
			}
			port, _ := strconv.Atoi(portStr)
			allowed, reason := cfg.Scope.CheckTarget("https", host, port, "")
			if !allowed {
				connLogger.Info("CONNECT target blocked by scope",
					"reason", reason)
				return nil
			}
		}

		// Step 3: RateLimit check.
		if cfg.RateLimiter != nil {
			host, _, _ := net.SplitHostPort(target)
			if denial := cfg.RateLimiter.Check(host); denial != nil {
				connLogger.Info("CONNECT target blocked by rate limit",
					"limit_type", denial.LimitType,
					"effective_rps", denial.EffectiveRPS)
				return nil
			}
		}

		// Step 4: Build ConnectionStack.
		stack, snap, err := BuildConnectionStack(ctx, pc, target, cfg.BuildCfg)
		if err != nil {
			connLogger.Warn("stack build failed", "error", err)
			return nil
		}

		connLogger.Debug("connection stack built")

		// Step 5: Hand off to OnStack callback for session wiring.
		if cfg.OnStack != nil {
			cfg.OnStack(ctx, stack, snap, target)
		} else {
			stack.Close()
		}

		return nil
	}
}
