package connector

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"

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

	// OnStack is called when a non-h2 ConnectionStack is ready. The callback
	// owns the session lifecycle (RunSession wiring). This avoids an import
	// cycle between connector and pipeline/session. h2-routed stacks are
	// dispatched via OnHTTP2Stack instead.
	OnStack OnStackFunc

	// OnHTTP2Stack is called when the stack was built for the "h2" ALPN route.
	// See OnHTTP2StackFunc for the callback contract. When nil, h2 stacks are
	// closed immediately after Pool.Put.
	OnHTTP2Stack OnHTTP2StackFunc

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger
}

// passDialOpts builds DialRawOpts for TLS passthrough relay. It safely
// handles a nil BuildCfg (only UpstreamProxy is needed for passthrough).
func passDialOpts(buildCfg *BuildConfig) DialRawOpts {
	var opts DialRawOpts
	if buildCfg != nil {
		opts.UpstreamProxy = buildCfg.UpstreamProxy
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

		// Step 4: TLS passthrough check.
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

		// Step 5: Build ConnectionStack.
		stack, clientSnap, upstreamSnap, err := BuildConnectionStack(ctx, pc, target, cfg.BuildCfg)
		if err != nil {
			connLogger.Warn("stack build failed", "error", err)
			return nil
		}

		connLogger.Debug("connection stack built")

		// Step 6: Hand off to the appropriate callback based on ALPN route.
		dispatchStack(ctx, stack, clientSnap, upstreamSnap, target, cfg.BuildCfg, cfg.OnStack, cfg.OnHTTP2Stack)

		return nil
	}
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
