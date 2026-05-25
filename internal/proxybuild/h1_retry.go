package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// retryingUpstreamChannel wraps the per-exchange upstream layer.Channel
// returned by the runHTTP1Exchange dial closure (USK-999 / USK-998
// Phase 2). On the FIRST Send, it inspects the returned error for
// *http1.StaleUpstreamError; when ReplaySafe is true and the one-shot
// retry budget has not been consumed, it:
//
//  1. force-redials the per-CONNECT h1Chain (chain.Redial) — which
//     closes the stale Layer and installs a fresh one.
//  2. opens a fresh per-exchange Channel on the new Layer via
//     openExchange.
//  3. re-applies the dispatch wrapper (so a gRPC-Web exchange stays a
//     grpcweb.Wrap on the retry leg).
//  4. atomically swaps the inner Channel.
//  5. replays the same Envelope through Send on the fresh inner.
//
// The wrapper closes the ~5% race window left by USK-998 Phase 1's
// HealthCheck-then-Write gap (server FIN between HealthCheck and the
// first wire Write). Browser-parity north star: when a browser would
// silently retry through Connection: keep-alive churn, the proxy should
// too — without surfacing as a hard state=error (see CLAUDE.md feedback
// memory: MITM browser-parity north star).
//
// Concurrency invariants:
//
//   - retried atomic.Bool is one-shot per Channel lifetime. Even though
//     HTTP/1 is wire-serial and one Send per Channel lifetime is the
//     production shape, the atomic guarantees a single replay budget
//     across any pathological caller.
//   - inner atomic.Pointer[layer.Channel] is swapped exactly once (on
//     successful retry). All forwarding methods (StreamID, Next, Send,
//     Close, Closed, Err) read inner via Load on every call so the
//     post-swap Channel is observed transparently.
//   - The OLD inner Channel is NOT explicitly closed by the wrapper —
//     its parent Layer is closed by chain.Redial, which cascades termDone
//     to the old Channel. Calling Close on the old Channel directly here
//     would race the layer-level cascade.
//   - chain.mu serialises Redial against EnsureFresh and closeAll.
type retryingUpstreamChannel struct {
	inner   atomic.Pointer[layer.Channel]
	chain   *h1Chain
	wrapper func(layer.Channel) layer.Channel
	retried atomic.Bool
	logger  *slog.Logger
	target  string
}

// newRetryingUpstreamChannel constructs the wrapper around an already-
// dispatched upstream channel. inner MUST be the channel produced by
// the dial closure AFTER WrapH1UpstreamForDispatch — the wrapper does
// not invoke the dispatch wrapper on the initial leg. wrapper is the
// SAME dispatch closure (typically `connector.WrapH1UpstreamForDispatch(_,
// reqProto, streamGRPCWebOpts)`) so the retry leg is dispatched
// identically.
func newRetryingUpstreamChannel(
	inner layer.Channel,
	chain *h1Chain,
	wrapper func(layer.Channel) layer.Channel,
	logger *slog.Logger,
	target string,
) *retryingUpstreamChannel {
	r := &retryingUpstreamChannel{
		chain:   chain,
		wrapper: wrapper,
		logger:  logger,
		target:  target,
	}
	r.inner.Store(&inner)
	return r
}

// StreamID forwards to the current inner. The retry leg uses a different
// per-exchange Channel (fresh OpenExchange on the redialed Layer), so
// the StreamID may change after retry — callers that captured the
// pre-retry StreamID for diagnostics still see the original value (the
// session loop uses clientCh.StreamID(), which is unaffected). The
// minted-on-Send currentStreamID on the channel itself is captured at
// sendRequest time via env.StreamID, so the response on the retry leg
// inherits the same upstream-exchange identifier the session expects.
func (r *retryingUpstreamChannel) StreamID() string {
	return (*r.inner.Load()).StreamID()
}

// Next forwards to the current inner. The session loop reads Next AFTER
// Send completes (uh.ready fires post-first-Send, see
// internal/session/session.go), so by the time Next is called the inner
// pointer is either the original (no retry needed) or the retried Channel
// (retry succeeded). Either way the response read lands on the right
// upstream conn.
func (r *retryingUpstreamChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	return (*r.inner.Load()).Next(ctx)
}

// Send forwards to the current inner. On the FIRST Send, if the inner
// returned a *http1.StaleUpstreamError with ReplaySafe=true and the retry
// budget is unused, the wrapper redials the chain, opens a fresh inner
// Channel, swaps, and re-Sends exactly once. Subsequent Send invocations
// (which only happen if the session loop reuses the same Channel for a
// second message — not the production h1 shape) flow through to the
// current inner without retry.
func (r *retryingUpstreamChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	cur := *r.inner.Load()
	err := cur.Send(ctx, env)
	if err == nil {
		return nil
	}

	var stale *http1.StaleUpstreamError
	if !errors.As(err, &stale) || !stale.ReplaySafe {
		return err
	}
	if r.retried.Load() {
		return err
	}
	// Budget claim. CompareAndSwap so a hypothetical concurrent Send
	// (not the production shape, but defensive) cannot consume the
	// budget twice.
	if !r.retried.CompareAndSwap(false, true) {
		return err
	}

	r.logger.Debug("proxybuild: http1 upstream stale on send, redialing for replay",
		"target", r.target, "stage", stale.Stage, "underlying", stale.Underlying)

	freshLayer, derr := r.chain.Redial(ctx)
	if derr != nil {
		// Surface the original stale error wrapped so the session
		// records state=error with the underlying syscall reason
		// intact; the dial error is annotated for operator triage.
		return fmt.Errorf("http1: stale-conn redial: %w (after %v)", derr, err)
	}

	freshCh := freshLayer.OpenExchange()
	if freshCh == nil {
		return fmt.Errorf("http1: stale-conn replay: fresh layer closed before OpenExchange (after %v)", err)
	}

	wrapped := freshCh
	if r.wrapper != nil {
		wrapped = r.wrapper(freshCh)
	}
	r.inner.Store(&wrapped)

	// Replay the same envelope. The fresh inner.Send registers the new
	// Channel in the redialed Layer's pendingQ atomically with the wire
	// Write (sendRequest holds writeMu). On a second EPIPE the wrapper
	// returns it verbatim — budget already consumed.
	if rerr := wrapped.Send(ctx, env); rerr != nil {
		r.logger.Debug("proxybuild: http1 stale-conn replay failed",
			"target", r.target, "original_stage", stale.Stage, "replay_error", rerr)
		return rerr
	}
	return nil
}

// Close forwards to the current inner. Layer-level teardown is owned by
// the per-CONNECT h1Chain.closeAll() called from runHTTP1ExchangeLoop's
// defer; this Close only releases the per-exchange Channel.
func (r *retryingUpstreamChannel) Close() error {
	return (*r.inner.Load()).Close()
}

// Closed forwards to the current inner. The Closed channel is per-
// Channel-instance, so a swap mid-flight changes which channel the
// caller observes — but the session loop only reads Closed via
// uh.ch.Closed() after Send completes (USK-715 / RFC §3.3), by which
// time the inner pointer is stable on the post-retry Channel.
func (r *retryingUpstreamChannel) Closed() <-chan struct{} {
	return (*r.inner.Load()).Closed()
}

// Err forwards to the current inner. Same observability shape as Closed.
func (r *retryingUpstreamChannel) Err() error {
	return (*r.inner.Load()).Err()
}
