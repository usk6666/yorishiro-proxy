package proxybuild

import (
	"context"
	"log/slog"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// h1Chain owns the per-CONNECT chain of upstream HTTP/1.x Layers (USK-998).
//
// HTTP/1 has no connection pool — each CONNECT tunnel owns its single
// upstream Layer. When the upstream peer closes its keep-alive connection
// during idle (Keep-Alive: timeout expiry, RFC 9112 §9.6), the parser
// goroutine in [http1.Layer] does not observe the FIN until the next
// response read; meanwhile the next request's wire Write hits EPIPE.
//
// The chain wraps the per-CONNECT upstream Layer and, on each per-exchange
// dial, calls [http1.Layer.HealthCheck] to detect the stale state proactively
// and transparently redial via [connector.RedialUpstreamH1] when needed.
//
// Shape vs h2's redialChain (USK-991/992):
//   - Thinner: HTTP/1 has no pool, no GOAWAY observer, no pre-warm worker.
//   - Layer slice retains every layer (the original + every redial) so
//     closeAll on CONNECT exit reliably terminates every parser goroutine
//     and underlying conn.
//   - Single sync.Mutex serialises EnsureFresh with closeAll. EnsureFresh
//     calls do not overlap meaningfully in HTTP/1 — the wire is strictly
//     serial per RFC 9112 §9.5 and the per-exchange goroutines pulling
//     from the client Channel are time-sliced by the spawn loop anyway —
//     but the mutex defends against concurrent dial closures from
//     pipelined exchanges and against a racing CONNECT teardown.
//
// USK-1000: chains carry a back-reference to the Manager-level
// [h1UpstreamMetrics] so each stale-detect / redial / close-all event
// updates the manager-wide counters. metrics may be nil for tests that
// construct an h1Chain directly without a Manager; every counter call
// is nil-safe.
type h1Chain struct {
	mu      sync.Mutex
	current *http1.Layer
	layers  []*http1.Layer
	target  string
	cfg     *connector.BuildConfig

	// logger is used for stale-detect / redial-success / redial-failure
	// observability per CLAUDE.md Log Level Guidelines. Debug for normal
	// detect/success, Warn for dial failures (matches h2's
	// `proxybuild: upstream h2 redial failed` Warn).
	logger *slog.Logger

	// metrics receives counter updates for stale_detected_total,
	// redial_total, redial_failed_total, and the chain_generation
	// gauge family. Nil-safe.
	metrics *H1UpstreamMetrics

	// liveGen is the number of redial steps this chain currently
	// contributes to the manager-wide chainGenerationLive gauge. Bumped
	// under c.mu on every redial-append; consumed by closeAll so the
	// manager's live counter is decremented by the exact contribution
	// of this chain. Tracking the contribution here (rather than
	// recomputing from len(c.layers) at close time) keeps the counter
	// stable if future evolutions change how layers are accounted.
	liveGen int64
}

// newH1Chain wraps the initial upstream Layer (the one constructed at
// CONNECT-time by buildStackFromRoute) so subsequent dial-time stale checks
// can redial transparently. logger and metrics are USK-1000 plumbing
// (see h1UpstreamMetrics); both may be nil — the chain operates
// identically minus the observability emit.
func newH1Chain(
	initial *http1.Layer,
	target string,
	cfg *connector.BuildConfig,
	logger *slog.Logger,
	metrics *H1UpstreamMetrics,
) *h1Chain {
	return &h1Chain{
		current: initial,
		layers:  []*http1.Layer{initial},
		target:  target,
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
	}
}

// EnsureFresh returns a Layer guaranteed to have passed a HealthCheck. If
// the current Layer is stale, it is replaced with a freshly redialed Layer;
// the stale Layer is Closed synchronously. Returns the dial error verbatim
// on redial failure — the caller surfaces it through the per-exchange
// session as state="error" (same shape as the original dial closure's
// error path) and the next exchange retries via this same EnsureFresh.
//
// Concurrency: a single mutex serialises with concurrent EnsureFresh and
// closeAll. HealthCheck holds [http1.Layer.pendingMu] briefly during its
// 1-byte SetReadDeadline read; that mutex does not race with the parser
// goroutine in the expected (pendingQ empty) case.
//
// USK-1000 metrics: HealthCheck-err → incStaleDetectedHealthcheck.
// RedialUpstreamH1 success → incRedialHealthcheck + observeChainGeneration.
// RedialUpstreamH1 error → incRedialFailedHealthcheck.
func (c *h1Chain) EnsureFresh(ctx context.Context) (*http1.Layer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.current.HealthCheck(); err == nil {
		return c.current, nil
	}
	// HealthCheck failed: stale upstream observed.
	c.metrics.incStaleDetectedHealthcheck()
	if c.logger != nil {
		c.logger.Debug("proxybuild: http1 stale detected, redialing",
			"target", c.target, "trigger", "healthcheck", "generation", len(c.layers))
	}
	fresh, err := connector.RedialUpstreamH1(ctx, c.target, c.current, c.cfg, len(c.layers))
	if err != nil {
		c.metrics.incRedialFailedHealthcheck()
		if c.logger != nil {
			c.logger.Warn("proxybuild: http1 redial failed",
				"target", c.target, "trigger", "healthcheck", "error", err)
		}
		return nil, err
	}
	// Close the stale Layer synchronously. HTTP/1 is wire-serial and
	// HealthCheck's contract requires an empty pendingQ on call, so by
	// construction there is no in-flight Channel reader to disrupt. Close
	// is sync.Once-guarded inside the Layer.
	_ = c.current.Close()
	c.current = fresh
	c.layers = append(c.layers, fresh)
	c.bumpGenerationLocked()
	c.metrics.incRedialHealthcheck()
	return fresh, nil
}

// Redial forces a fresh upstream Layer regardless of HealthCheck verdict.
// Used by the USK-999 Phase 2 retry wrapper when a wire-Write surfaced a
// *http1.StaleUpstreamError — by definition the current Layer's peer
// closed mid-Write, so re-running HealthCheck would just confirm what the
// failed write already proved. The unconditional dial path is symmetric
// to EnsureFresh's redial branch (lines 71-82) — same RedialUpstreamH1
// call, same close-stale + append + swap-current bookkeeping — minus the
// HealthCheck short-circuit.
//
// Concurrency: acquires c.mu so concurrent EnsureFresh and closeAll are
// serialised the same way EnsureFresh's redial path serialises them.
// HTTP/1 is wire-serial per RFC 9112 §9.5 and the retry wrapper holds the
// per-exchange one-shot budget atomically, so two Redial calls cannot
// race on the same exchange — but the mutex defends against an upstream
// passing through a CONNECT teardown mid-retry (closeAll Close + Redial
// dial vs. one of them winning racily).
//
// Returns the fresh Layer on success or the dial error verbatim on
// failure; the caller surfaces the failure as state="error" on the
// session (matching the EnsureFresh dial-failure shape).
//
// USK-1000 metrics: success → incRedialWriteEpipe + observeChainGeneration.
// Failure → incRedialFailedWriteEpipe.
func (c *h1Chain) Redial(ctx context.Context) (*http1.Layer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fresh, err := connector.RedialUpstreamH1(ctx, c.target, c.current, c.cfg, len(c.layers))
	if err != nil {
		c.metrics.incRedialFailedWriteEpipe()
		if c.logger != nil {
			c.logger.Warn("proxybuild: http1 redial failed",
				"target", c.target, "trigger", "write_epipe", "error", err)
		}
		return nil, err
	}
	// Close the stale Layer synchronously. The retry wrapper is the
	// only path to Redial, and it holds an exclusive one-shot budget
	// per exchange — there is no in-flight reader on c.current to
	// disrupt. Close is sync.Once-guarded inside the Layer.
	_ = c.current.Close()
	c.current = fresh
	c.layers = append(c.layers, fresh)
	c.bumpGenerationLocked()
	c.metrics.incRedialWriteEpipe()
	if c.logger != nil {
		c.logger.Debug("proxybuild: http1 redialed after write EPIPE",
			"target", c.target, "trigger", "write_epipe", "generation", len(c.layers)-1)
	}
	return fresh, nil
}

// bumpGenerationLocked updates the chain-generation gauges after a
// successful redial-append. Caller MUST hold c.mu — both the layer
// slice and the local liveGen are mutated. The generation value
// reported to the metrics struct is the number of redial steps
// (len(layers) - 1) so the implicit initial Layer is generation 0
// and the first redial is generation 1, matching the
// RedialUpstreamH1(generation=N) ConnID suffix convention.
func (c *h1Chain) bumpGenerationLocked() {
	gen := int64(len(c.layers) - 1)
	c.liveGen = gen
	c.metrics.observeChainGeneration(gen)
}

// closeAll closes every Layer in the chain. Called from the CONNECT-exit
// deferred cleanup in runHTTP1ExchangeLoop so every redial step's parser
// goroutine and underlying conn is torn down.
//
// USK-1000: releases this chain's contribution to the manager-wide
// chainGenerationLive gauge so the gauge stays meaningful across many
// CONNECTs (otherwise it would grow monotonically forever).
func (c *h1Chain) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.layers {
		_ = l.Close()
	}
	if c.liveGen > 0 {
		c.metrics.releaseChainGeneration(c.liveGen)
		c.liveGen = 0
	}
}
