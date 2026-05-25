package proxybuild

import "sync/atomic"

// H2UpstreamMetrics aggregates per-Manager counters that observe the
// USK-991 (reactive GOAWAY-driven redial), USK-992 (proactive pre-warm
// worker), and USK-993 (OpenStream Refused-stream retry) live-wire
// surface for HTTP/2 upstreams. Each counter is an atomic.Int64 so
// increment-from-multiple-goroutines is safe; readers use
// [H2UpstreamMetrics.Snapshot] which loads each field with atomic.Load
// semantics.
//
// Scope: one struct instance per [Manager] (Manager-level singleton),
// shared by every per-CONNECT [redialChain] and every per-stream dial
// closure built under that manager. Multi-listener isolation is
// provided by Manager-per-listener — each Manager has its own metrics
// struct, never shared across managers.
//
// The struct is exported (vs the internal increment methods) so the
// production wiring (internal/mcpserver/init.go) can construct one
// instance before NewManager and thread the same pointer into
// [ManagerConfig.H2UpstreamMetrics] (status accessor) and
// [Deps.H2UpstreamMetrics] (per-listener instrumentation). Increment
// methods remain package-private — only redialChain / the per-stream
// dial closure emit.
//
// Counter convention mirrors [H1UpstreamMetrics] (USK-1000) — h2 carries
// a wider trigger-label space because it has THREE distinct stale-
// detect / redial paths (prewarm worker, reactive GOAWAY-driven
// selectUpstreamForDial, OpenStream Refused-stream retry) versus h1's
// two. There is no Prometheus exporter or HTTP listener in this repo;
// the MCP `status` resource is the single surface.
//
// Shared-seam extraction with H1UpstreamMetrics is deferred per memory
// `feedback_shared_seam_hardcoded_flag` — both protocols now have the
// same shape, so a follow-up Issue can lift them into a shared
// internal/proxybuild/upstream_metrics.go.
type H2UpstreamMetrics struct {
	// goAwayObservedPrewarm counts each time the pre-warm worker
	// drained a wake event (peer GOAWAY observed via the per-Layer
	// WithGoAwayObserver / pooled-Layer RegisterGoAwayObserver
	// callback) and proceeded to evaluate a fresh dial. Counted at the
	// CONSUMER (worker drain), NOT at the observer callback, so
	// spurious-wake races and head-mismatched callbacks do not
	// double-count.
	goAwayObservedPrewarm atomic.Int64

	// goAwayObservedReactive counts each time selectUpstreamForDial's
	// slow path observed a stale Layer (isStaleH2 returned true) and
	// proceeded to fresh-dial under chain.mu. Counted at the consumer
	// (slow-path entry), matching the "divergence point" convention
	// that h1's incStaleDetectedHealthcheck establishes.
	goAwayObservedReactive atomic.Int64

	// refused counts each time openUpstreamStreamWithRetryFn observed
	// OpenStream return *layer.StreamError{Code: ErrorRefused} on the
	// FIRST attempt. Counted BEFORE the retry attempt fires, so every
	// Refused observation contributes exactly once regardless of
	// retry outcome.
	refused atomic.Int64

	// redialPrewarm counts successful redials initiated by the pre-warm
	// worker. The post-dial Layer-append and chain.current swap
	// happened under chain.mu.
	redialPrewarm atomic.Int64

	// redialReactive counts successful redials initiated by
	// selectUpstreamForDial's slow path (reactive: stale Layer
	// observed on the live request path).
	redialReactive atomic.Int64

	// redialRefusedStream counts successful redials initiated by
	// openUpstreamStreamWithRetryFn's retry path. The retry's second
	// selectUpstreamForDial observed the now-stale Layer and
	// fresh-dialed; this counter increments on that fresh-dial
	// success.
	//
	// Q9 heuristic — see Snapshot godoc and openUpstreamStreamWithRetryFn:
	// approximate classification by (upL != upL2). Parallel pre-warm
	// can mis-classify in rare interleavings where chain.current was
	// already replaced by another goroutine before the second
	// selectUpstreamForDial call.
	redialRefusedStream atomic.Int64

	// redialFailedPrewarm counts dial failures inside the pre-warm
	// worker. The failed dial is NOT appended to chain.layers;
	// chain.current is unchanged.
	redialFailedPrewarm atomic.Int64

	// redialFailedReactive counts dial failures inside
	// selectUpstreamForDial's slow path. The stale Layer is returned
	// to the caller; OpenStream surfaces the underlying refused error.
	redialFailedReactive atomic.Int64

	// redialFailedRefusedStream counts dial failures observed inside
	// openUpstreamStreamWithRetryFn's retry path. Heuristic-classified
	// the same way as redialRefusedStream.
	redialFailedRefusedStream atomic.Int64

	// retrySuccess counts retry-wrapper attempts where the
	// post-redial OpenStream returned a healthy Channel. The request
	// reached the upstream on the second try.
	retrySuccess atomic.Int64

	// retryFailRedial counts retry-wrapper attempts where the retry
	// path's selectUpstreamForDial did NOT secure a fresh Layer (the
	// second select returned the same stale Layer; redial failed and
	// fell back to stale). The post-redial OpenStream then returned
	// an error.
	//
	// Heuristic — see Snapshot godoc and openUpstreamStreamWithRetryFn.
	retryFailRedial atomic.Int64

	// retryFailRedialRetry counts retry-wrapper attempts where redial
	// SUCCEEDED (the second select returned a fresh Layer different
	// from the first) but the post-redial OpenStream still returned
	// an error. The fresh Layer broke again on the second attempt.
	retryFailRedialRetry atomic.Int64

	// chainGenerationMax is the high-water mark of the redial chain
	// depth observed across the manager's lifetime. Updated under
	// chain.mu right after each layer-append (reactive slow path AND
	// pre-warm worker post-dial). Never decreases — diagnostic "worst
	// case" for upstream churn.
	chainGenerationMax atomic.Int64

	// chainGenerationLive is the sum of redial-step counts across
	// every currently-live redialChain. Each chain contributes the
	// number of redial steps it has executed (chain.layers length minus
	// the implicit pooled chain[0]). Incremented on redial-append,
	// decremented in [redialChain.closeAll] (CONNECT exit). Keeps the
	// gauge meaningful across many CONNECTs.
	chainGenerationLive atomic.Int64
}

// NewH2UpstreamMetrics returns a fresh zero-valued counter struct.
// Production wiring (internal/mcpserver/init.go) constructs one
// instance and threads it into both [ManagerConfig.H2UpstreamMetrics]
// and [Deps.H2UpstreamMetrics] so all per-listener instrumentation
// updates a single Manager-level counter set.
//
// Tests that need to read counters in isolation can construct one
// directly via &H2UpstreamMetrics{} or via this constructor — both
// produce identically-zeroed instances.
func NewH2UpstreamMetrics() *H2UpstreamMetrics {
	return &H2UpstreamMetrics{}
}

// incGoAwayObservedPrewarm increments the
// http2_upstream_goaway_observed_total{trigger="prewarm"} counter.
// Called from the pre-warm worker after draining c.wake.
func (m *H2UpstreamMetrics) incGoAwayObservedPrewarm() {
	if m == nil {
		return
	}
	m.goAwayObservedPrewarm.Add(1)
}

// incGoAwayObservedReactive increments the
// http2_upstream_goaway_observed_total{trigger="reactive"} counter.
// Called from selectUpstreamForDial when the slow path is taken
// (active Layer observed stale via isStaleH2).
func (m *H2UpstreamMetrics) incGoAwayObservedReactive() {
	if m == nil {
		return
	}
	m.goAwayObservedReactive.Add(1)
}

// incRefused increments the http2_upstream_refused_total counter.
// Called from openUpstreamStreamWithRetryFn when the FIRST OpenStream
// attempt returns *layer.StreamError{Code: ErrorRefused}. Fires
// BEFORE the retry attempt is made, so the counter is invariant under
// retry success/failure.
func (m *H2UpstreamMetrics) incRefused() {
	if m == nil {
		return
	}
	m.refused.Add(1)
}

// incRedialPrewarm increments the
// http2_upstream_redial_total{trigger="prewarm"} counter on a
// successful pre-warm worker dial. Pairs with the
// chainGenerationLive/Max gauge bump.
func (m *H2UpstreamMetrics) incRedialPrewarm() {
	if m == nil {
		return
	}
	m.redialPrewarm.Add(1)
}

// incRedialReactive increments the
// http2_upstream_redial_total{trigger="reactive"} counter on a
// successful selectUpstreamForDial slow-path fresh dial.
func (m *H2UpstreamMetrics) incRedialReactive() {
	if m == nil {
		return
	}
	m.redialReactive.Add(1)
}

// incRedialRefusedStream increments the
// http2_upstream_redial_total{trigger="refused_stream"} counter on a
// successful retry-path fresh dial. Heuristic — see Q9 godoc.
func (m *H2UpstreamMetrics) incRedialRefusedStream() {
	if m == nil {
		return
	}
	m.redialRefusedStream.Add(1)
}

// incRedialFailedPrewarm increments the
// http2_upstream_redial_failed_total{trigger="prewarm"} counter on a
// pre-warm worker dial failure.
func (m *H2UpstreamMetrics) incRedialFailedPrewarm() {
	if m == nil {
		return
	}
	m.redialFailedPrewarm.Add(1)
}

// incRedialFailedReactive increments the
// http2_upstream_redial_failed_total{trigger="reactive"} counter on a
// selectUpstreamForDial slow-path dial failure.
func (m *H2UpstreamMetrics) incRedialFailedReactive() {
	if m == nil {
		return
	}
	m.redialFailedReactive.Add(1)
}

// incRedialFailedRefusedStream increments the
// http2_upstream_redial_failed_total{trigger="refused_stream"} counter
// on a retry-path dial failure. Heuristic — see Q9 godoc.
func (m *H2UpstreamMetrics) incRedialFailedRefusedStream() {
	if m == nil {
		return
	}
	m.redialFailedRefusedStream.Add(1)
}

// incRetrySuccess increments the
// http2_upstream_retry_total{outcome="success"} counter on a
// successful retry-wrapper attempt.
func (m *H2UpstreamMetrics) incRetrySuccess() {
	if m == nil {
		return
	}
	m.retrySuccess.Add(1)
}

// incRetryFailRedial increments the
// http2_upstream_retry_total{outcome="fail_redial"} counter when the
// retry path observed no fresh Layer (heuristic: upL == upL2).
func (m *H2UpstreamMetrics) incRetryFailRedial() {
	if m == nil {
		return
	}
	m.retryFailRedial.Add(1)
}

// incRetryFailRedialRetry increments the
// http2_upstream_retry_total{outcome="fail_redial_retry"} counter when
// the retry path secured a fresh Layer (heuristic: upL != upL2) but
// the post-redial OpenStream still returned an error.
func (m *H2UpstreamMetrics) incRetryFailRedialRetry() {
	if m == nil {
		return
	}
	m.retryFailRedialRetry.Add(1)
}

// observeChainGeneration updates the chain-generation gauges after a
// redial-append. gen is the chain's redial-step count after the
// append (1 for the first redial, 2 for the second, etc.). Callers
// hold chain.mu so the relative ordering of Add(+1) on live and Max
// update is consistent within a single chain — the manager-wide
// chainGenerationMax is read-modify-write via CAS to track the
// process-wide high-water mark across all live chains.
func (m *H2UpstreamMetrics) observeChainGeneration(gen int64) {
	if m == nil {
		return
	}
	m.chainGenerationLive.Add(1)
	for {
		cur := m.chainGenerationMax.Load()
		if gen <= cur {
			return
		}
		if m.chainGenerationMax.CompareAndSwap(cur, gen) {
			return
		}
	}
}

// releaseChainGeneration drops the live gauge by gen, called from
// [redialChain.closeAll] at CONNECT exit. Without this, chainGenerationLive
// would grow monotonically with every CONNECT that redialed and the
// gauge becomes meaningless after enough churn.
func (m *H2UpstreamMetrics) releaseChainGeneration(gen int64) {
	if m == nil || gen <= 0 {
		return
	}
	m.chainGenerationLive.Add(-gen)
}

// H2UpstreamMetricsSnapshot is the immutable read-only view returned
// by [H2UpstreamMetrics.Snapshot] and [Manager.H2UpstreamMetrics]. JSON
// tags mirror the MCP query(resource:"status") field names so the same
// struct can be serialised on the MCP surface without an extra
// conversion. Counters are int64 (Prometheus convention "total");
// gauges are int64.
//
// The label-enum structure
// ({trigger=prewarm|reactive|refused_stream} and
// {outcome=success|fail_redial|fail_redial_retry}) is expressed as
// named fields rather than a map so the schema is statically typed and
// the MCP surface is stable across versions.
type H2UpstreamMetricsSnapshot struct {
	// GoAwayObservedPrewarm is
	// http2_upstream_goaway_observed_total{trigger="prewarm"}.
	GoAwayObservedPrewarm int64 `json:"goaway_observed_prewarm"`

	// GoAwayObservedReactive is
	// http2_upstream_goaway_observed_total{trigger="reactive"}.
	GoAwayObservedReactive int64 `json:"goaway_observed_reactive"`

	// Refused is http2_upstream_refused_total.
	Refused int64 `json:"refused"`

	// RedialPrewarm is
	// http2_upstream_redial_total{trigger="prewarm"}.
	RedialPrewarm int64 `json:"redial_prewarm"`

	// RedialReactive is
	// http2_upstream_redial_total{trigger="reactive"}.
	RedialReactive int64 `json:"redial_reactive"`

	// RedialRefusedStream is
	// http2_upstream_redial_total{trigger="refused_stream"}.
	RedialRefusedStream int64 `json:"redial_refused_stream"`

	// RedialFailedPrewarm is
	// http2_upstream_redial_failed_total{trigger="prewarm"}.
	RedialFailedPrewarm int64 `json:"redial_failed_prewarm"`

	// RedialFailedReactive is
	// http2_upstream_redial_failed_total{trigger="reactive"}.
	RedialFailedReactive int64 `json:"redial_failed_reactive"`

	// RedialFailedRefusedStream is
	// http2_upstream_redial_failed_total{trigger="refused_stream"}.
	RedialFailedRefusedStream int64 `json:"redial_failed_refused_stream"`

	// RetrySuccess is
	// http2_upstream_retry_total{outcome="success"}.
	RetrySuccess int64 `json:"retry_success"`

	// RetryFailRedial is
	// http2_upstream_retry_total{outcome="fail_redial"}.
	RetryFailRedial int64 `json:"retry_fail_redial"`

	// RetryFailRedialRetry is
	// http2_upstream_retry_total{outcome="fail_redial_retry"}.
	RetryFailRedialRetry int64 `json:"retry_fail_redial_retry"`

	// ChainGenerationMax is the all-time high-water mark of the
	// redial chain depth (CONNECT-scoped: each CONNECT's chain is
	// reported individually, the max across CONNECTs is reported
	// here).
	ChainGenerationMax int64 `json:"chain_generation_max"`

	// ChainGenerationLive is the current sum of redial-step counts
	// across all live redialChains. Decremented on CONNECT exit.
	ChainGenerationLive int64 `json:"chain_generation_live"`
}

// Snapshot returns the current values atomically-loaded from each
// counter. Safe to call concurrently with increments — each Load is
// independent, so the snapshot is a "tear-able" view (no global
// barrier across counters). Cross-counter invariants (e.g. retry_success
// + retry_fail_* == refused) MAY NOT hold under concurrent
// increments; this matches Prometheus scrape semantics (counters are
// independently scraped) and the connector.BudgetManager precedent.
// Returns the zero snapshot when m is nil.
func (m *H2UpstreamMetrics) Snapshot() H2UpstreamMetricsSnapshot {
	if m == nil {
		return H2UpstreamMetricsSnapshot{}
	}
	return H2UpstreamMetricsSnapshot{
		GoAwayObservedPrewarm:     m.goAwayObservedPrewarm.Load(),
		GoAwayObservedReactive:    m.goAwayObservedReactive.Load(),
		Refused:                   m.refused.Load(),
		RedialPrewarm:             m.redialPrewarm.Load(),
		RedialReactive:            m.redialReactive.Load(),
		RedialRefusedStream:       m.redialRefusedStream.Load(),
		RedialFailedPrewarm:       m.redialFailedPrewarm.Load(),
		RedialFailedReactive:      m.redialFailedReactive.Load(),
		RedialFailedRefusedStream: m.redialFailedRefusedStream.Load(),
		RetrySuccess:              m.retrySuccess.Load(),
		RetryFailRedial:           m.retryFailRedial.Load(),
		RetryFailRedialRetry:      m.retryFailRedialRetry.Load(),
		ChainGenerationMax:        m.chainGenerationMax.Load(),
		ChainGenerationLive:       m.chainGenerationLive.Load(),
	}
}
