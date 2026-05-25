package proxybuild

import "sync/atomic"

// H1UpstreamMetrics aggregates per-Manager counters that observe the
// USK-998 Phase 1 (stale-conn HealthCheck + redial) and USK-999 Phase 2
// (replay-safe retry on EPIPE) live-wire surface. Each counter is an
// atomic.Int64 so increment-from-multiple-goroutines is safe; readers
// use [H1UpstreamMetrics.Snapshot] which loads each field with
// atomic.Load semantics.
//
// Scope: one struct instance per [Manager] (Manager-level singleton),
// shared by every per-CONNECT [h1Chain] and every per-exchange
// [retryingUpstreamChannel] built under that manager. Multi-listener
// isolation is provided by Manager-per-listener — each Manager has its
// own metrics struct, never shared across managers.
//
// The struct is exported (vs the internal increment methods) so the
// production wiring (internal/mcpserver/init.go) can construct one
// instance before NewManager and thread the same pointer into
// [ManagerConfig.H1UpstreamMetrics] (status accessor) and
// [Deps.H1UpstreamMetrics] (per-listener instrumentation). Increment
// methods remain package-private — only h1Chain / retryingUpstreamChannel
// emit.
//
// Counter convention: established by internal/connector/budget.go's
// requestCount field + RequestCount() accessor. No new dependencies —
// sync/atomic is stdlib. There is no Prometheus exporter or HTTP
// listener in this repo; the MCP `status` resource is the single
// surface (see CLAUDE.md and design review Q1/Q2).
//
// h2 parity is deferred. After h2 grows an identical-shape
// H2UpstreamMetrics in a follow-up Issue, both can be lifted into a
// shared internal/proxybuild/upstream_metrics.go (memory:
// feedback_shared_seam_hardcoded_flag — don't extract shared infra at
// N=1).
type H1UpstreamMetrics struct {
	// staleDetectedHealthcheck counts the number of times
	// [h1Chain.EnsureFresh] observed a non-nil HealthCheck error and
	// proceeded to redial. Each increment maps to one
	// "trigger=healthcheck" stale-detection event on the wire.
	staleDetectedHealthcheck atomic.Int64

	// writeEpipe counts the number of times the retry wrapper observed
	// a *http1.StaleUpstreamError returned from the FIRST Send on a
	// per-exchange Channel — the race window between Phase 1's
	// HealthCheck and the wire Write where the server FINs in flight.
	// Every increment indicates a HealthCheck "miss" — Phase 1 cleared
	// the conn but the peer dropped it before our bytes landed.
	writeEpipe atomic.Int64

	// redialHealthcheck counts successful redials triggered by
	// [h1Chain.EnsureFresh] (HealthCheck err -> RedialUpstreamH1
	// success). The post-dial Layer-append and chain.current swap
	// happened.
	redialHealthcheck atomic.Int64

	// redialWriteEpipe counts successful redials triggered by
	// [h1Chain.Redial] (called from the retry wrapper after observing
	// a *http1.StaleUpstreamError on first Send). The post-dial
	// Layer-append and chain.current swap happened.
	redialWriteEpipe atomic.Int64

	// redialFailedHealthcheck counts dial failures inside
	// [h1Chain.EnsureFresh] (HealthCheck err -> RedialUpstreamH1
	// returned a non-nil error). The current Layer is unchanged in
	// this branch; the caller surfaces the dial error as
	// state="error" on the session.
	redialFailedHealthcheck atomic.Int64

	// redialFailedWriteEpipe counts dial failures inside
	// [h1Chain.Redial] (force-redial from the retry wrapper).
	// Symmetric to redialFailedHealthcheck.
	redialFailedWriteEpipe atomic.Int64

	// replaySuccess counts retry wrapper replays that landed (the
	// post-redial fresh-inner Send returned nil — the request reached
	// the upstream on the second try).
	replaySuccess atomic.Int64

	// replayFailNonidempotent counts retries refused because
	// [http1.StaleUpstreamError.ReplaySafe] was false at the header
	// stage (Stage=="header") — typically a non-idempotent method
	// (POST, PATCH) with no body buffer.
	replayFailNonidempotent atomic.Int64

	// replayFailBodyConsumed counts retries refused because
	// [http1.StaleUpstreamError.ReplaySafe] was false at the body
	// stage (Stage=="body") — the body has already been streamed and
	// cannot be replayed without a buffer.
	replayFailBodyConsumed atomic.Int64

	// replayFailRedial counts retries that aborted because
	// [h1Chain.Redial] itself returned a dial error. The original
	// stale error is wrapped + joined for diagnostics; the
	// post-redial Send was never attempted.
	replayFailRedial atomic.Int64

	// replayFailRedialReplay counts retries where [h1Chain.Redial]
	// succeeded but the post-redial replay Send still returned a
	// non-nil error (the fresh upstream broke again on the second
	// attempt). The retry budget is consumed; no second retry.
	replayFailRedialReplay atomic.Int64

	// chainGenerationMax is the high-water mark of the redial chain
	// depth observed across the manager's lifetime. Updated under
	// chain.mu in [h1Chain.EnsureFresh] / [h1Chain.Redial] right after
	// the layer-append. Never decreases — diagnostic "worst case" for
	// upstream churn.
	chainGenerationMax atomic.Int64

	// chainGenerationLive is the sum of redial-step counts across
	// every currently-live h1Chain. Each chain contributes the number
	// of redial steps it has executed (chain.layers length minus the
	// implicit initial Layer). Incremented on redial-append,
	// decremented on [h1Chain.closeAll] (CONNECT exit). Keeps the
	// gauge meaningful across many CONNECTs.
	chainGenerationLive atomic.Int64
}

// NewH1UpstreamMetrics returns a fresh zero-valued counter struct.
// Production wiring (internal/mcpserver/init.go) constructs one
// instance and threads it into both [ManagerConfig.H1UpstreamMetrics]
// and [Deps.H1UpstreamMetrics] so all per-listener instrumentation
// updates a single Manager-level counter set.
//
// Tests that need to read counters in isolation can construct one
// directly via &H1UpstreamMetrics{} or via this constructor — both
// produce identically-zeroed instances.
func NewH1UpstreamMetrics() *H1UpstreamMetrics {
	return &H1UpstreamMetrics{}
}

// incStaleDetectedHealthcheck increments the
// http1_upstream_stale_detected_total{trigger="healthcheck"} counter.
// Called from [h1Chain.EnsureFresh] on HealthCheck err.
func (m *H1UpstreamMetrics) incStaleDetectedHealthcheck() {
	if m == nil {
		return
	}
	m.staleDetectedHealthcheck.Add(1)
}

// incWriteEpipe increments the http1_upstream_write_epipe_total
// counter. Called from [retryingUpstreamChannel.Send] when the FIRST
// Send returns a *http1.StaleUpstreamError (race-window-after-Phase-1
// failure).
func (m *H1UpstreamMetrics) incWriteEpipe() {
	if m == nil {
		return
	}
	m.writeEpipe.Add(1)
}

// incRedialHealthcheck increments the
// http1_upstream_redial_total{trigger="healthcheck"} counter on
// successful EnsureFresh-triggered redial. Pairs with the
// chainGenerationLive/Max gauge bump in [h1Chain.bumpGenerationLocked].
func (m *H1UpstreamMetrics) incRedialHealthcheck() {
	if m == nil {
		return
	}
	m.redialHealthcheck.Add(1)
}

// incRedialWriteEpipe increments the
// http1_upstream_redial_total{trigger="write_epipe"} counter on
// successful retry-wrapper-triggered redial.
func (m *H1UpstreamMetrics) incRedialWriteEpipe() {
	if m == nil {
		return
	}
	m.redialWriteEpipe.Add(1)
}

// incRedialFailedHealthcheck increments the
// http1_upstream_redial_failed_total{trigger="healthcheck"} counter
// (scope-adjustment #1) — captures EnsureFresh dial failures that the
// retry wrapper's replay path cannot cover.
func (m *H1UpstreamMetrics) incRedialFailedHealthcheck() {
	if m == nil {
		return
	}
	m.redialFailedHealthcheck.Add(1)
}

// incRedialFailedWriteEpipe increments the
// http1_upstream_redial_failed_total{trigger="write_epipe"} counter
// (scope-adjustment #1) — symmetric to incRedialFailedHealthcheck
// for the retry wrapper's force-redial path.
func (m *H1UpstreamMetrics) incRedialFailedWriteEpipe() {
	if m == nil {
		return
	}
	m.redialFailedWriteEpipe.Add(1)
}

// incReplaySuccess increments the
// http1_upstream_replay_total{outcome="success"} counter on a
// successful retry-wrapper replay.
func (m *H1UpstreamMetrics) incReplaySuccess() {
	if m == nil {
		return
	}
	m.replaySuccess.Add(1)
}

// incReplayFailNonidempotent increments the
// http1_upstream_replay_total{outcome="fail_nonidempotent"} counter
// when ReplaySafe=false at the header stage.
func (m *H1UpstreamMetrics) incReplayFailNonidempotent() {
	if m == nil {
		return
	}
	m.replayFailNonidempotent.Add(1)
}

// incReplayFailBodyConsumed increments the
// http1_upstream_replay_total{outcome="fail_body_consumed"} counter
// when ReplaySafe=false at the body stage.
func (m *H1UpstreamMetrics) incReplayFailBodyConsumed() {
	if m == nil {
		return
	}
	m.replayFailBodyConsumed.Add(1)
}

// incReplayFailRedial increments the
// http1_upstream_replay_total{outcome="fail_redial"} counter when the
// retry-wrapper's chain.Redial itself returned a dial error.
func (m *H1UpstreamMetrics) incReplayFailRedial() {
	if m == nil {
		return
	}
	m.replayFailRedial.Add(1)
}

// incReplayFailRedialReplay increments the
// http1_upstream_replay_total{outcome="fail_redial_replay"} counter
// (scope-adjustment #3) when chain.Redial succeeded but the
// post-redial replay Send still returned an error.
func (m *H1UpstreamMetrics) incReplayFailRedialReplay() {
	if m == nil {
		return
	}
	m.replayFailRedialReplay.Add(1)
}

// observeChainGeneration updates the chain-generation gauges after a
// redial-append. gen is the chain's redial-step count after the
// append (1 for the first redial, 2 for the second, etc.). Callers
// hold chain.mu so the relative ordering of Add(+1) on live and Max
// update is consistent within a single chain — the manager-wide
// chainGenerationMax is read-modify-write via CAS to track the
// process-wide high-water mark across all live chains.
func (m *H1UpstreamMetrics) observeChainGeneration(gen int64) {
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
// [h1Chain.closeAll] at CONNECT exit. Without this, chainGenerationLive
// would grow monotonically with every CONNECT that redialed and the
// gauge becomes meaningless after enough churn.
func (m *H1UpstreamMetrics) releaseChainGeneration(gen int64) {
	if m == nil || gen <= 0 {
		return
	}
	m.chainGenerationLive.Add(-gen)
}

// H1UpstreamMetricsSnapshot is the immutable read-only view returned
// by [H1UpstreamMetrics.Snapshot] and [Manager.H1UpstreamMetrics]. JSON
// tags mirror the MCP query(resource:"status") field names so the same
// struct can be serialised on the MCP surface without an extra
// conversion. Counters are int64 (Prometheus convention "total");
// gauges are int64.
//
// The label-enum structure ({trigger=healthcheck|write_epipe} and
// {outcome=success|fail_nonidempotent|fail_body_consumed|fail_redial|fail_redial_replay})
// is expressed as named fields rather than a map so the schema is
// statically typed and the MCP surface is stable across versions.
type H1UpstreamMetricsSnapshot struct {
	// StaleDetectedHealthcheck is
	// http1_upstream_stale_detected_total{trigger="healthcheck"}.
	StaleDetectedHealthcheck int64 `json:"stale_detected_healthcheck"`

	// WriteEpipe is http1_upstream_write_epipe_total.
	WriteEpipe int64 `json:"write_epipe"`

	// RedialHealthcheck is
	// http1_upstream_redial_total{trigger="healthcheck"}.
	RedialHealthcheck int64 `json:"redial_healthcheck"`

	// RedialWriteEpipe is
	// http1_upstream_redial_total{trigger="write_epipe"}.
	RedialWriteEpipe int64 `json:"redial_write_epipe"`

	// RedialFailedHealthcheck is
	// http1_upstream_redial_failed_total{trigger="healthcheck"}
	// (scope-adjustment #1).
	RedialFailedHealthcheck int64 `json:"redial_failed_healthcheck"`

	// RedialFailedWriteEpipe is
	// http1_upstream_redial_failed_total{trigger="write_epipe"}
	// (scope-adjustment #1).
	RedialFailedWriteEpipe int64 `json:"redial_failed_write_epipe"`

	// ReplaySuccess is http1_upstream_replay_total{outcome="success"}.
	ReplaySuccess int64 `json:"replay_success"`

	// ReplayFailNonidempotent is
	// http1_upstream_replay_total{outcome="fail_nonidempotent"}.
	ReplayFailNonidempotent int64 `json:"replay_fail_nonidempotent"`

	// ReplayFailBodyConsumed is
	// http1_upstream_replay_total{outcome="fail_body_consumed"}.
	ReplayFailBodyConsumed int64 `json:"replay_fail_body_consumed"`

	// ReplayFailRedial is
	// http1_upstream_replay_total{outcome="fail_redial"}.
	ReplayFailRedial int64 `json:"replay_fail_redial"`

	// ReplayFailRedialReplay is
	// http1_upstream_replay_total{outcome="fail_redial_replay"}
	// (scope-adjustment #3).
	ReplayFailRedialReplay int64 `json:"replay_fail_redial_replay"`

	// ChainGenerationMax is the all-time high-water mark of redial
	// chain depth (CONNECT-scoped: each CONNECT's chain is reported
	// individually, the max across CONNECTs is reported here).
	ChainGenerationMax int64 `json:"chain_generation_max"`

	// ChainGenerationLive is the current sum of redial-step counts
	// across all live h1Chains. Decremented on CONNECT exit.
	ChainGenerationLive int64 `json:"chain_generation_live"`
}

// Snapshot returns the current values atomically-loaded from each
// counter. Safe to call concurrently with increments — each Load is
// independent, so the snapshot is a "tear-able" view (no global
// barrier across counters). This matches Prometheus scrape semantics
// (counters are independently scraped) and the connector.BudgetManager
// precedent. Returns the zero snapshot when m is nil.
func (m *H1UpstreamMetrics) Snapshot() H1UpstreamMetricsSnapshot {
	if m == nil {
		return H1UpstreamMetricsSnapshot{}
	}
	return H1UpstreamMetricsSnapshot{
		StaleDetectedHealthcheck: m.staleDetectedHealthcheck.Load(),
		WriteEpipe:               m.writeEpipe.Load(),
		RedialHealthcheck:        m.redialHealthcheck.Load(),
		RedialWriteEpipe:         m.redialWriteEpipe.Load(),
		RedialFailedHealthcheck:  m.redialFailedHealthcheck.Load(),
		RedialFailedWriteEpipe:   m.redialFailedWriteEpipe.Load(),
		ReplaySuccess:            m.replaySuccess.Load(),
		ReplayFailNonidempotent:  m.replayFailNonidempotent.Load(),
		ReplayFailBodyConsumed:   m.replayFailBodyConsumed.Load(),
		ReplayFailRedial:         m.replayFailRedial.Load(),
		ReplayFailRedialReplay:   m.replayFailRedialReplay.Load(),
		ChainGenerationMax:       m.chainGenerationMax.Load(),
		ChainGenerationLive:      m.chainGenerationLive.Load(),
	}
}
