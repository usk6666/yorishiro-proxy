package proxybuild

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestH2Metrics_NewIsZero asserts a fresh counter set returns the zero
// snapshot. Mirrors TestH1Metrics_NewIsZero.
func TestH2Metrics_NewIsZero(t *testing.T) {
	t.Parallel()
	m := NewH2UpstreamMetrics()
	snap := m.Snapshot()
	if snap != (H2UpstreamMetricsSnapshot{}) {
		t.Errorf("NewH2UpstreamMetrics: snapshot = %+v, want zero", snap)
	}
}

// TestH2Metrics_NilSafe asserts every emit method short-circuits on a
// nil receiver. Production callers do not check for nil — the
// emit-site doc-comment promises nil-safety. Mirrors
// TestH1Metrics_NilSafe.
func TestH2Metrics_NilSafe(t *testing.T) {
	t.Parallel()
	var m *H2UpstreamMetrics // nil pointer
	// All emit methods must not panic on nil. Snapshot returns the
	// zero value.
	m.incGoAwayObservedPrewarm()
	m.incGoAwayObservedReactive()
	m.incRefused()
	m.incRedialPrewarm()
	m.incRedialReactive()
	m.incRedialRefusedStream()
	m.incRedialFailedPrewarm()
	m.incRedialFailedReactive()
	m.incRedialFailedRefusedStream()
	m.incRetrySuccess()
	m.incRetryFailRedial()
	m.incRetryFailRedialRetry()
	m.observeChainGeneration(5)
	m.releaseChainGeneration(5)
	snap := m.Snapshot()
	if snap != (H2UpstreamMetricsSnapshot{}) {
		t.Errorf("nil-receiver Snapshot: %+v, want zero", snap)
	}
}

// TestH2Metrics_DirectIncrements asserts each emit helper increments
// the corresponding atomic.Int64 exactly once. Mirrors
// TestH1Metrics_DirectIncrements — one row per (counter, label) tuple.
func TestH2Metrics_DirectIncrements(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		emit func(*H2UpstreamMetrics)
		want func(H2UpstreamMetricsSnapshot) int64
	}{
		{
			name: "goaway_observed_prewarm",
			emit: (*H2UpstreamMetrics).incGoAwayObservedPrewarm,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.GoAwayObservedPrewarm },
		},
		{
			name: "goaway_observed_reactive",
			emit: (*H2UpstreamMetrics).incGoAwayObservedReactive,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.GoAwayObservedReactive },
		},
		{
			name: "refused",
			emit: (*H2UpstreamMetrics).incRefused,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.Refused },
		},
		{
			name: "redial_prewarm",
			emit: (*H2UpstreamMetrics).incRedialPrewarm,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RedialPrewarm },
		},
		{
			name: "redial_reactive",
			emit: (*H2UpstreamMetrics).incRedialReactive,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RedialReactive },
		},
		{
			name: "redial_refused_stream",
			emit: (*H2UpstreamMetrics).incRedialRefusedStream,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RedialRefusedStream },
		},
		{
			name: "redial_failed_prewarm",
			emit: (*H2UpstreamMetrics).incRedialFailedPrewarm,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RedialFailedPrewarm },
		},
		{
			name: "redial_failed_reactive",
			emit: (*H2UpstreamMetrics).incRedialFailedReactive,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RedialFailedReactive },
		},
		{
			name: "redial_failed_refused_stream",
			emit: (*H2UpstreamMetrics).incRedialFailedRefusedStream,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RedialFailedRefusedStream },
		},
		{
			name: "retry_success",
			emit: (*H2UpstreamMetrics).incRetrySuccess,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RetrySuccess },
		},
		{
			name: "retry_fail_redial",
			emit: (*H2UpstreamMetrics).incRetryFailRedial,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RetryFailRedial },
		},
		{
			name: "retry_fail_redial_retry",
			emit: (*H2UpstreamMetrics).incRetryFailRedialRetry,
			want: func(s H2UpstreamMetricsSnapshot) int64 { return s.RetryFailRedialRetry },
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewH2UpstreamMetrics()
			tc.emit(m)
			tc.emit(m)
			snap := m.Snapshot()
			if got := tc.want(snap); got != 2 {
				t.Errorf("%s after 2 increments = %d, want 2", tc.name, got)
			}
		})
	}
}

// TestH2Metrics_ChainGeneration asserts the gauge family: observe
// increments Live and updates Max; release decrements Live but does
// not touch Max. Max records the high-water mark across the lifetime.
// Mirrors TestH1Metrics_ChainGeneration.
func TestH2Metrics_ChainGeneration(t *testing.T) {
	t.Parallel()
	m := NewH2UpstreamMetrics()

	// First chain redials twice -> generations 1, 2.
	m.observeChainGeneration(1)
	m.observeChainGeneration(2)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 2 || snap.ChainGenerationMax != 2 {
		t.Errorf("after 2 observes (1,2): live=%d max=%d, want live=2 max=2",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// Second chain redials thrice -> generations 1, 2, 3.
	m.observeChainGeneration(1)
	m.observeChainGeneration(2)
	m.observeChainGeneration(3)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 5 || snap.ChainGenerationMax != 3 {
		t.Errorf("after second chain (1,2,3): live=%d max=%d, want live=5 max=3",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// First chain closes (released gen=2). Live drops by 2; max stays at 3.
	m.releaseChainGeneration(2)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 3 || snap.ChainGenerationMax != 3 {
		t.Errorf("after release(2): live=%d max=%d, want live=3 max=3",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// Second chain closes (released gen=3). Live -> 0, max stays.
	m.releaseChainGeneration(3)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 0 || snap.ChainGenerationMax != 3 {
		t.Errorf("after release(3): live=%d max=%d, want live=0 max=3",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// release(0) is a no-op.
	m.releaseChainGeneration(0)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 0 {
		t.Errorf("release(0): live=%d, want 0", snap.ChainGenerationLive)
	}
}

// TestH2Chain_Metrics_ReactiveRedialFail drives a stale pooled Layer
// through selectUpstreamForDial with a failing redialFn and asserts
// the reactive trigger labels fire: incGoAwayObservedReactive +
// incRedialFailedReactive. Mirrors the h1
// TestH1Chain_Metrics_EnsureFreshDialFail shape.
func TestH2Chain_Metrics_ReactiveRedialFail(t *testing.T) {
	t.Parallel()
	stale, peer := dialPeerH2Layer(t)
	defer stale.Close()
	_ = peer.Close()
	awaitShutdown(t, stale)

	wantErr := errors.New("dial: synthetic")
	dialFresh := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		return nil, wantErr
	}

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	defer chain.closeAll()

	got := selectUpstreamForDial(
		context.Background(), "example.test:443",
		stale, chain, dialFresh, silentLogger(),
	)
	if got != stale {
		t.Errorf("selectUpstreamForDial after redial-fail = %p, want stale %p", got, stale)
	}
	snap := m.Snapshot()
	if snap.GoAwayObservedReactive < 1 {
		t.Errorf("goaway_observed_reactive = %d, want >= 1", snap.GoAwayObservedReactive)
	}
	if snap.RedialFailedReactive < 1 {
		t.Errorf("redial_failed_reactive = %d, want >= 1", snap.RedialFailedReactive)
	}
	// Successful redial did NOT fire.
	if snap.RedialReactive != 0 {
		t.Errorf("redial_reactive = %d, want 0 on dial-failure path", snap.RedialReactive)
	}
	// The prewarm / refused_stream triggers must NOT fire from a
	// reactive call.
	if snap.GoAwayObservedPrewarm != 0 || snap.RedialPrewarm != 0 || snap.RedialFailedPrewarm != 0 {
		t.Errorf("prewarm counters fired during reactive path: %+v", snap)
	}
	if snap.RedialRefusedStream != 0 || snap.RedialFailedRefusedStream != 0 || snap.Refused != 0 {
		t.Errorf("refused_stream counters fired during reactive path: %+v", snap)
	}
}

// TestH2Chain_Metrics_ReactiveRedialSuccess pins the success-path
// reactive counter set: stale pooled triggers exactly one
// goaway_observed_reactive + one redial_reactive + one
// chain_generation gauge bump.
func TestH2Chain_Metrics_ReactiveRedialSuccess(t *testing.T) {
	t.Parallel()
	stale, stalePeer := dialPeerH2Layer(t)
	defer stale.Close()
	_ = stalePeer.Close()
	awaitShutdown(t, stale)

	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	dialFresh := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		return fresh, nil
	}

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	defer chain.closeAll()

	got := selectUpstreamForDial(
		context.Background(), "example.test:443",
		stale, chain, dialFresh, silentLogger(),
	)
	if got != fresh {
		t.Errorf("selectUpstreamForDial = %p, want fresh %p", got, fresh)
	}
	snap := m.Snapshot()
	if snap.GoAwayObservedReactive != 1 {
		t.Errorf("goaway_observed_reactive = %d, want 1", snap.GoAwayObservedReactive)
	}
	if snap.RedialReactive != 1 {
		t.Errorf("redial_reactive = %d, want 1", snap.RedialReactive)
	}
	if snap.RedialFailedReactive != 0 {
		t.Errorf("redial_failed_reactive = %d, want 0", snap.RedialFailedReactive)
	}
	if snap.ChainGenerationLive != 1 || snap.ChainGenerationMax != 1 {
		t.Errorf("chain_generation: live=%d max=%d, want live=1 max=1",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}
}

// TestH2Retry_Metrics_RefusedSuccess drives the USK-993 retry path
// (first OpenStream returns Refused → fresh dial → second OpenStream
// succeeds) and asserts the refused + retry_success counters fire
// (plus redial_refused_stream because the second selectUpstreamForDial
// uses dialTriggerRefusedStream).
func TestH2Retry_Metrics_RefusedSuccess(t *testing.T) {
	t.Parallel()
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()
	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)

	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		return fresh, nil
	}

	stubChan := stubChannel{streamID: 7}
	var openCalls int32
	openFn := func(_ context.Context, l *http2.Layer) (layer.Channel, error) {
		n := atomic.AddInt32(&openCalls, 1)
		if n == 1 {
			return nil, &layer.StreamError{Code: layer.ErrorRefused, Reason: "layer shutdown"}
		}
		if l != fresh {
			t.Errorf("attempt %d: openStream got %p, want fresh %p", n, l, fresh)
		}
		return stubChan, nil
	}

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	defer chain.closeAll()

	_, _, err := openUpstreamStreamWithRetryFn(
		context.Background(), "example.test:443",
		pooled, chain, redialFn, openFn, silentLogger(),
	)
	if err != nil {
		t.Fatalf("openUpstreamStreamWithRetryFn: %v", err)
	}
	snap := m.Snapshot()
	if snap.Refused != 1 {
		t.Errorf("refused = %d, want 1", snap.Refused)
	}
	if snap.RetrySuccess != 1 {
		t.Errorf("retry_success = %d, want 1", snap.RetrySuccess)
	}
	if snap.RetryFailRedial != 0 || snap.RetryFailRedialRetry != 0 {
		t.Errorf("retry_fail_* counters fired during retry-success path: %+v", snap)
	}
	// The retry path uses dialTriggerRefusedStream. The first
	// selectUpstreamForDial inside the helper uses the reactive
	// trigger (incRedialReactive on success), but the SECOND call —
	// the one driven by the Refused retry — uses
	// dialTriggerRefusedStream. The pooled was stale at construction,
	// so the first call dials fresh under reactive and the second
	// call observes that fresh head and bypasses its own dial
	// (no refused_stream redial). Net: redial_reactive=1,
	// redial_refused_stream=0.
	if snap.RedialReactive != 1 {
		t.Errorf("redial_reactive = %d, want 1", snap.RedialReactive)
	}
	if snap.RedialRefusedStream != 0 {
		t.Errorf("redial_refused_stream = %d, want 0 (first-call reactive dial fresh-handled the chain head)",
			snap.RedialRefusedStream)
	}
}

// TestH2Retry_Metrics_NonRefusedNoCount asserts a non-Refused error
// from the first OpenStream attempt does NOT increment refused/retry
// counters — the error passes through verbatim.
func TestH2Retry_Metrics_NonRefusedNoCount(t *testing.T) {
	t.Parallel()
	pooled, peer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer peer.Close()

	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		t.Error("redialFn must not be called for non-Refused error")
		return nil, errors.New("unexpected redial")
	}
	wantErr := errors.New("synthetic non-refused")
	openFn := func(_ context.Context, _ *http2.Layer) (layer.Channel, error) {
		return nil, wantErr
	}

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	defer chain.closeAll()

	_, _, err := openUpstreamStreamWithRetryFn(
		context.Background(), "example.test:443",
		pooled, chain, redialFn, openFn, silentLogger(),
	)
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	snap := m.Snapshot()
	if snap.Refused != 0 || snap.RetrySuccess != 0 || snap.RetryFailRedial != 0 || snap.RetryFailRedialRetry != 0 {
		t.Errorf("non-Refused path incremented retry counters: %+v", snap)
	}
}

// TestH2Chain_Metrics_CloseAllReleasesGauge asserts closeAll
// decrements chainGenerationLive by this chain's contribution but
// leaves chainGenerationMax intact. Multi-chain scoping is exercised
// by manually injecting a second chain's contribution into the same
// metrics struct. Mirrors TestH1Chain_Metrics_CloseAllReleasesGauge.
func TestH2Chain_Metrics_CloseAllReleasesGauge(t *testing.T) {
	t.Parallel()
	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)

	// Simulate 2 successful redials by directly bumping the gauge
	// under c.mu (avoids needing a working dial).
	chain.mu.Lock()
	chain.liveGen = 2
	chain.mu.Unlock()
	m.observeChainGeneration(1)
	m.observeChainGeneration(2)
	// Add a second chain's contribution to verify isolation.
	m.observeChainGeneration(1)

	beforeMax := m.Snapshot().ChainGenerationMax
	beforeLive := m.Snapshot().ChainGenerationLive
	if beforeLive != 3 || beforeMax != 2 {
		t.Fatalf("setup: live=%d max=%d, want live=3 max=2", beforeLive, beforeMax)
	}

	chain.closeAll()

	snap := m.Snapshot()
	if snap.ChainGenerationLive != 1 {
		t.Errorf("closeAll: live=%d, want 1 (second chain's contribution remains)",
			snap.ChainGenerationLive)
	}
	if snap.ChainGenerationMax != 2 {
		t.Errorf("closeAll: max=%d, want 2 (Max never decreases)", snap.ChainGenerationMax)
	}
	// Repeat call: closeAll is idempotent. liveGen has been zeroed so
	// the second call is a no-op (no double-decrement of the manager
	// gauge).
	chain.closeAll()
	if snap2 := m.Snapshot(); snap2.ChainGenerationLive != 1 {
		t.Errorf("second closeAll caused double-decrement: live=%d, want 1",
			snap2.ChainGenerationLive)
	}
}

// TestH2Metrics_PrewarmTriggersIsolated drives the pre-warm worker
// drain via tickleWake and asserts the prewarm trigger labels fire
// without leaking into reactive / refused_stream slots. The dialFresh
// closure returns an error so we exercise the failure path; the
// drain count is asserted via incGoAwayObservedPrewarm.
func TestH2Metrics_PrewarmTriggersIsolated(t *testing.T) {
	t.Parallel()
	stale, stalePeer := dialPeerH2Layer(t)
	defer stale.Close()
	_ = stalePeer.Close()
	awaitShutdown(t, stale)

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	// Manually seed chain.current so the worker's head check returns
	// the stale Layer (and is_stale=true so the dial path is taken).
	chain.current.Store(stale)
	defer chain.closeAll()

	dialErr := errors.New("dial: synthetic prewarm")
	dialDone := make(chan struct{}, 1)
	dialFresh := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		dialDone <- struct{}{}
		return nil, dialErr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(ctx, "example.test:443", dialFresh, nil, silentLogger())

	chain.tickleWake()

	// Wait for the worker to drain the wake and run dialFresh.
	<-dialDone

	// Allow the worker a moment to update counters after dialFresh
	// returns; we poll the metric since the worker emits AFTER the
	// dial returns.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Snapshot().RedialFailedPrewarm < 1 {
		time.Sleep(5 * time.Millisecond)
	}

	snap := m.Snapshot()
	if snap.GoAwayObservedPrewarm < 1 {
		t.Errorf("goaway_observed_prewarm = %d, want >= 1", snap.GoAwayObservedPrewarm)
	}
	if snap.RedialFailedPrewarm < 1 {
		t.Errorf("redial_failed_prewarm = %d, want >= 1", snap.RedialFailedPrewarm)
	}
	if snap.RedialPrewarm != 0 {
		t.Errorf("redial_prewarm = %d, want 0 on dial-failure path", snap.RedialPrewarm)
	}
	// Reactive / refused_stream labels must NOT fire from a prewarm
	// drain.
	if snap.GoAwayObservedReactive != 0 || snap.RedialReactive != 0 || snap.RedialFailedReactive != 0 {
		t.Errorf("reactive counters fired during prewarm path: %+v", snap)
	}
	if snap.Refused != 0 || snap.RedialRefusedStream != 0 || snap.RedialFailedRefusedStream != 0 {
		t.Errorf("refused_stream counters fired during prewarm path: %+v", snap)
	}
}
