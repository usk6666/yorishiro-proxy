//go:build e2e && !e2e_smoke

// USK-1001 integration: h2 upstream redial metrics counted through the
// real selectUpstreamForDial / openUpstreamStreamWithRetryFn / pre-warm
// worker dispatch on real *http2.Layer pairs (preface-completed via
// dialPeerH2Layer). Exhaustive tier (`//go:build e2e && !e2e_smoke`)
// per CLAUDE.md — counter wiring is diagnostic, not browser-parity
// wire-behavior gate.
//
// The three scenarios covered:
//
//	1. reactive — a peer-FINed pooled Layer drives selectUpstreamForDial's
//	   slow path; goaway_observed_reactive + redial_reactive +
//	   chain_generation gauge bump fire exactly once.
//	2. refused-retry — first OpenStream returns Refused, the retry path
//	   uses dialTriggerRefusedStream and bumps retry_success.
//	3. pre-warm — chain.tickleWake drives the worker, which dials and
//	   bumps redial_prewarm (or redial_failed_prewarm on dial error).

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

// TestE2E_H2Metrics_Reactive drives the full
// selectUpstreamForDial slow path on a peer-FINed pooled Layer and
// asserts the reactive trigger counters fire on a SUCCESSFUL redial.
func TestE2E_H2Metrics_Reactive(t *testing.T) {
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
		t.Fatalf("selectUpstreamForDial = %p, want fresh %p", got, fresh)
	}

	snap := m.Snapshot()
	if snap.GoAwayObservedReactive != 1 {
		t.Errorf("goaway_observed_reactive = %d, want 1", snap.GoAwayObservedReactive)
	}
	if snap.RedialReactive != 1 {
		t.Errorf("redial_reactive = %d, want 1", snap.RedialReactive)
	}
	if snap.ChainGenerationLive != 1 || snap.ChainGenerationMax != 1 {
		t.Errorf("chain_generation: live=%d max=%d, want live=1 max=1",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}
}

// TestE2E_H2Metrics_RefusedRetrySuccess drives the USK-993 retry path
// end-to-end: first OpenStream returns Refused → metrics record one
// `refused` + one `retry_success`. The first selectUpstreamForDial
// dialed fresh under reactive (the pooled was already stale), so
// redial_reactive=1; the second selectUpstreamForDial saw the fresh
// head and short-circuited so redial_refused_stream=0.
func TestE2E_H2Metrics_RefusedRetrySuccess(t *testing.T) {
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
	stubChan := stubChannel{streamID: 5}
	var openCalls int32
	openFn := func(_ context.Context, l *http2.Layer) (layer.Channel, error) {
		n := atomic.AddInt32(&openCalls, 1)
		if n == 1 {
			return nil, &layer.StreamError{Code: layer.ErrorRefused, Reason: "GOAWAY sent"}
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
		t.Errorf("retry_fail_* fired during retry-success: %+v", snap)
	}
}

// TestE2E_H2Metrics_PrewarmDialSuccess drives the pre-warm worker
// against a stale chain head with a successful dialFresh and asserts
// the prewarm-trigger counters fire (goaway_observed_prewarm +
// redial_prewarm + chain_generation gauge bump).
func TestE2E_H2Metrics_PrewarmDialSuccess(t *testing.T) {
	t.Parallel()
	stale, stalePeer := dialPeerH2Layer(t)
	defer stale.Close()
	_ = stalePeer.Close()
	awaitShutdown(t, stale)

	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	// Manually point chain.current at the stale Layer so the worker's
	// head-check sees staleness and proceeds to dial. The worker
	// otherwise reads chain.headLayer() == nil and skips on the first
	// wake.
	chain.current.Store(stale)
	defer chain.closeAll()

	dialReturned := make(chan struct{}, 1)
	dialFresh := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		dialReturned <- struct{}{}
		return fresh, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(ctx, "example.test:443", dialFresh, nil, silentLogger())

	chain.tickleWake()
	<-dialReturned

	// Wait for the worker to publish the metric updates (append +
	// counter inc happen after dialFresh returns).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Snapshot().RedialPrewarm < 1 {
		time.Sleep(5 * time.Millisecond)
	}

	snap := m.Snapshot()
	if snap.GoAwayObservedPrewarm != 1 {
		t.Errorf("goaway_observed_prewarm = %d, want 1", snap.GoAwayObservedPrewarm)
	}
	if snap.RedialPrewarm != 1 {
		t.Errorf("redial_prewarm = %d, want 1", snap.RedialPrewarm)
	}
	if snap.RedialFailedPrewarm != 0 {
		t.Errorf("redial_failed_prewarm = %d, want 0 on success path", snap.RedialFailedPrewarm)
	}
	if snap.ChainGenerationLive != 1 || snap.ChainGenerationMax != 1 {
		t.Errorf("chain_generation: live=%d max=%d, want live=1 max=1",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}
	// Reactive / refused_stream labels must NOT fire from a prewarm
	// drain.
	if snap.GoAwayObservedReactive != 0 || snap.RedialReactive != 0 {
		t.Errorf("reactive counters fired during prewarm path: %+v", snap)
	}
	if snap.Refused != 0 || snap.RedialRefusedStream != 0 {
		t.Errorf("refused_stream counters fired during prewarm path: %+v", snap)
	}
}

// TestE2E_H2Metrics_PrewarmDialFail mirrors PrewarmDialSuccess but
// with dialFresh returning an error → incRedialFailedPrewarm fires
// without redial_prewarm; chain_generation gauge stays at 0.
func TestE2E_H2Metrics_PrewarmDialFail(t *testing.T) {
	t.Parallel()
	stale, stalePeer := dialPeerH2Layer(t)
	defer stale.Close()
	_ = stalePeer.Close()
	awaitShutdown(t, stale)

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	chain.current.Store(stale)
	defer chain.closeAll()

	dialReturned := make(chan struct{}, 1)
	dialFresh := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		dialReturned <- struct{}{}
		return nil, errors.New("synthetic prewarm dial failure")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(ctx, "example.test:443", dialFresh, nil, silentLogger())

	chain.tickleWake()
	<-dialReturned

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Snapshot().RedialFailedPrewarm < 1 {
		time.Sleep(5 * time.Millisecond)
	}

	snap := m.Snapshot()
	if snap.GoAwayObservedPrewarm != 1 {
		t.Errorf("goaway_observed_prewarm = %d, want 1", snap.GoAwayObservedPrewarm)
	}
	if snap.RedialFailedPrewarm != 1 {
		t.Errorf("redial_failed_prewarm = %d, want 1", snap.RedialFailedPrewarm)
	}
	if snap.RedialPrewarm != 0 {
		t.Errorf("redial_prewarm = %d, want 0 on failure path", snap.RedialPrewarm)
	}
	if snap.ChainGenerationLive != 0 {
		t.Errorf("chain_generation_live = %d, want 0 (failed dial does NOT append)",
			snap.ChainGenerationLive)
	}
}
