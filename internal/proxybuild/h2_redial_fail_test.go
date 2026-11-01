package proxybuild

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// A failed upstream h2 redial is a proxy-local failure. OpenStream on the
// stale Layer it leaves behind refuses, but that refusal must not reach
// the session as an upstream ErrorRefused: the session would then reset
// the client stream with the retryable REFUSED_STREAM and the client would
// loop on it until its own timeout. These tests pin that the redial
// error comes back as a non-Refused error (the session then resets with
// CANCEL) after a single dial.

var errRedialRefused = errors.New("dial tcp 127.0.0.1:9: connect: connection refused")

// TestOpenUpstreamStreamWithRetry_RedialFailsReturnsDialError: the pooled
// Layer is stale (peer gone) and the redial fails. The helper must return
// an error wrapping the dial error, not the stale Layer's refusal, and
// must dial exactly once — the refused-stream retry must not re-dial a
// target whose redial just failed in the same call.
func TestOpenUpstreamStreamWithRetry_RedialFailsReturnsDialError(t *testing.T) {
	stale, peer := dialPeerH2Layer(t)
	defer stale.Close()
	_ = peer.Close()
	awaitShutdown(t, stale)

	var redialCalls atomic.Int32
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		redialCalls.Add(1)
		return nil, errRedialRefused
	}

	chain := newRedialChain(nil)
	defer chain.closeAll()
	gotL, gotCh, err := openUpstreamStreamWithRetryFn(
		context.Background(), "example.test:443",
		stale, chain, redialFn, http2OpenStream, silentLogger(),
	)
	if err == nil {
		_ = gotCh.Close()
		t.Fatalf("openUpstreamStreamWithRetryFn returned Layer %p, want an error", gotL)
	}
	if isRefusedStreamError(err) {
		t.Errorf("err = %v is ErrorRefused; want a non-Refused error for a failed redial", err)
	}
	if !errors.Is(err, errRedialRefused) {
		t.Errorf("err = %v, want it to wrap the redial error %v", err, errRedialRefused)
	}
	if n := redialCalls.Load(); n != 1 {
		t.Errorf("redialFn called %d times, want exactly 1 (no re-dial on the refused retry)", n)
	}
}

// TestOpenUpstreamStreamWithRetry_RetryRedialFailsReturnsDialError: the
// first selection finds the pooled Layer healthy (no redial in that
// call), and the first OpenStream is refused because the Layer went stale
// in between (the residual race). The retry must still redial; when that
// redial fails, the error is the wrapped dial error, not the stale
// Layer's refusal.
func TestOpenUpstreamStreamWithRetry_RetryRedialFailsReturnsDialError(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()

	var redialCalls atomic.Int32
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		redialCalls.Add(1)
		return nil, errRedialRefused
	}
	var openCalls atomic.Int32
	openFn := func(ctx context.Context, l *http2.Layer) (layer.Channel, error) {
		if openCalls.Add(1) == 1 {
			// The race: the Layer goes stale after selection.
			_ = pooledPeer.Close()
			awaitShutdown(t, pooled)
			return nil, &layer.StreamError{Code: layer.ErrorRefused, Reason: "layer shutdown"}
		}
		return http2OpenStream(ctx, l)
	}

	chain := newRedialChain(nil)
	defer chain.closeAll()
	_, _, err := openUpstreamStreamWithRetryFn(
		context.Background(), "example.test:443",
		pooled, chain, redialFn, openFn, silentLogger(),
	)
	if err == nil {
		t.Fatal("openUpstreamStreamWithRetryFn returned nil error, want the redial failure")
	}
	if isRefusedStreamError(err) {
		t.Errorf("err = %v is ErrorRefused; want a non-Refused error for a failed redial", err)
	}
	if !errors.Is(err, errRedialRefused) {
		t.Errorf("err = %v, want it to wrap the redial error %v", err, errRedialRefused)
	}
	if n := redialCalls.Load(); n != 1 {
		t.Errorf("redialFn called %d times, want exactly 1 (the retry's redial)", n)
	}
	if n := openCalls.Load(); n != 2 {
		t.Errorf("openStream called %d times, want 2 (attempt + 1 retry)", n)
	}
}

// TestH2Retry_Metrics_RedialFailNoRetry pins the counters for a request
// whose reactive redial fails on a stale head: the failed dial is counted
// once under the reactive trigger, and because the refused OpenStream on
// the stale Layer is a consequence of that failure (not an OpenStream-side
// race) no refused / refused_stream / retry_* counter fires.
func TestH2Retry_Metrics_RedialFailNoRetry(t *testing.T) {
	t.Parallel()
	stale, peer := dialPeerH2Layer(t)
	defer stale.Close()
	_ = peer.Close()
	awaitShutdown(t, stale)

	dialFresh := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		return nil, errRedialRefused
	}

	m := NewH2UpstreamMetrics()
	chain := newRedialChain(m)
	defer chain.closeAll()

	if _, _, err := openUpstreamStreamWithRetryFn(
		context.Background(), "example.test:443",
		stale, chain, dialFresh, http2OpenStream, silentLogger(),
	); err == nil {
		t.Fatal("openUpstreamStreamWithRetryFn returned nil error, want the redial failure")
	}
	snap := m.Snapshot()
	if snap.GoAwayObservedReactive != 1 || snap.RedialFailedReactive != 1 {
		t.Errorf("goaway_observed_reactive=%d redial_failed_reactive=%d, want 1 and 1",
			snap.GoAwayObservedReactive, snap.RedialFailedReactive)
	}
	if snap.Refused != 0 || snap.RedialFailedRefusedStream != 0 || snap.RedialRefusedStream != 0 {
		t.Errorf("refused=%d redial_failed_refused_stream=%d redial_refused_stream=%d, want all 0",
			snap.Refused, snap.RedialFailedRefusedStream, snap.RedialRefusedStream)
	}
	if snap.RetrySuccess != 0 || snap.RetryFailRedial != 0 || snap.RetryFailRedialRetry != 0 {
		t.Errorf("retry_* counters fired without a retry: %+v", snap)
	}
}

// TestForwardH2Upstream_RedialFailsReturnsDialError: after upstream GOAWAY
// the tcp_forward connection's chain[0] is stale and the redial fails.
// open must return a non-Refused error wrapping the dial error after a
// single dial — the same contract as the CONNECT path.
func TestForwardH2Upstream_RedialFailsReturnsDialError(t *testing.T) {
	chain0, chain0Peer := dialPeerH2Layer(t)
	defer chain0.Close()
	defer chain0Peer.Close()

	injectGoAwayFromPeer(t, chain0Peer, 1, 0)
	awaitGoAwayClosed(t, chain0)

	var redials atomic.Int32
	u := &forwardH2Upstream{
		target: "127.0.0.1:9",
		chain0: chain0,
		chain:  newRedialChain(nil),
		redial: func(context.Context, string, *http2.Layer, int) (*http2.Layer, error) {
			redials.Add(1)
			return nil, errRedialRefused
		},
		openStream: http2OpenStream,
		logger:     silentLogger(),
	}
	defer u.chain.closeAll()
	_, ch, err := u.open(context.Background())
	if err == nil {
		_ = ch.Close()
		t.Fatal("open succeeded, want the redial failure")
	}
	if isRefusedStreamError(err) {
		t.Errorf("open err = %v is ErrorRefused; want a non-Refused error for a failed redial", err)
	}
	if !errors.Is(err, errRedialRefused) {
		t.Errorf("open err = %v, want it to wrap %v", err, errRedialRefused)
	}
	if n := redials.Load(); n != 1 {
		t.Errorf("redials = %d, want 1", n)
	}
}
