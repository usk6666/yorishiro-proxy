package proxybuild

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-816: when the pooled upstream H2 Layer goes stale during a long
// intercept hold (server GOAWAY / idle FIN), selectUpstreamForDial must
// fresh-dial via the injected redialFn instead of returning the stale
// Layer. Without this guard the next OpenStream on the stale Layer either
// fails with ErrorRefused (state=error/refused) or succeeds-but-returns
// END_STREAM only (silent state=complete with empty response). Both
// failure modes are recorded in phase5.md as the production symptom.

// dialPeerH2Layer constructs a real *http2.Layer in ClientRole at one end
// of a net.Pipe. The peer end is returned so the test can close it (to
// trigger IsShutdown on the layer's reader) or hold it open. The Layer's
// New() blocks on the preface, so the peer goroutine reads it eagerly.
func dialPeerH2Layer(t *testing.T) (*http2.Layer, net.Conn) {
	t.Helper()
	cliConn, srvConn := net.Pipe()

	prefaceDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(srvConn, buf); err != nil {
			prefaceDone <- err
			return
		}
		if string(buf) != http2.ClientPreface {
			prefaceDone <- errors.New("preface mismatch")
			return
		}
		prefaceDone <- nil
	}()

	l, err := http2.New(cliConn, "test-stale-peer", http2.ClientRole)
	if err != nil {
		t.Fatalf("http2.New: %v", err)
	}
	if perr := <-prefaceDone; perr != nil {
		t.Fatalf("preface read: %v", perr)
	}
	return l, srvConn
}

// awaitShutdown polls IsShutdown() with a generous deadline. The reader
// goroutine drives the flip asynchronously after the peer FINs.
func awaitShutdown(t *testing.T, l *http2.Layer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !l.IsShutdown() {
		time.Sleep(5 * time.Millisecond)
	}
	if !l.IsShutdown() {
		t.Fatalf("IsShutdown() did not flip true within 2s")
	}
}

// TestSelectUpstreamForDial_StaleLayerTriggersRedial reproduces the core
// USK-816 invariant. The pooled upstreamH2 is forced into stale state
// (peer FIN → IsShutdown==true). selectUpstreamForDial must invoke the
// injected redialFn to obtain a fresh Layer, store it via the atomic
// pointer, and return it.
func TestSelectUpstreamForDial_StaleLayerTriggersRedial(t *testing.T) {
	stale, peer := dialPeerH2Layer(t)
	defer stale.Close()

	// Trigger upstream FIN → reader observes EOF → shutdown closed (USK-796
	// surfaces this through IsShutdown).
	_ = peer.Close()
	awaitShutdown(t, stale)

	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	var redialCalls int32
	redialFn := func(ctx context.Context, target string, prev *http2.Layer) (*http2.Layer, error) {
		atomic.AddInt32(&redialCalls, 1)
		if prev != stale {
			t.Errorf("redialFn prev = %p, want %p (stale Layer)", prev, stale)
		}
		if target != "example.test:443" {
			t.Errorf("redialFn target = %q, want %q", target, "example.test:443")
		}
		return fresh, nil
	}

	var ptr atomic.Pointer[http2.Layer]
	var mu sync.Mutex
	got := selectUpstreamForDial(context.Background(), "example.test:443",
		stale, &ptr, &mu, redialFn, silentLogger())

	if got != fresh {
		t.Errorf("selectUpstreamForDial returned %p, want fresh %p", got, fresh)
	}
	if ptr.Load() != fresh {
		t.Errorf("redial pointer = %p, want fresh %p", ptr.Load(), fresh)
	}
	if n := atomic.LoadInt32(&redialCalls); n != 1 {
		t.Errorf("redialFn called %d times, want 1", n)
	}

	// Subsequent calls reuse the cached fresh Layer; redialFn must not fire
	// again.
	got2 := selectUpstreamForDial(context.Background(), "example.test:443",
		stale, &ptr, &mu, redialFn, silentLogger())
	if got2 != fresh {
		t.Errorf("second call returned %p, want fresh %p", got2, fresh)
	}
	if n := atomic.LoadInt32(&redialCalls); n != 1 {
		t.Errorf("redialFn called %d times (after second call), want 1", n)
	}
}

// TestSelectUpstreamForDial_HealthyLayerSkipsRedial confirms the no-op
// path: when the pooled Layer is healthy (not GoAway, not Shutdown) the
// helper returns it directly without invoking redialFn.
func TestSelectUpstreamForDial_HealthyLayerSkipsRedial(t *testing.T) {
	healthy, peer := dialPeerH2Layer(t)
	defer healthy.Close()
	defer peer.Close()

	if healthy.IsShutdown() || healthy.GoAwayClosed() {
		t.Fatalf("freshly constructed Layer is already stale: shutdown=%v goAway=%v",
			healthy.IsShutdown(), healthy.GoAwayClosed())
	}

	redialFn := func(_ context.Context, _ string, _ *http2.Layer) (*http2.Layer, error) {
		t.Error("redialFn should not be called for a healthy Layer")
		return nil, errors.New("unexpected redial")
	}

	var ptr atomic.Pointer[http2.Layer]
	var mu sync.Mutex
	got := selectUpstreamForDial(context.Background(), "example.test:443",
		healthy, &ptr, &mu, redialFn, silentLogger())

	if got != healthy {
		t.Errorf("selectUpstreamForDial returned %p, want healthy %p", got, healthy)
	}
	if ptr.Load() != nil {
		t.Errorf("redial pointer = %p, want nil (no redial)", ptr.Load())
	}
}

// TestSelectUpstreamForDial_RedialFailureFallsBackToStale documents the
// behaviour when the fresh dial itself fails (network down, cert reject,
// etc.). The helper returns the stale Layer so OpenStream surfaces the
// underlying error to the session — failure propagates as
// state=error/failure_reason=refused via dispatchClientAction's wrap.
// Picking "no fallback / return nil" would silently complete with empty
// response, which is the very USK-816 symptom we are fixing.
func TestSelectUpstreamForDial_RedialFailureFallsBackToStale(t *testing.T) {
	stale, peer := dialPeerH2Layer(t)
	defer stale.Close()

	_ = peer.Close()
	awaitShutdown(t, stale)

	wantErr := errors.New("redial: network unreachable")
	redialFn := func(_ context.Context, _ string, _ *http2.Layer) (*http2.Layer, error) {
		return nil, wantErr
	}

	var ptr atomic.Pointer[http2.Layer]
	var mu sync.Mutex
	got := selectUpstreamForDial(context.Background(), "example.test:443",
		stale, &ptr, &mu, redialFn, silentLogger())

	if got != stale {
		t.Errorf("selectUpstreamForDial after redial-fail = %p, want stale %p", got, stale)
	}
	if ptr.Load() != nil {
		t.Errorf("redial pointer = %p, want nil (failed redial must not be cached)", ptr.Load())
	}
}

// TestSelectUpstreamForDial_PreFix_OpenStreamOnStaleLayerFails documents
// the pre-USK-816 behaviour that this fix targets. Calling OpenStream
// directly on a stale Layer (as the old dial closure did) returns
// *layer.StreamError{Code: ErrorRefused} on the GOAWAY path or fails
// (depends on transport reality) on the IsShutdown path. The test pins
// the symptom so a future regression that re-introduces direct OpenStream
// without the staleness re-check fails this assertion. Production
// equivalence: phase5.md line 75 — failure_reason=refused after intercept
// modify_and_forward.
func TestSelectUpstreamForDial_PreFix_OpenStreamOnStaleLayerFails(t *testing.T) {
	stale, peer := dialPeerH2Layer(t)
	defer stale.Close()

	_ = peer.Close()
	awaitShutdown(t, stale)

	// Direct OpenStream on the stale Layer — what the old dial closure did.
	// IsShutdown returns true so OpenStream returns a refused StreamError.
	_, err := stale.OpenStream(context.Background())
	if err == nil {
		t.Fatal("OpenStream on stale Layer = nil, want StreamError refused (precondition violated)")
	}
}

// TestSelectUpstreamForDial_ConcurrentStreamsShareSingleRedial exercises
// the redialDial single-flight invariant: when N streams observe the
// stale state simultaneously, redialFn must fire exactly once and all N
// callers must observe the same fresh Layer. Without serialisation each
// stream would dial its own upstream conn — wasted handshakes plus the
// pool-key invariant violation pointed out in the design plan.
func TestSelectUpstreamForDial_ConcurrentStreamsShareSingleRedial(t *testing.T) {
	stale, peer := dialPeerH2Layer(t)
	defer stale.Close()

	_ = peer.Close()
	awaitShutdown(t, stale)

	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	var redialCalls int32
	// Block the first redial briefly so concurrent callers stack up on the
	// mutex; the test then asserts only one call ever ran.
	gate := make(chan struct{})
	redialFn := func(_ context.Context, _ string, _ *http2.Layer) (*http2.Layer, error) {
		<-gate
		atomic.AddInt32(&redialCalls, 1)
		return fresh, nil
	}

	var ptr atomic.Pointer[http2.Layer]
	var mu sync.Mutex
	const n = 8
	results := make(chan *http2.Layer, n)
	for i := 0; i < n; i++ {
		go func() {
			results <- selectUpstreamForDial(context.Background(), "example.test:443",
				stale, &ptr, &mu, redialFn, silentLogger())
		}()
	}

	// Give goroutines a moment to converge on the mutex, then release.
	time.Sleep(50 * time.Millisecond)
	close(gate)

	for i := 0; i < n; i++ {
		select {
		case got := <-results:
			if got != fresh {
				t.Errorf("goroutine %d got %p, want fresh %p", i, got, fresh)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("goroutine %d did not return", i)
		}
	}
	if got := atomic.LoadInt32(&redialCalls); got != 1 {
		t.Errorf("redialFn fired %d times, want 1 (single-flight)", got)
	}
}
