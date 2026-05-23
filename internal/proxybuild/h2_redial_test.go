package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-816 / USK-991: when the pooled upstream H2 Layer goes stale during a
// long intercept hold (server GOAWAY / idle FIN), selectUpstreamForDial
// must fresh-dial via the injected redialFn instead of returning the
// stale Layer. Without this guard the next OpenStream on the stale Layer
// either fails with ErrorRefused (state=error/refused) or succeeds-but-
// returns END_STREAM only (silent state=complete with empty response).
// USK-991 extends the same guard recursively: a previously redialed
// Layer that itself goes stale must trigger a 2nd (and Nth) fresh dial,
// not be returned as-is.

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
// injected redialFn to obtain a fresh Layer, store it via chain.current,
// and return it.
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
	redialFn := func(ctx context.Context, target string, prev *http2.Layer, gen int) (*http2.Layer, error) {
		atomic.AddInt32(&redialCalls, 1)
		if prev != stale {
			t.Errorf("redialFn prev = %p, want %p (stale Layer)", prev, stale)
		}
		if target != "example.test:443" {
			t.Errorf("redialFn target = %q, want %q", target, "example.test:443")
		}
		if gen != 1 {
			t.Errorf("redialFn generation = %d, want 1 (first redial)", gen)
		}
		return fresh, nil
	}

	chain := newRedialChain()
	got := selectUpstreamForDial(context.Background(), "example.test:443",
		stale, chain, redialFn, silentLogger())

	if got != fresh {
		t.Errorf("selectUpstreamForDial returned %p, want fresh %p", got, fresh)
	}
	if cur := chain.current.Load(); cur != fresh {
		t.Errorf("chain.current = %p, want fresh %p", cur, fresh)
	}
	if n := atomic.LoadInt32(&redialCalls); n != 1 {
		t.Errorf("redialFn called %d times, want 1", n)
	}

	// Subsequent calls reuse the cached fresh Layer; redialFn must not fire
	// again as long as fresh is healthy.
	got2 := selectUpstreamForDial(context.Background(), "example.test:443",
		stale, chain, redialFn, silentLogger())
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

	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		t.Error("redialFn should not be called for a healthy Layer")
		return nil, errors.New("unexpected redial")
	}

	chain := newRedialChain()
	got := selectUpstreamForDial(context.Background(), "example.test:443",
		healthy, chain, redialFn, silentLogger())

	if got != healthy {
		t.Errorf("selectUpstreamForDial returned %p, want healthy %p", got, healthy)
	}
	if cur := chain.current.Load(); cur != nil {
		t.Errorf("chain.current = %p, want nil (no redial)", cur)
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
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		return nil, wantErr
	}

	chain := newRedialChain()
	got := selectUpstreamForDial(context.Background(), "example.test:443",
		stale, chain, redialFn, silentLogger())

	if got != stale {
		t.Errorf("selectUpstreamForDial after redial-fail = %p, want stale %p", got, stale)
	}
	if cur := chain.current.Load(); cur != nil {
		t.Errorf("chain.current = %p, want nil (failed redial must not be cached)", cur)
	}
	if got := len(chain.layers); got != 0 {
		t.Errorf("chain.layers length = %d, want 0 (failed dial must not be appended)", got)
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
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		<-gate
		atomic.AddInt32(&redialCalls, 1)
		return fresh, nil
	}

	chain := newRedialChain()
	const n = 8
	results := make(chan *http2.Layer, n)
	for i := 0; i < n; i++ {
		go func() {
			results <- selectUpstreamForDial(context.Background(), "example.test:443",
				stale, chain, redialFn, silentLogger())
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

// closeRecordingLayer wraps a real *http2.Layer with an atomic Close
// counter so chain.closeAll() assertions can verify each chain step is
// closed exactly once. (Methods that are not exercised by the test are
// untouched; we only need Close + the staleness pollers.)
//
// Note: http2.Layer has methods that the chain doesn't call in tests
// (e.g. OpenStream), so we wrap only for Close-count verification and
// keep the real Layer reachable via .l for the assertions that need it.

// TestSelectUpstreamForDial_NChainRedials reproduces the USK-991 core
// case: a previously redialed Layer that itself receives GOAWAY/EOF
// must trigger an Nth fresh dial, not be returned as-is.
//
// Staging: pooled → fresh1 → fresh2 → fresh3.
// Each stage is driven into IsShutdown via peer.Close(); the next call
// to selectUpstreamForDial must observe the new staleness, take the
// chain.mu, and dial the next fresh Layer with monotonically increasing
// generation (1, 2, 3, ...).
func TestSelectUpstreamForDial_NChainRedials(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()

	// Stage 3 fresh Layers up front; the redialFn returns them in order.
	fresh1, peer1 := dialPeerH2Layer(t)
	defer fresh1.Close()
	defer peer1.Close()
	fresh2, peer2 := dialPeerH2Layer(t)
	defer fresh2.Close()
	defer peer2.Close()
	fresh3, peer3 := dialPeerH2Layer(t)
	defer fresh3.Close()
	defer peer3.Close()

	freshSeq := []*http2.Layer{fresh1, fresh2, fresh3}
	var seenGens []int
	var idx int32
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, gen int) (*http2.Layer, error) {
		i := atomic.AddInt32(&idx, 1)
		seenGens = append(seenGens, gen)
		if int(i) > len(freshSeq) {
			t.Fatalf("redialFn called more than %d times (got %d)", len(freshSeq), i)
		}
		return freshSeq[i-1], nil
	}

	chain := newRedialChain()

	// Stage 0: kill pooled, expect fresh1 with generation=1.
	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)
	got := selectUpstreamForDial(context.Background(), "example.test:443",
		pooled, chain, redialFn, silentLogger())
	if got != fresh1 {
		t.Fatalf("stage 1: got %p, want fresh1 %p", got, fresh1)
	}

	// Stage 1: kill fresh1, expect fresh2 with generation=2.
	_ = peer1.Close()
	awaitShutdown(t, fresh1)
	got = selectUpstreamForDial(context.Background(), "example.test:443",
		pooled, chain, redialFn, silentLogger())
	if got != fresh2 {
		t.Fatalf("stage 2: got %p, want fresh2 %p", got, fresh2)
	}

	// Stage 2: kill fresh2, expect fresh3 with generation=3.
	_ = peer2.Close()
	awaitShutdown(t, fresh2)
	got = selectUpstreamForDial(context.Background(), "example.test:443",
		pooled, chain, redialFn, silentLogger())
	if got != fresh3 {
		t.Fatalf("stage 3: got %p, want fresh3 %p", got, fresh3)
	}

	wantGens := []int{1, 2, 3}
	if len(seenGens) != len(wantGens) {
		t.Fatalf("redialFn generation sequence = %v, want %v", seenGens, wantGens)
	}
	for i, g := range seenGens {
		if g != wantGens[i] {
			t.Errorf("redialFn call #%d: generation = %d, want %d", i+1, g, wantGens[i])
		}
	}

	// Chain holds every fresh Layer for closeAll.
	if got, want := len(chain.layers), 3; got != want {
		t.Errorf("chain.layers length = %d, want %d", got, want)
	}
	if cur := chain.current.Load(); cur != fresh3 {
		t.Errorf("chain.current = %p, want fresh3 %p (final stage)", cur, fresh3)
	}
}

// TestSelectUpstreamForDial_NChainConcurrentSingleFlightPerStep extends
// the concurrent-streams test (USK-816) to the N-chain case (USK-991).
// At each chain step, M concurrent goroutines that observe the same
// staleness must coalesce into a single fresh dial — verified across
// two consecutive chain steps in one test.
func TestSelectUpstreamForDial_NChainConcurrentSingleFlightPerStep(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()
	fresh1, peer1 := dialPeerH2Layer(t)
	defer fresh1.Close()
	defer peer1.Close()
	fresh2, peer2 := dialPeerH2Layer(t)
	defer fresh2.Close()
	defer peer2.Close()

	var dialCount int32
	gate := make(chan struct{})
	// We unblock the dial sequentially, one chain step at a time.
	// On the 1st redial call we return fresh1; on the 2nd, fresh2.
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		<-gate
		n := atomic.AddInt32(&dialCount, 1)
		switch n {
		case 1:
			return fresh1, nil
		case 2:
			return fresh2, nil
		default:
			return nil, fmt.Errorf("unexpected dial #%d", n)
		}
	}

	chain := newRedialChain()
	const m = 8

	// Step A: pooled is stale → all M goroutines must converge on fresh1.
	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)

	resultsA := make(chan *http2.Layer, m)
	var startA sync.WaitGroup
	startA.Add(m)
	for i := 0; i < m; i++ {
		go func() {
			startA.Done()
			resultsA <- selectUpstreamForDial(context.Background(), "example.test:443",
				pooled, chain, redialFn, silentLogger())
		}()
	}
	startA.Wait()
	time.Sleep(50 * time.Millisecond)
	// Unblock the 1st dial only — and wait for it to complete so all
	// goroutines on this step return.
	gate <- struct{}{}
	for i := 0; i < m; i++ {
		select {
		case got := <-resultsA:
			if got != fresh1 {
				t.Errorf("step A goroutine %d got %p, want fresh1 %p", i, got, fresh1)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("step A goroutine %d did not return", i)
		}
	}
	if got := atomic.LoadInt32(&dialCount); got != 1 {
		t.Fatalf("step A dialCount = %d, want 1", got)
	}

	// Step B: fresh1 is now stale → all M goroutines must converge on fresh2.
	_ = peer1.Close()
	awaitShutdown(t, fresh1)

	resultsB := make(chan *http2.Layer, m)
	var startB sync.WaitGroup
	startB.Add(m)
	for i := 0; i < m; i++ {
		go func() {
			startB.Done()
			resultsB <- selectUpstreamForDial(context.Background(), "example.test:443",
				pooled, chain, redialFn, silentLogger())
		}()
	}
	startB.Wait()
	time.Sleep(50 * time.Millisecond)
	gate <- struct{}{}
	for i := 0; i < m; i++ {
		select {
		case got := <-resultsB:
			if got != fresh2 {
				t.Errorf("step B goroutine %d got %p, want fresh2 %p", i, got, fresh2)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("step B goroutine %d did not return", i)
		}
	}
	if got := atomic.LoadInt32(&dialCount); got != 2 {
		t.Fatalf("step B dialCount = %d, want 2 (one new dial per step)", got)
	}
}

// TestRedialChain_CloseAllClosesEveryStep asserts that closeAll() closes
// every fresh Layer accumulated in the chain — required for the defer
// in buildOnHTTP2Stack to release the chain at CONNECT exit. The chain
// also clears current+layers so a repeat call is a no-op (idempotent).
func TestRedialChain_CloseAllClosesEveryStep(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()
	fresh1, peer1 := dialPeerH2Layer(t)
	defer peer1.Close()
	fresh2, peer2 := dialPeerH2Layer(t)
	defer peer2.Close()
	fresh3, peer3 := dialPeerH2Layer(t)
	defer peer3.Close()

	chain := newRedialChain()
	chain.layers = append(chain.layers, fresh1, fresh2, fresh3)
	chain.current.Store(fresh3)

	chain.closeAll()

	for i, l := range []*http2.Layer{fresh1, fresh2, fresh3} {
		if !l.IsShutdown() && !l.GoAwayClosed() {
			// Layer.Close sets the underlying signals; assert at least one
			// observable shutdown signal is set.
			t.Errorf("chain step %d: Close did not signal shutdown (IsShutdown=%v GoAwayClosed=%v)",
				i+1, l.IsShutdown(), l.GoAwayClosed())
		}
	}
	if got := len(chain.layers); got != 0 {
		t.Errorf("after closeAll, chain.layers length = %d, want 0", got)
	}
	if cur := chain.current.Load(); cur != nil {
		t.Errorf("after closeAll, chain.current = %p, want nil", cur)
	}

	// Repeat call must be a no-op (defer might run twice in hypothetical
	// re-entry; closeAll must not panic).
	chain.closeAll()
}
