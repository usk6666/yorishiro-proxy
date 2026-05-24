package proxybuild

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// USK-992 — proactive pre-warm. When a chain head Layer observes peer
// GOAWAY, the redialChain's pre-warm worker dials a fresh upstream
// before the next client request arrives. This trades wire-side TCP +
// TLS handshake latency on the user-visible path for an idle-period
// dial that the next OpenStream picks up via chain.current.Load().
//
// Tests in this file exercise:
//   - the worker fires a dial on wake
//   - cap=1 wake dedup (rapid GOAWAY bursts collapse to one in-flight dial)
//   - worker honors ctx cancel + closeAll (no goroutine leak)
//   - failed pre-warm dial does not corrupt chain
//   - pre-warm + reactive paths cooperate (chain.mu single-flight)
//
// Test harness: dialPeerH2LayerWithOpts mints a *http2.Layer at one end
// of a net.Pipe (mirrors dialPeerH2Layer in h2_redial_test.go) but
// accepts http2.New Options so tests can install
// WithGoAwayObserver(...) on a freshly minted Layer. The peer end is
// returned along with a frame.Writer so the test can inject a real
// GOAWAY frame deterministically (no time.Sleep gating).

// dialPeerH2LayerWithOpts mirrors dialPeerH2Layer but accepts variadic
// http2 Options so tests can install observers.
func dialPeerH2LayerWithOpts(t *testing.T, opts ...http2.Option) (*http2.Layer, net.Conn) {
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

	l, err := http2.New(cliConn, "test-prewarm-peer", http2.ClientRole, opts...)
	if err != nil {
		t.Fatalf("http2.New: %v", err)
	}
	if perr := <-prefaceDone; perr != nil {
		t.Fatalf("preface read: %v", perr)
	}
	return l, srvConn
}

// injectGoAwayFromPeer writes a real GOAWAY frame to srvConn (the peer
// end of the Layer's net.Pipe). The Layer's reader goroutine consumes
// it via handleGoAwayFrame, fires the WithGoAwayObserver, and flips
// GoAwayClosed() to true. The test uses this to deterministically stage
// "Layer observes GOAWAY" without driving EOF-via-Close (the FIN path
// flips IsShutdown but bypasses the observer because it never enters
// handleGoAwayFrame).
//
// errCode follows RFC 9113 §7 error codes (ErrCodeNo = NO_ERROR /
// graceful shutdown). lastStreamID=0 means every stream is canceled.
func injectGoAwayFromPeer(t *testing.T, srvConn net.Conn, lastStreamID uint32, errCode uint32) {
	t.Helper()
	wr := frame.NewWriter(srvConn)
	if err := wr.WriteGoAway(lastStreamID, errCode, nil); err != nil {
		t.Fatalf("injectGoAwayFromPeer: WriteGoAway: %v", err)
	}
}

// awaitGoAwayClosed polls GoAwayClosed() with a generous deadline; the
// reader goroutine processes the injected GOAWAY frame asynchronously.
func awaitGoAwayClosed(t *testing.T, l *http2.Layer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !l.GoAwayClosed() {
		time.Sleep(5 * time.Millisecond)
	}
	if !l.GoAwayClosed() {
		t.Fatalf("GoAwayClosed() did not flip true within 2s")
	}
}

// TestRedialChain_PrewarmFiresOnGoAwayObservation is the core USK-992
// invariant: a fresh chain step receives GOAWAY on the wire → the
// observer tickles wake → the pre-warm worker dials → chain.current
// updates with the new Layer before any selectUpstreamForDial call.
//
// Staging:
//  1. Construct a real *http2.Layer ("pooled") and seed it as chain[0]
//     (manually appended; we are not testing the connector's pool
//     branch here, just the worker's wake-driven dial behaviour).
//  2. Build a redialFn that, on first invocation, returns a "fresh"
//     Layer (gated by a channel so the test controls completion order).
//  3. Inject a real GOAWAY into the chain head — but the pooled Layer
//     in this test has no observer (chain[0] is not wired per design,
//     see buildOnHTTP2Stack), so we manually tickle the wake channel
//     to stage the observer-firing edge.
//  4. Open the gate; the worker dials fresh; assert chain.current
//     becomes the fresh Layer before any other actor (selectUpstream
//     or test) reads it.
func TestRedialChain_PrewarmFiresOnWake(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()
	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	var dialCount int32
	dialReady := make(chan struct{})
	dialReleased := make(chan struct{})
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		atomic.AddInt32(&dialCount, 1)
		close(dialReady)
		<-dialReleased
		return fresh, nil
	}

	// Drive pooled stale so the worker's pre-dial isStaleH2 check passes
	// — the worker only dials when chain.headLayer() is stale (or nil
	// with no head, the first dial fires unconditionally).
	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)

	chain := newRedialChain()
	// Manually seed the chain head with pooled (mirrors what
	// selectUpstreamForDial would do on first reactive redial).
	chain.layers = append(chain.layers, pooled)
	chain.current.Store(pooled)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	defer chain.closeAll()

	// Tickle wake to simulate "observer fired".
	chain.tickleWake()

	// Wait for dial to enter (gated).
	select {
	case <-dialReady:
	case <-time.After(2 * time.Second):
		t.Fatal("redialFn did not run within 2s of wake")
	}
	close(dialReleased)

	// Wait until chain.current swaps to fresh (the worker stores under mu
	// after the dial completes).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && chain.current.Load() != fresh {
		time.Sleep(5 * time.Millisecond)
	}
	if chain.current.Load() != fresh {
		t.Fatalf("chain.current = %p, want fresh %p (worker did not swap)", chain.current.Load(), fresh)
	}
	if got := atomic.LoadInt32(&dialCount); got != 1 {
		t.Errorf("redialFn called %d times, want 1", got)
	}
}

// TestRedialChain_PrewarmDedupsOnRapidWakeBursts covers the cap=1 wake
// channel + non-blocking-send invariant. A burst of rapid wake events
// (simulating multi-GOAWAY flooding from a hostile peer, or just legit
// multi-GOAWAY per RFC 9113 §6.8) must collapse into at most one in-
// flight dial per drained wake. With the dial gated, even tickling N
// times before releasing the gate must result in exactly 1 dial.
func TestRedialChain_PrewarmDedupsOnRapidWakeBursts(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()
	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)

	var dialCount int32
	dialReady := make(chan struct{})
	dialReleased := make(chan struct{})
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		atomic.AddInt32(&dialCount, 1)
		select {
		case <-dialReady:
		default:
			close(dialReady)
		}
		<-dialReleased
		return fresh, nil
	}

	chain := newRedialChain()
	chain.layers = append(chain.layers, pooled)
	chain.current.Store(pooled)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	defer chain.closeAll()

	// Tickle wake 8 times rapidly. The cap=1 channel + non-blocking send
	// idiom drops 7 of them. The worker drains once and is blocked on
	// the gate.
	for i := 0; i < 8; i++ {
		chain.tickleWake()
	}

	// Confirm exactly one dial entered.
	select {
	case <-dialReady:
	case <-time.After(2 * time.Second):
		t.Fatal("redialFn did not enter within 2s")
	}
	if got := atomic.LoadInt32(&dialCount); got != 1 {
		t.Errorf("after 8 rapid tickles, dialCount = %d, want 1 (cap=1 dedup)", got)
	}

	close(dialReleased)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && chain.current.Load() != fresh {
		time.Sleep(5 * time.Millisecond)
	}
	if chain.current.Load() != fresh {
		t.Fatal("chain.current did not swap to fresh after the single dial")
	}
	// After the dial completes the head is fresh, which is healthy, so
	// further wake tickles should be drained without firing additional
	// dials. Give the worker a moment to drain spurious wakes.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&dialCount); got != 1 {
		t.Errorf("after swap, dialCount = %d, want still 1 (no spurious post-swap dials)", got)
	}
}

// TestRedialChain_PrewarmWorkerExitsCleanlyOnCtxCancel verifies the
// concurrency-checklist invariant: the worker goroutine has an explicit
// termination via ctx.Done(). When the CONNECT context cancels, the
// worker exits without leaking goroutines.
func TestRedialChain_PrewarmWorkerExitsCleanlyOnCtxCancel(t *testing.T) {
	chain := newRedialChain()
	// dialFn never fires because we don't tickle wake.
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		t.Error("redialFn must not be called when wake is never tickled")
		return nil, errors.New("unexpected dial")
	}

	beforeGo := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	// Give the worker a moment to start.
	time.Sleep(20 * time.Millisecond)

	cancel()
	chain.closeAll()

	// The worker goroutine should exit. Poll NumGoroutine briefly — Go
	// goroutine count can have transient noise, but with a steady-state
	// system the count should return to its pre-start baseline.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := runtime.NumGoroutine(); got <= beforeGo+1 {
			return // worker exited (the +1 accounts for GC / runtime noise)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("worker goroutine did not exit within 2s after cancel + closeAll (numGoroutines now=%d, before=%d)",
		runtime.NumGoroutine(), beforeGo)
}

// TestRedialChain_PrewarmFailedDialKeepsWorkerAlive documents the
// resilience invariant: a failed pre-warm dial logs at Debug level,
// does NOT append to chain.layers, leaves chain.current unchanged, and
// the worker keeps running for subsequent wake events.
func TestRedialChain_PrewarmFailedDialKeepsWorkerAlive(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()
	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)

	var attempts int32
	// First wake → fail. Second wake → also fail (we never let it succeed).
	dialErr := errors.New("dial: network unreachable")
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, dialErr
	}

	chain := newRedialChain()
	chain.layers = append(chain.layers, pooled)
	chain.current.Store(pooled)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	defer chain.closeAll()

	chain.tickleWake()
	// Wait for attempt 1.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&attempts) < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&attempts) < 1 {
		t.Fatal("first wake did not produce a dial attempt")
	}

	// Chain state is unchanged (no fresh Layer appended).
	if got := len(chain.layers); got != 1 {
		t.Errorf("after failed dial: chain.layers length = %d, want 1 (pooled only)", got)
	}
	if cur := chain.current.Load(); cur != pooled {
		t.Errorf("after failed dial: chain.current = %p, want pooled %p (unchanged)", cur, pooled)
	}

	// Second wake — confirm the worker still runs (didn't exit on the
	// first failure).
	chain.tickleWake()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&attempts) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&attempts); got < 2 {
		t.Errorf("second wake did not produce a dial attempt; attempts = %d, want >= 2", got)
	}
}

// TestRedialChain_PrewarmFiresViaRealGoAwayObserver wires the full
// USK-992 path: a fresh chain step is constructed with the test's
// observer wrapper (which tickles chain.wake), a real GOAWAY frame is
// injected from the peer, the observer fires, the worker dials, and
// chain.current updates to a follow-up fresh Layer.
//
// Staging walks the production wiring shape from buildOnHTTP2Stack:
//  1. Mint chain[1] (fresh1) with WithGoAwayObserver(chain.tickleWake)
//     — chain[1] is the "first redial" in the production model.
//  2. Inject a real GOAWAY into fresh1 — observer fires.
//  3. Worker drains wake, calls redialFn (gated), returns fresh2.
//  4. Assert chain.current swaps to fresh2 before any selectUpstreamForDial.
func TestRedialChain_PrewarmFiresViaRealGoAwayObserver(t *testing.T) {
	chain := newRedialChain()

	// Pre-mint fresh2 up front so we don't race on assignment inside the
	// worker goroutine.
	fresh2, fresh2Peer := dialPeerH2Layer(t)
	defer fresh2.Close()
	defer fresh2Peer.Close()

	var dialCount int32
	dialReady := make(chan struct{}, 1)
	dialReleased := make(chan struct{})
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		atomic.AddInt32(&dialCount, 1)
		select {
		case dialReady <- struct{}{}:
		default:
		}
		<-dialReleased
		return fresh2, nil
	}

	// fresh1 is the head of the chain. The observer tickles chain.wake.
	fresh1, fresh1Peer := dialPeerH2LayerWithOpts(t, http2.WithGoAwayObserver(chain.tickleWake))
	defer fresh1.Close()
	defer fresh1Peer.Close()

	chain.layers = append(chain.layers, fresh1)
	chain.current.Store(fresh1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	defer chain.closeAll()

	// Inject real GOAWAY → observer fires → wake tickled.
	injectGoAwayFromPeer(t, fresh1Peer, 0, 0)
	awaitGoAwayClosed(t, fresh1)

	// Worker enters dial.
	select {
	case <-dialReady:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not enter dial within 2s of injected GOAWAY")
	}
	close(dialReleased)

	// Wait for the swap.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur := chain.current.Load(); cur != nil && cur != fresh1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cur := chain.current.Load()
	if cur == fresh1 || cur == nil {
		t.Fatalf("chain.current did not swap away from fresh1; current=%p, fresh1=%p", cur, fresh1)
	}
	if cur != fresh2 {
		t.Errorf("chain.current = %p, want fresh2 %p (the worker's dial return)", cur, fresh2)
	}
	if got := atomic.LoadInt32(&dialCount); got != 1 {
		t.Errorf("redialFn called %d times, want 1", got)
	}
}

// TestRedialChain_CloseAllExitsWorkerEvenWithoutCtxCancel pins the
// closeAll → prewarmDone → worker exit path independently of ctx
// cancel. The defer in buildOnHTTP2Stack runs closeAll before the ctx
// is technically canceled (it's the CONNECT-exit defer); the worker
// must respect prewarmDone in its select.
func TestRedialChain_CloseAllExitsWorkerEvenWithoutCtxCancel(t *testing.T) {
	chain := newRedialChain()
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		t.Error("redialFn must not fire when wake is never tickled")
		return nil, errors.New("unexpected dial")
	}

	beforeGo := runtime.NumGoroutine()
	ctx := context.Background() // explicitly not canceled
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	time.Sleep(20 * time.Millisecond)

	chain.closeAll()
	// Worker must exit via prewarmDone within a short window.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := runtime.NumGoroutine(); got <= beforeGo+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("worker did not exit via prewarmDone within 2s (numGoroutines now=%d, before=%d)",
		runtime.NumGoroutine(), beforeGo)
}

// TestRedialChain_CloseAllIsIdempotent verifies the closeOnce
// invariant: a second closeAll call must not double-close prewarmDone
// (which would panic with "close of closed channel"). Mirrors the
// USK-991 idempotency test of closeAll's layer-close pass.
func TestRedialChain_CloseAllIsIdempotent(t *testing.T) {
	chain := newRedialChain()

	// Run a second time after the worker has exited. closeAll wraps the
	// close(prewarmDone) in sync.Once so the second call is a no-op.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("second closeAll panicked: %v", r)
		}
	}()

	chain.closeAll()
	chain.closeAll()
}

// TestRedialChain_PrewarmRespectsCtxCancelMidDial covers the worker's
// post-dial ctx.Err() check — when a pre-warm dial returns after the
// CONNECT ctx has canceled, the worker must close the returned Layer
// instead of appending it (otherwise the Layer's goroutines leak
// across the CONNECT boundary).
func TestRedialChain_PrewarmRespectsCtxCancelMidDial(t *testing.T) {
	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()

	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)

	// Pre-mint the fresh Layer + peer up front so the test doesn't race
	// with the worker on assignment.
	fresh, freshPeer := dialPeerH2Layer(t)
	defer freshPeer.Close()
	defer func() {
		// fresh should already be Closed by the worker; calling Close
		// again is idempotent (Layer.Close uses sync.Once).
		_ = fresh.Close()
	}()

	// Gate the dial so the test can cancel ctx while the dial is in
	// progress, then release the dial to return.
	dialReady := make(chan struct{}, 1)
	dialReleased := make(chan struct{})
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		select {
		case dialReady <- struct{}{}:
		default:
		}
		<-dialReleased
		return fresh, nil
	}

	chain := newRedialChain()
	chain.layers = append(chain.layers, pooled)
	chain.current.Store(pooled)

	ctx, cancel := context.WithCancel(context.Background())
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	defer chain.closeAll()

	chain.tickleWake()
	select {
	case <-dialReady:
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not enter within 2s")
	}

	// Cancel ctx while the dial is in flight.
	cancel()
	close(dialReleased)

	// Give the worker a moment to handle the post-dial ctx.Err() check
	// and Close the fresh Layer.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fresh.IsShutdown() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// chain.current is unchanged (the fresh Layer was NOT appended; ctx
	// canceled before the swap). Note closeAll runs in defer, but
	// hasn't run yet at this point (we're inside the test body still).
	if cur := chain.current.Load(); cur == fresh {
		t.Errorf("chain.current = %p (fresh), want pooled — worker appended despite ctx cancel", cur)
	}
	if !fresh.IsShutdown() && !fresh.GoAwayClosed() {
		t.Errorf("fresh Layer was not closed by the worker after ctx cancel")
	}
}

// TestRedialChain_ObserverDoesNotFireForNonHeadLayer is the design
// review Q5 invariant in test form: when a GOAWAY arrives on a Layer
// that is no longer the chain head (i.e. a previously-swapped-out
// chain step finishing its drain), the observer closure built in
// buildOnHTTP2Stack returns without tickling wake. This test reuses
// the chain's tickleWake directly to confirm the gating is per-Layer
// (the production wiring's closure compares against chain.current
// before calling tickleWake — see buildOnHTTP2Stack's onGoAway
// closure body).
//
// Because the head-comparison lives in the closure constructed inside
// buildOnHTTP2Stack (not on redialChain itself), this test asserts on
// the assembled production closure shape by recreating it.
func TestRedialChain_ObserverGatesByCurrentHead(t *testing.T) {
	chain := newRedialChain()
	// We construct two fresh Layers: layerA and layerB. layerB becomes
	// the current head; layerA's observer fires after the swap and must
	// NOT tickle wake.
	layerA, peerA := dialPeerH2Layer(t)
	defer layerA.Close()
	defer peerA.Close()
	layerB, peerB := dialPeerH2Layer(t)
	defer layerB.Close()
	defer peerB.Close()

	chain.layers = append(chain.layers, layerA, layerB)
	chain.current.Store(layerB) // layerB is the head

	// Build observer closures mirroring the production redialFn wrapper.
	makeObserver := func(firing *http2.Layer) func() {
		return func() {
			if firing != chain.current.Load() {
				return // gated: not head
			}
			chain.tickleWake()
		}
	}

	obsA := makeObserver(layerA)
	obsB := makeObserver(layerB)

	// Fire obsA — layerA is NOT head; wake must remain empty.
	obsA()
	select {
	case <-chain.wake:
		t.Error("obsA tickled wake despite layerA not being chain head")
	default:
		// expected
	}

	// Fire obsB — layerB IS head; wake must be tickled.
	obsB()
	select {
	case <-chain.wake:
		// expected
	default:
		t.Error("obsB did not tickle wake despite layerB being chain head")
	}
}

// TestRedialChain_TickleWakeCapacityOne asserts the wake channel is
// cap=1 with non-blocking-send semantics: a second tickle while a
// first is buffered is silently dropped. This is the foundation of
// the rapid-burst dedup tested in
// TestRedialChain_PrewarmDedupsOnRapidWakeBursts.
func TestRedialChain_TickleWakeCapacityOne(t *testing.T) {
	chain := newRedialChain()
	// 3 tickles back-to-back — only the first should buffer.
	chain.tickleWake()
	chain.tickleWake()
	chain.tickleWake()

	// Drain.
	select {
	case <-chain.wake:
	default:
		t.Fatal("first tickle did not buffer on wake")
	}

	// No more should be readable.
	select {
	case <-chain.wake:
		t.Error("second tickle leaked past cap=1")
	default:
		// expected
	}
}

// TestRedialChain_PrewarmDoesNotDoubleStartWorker covers the start API
// boundary: startPrewarmWorker is called exactly once per chain. The
// test verifies the worker is alive after the call and exits cleanly
// — we don't need a "calling it twice panics" invariant (the worker
// API is internal and only called by buildOnHTTP2Stack).
func TestRedialChain_PrewarmWorkerExitsViaCloseAllAfterIdle(t *testing.T) {
	chain := newRedialChain()
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		t.Error("redialFn must not fire when wake is never tickled")
		return nil, errors.New("unexpected dial")
	}

	beforeGo := runtime.NumGoroutine()
	ctx := context.Background()
	chain.startPrewarmWorker(ctx, "example.test:443", redialFn, nil, silentLogger())
	// Worker is idle (no wake). Sit for a moment so it's blocked on
	// the select.
	time.Sleep(50 * time.Millisecond)

	chain.closeAll()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= beforeGo+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("worker did not exit after closeAll (numGoroutines now=%d, before=%d)",
		runtime.NumGoroutine(), beforeGo)
}

// stubWorkerHarness wraps the per-CONNECT chain + worker setup so
// tests below can drive multi-step scenarios without re-typing the
// scaffold.
type stubWorkerHarness struct {
	chain *redialChain
	ctx   context.Context
	stop  context.CancelFunc

	dialCount atomic.Int32
	dialReady chan struct{}
	dialNext  chan *http2.Layer

	t *testing.T
}

func newStubWorkerHarness(t *testing.T) *stubWorkerHarness {
	t.Helper()
	h := &stubWorkerHarness{
		chain:     newRedialChain(),
		dialReady: make(chan struct{}, 8),
		dialNext:  make(chan *http2.Layer, 8),
		t:         t,
	}
	h.ctx, h.stop = context.WithCancel(context.Background())
	redialFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		h.dialCount.Add(1)
		h.dialReady <- struct{}{}
		l, ok := <-h.dialNext
		if !ok {
			return nil, errors.New("dialNext closed")
		}
		return l, nil
	}
	h.chain.startPrewarmWorker(h.ctx, "example.test:443", redialFn, nil, silentLogger())
	return h
}

func (h *stubWorkerHarness) Cleanup() {
	h.stop()
	h.chain.closeAll()
}

// TestRedialChain_PrewarmAndReactiveCooperate is a smoke-level check
// of the interaction between proactive pre-warm and reactive
// selectUpstreamForDial. Both share chain.mu; we assert that the
// worker's swap and a concurrent selectUpstreamForDial converge on a
// single fresh Layer (the worker's dial result) without violating the
// chain invariant of monotonically-appended layers.
func TestRedialChain_PrewarmAndReactiveCooperate(t *testing.T) {
	h := newStubWorkerHarness(t)
	defer h.Cleanup()

	pooled, pooledPeer := dialPeerH2Layer(t)
	defer pooled.Close()
	defer pooledPeer.Close()
	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	_ = pooledPeer.Close()
	awaitShutdown(t, pooled)

	h.chain.layers = append(h.chain.layers, pooled)
	h.chain.current.Store(pooled)

	// Worker dial is gated on h.dialNext send.
	h.chain.tickleWake()
	select {
	case <-h.dialReady:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not enter dial within 2s")
	}

	// While worker is in dial, fire a reactive selectUpstreamForDial.
	// Its redialFn is a separate closure (not h's) — it must observe
	// chain.mu serialisation but not deadlock.
	reactiveDone := make(chan *http2.Layer, 1)
	reactiveFreshUsed := make(chan struct{}, 1)
	reactiveFn := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		// We use the same fresh layer; the test asserts the reactive
		// call coalesces with the worker's pending dial.
		select {
		case reactiveFreshUsed <- struct{}{}:
		default:
		}
		return fresh, nil
	}
	go func() {
		reactiveDone <- selectUpstreamForDial(context.Background(), "example.test:443",
			pooled, h.chain, reactiveFn, silentLogger())
	}()

	// Let the worker complete its dial.
	h.dialNext <- fresh

	// Both worker and reactive must converge on fresh.
	var got *http2.Layer
	select {
	case got = <-reactiveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("reactive selectUpstreamForDial did not return within 2s")
	}
	if got != fresh {
		t.Errorf("reactive selectUpstreamForDial returned %p, want fresh %p", got, fresh)
	}
	if cur := h.chain.current.Load(); cur != fresh {
		t.Errorf("chain.current = %p, want fresh %p", cur, fresh)
	}
}

// Compile-time sanity: confirm the test file compiles without unused
// imports.
var _ = sync.Once{}
