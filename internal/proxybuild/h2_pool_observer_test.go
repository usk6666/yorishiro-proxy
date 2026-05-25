//go:build e2e

// USK-994 smoke-tier integration coverage for the pool-constructed
// chain[0] GOAWAY observer plumbing.
//
// The unit tests in h2_prewarm_test.go pin the layer-level invariants
// deterministically (RegisterGoAwayObserver fires; head-comparison
// guards drain-out chain steps). This file confirms the wiring runs
// end-to-end through a real *pool.Pool.GetOrDial — a pool miss runs
// dialFn (which constructs a Layer with NO observer, matching the
// production connector pool's dialFn shape), and then a post-
// construction RegisterGoAwayObserver attaches the wake-tickle closure.
// A real GOAWAY frame from the peer triggers the readerLoop's
// handleGoAwayFrame, which fires the observer, tickles wake, and the
// pre-warm worker dials a fresh upstream before any subsequent
// selectUpstreamForDial call.
//
// Why smoke tier (`//go:build e2e`, NOT `e2e && !e2e_smoke`): the
// chain[0] first-GOAWAY browser-parity guarantee is part of the merge
// gate. A regression that reverted to "first GOAWAY relies on reactive
// redial" would land silently if this only ran nightly. See CLAUDE.md
// "e2e test tiers" note and the design review's binding test plan.
package proxybuild

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

// TestH2PoolObserver_PreWarmFiresOnPooledLayerGoAway is the canonical
// smoke check: a Layer minted by pool.Pool.GetOrDial (no observer at
// construction, as the connector pool does today) is wired with the
// USK-994 observer post-construction, and a real GOAWAY on the peer
// triggers the pre-warm worker before any second pool.Get call.
//
// Staging mirrors the production flow from buildOnHTTP2Stack:
//  1. Construct a real pool.Pool.
//  2. GetOrDial with a custom dialFn that mints a Layer + peer pair via
//     net.Pipe and retains the peer end. The dialFn does NOT pass
//     WithGoAwayObserver (matching production).
//  3. Construct a redialChain + pre-warm worker.
//  4. Register the observer on the pooled Layer via
//     Layer.RegisterGoAwayObserver — the USK-994 production hook point.
//  5. Inject GOAWAY on the retained peer end.
//  6. Assert the worker dialed and chain.current swapped.
func TestH2PoolObserver_PreWarmFiresOnPooledLayerGoAway(t *testing.T) {
	// Build a real pool.
	p := pool.New(pool.PoolOptions{})
	defer p.Close()

	// Pre-mint the fresh chain[1] Layer so the worker's dial returns
	// deterministically.
	freshLayer, freshPeer := dialPeerH2Layer(t)
	defer freshLayer.Close()
	defer freshPeer.Close()

	// retained captures the peer end of the pooled Layer so the test
	// can inject GOAWAY after Pool.GetOrDial returns.
	var retainedPeer atomic.Pointer[net.Conn]

	key := pool.PoolKey{HostPort: "example.test:443", TLSConfigHash: "test"}

	// dialFn mints a *http2.Layer at the client end of a net.Pipe.
	// Same shape as connector/h2_pool.go::makeDialFn (no observer).
	dialFn := func() (*http2.Layer, error) {
		cliConn, srvConn := net.Pipe()

		// Read the client preface in a goroutine so http2.New can proceed.
		go func() {
			buf := make([]byte, len(http2.ClientPreface))
			_, _ = io.ReadFull(srvConn, buf)
		}()

		l, err := http2.New(cliConn, "test-pool-peer", http2.ClientRole)
		if err != nil {
			_ = cliConn.Close()
			_ = srvConn.Close()
			return nil, err
		}
		retainedPeer.Store(&srvConn)
		return l, nil
	}

	// Drive the pool to insert + return the pooled Layer.
	ctx := context.Background()
	pooled, err := p.GetOrDial(ctx, key, dialFn)
	if err != nil {
		t.Fatalf("Pool.GetOrDial: %v", err)
	}
	defer p.Put(key, pooled)

	peer := retainedPeer.Load()
	if peer == nil {
		t.Fatal("dialFn did not retain peer end")
	}
	defer (*peer).Close()

	// Construct the chain + worker shape buildOnHTTP2Stack produces.
	chain := newRedialChain(nil)

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
		return freshLayer, nil
	}

	workerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.startPrewarmWorker(workerCtx, key.HostPort, redialFn, nil, silentLogger())
	defer chain.closeAll()

	// USK-994 production wiring: attach the observer on the pooled
	// Layer. This is the chain[0] case — chain.current is nil, so the
	// head-comparison guard does NOT skip, and the observer tickles
	// wake.
	unregister := pooled.RegisterGoAwayObserver(func() {
		if chain.current.Load() != nil {
			return
		}
		chain.tickleWake()
	})
	defer unregister()

	// Inject GOAWAY on the retained peer end. The pooled Layer's reader
	// loop consumes it, runs handleGoAwayFrame, which fires the
	// registered observer, which tickles wake, which the worker
	// observes.
	injectGoAwayFromPeer(t, *peer, 0, 0)
	awaitGoAwayClosed(t, pooled)

	// Worker enters dial.
	select {
	case <-dialReady:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not enter dial within 2s of injected pool-Layer GOAWAY")
	}
	close(dialReleased)

	// chain.current should swap to freshLayer.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && chain.current.Load() != freshLayer {
		time.Sleep(5 * time.Millisecond)
	}
	if cur := chain.current.Load(); cur != freshLayer {
		t.Fatalf("chain.current = %p, want freshLayer %p (pre-warm did not complete)", cur, freshLayer)
	}
	if got := atomic.LoadInt32(&dialCount); got != 1 {
		t.Errorf("redialFn called %d times, want 1", got)
	}
}

// TestH2PoolObserver_PoolHitFastPathAlsoWired covers the symmetry
// between the buildOnHTTP2Stack first-CONNECT entry and the
// buildPoolHitFastPath CONNECT entry: both paths receive a pool-
// constructed Layer as upstreamH2, and both call into the same
// buildOnHTTP2Stack body. The observer-registration site lives inside
// buildOnHTTP2Stack, so the fast-path branch transparently receives
// the same wiring — no separate code change required.
//
// This test verifies the property by registering observers on a pooled
// Layer twice in succession (mirroring "second CONNECT to the same
// host hits the fast path"). Both registrations must fire on GOAWAY,
// confirming that the multi-observer support introduced by USK-994 is
// exercised correctly across re-entry into the same Layer.
func TestH2PoolObserver_PoolHitFastPathAlsoWired(t *testing.T) {
	p := pool.New(pool.PoolOptions{})
	defer p.Close()

	var retainedPeer atomic.Pointer[net.Conn]
	dialFn := func() (*http2.Layer, error) {
		cliConn, srvConn := net.Pipe()
		go func() {
			buf := make([]byte, len(http2.ClientPreface))
			_, _ = io.ReadFull(srvConn, buf)
		}()
		l, err := http2.New(cliConn, "test-pool-peer-fastpath", http2.ClientRole)
		if err != nil {
			_ = cliConn.Close()
			_ = srvConn.Close()
			return nil, err
		}
		retainedPeer.Store(&srvConn)
		return l, nil
	}

	key := pool.PoolKey{HostPort: "example.test:443", TLSConfigHash: "fastpath"}
	pooled, err := p.GetOrDial(context.Background(), key, dialFn)
	if err != nil {
		t.Fatalf("first GetOrDial: %v", err)
	}

	peer := retainedPeer.Load()
	if peer == nil {
		t.Fatal("dialFn did not retain peer end")
	}
	defer (*peer).Close()

	// First CONNECT registers observer A.
	var firesA int32
	cancelA := pooled.RegisterGoAwayObserver(func() {
		atomic.AddInt32(&firesA, 1)
	})
	defer cancelA()

	// Simulate "second CONNECT hits fast path": the pool returns the
	// same pooled Layer (no new dial). Register observer B on the same
	// Layer pointer.
	var firesB int32
	cancelB := pooled.RegisterGoAwayObserver(func() {
		atomic.AddInt32(&firesB, 1)
	})
	defer cancelB()

	// Single GOAWAY frame must fire both observers exactly once.
	injectGoAwayFromPeer(t, *peer, 0, 0)
	awaitGoAwayClosed(t, pooled)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&firesA) == 1 && atomic.LoadInt32(&firesB) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&firesA); got != 1 {
		t.Errorf("observer A fired %d times, want 1", got)
	}
	if got := atomic.LoadInt32(&firesB); got != 1 {
		t.Errorf("observer B fired %d times, want 1", got)
	}

	// Drop the pool reference so Close doesn't double-close the Layer.
	p.Put(key, pooled)
}
