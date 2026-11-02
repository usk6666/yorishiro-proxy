package proxybuild

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// testTCPPair returns a connected TCP pair. Both ends are registered
// with t.Cleanup so they stay alive (preventing the *net.TCPConn
// finalizer from closing whichever side the caller discards via `_`,
// which surfaced as a ~0.2% HealthCheck EOF flake) and are closed when
// the test ends. Callers may still defer Close on either end without
// double-close concerns — net.Conn.Close is idempotent.
// We use real loopback TCP rather than net.Pipe so SetReadDeadline
// behaves the same way the production code path observes (net.Pipe is
// strictly synchronous and does not surface a queued FIN through the
// netpoller cycle the health probe relies on).
func testTCPPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// TestH1Chain_EnsureFresh_PassThroughWhenAlive verifies the happy path:
// HealthCheck returns nil on a fresh idle conn, so EnsureFresh returns
// the same Layer pointer without dialing anything (cfg is nil — a real
// redial would panic before reaching the dial code).
func TestH1Chain_EnsureFresh_PassThroughWhenAlive(t *testing.T) {
	_, server := testTCPPair(t)
	defer server.Close()

	initial := http1.New(server, "stream-passthru", envelope.Receive)
	defer initial.Close()

	chain := newH1Chain(initial, connector.SameUpstreamTarget("example.com:443"), connector.UpstreamTLSProfiled, nil, nil, nil)
	defer chain.closeAll()

	got, err := chain.EnsureFresh(context.Background())
	if err != nil {
		t.Fatalf("EnsureFresh: %v", err)
	}
	if got != initial {
		t.Errorf("EnsureFresh returned a new Layer when the current was alive (no redial expected)")
	}
}

// TestH1Chain_EnsureFresh_RedialFailureSurfaced asserts that when the
// current Layer is stale (peer-closed) and the BuildConfig is nil so the
// redial cannot succeed, the dial error is returned to the caller (it
// surfaces through the per-exchange session as state="error" — same
// shape as the original dial closure's error path).
func TestH1Chain_EnsureFresh_RedialFailureSurfaced(t *testing.T) {
	client, server := testTCPPair(t)

	initial := http1.New(server, "stream-redial-fail", envelope.Receive)
	defer initial.Close()

	// Close the peer to make HealthCheck observe a stale state.
	_ = client.Close()

	chain := newH1Chain(initial, connector.SameUpstreamTarget("127.0.0.1:1"), connector.UpstreamTLSProfiled, nil, nil, nil) // nil cfg + invalid target
	defer chain.closeAll()

	// Poll EnsureFresh until the loopback FIN propagates and HealthCheck
	// flips to stale; once stale the nil cfg surfaces a dial error.
	// Bounded; flake-resistant on slow CI.
	deadline := time.Now().Add(2 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		_, err = chain.EnsureFresh(context.Background())
		if err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err == nil {
		t.Fatal("EnsureFresh on stale Layer with nil cfg: got nil after polling, want dial error")
	}
}

// TestH1Chain_CloseAll_ClosesEveryLayer verifies that after a swap both
// the original and the swapped-in Layer end up closed once closeAll runs:
// the predecessor by the swap itself, the current one by closeAll. The
// underlying conn close is observable via a Read on the peer side.
func TestH1Chain_CloseAll_ClosesEveryLayer(t *testing.T) {
	client1, server1 := testTCPPair(t)
	defer client1.Close()
	client2, server2 := testTCPPair(t)
	defer client2.Close()

	layer1 := http1.New(server1, "stream-close-1", envelope.Receive)
	layer2 := http1.New(server2, "stream-close-2", envelope.Receive)

	chain := newH1Chain(layer1, connector.SameUpstreamTarget("example.com:443"), connector.UpstreamTLSProfiled, nil, nil, nil)
	// Simulate a prior successful redial by swapping the second Layer in
	// by hand, the bookkeeping every real redial / retarget runs.
	chain.mu.Lock()
	chain.swapLocked(layer2)
	chain.mu.Unlock()

	chain.closeAll()

	// After closeAll, the peer side observes EOF (the server-side conn
	// owned by each Layer is closed).
	_ = client1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_ = client2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var buf [1]byte
	if _, err := client1.Read(buf[:]); err == nil {
		t.Error("closeAll: layer1 conn still readable; expected EOF after Close")
	}
	if _, err := client2.Read(buf[:]); err == nil {
		t.Error("closeAll: layer2 conn still readable; expected EOF after Close")
	}
}

// TestH1Chain_SwapRetainsOnlyCurrent covers a client that switches its
// forward target many times on one connection (USK-1410): each swap
// closes and drops its predecessor, so the chain holds only the live
// Layer, the ConnID generation keeps advancing, and — swaps alone being
// no staleness — the chain_generation gauges stay untouched.
func TestH1Chain_SwapRetainsOnlyCurrent(t *testing.T) {
	const swaps = 8
	m := NewH1UpstreamMetrics()
	peers := make([]net.Conn, 0, swaps+1)
	newLayer := func(i int) *http1.Layer {
		client, server := testTCPPair(t)
		peers = append(peers, client)
		return http1.New(server, "stream-swap-"+strconv.Itoa(i), envelope.Receive)
	}

	chain := newH1Chain(newLayer(0), connector.SameUpstreamTarget("a.example:80"), connector.UpstreamTLSProfiled, nil, discardLogger(), m)
	var last *http1.Layer
	for i := 1; i <= swaps; i++ {
		last = newLayer(i)
		chain.mu.Lock()
		chain.swapLocked(last)
		chain.mu.Unlock()
	}

	if chain.current != last {
		t.Fatal("current is not the last swapped-in Layer")
	}
	if chain.generation != swaps {
		t.Errorf("generation = %d, want %d", chain.generation, swaps)
	}
	if chain.liveGen != 0 {
		t.Errorf("liveGen = %d after swaps alone, want 0", chain.liveGen)
	}
	if snap := m.Snapshot(); snap.ChainGenerationLive != 0 || snap.ChainGenerationMax != 0 {
		t.Errorf("chain_generation live=%d max=%d after swaps alone, want 0/0", snap.ChainGenerationLive, snap.ChainGenerationMax)
	}
	// Every predecessor is already closed; the current one is still open.
	var buf [1]byte
	for i, c := range peers[:swaps] {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := c.Read(buf[:]); err == nil {
			t.Errorf("predecessor %d still readable after its swap; want closed", i)
		}
	}
	_ = peers[swaps].SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := peers[swaps].Read(buf[:]); err == nil || !isTimeout(err) {
		t.Errorf("current Layer's conn: Read err = %v, want a timeout (still open)", err)
	}

	chain.closeAll()
	_ = peers[swaps].SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := peers[swaps].Read(buf[:]); err == nil || isTimeout(err) {
		t.Errorf("current Layer's conn after closeAll: Read err = %v, want EOF", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// _ guards against the linter pruning the connector import when none of
// the cfg-driven dial paths are exercised in this file (the chain tests
// use a nil cfg + invalid target path). The import is required for
// chain construction via newH1Chain's *connector.BuildConfig parameter.
var _ = connector.BuildConfig{}
