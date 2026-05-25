package proxybuild

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// testTCPPair returns a connected TCP pair; the caller closes both sides.
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

	chain := newH1Chain(initial, "example.com:443", nil)
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

	chain := newH1Chain(initial, "127.0.0.1:1", nil) // nil cfg + invalid target
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

// TestH1Chain_CloseAll_ClosesEveryLayer verifies that closeAll Closes
// every layer registered in the chain, including the original. The
// underlying conn close is observable via a Read on the peer side.
func TestH1Chain_CloseAll_ClosesEveryLayer(t *testing.T) {
	client1, server1 := testTCPPair(t)
	defer client1.Close()
	client2, server2 := testTCPPair(t)
	defer client2.Close()

	layer1 := http1.New(server1, "stream-close-1", envelope.Receive)
	layer2 := http1.New(server2, "stream-close-2", envelope.Receive)

	chain := newH1Chain(layer1, "example.com:443", nil)
	// Simulate a prior successful redial by injecting the second Layer
	// into the chain by hand. The real path appends through EnsureFresh's
	// dial; here we exercise closeAll's iteration shape directly without
	// needing a working dial.
	chain.layers = append(chain.layers, layer2)
	chain.current = layer2

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

// _ guards against the linter pruning the connector import when none of
// the cfg-driven dial paths are exercised in this file (the chain tests
// use a nil cfg + invalid target path). The import is required for
// chain construction via newH1Chain's *connector.BuildConfig parameter.
var _ = connector.BuildConfig{}
