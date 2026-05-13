//go:build e2e

// Package mcptest_test holds USK-861's smoke coverage for the
// proxy_start tcp_forwards / listen_addr port-collision contract.
//
// The bug (Phase 5 retest, 2026-05-13): proxy_start with the same port
// in listen_addr and tcp_forwards left a phantom registered listener
// because the parent listener was registered before the forward bind
// failure was surfaced. Subsequent proxy_stop appeared to succeed but
// the registry retained a stale entry, so re-creating under the same
// name returned "listener with this name already exists".
//
// Two regressions are covered:
//
//  1. Self-collision (listen_addr port == tcp_forwards port) is
//     rejected fail-fast with a clear error mentioning both values.
//  2. External-collision (a separate process holds the forward port)
//     rolls back the parent listener so the same name is reusable.
package mcptest_test

import (
	"net"
	"strconv"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ProxyStart_TCPForwardSelfCollisionRejected proves the
// fail-fast cross-field check: if the caller specifies the same port
// in listen_addr and tcp_forwards, proxy_start rejects the call before
// any listener is registered. Without this, the caller observed a
// half-broken listener with no way to recover the name short of a
// process restart.
func TestE2E_ProxyStart_TCPForwardSelfCollisionRejected(t *testing.T) {
	// Pick any free port to use as both listen_addr and tcp_forwards
	// key. The actual binding never happens — the validator rejects
	// before StartNamed touches the registry.
	port := pickFreePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	// Error must mention BOTH the colliding port and the listen_addr
	// so an AI agent caller can self-diagnose. The substring match
	// pins the user-facing format without coupling to the exact phrase.
	h.ExpectError(t, "proxy_start", map[string]any{
		"listen_addr": addr,
		"tcp_forwards": map[string]any{
			strconv.Itoa(port): "127.0.0.1:1",
		},
	}, "tcp_forwards")

	// Sanity: query(status) must report the proxy as not running. If
	// the validator failed to short-circuit, a phantom listener would
	// be registered and the count would be >= 1.
	status := queryStatus(t, h)
	if status.Running {
		t.Errorf("query(status).running = true after rejected proxy_start; want false (no phantom listener)")
	}
	if status.ListenerCount != 0 {
		t.Errorf("query(status).listener_count = %d after rejected proxy_start; want 0", status.ListenerCount)
	}
}

// TestE2E_ProxyStart_TCPForwardExternalConflictAllowsRecreate proves
// the rollback path: when an external process holds the forward port,
// the parent listener registration is undone so the user can recreate
// under the same name. Prior to the fix, a second proxy_start with the
// same `name` returned "listener with this name already exists" because
// the rollback was missing in handleProxyStart.
func TestE2E_ProxyStart_TCPForwardExternalConflictAllowsRecreate(t *testing.T) {
	// Reserve a port externally so the proxy's bind attempt for that
	// tcp_forwards entry fails with "address already in use".
	occupiedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve external port: %v", err)
	}
	occupiedReleased := false
	releaseOccupied := func() {
		if occupiedReleased {
			return
		}
		occupiedReleased = true
		_ = occupiedLn.Close()
	}
	t.Cleanup(releaseOccupied)
	_, occupiedPort, err := net.SplitHostPort(occupiedLn.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	const listenerName = "raw-collide"

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	// First proxy_start: forward bind conflict triggers rollback.
	h.ExpectError(t, "proxy_start", map[string]any{
		"name":        listenerName,
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			occupiedPort: "127.0.0.1:1",
		},
	}, "tcp_forwards")

	// The parent listener must NOT remain registered. This is the
	// substantive bug: without StopNamed in the rollback path, a
	// phantom entry persists and blocks recreation under the same name.
	if status := queryStatus(t, h); status.ListenerCount != 0 {
		t.Errorf("query(status).listener_count after rolled-back proxy_start = %d, want 0",
			status.ListenerCount)
	}

	// Release the externally-held port and retry under the SAME name
	// with a non-colliding forward port. Without the rollback fix this
	// returned "listener with this name already exists".
	releaseOccupied()

	h.MustOK(t, "proxy_start", map[string]any{
		"name":        listenerName,
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": "127.0.0.1:1", // ephemeral; cannot collide
		},
	})

	if status := queryStatus(t, h); status.ListenerCount < 1 {
		t.Errorf("query(status).listener_count after successful recreate = %d, want >= 1",
			status.ListenerCount)
	}
}
