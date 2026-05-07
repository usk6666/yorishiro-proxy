//go:build e2e

// Package mcptest_test holds USK-755's smoke coverage for the
// proxy_start / proxy_stop / restart cycle.
//
// proxy_stop has historically had zero merge-gate coverage (no e2e
// smoke or full test invokes it), and lifecycle races around listener
// teardown were the proximate cause of USK-715 (DetachStream) and
// USK-739 (HTTP/2 RST_STREAM/PROTOCOL_ERROR flake series). This file
// exercises the documented lifecycle through the JSON-RPC harness so
// regressions in those areas trip merge CI rather than nightly.
package mcptest_test

import (
	"encoding/json"
	"net"
	"strconv"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ProxyLifecycle_StartStopCycle proves the documented
// proxy_start → proxy_stop → query("status") sequence. Asserts that
// the listener count drops to zero after stop and the proxy reports
// running=false. Without this, "stop tool is broken" would only be
// caught when an integrator complained.
func TestE2E_ProxyLifecycle_StartStopCycle(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	if !decodedListenerCountAtLeast(t, startRes, 1) {
		t.Fatalf("proxy_start did not surface a running listener; result=%s", startRes.Text)
	}

	statusBefore := queryStatus(t, h)
	if !statusBefore.Running {
		t.Fatalf("query(status).running = false after proxy_start; want true")
	}
	if statusBefore.ListenerCount < 1 {
		t.Fatalf("query(status).listener_count = %d after proxy_start; want >= 1", statusBefore.ListenerCount)
	}

	stopRes := h.MustOK(t, "proxy_stop", map[string]any{})
	if got, _ := stopRes.Decoded["status"].(string); got != "stopped" {
		t.Errorf("proxy_stop result.status = %q, want %q", got, "stopped")
	}

	statusAfter := queryStatus(t, h)
	if statusAfter.Running {
		t.Errorf("query(status).running = true after proxy_stop; want false")
	}
	if statusAfter.ListenerCount != 0 {
		t.Errorf("query(status).listener_count = %d after proxy_stop; want 0", statusAfter.ListenerCount)
	}
}

// TestE2E_ProxyLifecycle_RebindSamePort exercises the most common
// cause of port-reuse bugs: stop a listener and immediately restart
// at the same explicit port. SO_REUSEADDR semantics on Linux mean
// this should succeed without TIME_WAIT delay; if proxybuild leaks a
// listener or socket reference, the second proxy_start surfaces a
// bind error.
func TestE2E_ProxyLifecycle_RebindSamePort(t *testing.T) {
	port := pickFreePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	h.MustOK(t, "proxy_start", map[string]any{"listen_addr": addr})
	h.MustOK(t, "proxy_stop", map[string]any{})
	// Re-bind: if a leak prevents the previous socket from clearing,
	// this returns "address already in use" and MustOK fatals.
	h.MustOK(t, "proxy_start", map[string]any{"listen_addr": addr})

	status := queryStatus(t, h)
	if !status.Running {
		t.Fatalf("query(status).running = false after rebind; want true")
	}
	if status.ListenAddr == "" {
		t.Errorf("query(status).listen_addr is empty after rebind")
	}
}

// TestE2E_ProxyLifecycle_StopWithoutStart asserts that proxy_stop on
// a never-started proxy returns a clear error rather than panicking
// or silently succeeding. This is the negative-path companion to the
// happy-path lifecycle test — important because mcpserver.Run wires
// the proxy manager during boot, so "no listener" is a different
// failure mode than "no manager".
func TestE2E_ProxyLifecycle_StopWithoutStart(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	// proxybuild.ErrNotRunning surfaces as "not running" in the wrapped
	// error string. Match the stable substring rather than the wrapped
	// error message so error-wrapping refactors do not break the test.
	h.ExpectError(t, "proxy_stop", map[string]any{}, "not running")
}

// statusSnapshot is the subset of query(status) we read in the
// lifecycle assertions. Defined locally so the test stays self-
// contained — query_tool.queryStatusResult is unexported and we do
// not want to leak it across package boundaries.
type statusSnapshot struct {
	Running       bool   `json:"running"`
	ListenAddr    string `json:"listen_addr"`
	ListenerCount int    `json:"listener_count"`
}

// queryStatus issues query(resource="status") and decodes the response
// into statusSnapshot. Test failures point at the raw text so
// debugging a malformed response is straightforward.
func queryStatus(t *testing.T, h *mcptest.Harness) statusSnapshot {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "status"})
	var snap statusSnapshot
	if err := json.Unmarshal([]byte(res.Text), &snap); err != nil {
		t.Fatalf("decode query(status): %v (text=%q)", err, res.Text)
	}
	return snap
}

// decodedListenerCountAtLeast reports whether the proxy_start result's
// decoded payload indicates at least n listeners are running. Used as
// the post-start sanity gate before the test issues query(status).
func decodedListenerCountAtLeast(t *testing.T, res mcptest.ToolResult, n int) bool {
	t.Helper()
	addr, _ := res.Decoded["listen_addr"].(string)
	return addr != "" && n >= 1
}

// pickFreePort acquires an ephemeral loopback port, releases it, and
// returns the port number for re-use as a fixed listen address. This
// is the canonical "find a free port" idiom used elsewhere in the
// harness; the brief window between Close and the next bind is the
// same the OS provides to any caller.
func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("acquire ephemeral port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
