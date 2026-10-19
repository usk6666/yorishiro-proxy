//go:build e2e && !e2e_smoke

// USK-1161 exhaustive tier: the tcp_forwards accept-time gate against a
// scope changed at runtime, and live-connection reconciliation of open
// tcp_forwards connections. Helpers live in
// raw_target_scope_smoke_integration_test.go,
// live_conn_reconcile_*_integration_test.go and
// live_conn_hold_defer_integration_test.go.
package mcptest_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_TCPForwardScope_AgentDenyRejectsAtAccept is test-plan 3: a deny
// the agent adds after the forward started (security tool, no reload)
// rejects new raw connections at accept — the client reads EOF with no
// bytes and the upstream sees no connection at all.
func TestE2E_TCPForwardScope_AgentDenyRejectsAtAccept(t *testing.T) {
	target, _, accepts := countingEchoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw"})[0]

	h.MustOK(t, "security", map[string]any{
		"action": "update_target_scope",
		"params": map[string]any{"add_denies": []map[string]any{{"hostname": "127.0.0.1", "ports": []int{rawAddrPort(t, target)}}}},
	})

	c := writeRaw(t, fwd, rawProbe)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if n > 0 {
		t.Errorf("read %d bytes from a denied forward, want none", n)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("denied forward connection still open after 5s")
	}
	time.Sleep(200 * time.Millisecond)
	if got := accepts.Load(); got != 0 {
		t.Errorf("denied upstream accepted %d connections, want 0", got)
	}
}

// TestE2E_TCPForwardScope_RawCutOnReload is test-plan 6: a policy reload
// that denies the target closes a live raw tcp_forwards relay, and no
// byte reaches the upstream afterwards.
func TestE2E_TCPForwardScope_RawCutOnReload(t *testing.T) {
	target, received := echoUpstream(t)
	h, policyPath := bootReloadHarness(t)
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw"})[0]

	c := writeRaw(t, fwd, rawProbe)
	readEcho(t, c, rawProbe)

	reloadDenyLoopback(t, h, policyPath)
	assertConnClosedWithin(t, c, c.SetReadDeadline, 5*time.Second)
	before := received.Load()
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write(rawProbe)
	time.Sleep(200 * time.Millisecond)
	if got := received.Load(); got != before {
		t.Errorf("upstream received %d bytes after the cut, want 0", got-before)
	}
}

// countingHTTPUpstream is a plain HTTP server counting requests.
func countingHTTPUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), &hits
}

// forwardGET sends a keep-alive GET on c and returns the status code.
func forwardGET(t *testing.T, c net.Conn, br *bufio.Reader, host, path string) int {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestE2E_TCPForwardScope_HTTPCutOnReload is test-plan 7: a widening
// reload leaves a live L7 (http) tcp_forwards connection alone; a reload
// that denies the target closes it.
func TestE2E_TCPForwardScope_HTTPCutOnReload(t *testing.T) {
	target, hits := countingHTTPUpstream(t)
	h, policyPath := bootReloadHarness(t)
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "http"})[0]

	c, err := net.DialTimeout("tcp", fwd, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	br := bufio.NewReader(c)
	if got := forwardGET(t, c, br, target, "/1"); got != http.StatusOK {
		t.Fatalf("GET /1 = %d", got)
	}

	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"127.0.0.1"},{"hostname":"other.test"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy (widen): %v", err)
	}
	if got := forwardGET(t, c, br, target, "/2"); got != http.StatusOK {
		t.Fatalf("GET /2 after widening reload = %d", got)
	}

	reloadDenyLoopback(t, h, policyPath)
	assertConnClosedWithin(t, br, c.SetReadDeadline, 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if got := hits.Load(); got != 2 {
		t.Errorf("upstream hits = %d, want 2", got)
	}
}

// TestE2E_TCPForwardScope_HoldDefersCut is test-plan 8 (USK-1192 parity):
// a request held by an intercept rule on a tcp_forwards http connection
// defers the reload's cut; releasing it answers 403 target_scope, then
// the connection is closed. Nothing reaches the upstream.
func TestE2E_TCPForwardScope_HoldDefersCut(t *testing.T) {
	target, hits := countingHTTPUpstream(t)
	h, policyPath := bootReloadHarness(t)
	fwd := startForwards(t, h, map[string]any{"intercept_rules": holdHeldPathRule},
		map[string]any{"target": target, "protocol": "http"})[0]

	c, err := net.DialTimeout("tcp", fwd, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := io.WriteString(c, "GET /held-1 HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	entry := waitForHeldEntry(t, h, 5*time.Second)

	reloadDenyLoopback(t, h, policyPath)
	releaseHeld(t, h, entry)

	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("held request: no response after release (%v); the cut was not deferred", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assertTargetScope403Body(t, resp.StatusCode, body, "released held request")

	assertConnClosedWithin(t, br, c.SetReadDeadline, 5*time.Second)
	if got := hits.Load(); got != 0 {
		t.Errorf("upstream hits = %d, want 0", got)
	}
}
