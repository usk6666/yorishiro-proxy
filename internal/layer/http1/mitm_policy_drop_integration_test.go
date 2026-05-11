//go:build e2e && !e2e_smoke

// USK-829: policy-drop terminator e2e coverage.
//
// Verifies that when a Pipeline policy Step (Intercept / HostScope /
// HTTPScope / Safety) blocks a Send-direction HTTP request, the proxy
// emits a synthetic 403 Forbidden response on the wire instead of
// dropping the envelope silently. The pre-fix behaviour left the client
// hanging until its own read timeout (curl exit 28 in the bug report).

package http1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// assertPolicyDropResponse checks the response is a well-formed 403 JSON
// terminator with the expected headers and body shape.
func assertPolicyDropResponse(t *testing.T, resp, wantBlockedBy string) {
	t.Helper()
	if !strings.HasPrefix(resp, "HTTP/1.1 403") {
		t.Errorf("expected 403 status line, got %q", firstLine(resp))
	}
	if !strings.Contains(resp, "Content-Type: application/json") {
		t.Errorf("expected Content-Type: application/json header, missing in %q", resp)
	}
	if !strings.Contains(resp, "Connection: close") {
		t.Errorf("expected Connection: close header, missing in %q", resp)
	}
	if !strings.Contains(resp, "Server: yorishiro-proxy") {
		t.Errorf("expected Server: yorishiro-proxy header, missing in %q", resp)
	}
	// Extract body (after \r\n\r\n) and ensure it is parseable JSON
	// carrying the expected blocked_by value.
	idx := strings.Index(resp, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("response has no header/body separator: %q", resp)
	}
	body := resp[idx+4:]
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("body is not parseable JSON (%v): %q", err, body)
	}
	if payload["blocked_by"] != wantBlockedBy {
		t.Errorf("body blocked_by = %v, want %q (full body: %q)", payload["blocked_by"], wantBlockedBy, body)
	}
	if _, ok := payload["error"]; !ok {
		t.Errorf("body missing 'error' field: %q", body)
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// TestHTTPSMITM_InterceptDrop verifies that intercept "drop" emits a 403
// JSON terminator on the wire so the client closes cleanly rather than
// hanging on its read timeout.
func TestHTTPSMITM_InterceptDrop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamReceived := make(chan struct{}, 1)
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		upstreamReceived <- struct{}{}
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	interceptEngine := httprules.NewInterceptEngine()
	interceptEngine.AddRule(httprules.InterceptRule{
		ID:          "test-intercept-drop",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`/intercept`),
	})
	holdQueue := common.NewHoldQueue()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		interceptEngine: interceptEngine,
		holdQueue:       holdQueue,
	})

	// Issue the request in a goroutine — it blocks on the intercept hold
	// until we release with ActionDrop.
	respCh := make(chan string, 1)
	go func() {
		rawReq := fmt.Sprintf("GET /intercept HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
		respCh <- connectAndSendHTTP(t, proxyAddr, target, rawReq)
	}()

	// Poll for held entry.
	var entries []*common.HeldEntry
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries = holdQueue.List()
		if len(entries) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("no entry appeared in hold queue")
	}

	// Release with Drop.
	if err := holdQueue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionDrop}); err != nil {
		t.Fatalf("release with Drop: %v", err)
	}

	// USK-829: client must receive a 403 response within a few seconds —
	// well under any "max-time" budget the operator might set on curl.
	var resp string
	select {
	case resp = <-respCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for client response after intercept drop (USK-829 regression: client should not hang)")
	}

	assertPolicyDropResponse(t, resp, "intercept_drop")

	// Verify upstream never saw the request.
	select {
	case <-upstreamReceived:
		t.Error("upstream handler was called — intercept drop did not prevent forward")
	case <-time.After(500 * time.Millisecond):
		// Good: upstream was never called.
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// Note: the test harness uses a minimal pipeline (HostScope → HTTPScope
	// → Safety → Transform → Intercept → Record). When Intercept emits a
	// terminal Respond action, downstream Steps (Record) are skipped per
	// Pipeline contract, so the original held envelope is NOT recorded via
	// the harness's RecordStep. Audit Stream attribution for blocked
	// envelopes is wired in production by proxybuild's
	// buildPipelineDropRecorder via SessionOptions.OnPipelineDrop — that
	// callback fires for both Drop and Respond+blockedBy under USK-829
	// (covered by internal/proxybuild/manager_drop_recorder_test.go in
	// the broader test suite). This test focuses on the wire-level
	// guarantee: client receives a parseable 403 instead of hanging.
	_ = store
}

// TestHTTPSMITM_HostScopeReject verifies that a connection-level host
// deny surfaces as a 403 wire terminator (USK-829). In the test harness
// HostScopeStep is instantiated with nil scope (see
// startHTTPMITMProxy's pipeline build site), so the actual blocker on
// the wire is HTTPScopeStep — both Steps share the BlockedByTargetScope
// attribution so the e2e assertion is identical. Connection-level
// HostScopeStep behaviour is covered at the unit level in
// pipeline/host_scope_step_test.go (the _HTTPMessage_Respond tests).
func TestHTTPSMITM_HostScopeReject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamReceived := make(chan struct{}, 1)
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		upstreamReceived <- struct{}{}
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// Configure a TargetScope that explicitly denies the upstream host.
	// USK-829: the block must surface as a 403, not a silent drop. In the
	// harness this resolves through HTTPScopeStep (see comment above);
	// the unit tests prove the same Respond branch fires from
	// HostScopeStep when HostScopeStep is wired in production.
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{
		{Hostname: "127.0.0.1"},
	})

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		scope: scope,
	})

	rawReq := fmt.Sprintf("GET /any HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)

	respCh := make(chan string, 1)
	go func() {
		respCh <- connectAndSendHTTP(t, proxyAddr, target, rawReq)
	}()

	var resp string
	select {
	case resp = <-respCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for client response after host_scope reject (USK-829 regression)")
	}

	assertPolicyDropResponse(t, resp, "target_scope")

	select {
	case <-upstreamReceived:
		t.Error("upstream handler was called — host_scope did not block forwarding")
	case <-time.After(500 * time.Millisecond):
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}
}

// TestHTTPSMITM_HTTPScopeReject verifies that HTTPScopeStep emits a 403
// terminator on the wire when the per-request URL is denied.
func TestHTTPSMITM_HTTPScopeReject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamReceived := make(chan struct{}, 1)
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		upstreamReceived <- struct{}{}
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// Configure path-based scope: only /allowed/* is permitted; the
	// request below targets /forbidden, so HTTPScopeStep blocks it.
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "127.0.0.1", PathPrefix: "/allowed/"},
	}, nil)

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		scope: scope,
	})

	rawReq := fmt.Sprintf("GET /forbidden HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)

	respCh := make(chan string, 1)
	go func() {
		respCh <- connectAndSendHTTP(t, proxyAddr, target, rawReq)
	}()

	var resp string
	select {
	case resp = <-respCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for client response after http_scope reject (USK-829 regression)")
	}

	assertPolicyDropResponse(t, resp, "target_scope")

	select {
	case <-upstreamReceived:
		t.Error("upstream handler was called — http_scope did not block forwarding")
	case <-time.After(500 * time.Millisecond):
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}
}
