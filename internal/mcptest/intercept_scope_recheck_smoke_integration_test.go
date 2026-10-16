//go:build e2e

// USK-1159: an intercept hold released after the Policy Layer was reloaded
// to deny its target is re-checked against the scope, through the
// production assembly (mcpserver.Run → proxybuild.buildPipeline) and real
// plain-HTTP forward-proxy traffic.
package mcptest_test

import (
	"encoding/json"
	"fmt"
	gohttp "net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// holdHeldPathRule holds every request whose path starts with /held.
var holdHeldPathRule = []map[string]any{{
	"id":        "hold-held",
	"enabled":   true,
	"protocol":  "http",
	"direction": "request",
	"http":      map[string]any{"path_pattern": "^/held"},
}}

// startScopeRecheckProxy boots the harness with a policy file allowing
// 127.0.0.1 and starts a proxy whose intercept rule holds /held*.
func startScopeRecheckProxy(t *testing.T, policy string) (h *mcptest.Harness, policyPath string, client *gohttp.Client) {
	t.Helper()
	policyPath = filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, policy)
	h = mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})
	client = proxyHTTPClient(t, startProxyWithRules(t, h, holdHeldPathRule, nil))
	return h, policyPath, client
}

// assertScopeBlockedResponse asserts the client received the synthetic 403
// the head-of-pipeline scope Steps emit, attributed to target_scope.
func assertScopeBlockedResponse(t *testing.T, resp proxiedResponse) {
	t.Helper()
	if resp.err != nil {
		t.Fatalf("proxied request: %v", resp.err)
	}
	if resp.statusCode != gohttp.StatusForbidden {
		t.Fatalf("status = %d (body %q), want 403 — the scope re-check did not block the release", resp.statusCode, resp.body)
	}
	var body struct {
		BlockedBy string `json:"blocked_by"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatalf("403 body %q is not JSON: %v", resp.body, err)
	}
	if body.BlockedBy != "target_scope" {
		t.Errorf("403 body blocked_by = %q, want %q", body.BlockedBy, "target_scope")
	}
}

// assertBlockedFlowRecorded asserts the blocked release was recorded as an
// audit Stream with blocked_by=target_scope (session OnPipelineDrop).
func assertBlockedFlowRecorded(t *testing.T, h *mcptest.Harness) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter":   map[string]any{"blocked_by": "target_scope"},
		})
		if flows, _ := res.Decoded["flows"].([]any); len(flows) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("query(flows, blocked_by=target_scope) returned 0 results; the blocked release was not recorded")
}

func awaitResponse(t *testing.T, ch chan proxiedResponse) proxiedResponse {
	t.Helper()
	select {
	case resp := <-ch:
		return resp
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for the proxied response")
		return proxiedResponse{}
	}
}

// TestE2E_InterceptScopeRecheck_ReleaseAfterReloadBlocked is T11 /
// acceptance criterion 1: a request held by intercept, whose host the
// operator then denies by reloading the policy, is answered 403
// target_scope on release and never reaches the upstream. An allowed hold
// released before the reload still reaches the upstream (guard).
func TestE2E_InterceptScopeRecheck_ReleaseAfterReloadBlocked(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	h, policyPath, client := startScopeRecheckProxy(t, `{"allows":[{"hostname":"127.0.0.1"}]}`)

	// Guard: an allowed hold released unmodified is forwarded as before.
	respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/held-allowed", upstreamAddr), nil, nil)
	entry := waitForHeldEntry(t, h, 5*time.Second)
	h.MustOK(t, "intercept", map[string]any{"action": "release", "params": map[string]any{"intercept_id": entry["id"]}})
	if resp := awaitResponse(t, respCh); resp.err != nil || resp.statusCode != gohttp.StatusOK {
		t.Fatalf("allowed release: status=%d err=%v, want 200", resp.statusCode, resp.err)
	}
	if got := upstream.hitCount(); got != 1 {
		t.Fatalf("upstream hits after allowed release = %d, want 1", got)
	}

	// Hold a second request, deny its host by reload, then release it.
	respCh = requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/held-denied", upstreamAddr), nil, nil)
	entry = waitForHeldEntry(t, h, 5*time.Second)
	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	h.MustOK(t, "intercept", map[string]any{"action": "release", "params": map[string]any{"intercept_id": entry["id"]}})

	assertScopeBlockedResponse(t, awaitResponse(t, respCh))
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the released request reached the newly denied host", got)
	}
	assertBlockedFlowRecorded(t, h)
}
