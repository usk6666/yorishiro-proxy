//go:build e2e && !e2e_smoke

// USK-1159 exhaustive tier: timeout auto-release and modify_and_forward are
// re-checked against the scope the same way as a manual release (the smoke
// test in intercept_scope_recheck_smoke_integration_test.go).
package mcptest_test

import (
	"fmt"
	"testing"
	"time"
)

// TestE2E_InterceptScopeRecheck_TimeoutAutoReleaseBlocked is T12: a hold
// that expires into the default auto_release after a reload denied its host
// is blocked exactly like a manual release.
func TestE2E_InterceptScopeRecheck_TimeoutAutoReleaseBlocked(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	h, policyPath, client := startScopeRecheckProxy(t, `{"allows":[{"hostname":"127.0.0.1"}]}`)
	h.MustOK(t, "configure", map[string]any{
		"intercept_queue": map[string]any{"timeout_ms": 2000, "timeout_behavior": "auto_release"},
	})

	respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/held-timeout", upstreamAddr), nil, nil)
	waitForHeldEntry(t, h, 5*time.Second)
	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	// No intercept action: the hold times out into auto_release.
	assertScopeBlockedResponse(t, awaitResponse(t, respCh))
	if got := upstream.hitCount(); got != 0 {
		t.Errorf("upstream hits = %d, want 0 — the auto-released request reached the newly denied host", got)
	}
	assertBlockedFlowRecorded(t, h)
}

// TestE2E_InterceptScopeRecheck_ModifyAndForwardToDeniedPath is T13: with
// no reload at all, modify_and_forward rewriting the path into a
// policy-denied prefix is blocked; rewriting it to an allowed path is
// forwarded (guard).
func TestE2E_InterceptScopeRecheck_ModifyAndForwardToDeniedPath(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	h, _, client := startScopeRecheckProxy(t,
		`{"allows":[{"hostname":"127.0.0.1"}],"denies":[{"hostname":"127.0.0.1","path_prefix":"/admin"}]}`)

	modifyPath := func(path string) proxiedResponse {
		t.Helper()
		respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/held-public", upstreamAddr), nil, nil)
		entry := waitForHeldEntry(t, h, 5*time.Second)
		h.MustOK(t, "intercept", map[string]any{
			"action": "modify_and_forward",
			"params": map[string]any{"intercept_id": entry["id"]},
			"http":   map[string]any{"path": path},
		})
		return awaitResponse(t, respCh)
	}

	// Guard: an allowed rewrite is forwarded.
	if resp := modifyPath("/public-rewritten"); resp.err != nil || resp.statusCode != 200 {
		t.Fatalf("allowed modify_and_forward: status=%d err=%v, want 200", resp.statusCode, resp.err)
	}
	if got := upstream.hitCount(); got != 1 {
		t.Fatalf("upstream hits after allowed rewrite = %d, want 1", got)
	}

	assertScopeBlockedResponse(t, modifyPath("/admin/users"))
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the rewrite into the denied /admin prefix was forwarded", got)
	}
	assertBlockedFlowRecorded(t, h)
}
