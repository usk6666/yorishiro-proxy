//go:build e2e && !e2e_smoke

// USK-1115 exhaustive tier: the reverse direction of the smoke test (a
// host denied at boot becomes reachable after a reload) and an invalid
// rewrite that must leave the running policy in force.
package mcptest_test

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_PolicyReload_NewlyAllowedHostPasses is T2: the boot policy
// denies the upstream host; after the file is rewritten to allow it and a
// reload is requested, a new CONNECT reaches the upstream.
func TestE2E_PolicyReload_NewlyAllowedHostPasses(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})
	client := reloadProxyClient(t, startProxy(t, h))

	if resp, err := client.Get(upstream.URL + "/before"); err == nil {
		_ = resp.Body.Close()
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("precondition: upstream hits before reload = %d, want 0 (boot policy denies it)", got)
	}

	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"127.0.0.1"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	resp, err := client.Get(upstream.URL + "/after")
	if err != nil {
		t.Fatalf("GET after reload: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Errorf("after reload: status=%d upstream hits=%d, want 200 and 1", resp.StatusCode, hits.Load())
	}
}

// TestE2E_PolicyReload_InvalidRewriteKeepsRunningPolicy is the e2e form of
// T3(c) / acceptance criterion 2: the policy file is overwritten with an
// unrelated JSON document (a HAR export). The reload is rejected and the
// boot deny keeps blocking.
func TestE2E_PolicyReload_InvalidRewriteKeepsRunningPolicy(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})
	client := reloadProxyClient(t, startProxy(t, h))
	before := getPolicyView(t, h)

	writePolicyFile(t, policyPath, `{"log":{"version":"1.2","creator":{"name":"x"},"entries":[]}}`)
	if err := h.ReloadPolicy(t); err == nil {
		t.Fatal("ReloadPolicy accepted a HAR document as the policy")
	}

	if resp, err := client.Get(upstream.URL + "/after"); err == nil {
		_ = resp.Body.Close()
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("upstream hits after the rejected reload = %d, want 0 — the boot deny must stay in force", got)
	}
	after := getPolicyView(t, h)
	if len(after.denies) != 1 || after.denies[0] != "127.0.0.1" || after.loadedAt != before.loadedAt {
		t.Errorf("policy view changed by a rejected reload: before %+v, after %+v", before, after)
	}
}
