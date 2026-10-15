//go:build e2e

// USK-1115: Policy Layer reload through the production assembly
// (mcpserver.Run). The harness drives RunOptions.PolicyReload — the same
// hook cmd/yorishiro-proxy wires to SIGHUP — after rewriting the
// -target-policy-file in place, then drives real CONNECT traffic through
// the proxy listener.
package mcptest_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// reloadTestUpstream is an HTTPS upstream that counts the requests it
// served, so "blocked" is asserted as "never reached the upstream".
func reloadTestUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "policy-reload-upstream")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// reloadProxyClient sends HTTPS requests through the proxy via CONNECT.
// Keep-alives are off so every request opens a new CONNECT tunnel — the
// reload applies to new connections (U3).
func reloadProxyClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	pURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pURL),
			DisableKeepAlives: true,
			// The client does not trust the proxy's MITM CA; the load-bearing
			// assertion is whether the upstream was reached.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 10 * time.Second,
	}
}

// writePolicyFile replaces the policy file atomically (temp + rename), the
// way an operator's distributor should.
func writePolicyFile(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename policy: %v", err)
	}
}

func startProxy(t *testing.T, h *mcptest.Harness) string {
	t.Helper()
	res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	addr, _ := res.Decoded["listen_addr"].(string)
	if addr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", res.Text)
	}
	return addr
}

// TestE2E_PolicyReload_NewlyDeniedHostBlocked is T1 / acceptance criterion
// 1: on a running proxy, a host the policy allowed at boot is reachable;
// after the policy file is rewritten to deny it and a reload is requested,
// a new CONNECT to it never reaches the upstream — without a restart.
func TestE2E_PolicyReload_NewlyDeniedHostBlocked(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"127.0.0.1"}]}`)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})
	client := reloadProxyClient(t, startProxy(t, h))

	resp, err := client.Get(upstream.URL + "/before")
	if err != nil {
		t.Fatalf("GET before reload: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("before reload: status=%d upstream hits=%d, want 200 and 1", resp.StatusCode, hits.Load())
	}

	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	resp, err = client.Get(upstream.URL + "/after")
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("GET after reload returned 200; the newly denied host was not blocked")
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after reload = %d, want 1 — the reloaded deny did not apply to a new connection", got)
	}

	// The agent-visible view agrees with the data path.
	view := getPolicyView(t, h)
	if len(view.allows) != 0 || len(view.denies) != 1 || view.denies[0] != "127.0.0.1" || view.source != "policy file" {
		t.Errorf("get_target_scope policy after reload = %+v, want only the new deny from the policy file", view)
	}
}

// policyView is the Policy Layer part of a get_target_scope result.
type policyView struct {
	allows, denies []string
	source         string
	loadedAt       string
	immutable      bool
}

func getPolicyView(t *testing.T, h *mcptest.Harness) policyView {
	t.Helper()
	res := h.MustOK(t, "security", map[string]any{"action": "get_target_scope", "params": map[string]any{}})
	policy, ok := res.Decoded["policy"].(map[string]any)
	if !ok {
		t.Fatalf("get_target_scope: no policy object in %s", res.Text)
	}
	hosts := func(key string) []string {
		var out []string
		list, _ := policy[key].([]any)
		for _, r := range list {
			m, _ := r.(map[string]any)
			s, _ := m["hostname"].(string)
			out = append(out, s)
		}
		return out
	}
	v := policyView{allows: hosts("allows"), denies: hosts("denies")}
	v.source, _ = policy["source"].(string)
	v.loadedAt, _ = policy["loaded_at"].(string)
	v.immutable, _ = policy["immutable"].(bool)
	return v
}

// TestE2E_PolicyReload_AgentCannotModifyPolicyLayer is the HTTP-transport
// half of T5 / acceptance criterion 3. The agent-facing MCP gains no
// tool or action that touches the Policy Layer, and its agent-layer writes
// stay bounded by it.
func TestE2E_PolicyReload_AgentCannotModifyPolicyLayer(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"allowed.test"}]}`)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})

	for _, name := range h.Client.ListTools(t) {
		lower := strings.ToLower(name)
		for _, bad := range []string{"policy", "reload", "admin"} {
			if strings.Contains(lower, bad) {
				t.Errorf("tools/list exposes %q; the Policy Layer must not be reachable from the agent MCP", name)
			}
		}
	}

	for _, action := range []string{"reload_policy", "set_policy", "update_policy"} {
		h.ExpectError(t, "security", map[string]any{"action": action, "params": map[string]any{}}, "unknown action")
	}

	h.ExpectError(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{"allows": []map[string]any{{"hostname": "outside.test"}}},
	}, "outside policy allow boundary")

	view := getPolicyView(t, h)
	if len(view.allows) != 1 || view.allows[0] != "allowed.test" || len(view.denies) != 0 {
		t.Errorf("policy layer changed by agent calls: %+v", view)
	}
	if !view.immutable {
		t.Errorf("policy.immutable = false, want true: %+v", view)
	}
}
