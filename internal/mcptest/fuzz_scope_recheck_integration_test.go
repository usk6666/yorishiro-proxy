//go:build e2e && !e2e_smoke

// USK-1158 exhaustive tier: fuzz_http judges each variant's scope on the
// message AFTER position substitution, not on the base message the
// plan-time check saw. No reload is involved.
package mcptest_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_FuzzHTTP_PathPositionJudgedOnMutatedMessage is T10 / acceptance
// criterion 3: with a policy deny on path_prefix /admin, a `path`
// position ["/ok", "/admin"] must never put /admin on the wire.
func TestE2E_FuzzHTTP_PathPositionJudgedOnMutatedMessage(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath,
		`{"allows":[{"hostname":"127.0.0.1"}],"denies":[{"hostname":"127.0.0.1","path_prefix":"/admin"}]}`)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})

	authority := strings.TrimPrefix(upstream.URL, "http://")
	out := decodeFuzzScopeRecheckResult(t, h.CallTool(t, "fuzz_http", map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/ok", "/admin"}},
		},
		"timeout_ms": 10000,
	}))

	mu.Lock()
	seen := append([]string(nil), paths...)
	mu.Unlock()
	for _, p := range seen {
		if strings.HasPrefix(p, "/admin") {
			t.Errorf("upstream received %q — a path the policy denies was sent", p)
		}
	}
	if len(seen) != 1 || seen[0] != "/ok" {
		t.Errorf("upstream paths = %v, want [/ok]", seen)
	}
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	if v := out.Variants[0]; v.StatusCode != http.StatusOK || v.Error != "" {
		t.Errorf("variants[0] = status %d error %q, want 200 and no error", v.StatusCode, v.Error)
	}
	if v := out.Variants[1]; v.StatusCode != 0 || !strings.Contains(v.Error, "request blocked by target scope") {
		t.Errorf("variants[1] = status %d error %q, want status 0 and a target scope rejection", v.StatusCode, v.Error)
	}
}
