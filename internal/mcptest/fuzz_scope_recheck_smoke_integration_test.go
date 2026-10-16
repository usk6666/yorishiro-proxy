//go:build e2e

// USK-1158: a running fuzz_http re-checks TargetScope per variant, so a
// policy reload (the SIGHUP path, driven here through Harness.ReloadPolicy)
// that denies the target stops the remaining variants from being sent.
package mcptest_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// fuzzScopeRecheckResult is the subset of the fuzz_http result the
// scope-recheck tests assert on.
type fuzzScopeRecheckResult struct {
	TotalVariants     int    `json:"total_variants"`
	CompletedVariants int    `json:"completed_variants"`
	StoppedReason     string `json:"stopped_reason"`
	Variants          []struct {
		Index      int    `json:"index"`
		StatusCode int    `json:"status_code"`
		Error      string `json:"error"`
	} `json:"variants"`
}

func decodeFuzzScopeRecheckResult(t *testing.T, res mcptest.ToolResult) fuzzScopeRecheckResult {
	t.Helper()
	if res.Err != nil {
		t.Fatalf("fuzz_http: %v", res.Err)
	}
	if res.IsError {
		t.Fatalf("fuzz_http returned IsError=true: %s", res.Text)
	}
	raw, err := json.Marshal(res.Decoded)
	if err != nil {
		t.Fatalf("marshal fuzz_http result: %v", err)
	}
	var out fuzzScopeRecheckResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode fuzz_http result: %v (%s)", err, res.Text)
	}
	return out
}

// TestE2E_FuzzHTTP_ReloadDeniesRemainingVariants is T8 / acceptance
// criterion 1. The upstream holds variant 0 until the policy file has been
// rewritten to deny it and the reload has been applied; variants 1 and 2
// must then be recorded with a scope rejection and never reach the
// upstream.
func TestE2E_FuzzHTTP_ReloadDeniesRemainingVariants(t *testing.T) {
	var hits atomic.Int64
	arrived := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	open := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(open)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			close(arrived)
			<-release
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"127.0.0.1"}]}`)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})

	authority := strings.TrimPrefix(upstream.URL, "http://")
	done := make(chan mcptest.ToolResult, 1)
	go func() {
		done <- h.CallTool(t, "fuzz_http", map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/seed",
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/v0", "/v1", "/v2"}},
			},
			"timeout_ms": 10000,
		})
	}()

	select {
	case <-arrived:
	case <-time.After(15 * time.Second):
		t.Fatal("variant 0 never reached the upstream")
	}
	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	open()

	var res mcptest.ToolResult
	select {
	case res = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("fuzz_http did not return within 30s")
	}
	out := decodeFuzzScopeRecheckResult(t, res)

	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — variants built after the reload reached the newly denied host", got)
	}
	if len(out.Variants) != 3 || out.CompletedVariants != 3 {
		t.Fatalf("variants = %d, completed = %d, want 3 and 3 (a denied variant is recorded and the loop continues): %s",
			len(out.Variants), out.CompletedVariants, res.Text)
	}
	if out.StoppedReason != "" {
		t.Errorf("stopped_reason = %q, want empty", out.StoppedReason)
	}
	if v := out.Variants[0]; v.StatusCode != http.StatusOK || v.Error != "" {
		t.Errorf("variants[0] = status %d error %q, want 200 and no error (in flight at reload time)", v.StatusCode, v.Error)
	}
	for _, v := range out.Variants[1:] {
		if v.StatusCode != 0 || !strings.Contains(v.Error, "request blocked by target scope") {
			t.Errorf("variants[%d] = status %d error %q, want status 0 and a target scope rejection", v.Index, v.StatusCode, v.Error)
		}
	}
}
