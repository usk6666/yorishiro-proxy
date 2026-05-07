//go:build e2e

// Package mcptest_test holds USK-753's smoke coverage for the
// SafetyFilter engine — proof that the filter actually blocks a
// dangerous request when traffic flows through the proxy.
//
// Pre-USK-753 the only assertions were unit tests in
// internal/safety/engine_test.go and internal/mcp/security_safetyfilter_test.go.
// Both stub the pipeline. A regression that broke the
// pipeline.SafetyStep wiring path (e.g. a refactor that forgot to
// install the engine on http handlers, or a config-load bug that
// dropped the Policy Layer rules) would not surface until a user
// observed a malicious request reaching the upstream. This test
// closes that gap by booting the production server with a
// destructive-sql preset and confirming the upstream never sees the
// blocked request.
package mcptest_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// safetyFilterDestructiveSQLConfig is the harness config that enables
// the SafetyFilter engine with the built-in destructive-sql preset.
// "block" is explicit so the assertion is unambiguous: matching
// requests must not reach the upstream.
const safetyFilterDestructiveSQLConfig = `{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "block",
      "rules": [
        {"preset": "destructive-sql"}
      ]
    }
  }
}`

// TestE2E_SafetyFilter_BlocksDestructiveSQL proves the pipeline
// SafetyStep is wired into the HTTP send-direction path:
//
//   - A POST whose body matches the destructive-sql preset never
//     reaches the observed upstream.
//   - A POST whose body is benign DOES reach the upstream — proving
//     the test environment is otherwise functional and the block in
//     case (1) is the SafetyFilter doing its job, not a connectivity
//     issue.
//
// Both requests target the same path through the same proxy instance
// so any divergence in the result narrows directly to
// pipeline.SafetyStep behavior.
//
// USK-760 closed the wiring gap: NewLiveManager now populates
// proxybuild.Deps.HTTPSafetyEngine via InitPerProtocolSafetyEngines,
// so the live SafetyStep enforces the configured presets and this
// test passes against the production server assembly.
func TestE2E_SafetyFilter_BlocksDestructiveSQL(t *testing.T) {
	upstreamAddr, upstreamObs := startObservedUpstream(t)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: safetyFilterDestructiveSQLConfig,
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	client := proxyHTTPClient(t, proxyAddr)
	target := "http://" + upstreamAddr + "/api/query"

	// (1) Benign body must reach the upstream — sanity gate that
	// without this baseline a "blocked" assertion below would be
	// indistinguishable from a transport-broken proxy.
	benignResp, err := client.Post(target, "text/plain", bytes.NewBufferString("SELECT 1"))
	if err != nil {
		t.Fatalf("benign POST: %v", err)
	}
	_ = benignResp.Body.Close()
	if benignResp.StatusCode != http.StatusOK {
		t.Fatalf("benign POST status = %d, want 200", benignResp.StatusCode)
	}
	hitsAfterBenign := upstreamObs.hitCount()
	if hitsAfterBenign != 1 {
		t.Fatalf("upstream hits after benign POST = %d, want 1", hitsAfterBenign)
	}

	// (2) Destructive-SQL body must NOT reach the upstream. The
	// preset matches "DROP TABLE users" verbatim. We tolerate either
	// a transport error or a non-2xx response on the client side —
	// the SafetyStep contract is "drop the envelope", not "return a
	// specific status code", so the durable assertion is the
	// upstream hit counter.
	dropResp, err := client.Post(target, "text/plain", bytes.NewBufferString("DROP TABLE users"))
	if err == nil {
		_ = dropResp.Body.Close()
		// A non-2xx is acceptable; a 2xx would mean the upstream
		// responded, which contradicts the block.
		if dropResp.StatusCode == http.StatusOK {
			t.Errorf("destructive POST status = 200; SafetyFilter did not block")
		}
	}
	hitsAfterDrop := upstreamObs.hitCount()
	if hitsAfterDrop != hitsAfterBenign {
		t.Errorf("upstream hits advanced after destructive POST: before=%d after=%d (block failed)", hitsAfterBenign, hitsAfterDrop)
	}
}

// TestE2E_SafetyFilter_QueryReportsRulesLoaded asserts the
// configuration round-trip: the rules we passed via -config are
// reachable through query("safety_filter") (the read-only Policy
// Layer view of the engine). This catches the case where the file
// loaded but the engine ended up with zero rules (a different bug
// from "engine never built").
func TestE2E_SafetyFilter_QueryReportsRulesLoaded(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: safetyFilterDestructiveSQLConfig,
	})

	// security tool requires `params` even for action handlers that
	// take no parameters; pass an empty object so JSON-schema
	// validation passes.
	res := h.MustOK(t, "security", map[string]any{
		"action": "get_safety_filter",
		"params": map[string]any{},
	})
	enabled, _ := res.Decoded["enabled"].(bool)
	if !enabled {
		t.Fatalf("security.get_safety_filter: enabled=false; want true")
	}
	rulesAny, _ := res.Decoded["input_rules"].([]any)
	if len(rulesAny) == 0 {
		t.Fatalf("security.get_safety_filter: input_rules is empty; expected destructive-sql preset rules")
	}
	// Spot-check that at least one preset rule landed under the
	// expected category. The exact rule IDs are owned by
	// internal/safety/preset.go and may change; the durable contract
	// is "the destructive-sql category is represented".
	found := false
	for _, raw := range rulesAny {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if cat, _ := entry["category"].(string); strings.HasPrefix(cat, "destructive-sql") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("security.get_safety_filter: no rule with category=destructive-sql; rules=%v", rulesAny)
	}
}
