//go:build e2e && !e2e_smoke

// USK-1274 review S-1: the control-plane twin of the live absolute-form
// leg. resend_http and fuzz_http write msg.Path (+ "?" raw_query) verbatim
// as the HTTP/1.x request-target, so a `path` of `http://denied.example/`
// sent to an allowed authority with an allowed Host reached a server that
// routes on the URI authority (RFC 9112 §3.2.2). The authority inside the
// path is now judged as a name leg against the dial address, like the Host
// values; the path itself is still sent verbatim when it passes.
package mcptest_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_AbsoluteFormScope_ResendHTTP: resend_http with an absolute-form
// path naming a denied authority is refused before dialing; a non-denied
// one (IP-literal allow on the dial address) is sent verbatim.
func TestE2E_AbsoluteFormScope_ResendHTTP(t *testing.T) {
	up := startURIRecordingUpstream(t, false)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})

	resend := func(path string) mcptest.ToolResult {
		t.Helper()
		return h.CallTool(t, "resend_http", map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": up.addr,
			"path":      path,
		})
	}

	const allowed = "http://vhost.example/resend-abs"
	if res := resend(allowed); res.Err != nil || res.IsError {
		t.Fatalf("resend with non-denied absolute-form path: err=%v text=%s", res.Err, res.Text)
	}
	if got := up.requestURIs(); len(got) != 1 || got[0] != allowed {
		t.Fatalf("upstream request-targets = %q, want [%q] verbatim", got, allowed)
	}

	for _, path := range []string{
		"http://denied.example/resend-abs",
		"http://user@denied.example:80/resend-abs",
		"http://denied.example?q=1",
	} {
		res := resend(path)
		if res.Err != nil {
			t.Fatalf("resend_http transport error: %v", res.Err)
		}
		if !res.IsError || !strings.Contains(res.Text, "target scope") {
			t.Errorf("resend path %q: IsError=%v text=%q, want a target scope rejection", path, res.IsError, res.Text)
		}
	}
	if got := up.hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — resend_http put a denied absolute-form authority on the wire (URIs %q)", got, up.requestURIs())
	}
}

// TestE2E_AbsoluteFormScope_FuzzHTTP: fuzz_http judges each variant's
// absolute-form authority after position substitution, and refuses a run
// whose untargeted base path names a denied authority at plan time.
func TestE2E_AbsoluteFormScope_FuzzHTTP(t *testing.T) {
	t.Run("path position", func(t *testing.T) {
		up := startURIRecordingUpstream(t, false)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})

		out := decodeFuzzScopeRecheckResult(t, h.CallTool(t, "fuzz_http", map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": up.addr,
			"path":      "http://denied.example/seed",
			"positions": []map[string]any{{
				"path":     "path",
				"payloads": []string{"http://vhost.example/fuzz-abs", "http://denied.example/fuzz-abs"},
			}},
			"timeout_ms": 10000,
		}))

		if len(out.Variants) != 2 {
			t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
		}
		if v := out.Variants[0]; v.StatusCode != http.StatusOK || v.Error != "" {
			t.Errorf("variants[0] = status %d error %q, want 200 and no error", v.StatusCode, v.Error)
		}
		if v := out.Variants[1]; v.StatusCode != 0 || !strings.Contains(v.Error, "request blocked by target scope") {
			t.Errorf("variants[1] = status %d error %q, want status 0 and a target scope rejection", v.StatusCode, v.Error)
		}
		if got := up.requestURIs(); len(got) != 1 || got[0] != "http://vhost.example/fuzz-abs" {
			t.Errorf("upstream request-targets = %q, want only the non-denied variant verbatim", got)
		}
	})

	t.Run("untargeted base path refused at plan time", func(t *testing.T) {
		up := startURIRecordingUpstream(t, false)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})

		res := h.CallTool(t, "fuzz_http", map[string]any{
			"method":     "GET",
			"scheme":     "http",
			"authority":  up.addr,
			"path":       "http://denied.example/plan",
			"headers":    []map[string]any{{"name": "X-A", "value": "1"}},
			"positions":  []map[string]any{{"path": "headers[0].value", "payloads": []string{"2", "3"}}},
			"timeout_ms": 10000,
		})
		if res.Err != nil {
			t.Fatalf("fuzz_http transport error: %v", res.Err)
		}
		if !res.IsError || !strings.Contains(res.Text, "target scope") {
			t.Errorf("fuzz_http with denied base absolute-form path: IsError=%v text=%q, want a target scope rejection", res.IsError, res.Text)
		}
		if got := up.hits.Load(); got != 0 {
			t.Errorf("upstream hits = %d, want 0", got)
		}
	})
}
