//go:build e2e

// Package mcptest_test holds USK-756's smoke coverage for the
// resend_http MCP tool.
//
// All four resend tools (resend_http / resend_ws / resend_grpc /
// resend_raw) and all four fuzz tools have historically been gated
// behind `e2e && !e2e_smoke`, meaning the per-PR merge gate never
// invoked them. The USK-717 / USK-718 / USK-719 retrospective —
// three transport-wiring regressions that shipped because the
// relevant tests only ran nightly — directly motivates promoting
// at least one resend smoke path here. HTTP/1.1 was chosen as the
// representative because it is the highest-traffic resend variant in
// real usage; gRPC / WS / Raw stay full-only.
package mcptest_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ResendHTTP_FromRecordedFlow proves the end-to-end resend
// path works through the JSON-RPC harness:
//
//  1. proxy_start succeeds and binds an ephemeral loopback port.
//  2. A first request reaches the upstream and is recorded as a
//     Stream / Flow in the SQLite store.
//  3. resend_http with that flow_id reaches the same upstream — the
//     hit counter advances from 1 to 2 and the upstream sees the
//     same path. If the resend transport is broken (USK-717 class),
//     the second hit never lands.
//  4. The recorded resend creates a NEW stream id distinct from the
//     original — proves resend writes its own provenance row rather
//     than amending the original.
func TestE2E_ResendHTTP_FromRecordedFlow(t *testing.T) {
	upstreamAddr, upstreamObs := startObservedUpstream(t)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	// First request: through the proxy to the observed upstream. After
	// this returns the flow is committed and queryable.
	client := proxyHTTPClient(t, proxyAddr)
	first := proxiedGet(t, client, fmt.Sprintf("http://%s/resend-target", upstreamAddr))
	if first.statusCode != http.StatusOK {
		t.Fatalf("initial GET status = %d, want 200", first.statusCode)
	}
	if got := upstreamObs.hitCount(); got != 1 {
		t.Fatalf("upstream hit count after initial GET = %d, want 1", got)
	}

	originalStreamID := waitForFlowID(t, h, "/resend-target", 5*time.Second)
	if originalStreamID == "" {
		t.Fatalf("no flow recorded for /resend-target within 5s")
	}

	// resend_http re-issues the recorded flow. The upstream should see
	// a second hit. Without the USK-717 ALPN fix we would never reach
	// the upstream over h2-capable transports, but this test uses
	// plain HTTP/1.1 so the proof is the upstream counter advancing
	// rather than the ALPN value itself (covered by
	// resend_tls_alpn_integration_test.go).
	resendRes := h.MustOK(t, "resend_http", map[string]any{
		"flow_id": originalStreamID,
	})

	resendStreamID, _ := resendRes.Decoded["stream_id"].(string)
	if resendStreamID == "" {
		t.Fatalf("resend_http: missing stream_id in result: %s", resendRes.Text)
	}
	if resendStreamID == originalStreamID {
		t.Errorf("resend_http stream_id = %q (== original); want a new stream id for the resend variant", resendStreamID)
	}
	if status := decodedInt(resendRes.Decoded, "status_code"); status != http.StatusOK {
		t.Errorf("resend_http result.status_code = %d, want 200", status)
	}

	if got := upstreamObs.hitCount(); got != 2 {
		t.Errorf("upstream hit count after resend = %d, want 2", got)
	}
}

// waitForFlowID polls query("flows") until a flow whose URL contains
// pathSubstring appears, then returns that flow's id. Returns "" if
// the timeout elapses without a match. The substring match is tied
// to the URL field (which is path-only after MITM rewriting on
// plain-HTTP MITM, but defensively allows full URLs too).
func waitForFlowID(t *testing.T, h *mcptest.Harness, pathSubstring string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	const pollInterval = 30 * time.Millisecond
	for {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
		})
		var parsed struct {
			Flows []struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			} `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
		}
		// Most-recent first ordering is implementation-defined; sort by
		// id descending as a stable proxy and pick the first hit.
		sort.Slice(parsed.Flows, func(i, j int) bool {
			return parsed.Flows[i].ID > parsed.Flows[j].ID
		})
		for _, f := range parsed.Flows {
			if containsString(f.URL, pathSubstring) {
				return f.ID
			}
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(pollInterval)
	}
}

// decodedInt extracts an int field from a Decoded result. JSON numbers
// arrive as float64 through the gomcp SDK; coerce to int for the
// status-code comparison.
func decodedInt(decoded map[string]any, key string) int {
	if decoded == nil {
		return 0
	}
	switch v := decoded[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}

// containsString is a tiny substring helper kept inline so the test
// file does not pull in strings just for one use site. Equivalent to
// strings.Contains.
func containsString(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
