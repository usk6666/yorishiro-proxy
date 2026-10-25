//go:build e2e && !e2e_smoke

package mcp

// fuzz_http_body_contains_integration_test.go — fuzz_http against an
// upstream that gzips a reflected payload, then query fuzz_results with
// filter.body_contains. The recorded receive body is the gzip wire form, so
// the filter must look at the Content-Encoding-decoded body to find it.

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// startFuzzHTTPGzipReflect stands up an upstream that reflects the request
// path into an HTML page (padded so the page really compresses) and always
// answers with Content-Encoding: gzip.
func startFuzzHTTPGzipReflect(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pad := strings.Repeat("lorem ipsum dolor sit amet ", 40)
		page := "<html><body>" + pad + "<p>you asked for " + r.URL.Path + "</p>" + pad + "</body></html>"
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(page))
		_ = zw.Close()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFuzzHTTP_BodyContainsMatchesGzipReflection(t *testing.T) {
	cs, store, _, _ := setupFuzzHTTPSession(t)
	upstream := startFuzzHTTPGzipReflect(t)
	authority := strings.TrimPrefix(upstream.URL, "http://")

	const marker = "YPREFLECT9c41"
	payloads := []string{"/plain-a", "/" + marker, "/plain-b"}
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
			{"name": "Accept-Encoding", "value": "gzip"},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": payloads},
		},
		"timeout_ms": 5000,
	})
	if result.FuzzID == "" {
		t.Fatal("fuzz_http response missing fuzz_id")
	}
	if result.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}

	var markerStream string
	for _, v := range result.Variants {
		if v.Payloads["path"] == "/"+marker {
			markerStream = v.StreamID
		}
	}
	if markerStream == "" {
		t.Fatalf("no variant carried the marker payload: %+v", result.Variants)
	}

	// Precondition: the recorded receive body is the gzip wire form and does
	// not contain the marker verbatim (L4 bytes are not decoded at record time).
	recv, err := store.GetFlows(context.Background(), markerStream, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(recv) == 0 {
		t.Fatal("marker variant has no receive flow")
	}
	for _, f := range recv {
		if bytes.Contains(f.Body, []byte(marker)) {
			t.Fatalf("precondition: recorded body contains the marker verbatim; fixture does not exercise decoding")
		}
	}

	out := decodeQueryFuzzResults(t, queryFuzzResults(t, cs, result.FuzzID, map[string]any{"body_contains": marker}))
	if out.Total != 1 || out.Count != 1 {
		t.Fatalf("body_contains=%q: count=%d total=%d, want 1/1", marker, out.Count, out.Total)
	}
	if out.Results[0].StreamID != markerStream {
		t.Errorf("matched stream = %q, want %q", out.Results[0].StreamID, markerStream)
	}
	if out.Summary == nil || out.Summary.TotalResults != 1 {
		t.Errorf("summary.total_results = %+v, want 1", out.Summary)
	}
}
