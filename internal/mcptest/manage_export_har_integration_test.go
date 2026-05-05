//go:build e2e

package mcptest_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_Manage_ExportFlowsHAR exercises scenario #18: drive several
// distinct HTTP requests through the proxy, then export the recorded
// flows as HAR via the manage tool. We assert HAR 1.2 spec compliance
// at the structural level (top-level shape, per-entry mandatory fields)
// AND content integrity (method/url/status/body Content-Length match
// the requests we drove).
//
// The HAR exporter is the same path the WebUI uses — a regression here
// would produce HAR files that DevTools / curl-formatter / common HAR
// viewers refuse to open.
func TestE2E_Manage_ExportFlowsHAR(t *testing.T) {
	upstreamAddr, _ := startObservedUpstream(t)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := res.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %v", res.Decoded)
	}

	client := proxyHTTPClient(t, proxyAddr)

	// Drive 3 distinct requests so the HAR has interesting structure.
	cases := []struct {
		method string
		path   string
		body   []byte
	}{
		{"GET", "/api/users", nil},
		{"POST", "/api/items", []byte(`{"name":"widget"}`)},
		{"GET", "/health", nil},
	}
	for _, tc := range cases {
		target := fmt.Sprintf("http://%s%s", upstreamAddr, tc.path)
		respCh := requestThroughProxy(t, client, tc.method, target, nil, tc.body)
		select {
		case r := <-respCh:
			if r.err != nil {
				t.Fatalf("proxied %s %s: %v", tc.method, tc.path, r.err)
			}
			if r.statusCode != 200 {
				t.Fatalf("proxied %s %s: status = %d, want 200", tc.method, tc.path, r.statusCode)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out proxying %s %s", tc.method, tc.path)
		}
	}

	// Wait for the recording pipeline to drain. Without a sync
	// primitive we poll the flow store via query.
	waitForFlowCount(t, h, len(cases), 5*time.Second)

	// --- Export HAR via manage tool ---
	outPath := filepath.Join(t.TempDir(), "export.har")
	exportRes := h.MustOK(t, "manage", map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"format":      "har",
			"output_path": outPath,
		},
	})
	if got := numFromAny(exportRes.Decoded["exported_count"]); got < int64(len(cases)) {
		t.Errorf("manage export_flows: exported_count = %d, want >= %d", got, len(cases))
	}
	if got, _ := exportRes.Decoded["format"].(string); got != "har" {
		t.Errorf("manage export_flows: format = %q, want %q", got, "har")
	}

	// --- Read the file from disk and validate HAR 1.2 shape ---
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read HAR file: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("HAR file is empty")
	}

	var har struct {
		Log struct {
			Version string `json:"version"`
			Creator struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"creator"`
			Entries []struct {
				StartedDateTime string `json:"startedDateTime"`
				Time            float64
				Request         struct {
					Method      string `json:"method"`
					URL         string `json:"url"`
					HTTPVersion string `json:"httpVersion"`
					Headers     []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					QueryString []any `json:"queryString"`
					PostData    *struct {
						MimeType string `json:"mimeType"`
						Text     string `json:"text"`
					} `json:"postData,omitempty"`
					HeadersSize int64 `json:"headersSize"`
					BodySize    int64 `json:"bodySize"`
				} `json:"request"`
				Response struct {
					Status      int    `json:"status"`
					StatusText  string `json:"statusText"`
					HTTPVersion string `json:"httpVersion"`
					Headers     []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					Content struct {
						Size     int64  `json:"size"`
						MimeType string `json:"mimeType"`
						Text     string `json:"text,omitempty"`
						Encoding string `json:"encoding,omitempty"`
					} `json:"content"`
					HeadersSize int64 `json:"headersSize"`
					BodySize    int64 `json:"bodySize"`
				} `json:"response"`
				Timings struct {
					Send    float64 `json:"send"`
					Wait    float64 `json:"wait"`
					Receive float64 `json:"receive"`
				} `json:"timings"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &har); err != nil {
		t.Fatalf("HAR JSON parse: %v\nfile: %s", err, raw)
	}

	if har.Log.Version != "1.2" {
		t.Errorf("HAR log.version = %q, want %q", har.Log.Version, "1.2")
	}
	if har.Log.Creator.Name == "" {
		t.Errorf("HAR log.creator.name is empty (want yorishiro-proxy)")
	}
	if len(har.Log.Entries) < len(cases) {
		t.Fatalf("HAR entries = %d, want >= %d (file=%s)", len(har.Log.Entries), len(cases), outPath)
	}

	// Build a method+path -> entry map so the assertions are
	// resilient to ordering between concurrent recordings (the proxy
	// records on stream completion, which is fast but not strictly
	// ordered for parallel requests).
	entriesByPath := make(map[string]int, len(har.Log.Entries))
	for i, e := range har.Log.Entries {
		// URL may be "http://host:port/path"; we just need a unique
		// (method, path-suffix) match per case.
		for _, tc := range cases {
			suffix := tc.path
			if e.Request.Method == tc.method && strings.HasSuffix(e.Request.URL, suffix) {
				key := fmt.Sprintf("%s %s", tc.method, suffix)
				if _, exists := entriesByPath[key]; !exists {
					entriesByPath[key] = i
				}
			}
		}
	}

	for _, tc := range cases {
		key := fmt.Sprintf("%s %s", tc.method, tc.path)
		idx, ok := entriesByPath[key]
		if !ok {
			t.Errorf("HAR missing entry for %s", key)
			continue
		}
		e := har.Log.Entries[idx]

		// --- Required HAR 1.2 fields ---
		if e.Request.Method != tc.method {
			t.Errorf("HAR[%s].request.method = %q, want %q", key, e.Request.Method, tc.method)
		}
		if e.Request.URL == "" {
			t.Errorf("HAR[%s].request.url is empty", key)
		}
		if e.Response.Status != 200 {
			t.Errorf("HAR[%s].response.status = %d, want 200", key, e.Response.Status)
		}
		if e.Response.StatusText == "" {
			t.Errorf("HAR[%s].response.statusText is empty", key)
		}
		if len(e.Request.Headers) == 0 {
			t.Errorf("HAR[%s].request.headers is empty", key)
		}
		if len(e.Response.Headers) == 0 {
			t.Errorf("HAR[%s].response.headers is empty", key)
		}
		if e.Request.QueryString == nil {
			// HAR 1.2 requires queryString[] to be present even if
			// empty. Capturing nil here means JSON encoding emitted
			// "queryString": null, which is non-conformant.
			t.Errorf("HAR[%s].request.queryString is nil (HAR 1.2 requires array)", key)
		}
		// HAR 1.2 §timings: -1 means "not measured / not applicable"
		// and is explicitly allowed. Any other negative number is a
		// spec violation.
		if e.Timings.Send < -1 {
			t.Errorf("HAR[%s].timings.send = %v, want >= -1", key, e.Timings.Send)
		}
		if e.Timings.Wait < -1 {
			t.Errorf("HAR[%s].timings.wait = %v, want >= -1", key, e.Timings.Wait)
		}
		if e.Timings.Receive < -1 {
			t.Errorf("HAR[%s].timings.receive = %v, want >= -1", key, e.Timings.Receive)
		}

		// --- Body content integrity ---
		// For requests with a body, the HAR postData.text must match
		// what we sent. The request.bodySize must equal len(tc.body).
		if tc.body != nil {
			if e.Request.PostData == nil {
				t.Errorf("HAR[%s].request.postData is nil but request had a body", key)
			} else if e.Request.PostData.Text != string(tc.body) {
				t.Errorf("HAR[%s].request.postData.text = %q, want %q", key, e.Request.PostData.Text, string(tc.body))
			}
			if e.Request.BodySize != int64(len(tc.body)) {
				t.Errorf("HAR[%s].request.bodySize = %d, want %d", key, e.Request.BodySize, len(tc.body))
			}
		}

		// Response body integrity: the upstream's body length must
		// equal Content.Size when the HAR includes the body text.
		if e.Response.Content.Text != "" && int64(len(e.Response.Content.Text)) != e.Response.Content.Size && e.Response.Content.Encoding != "base64" {
			t.Errorf("HAR[%s].response.content size mismatch: text=%d, size=%d",
				key, len(e.Response.Content.Text), e.Response.Content.Size)
		}
	}
}

// numFromAny extracts a numeric value from a JSON-decoded any. JSON
// numbers decode to float64; some tools wrap counts as json.Number
// strings. Returns 0 when the type is unrecognised.
func numFromAny(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	case json.Number:
		n, _ := x.Int64()
		return n
	default:
		return 0
	}
}

// waitForFlowCount polls query(resource=flows) until it observes at
// least n recorded flows, or until the timeout elapses.
func waitForFlowCount(t *testing.T, h *mcptest.Harness, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows"})
		if got := numFromAny(res.Decoded["count"]); got >= int64(n) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d flows within %v", n, timeout)
}
