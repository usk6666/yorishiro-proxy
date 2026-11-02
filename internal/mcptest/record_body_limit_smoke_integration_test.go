//go:build e2e

// USK-1408: max_record_body_size is a record-only cap. Driven through the
// production wiring (config JSON → mcpserver init → proxybuild.Deps →
// pipeline.RecordStep) and observed only through the MCP query tool: the
// client still receives the whole response, while the recorded copy keeps
// its leading bytes and is marked truncated.
package mcptest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// startSizedUpstream starts a plain HTTP/1.1 server answering
// GET /size/<n> with an n-byte body ("R" repeated, Content-Length framed).
func startSizedUpstream(t *testing.T) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/size/"))
		if err != nil || n < 0 {
			http.Error(w, "bad size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("R"), n))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// bodyLimitConfigJSON marshals a harness config document.
func bodyLimitConfigJSON(t *testing.T, cfg map[string]any) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return string(b)
}

// startBodyLimitProxy boots the harness with cfg and starts a listener.
func startBodyLimitProxy(t *testing.T, cfg string) (*mcptest.Harness, string) {
	t.Helper()
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: cfg})
	res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	addr, _ := res.Decoded["listen_addr"].(string)
	if addr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", res.Text)
	}
	return h, addr
}

// waitRecordCapStream polls `query flows` until exactly one complete Stream
// matches urlPattern and returns its ID.
func waitRecordCapStream(t *testing.T, h *mcptest.Harness, urlPattern string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter":   map[string]any{"url_pattern": urlPattern, "state": "complete"},
		})
		flows, _ := res.Decoded["flows"].([]any)
		if len(flows) == 1 {
			st, _ := flows[0].(map[string]any)
			id, _ := st["id"].(string)
			return id
		}
		if len(flows) > 1 {
			t.Fatalf("%d complete Streams match %q, want 1", len(flows), urlPattern)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no complete Stream matched %q within 10s", urlPattern)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// receiveMessage returns the single recorded receive-direction message of
// streamID.
func recordCapReceiveMessage(t *testing.T, h *mcptest.Harness, streamID string) map[string]any {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "messages", "id": streamID})
	msgs, _ := res.Decoded["messages"].([]any)
	var out []map[string]any
	for _, m := range msgs {
		e, _ := m.(map[string]any)
		if d, _ := e["direction"].(string); d == "receive" {
			out = append(out, e)
		}
	}
	if len(out) != 1 {
		t.Fatalf("receive messages = %d, want 1 (messages=%v)", len(out), msgs)
	}
	return out[0]
}

func TestSmoke_MaxRecordBodySize_TruncatesRecordOnly(t *testing.T) {
	const recordCap = 1024
	const bodyLen = 4096
	upstream := startSizedUpstream(t)
	h, proxyAddr := startBodyLimitProxy(t, bodyLimitConfigJSON(t, map[string]any{
		"max_record_body_size": recordCap,
	}))

	// The forward cap is untouched: max_body_size keeps its default and
	// max_record_body_size echoes the configured value.
	cfgRes := h.MustOK(t, "query", map[string]any{"resource": "config"})
	if got, _ := cfgRes.Decoded["max_body_size"].(float64); int64(got) != 254<<20 {
		t.Errorf("query config max_body_size = %v, want %d (default unchanged)", cfgRes.Decoded["max_body_size"], 254<<20)
	}
	if got, _ := cfgRes.Decoded["max_record_body_size"].(float64); int64(got) != recordCap {
		t.Errorf("query config max_record_body_size = %v, want %d", cfgRes.Decoded["max_record_body_size"], recordCap)
	}

	client := proxyHTTPClient(t, proxyAddr)
	path := fmt.Sprintf("/size/%d", bodyLen)
	resp := proxiedGet(t, client, "http://"+upstream+path)
	if resp.err != nil {
		t.Fatalf("proxied GET: %v", resp.err)
	}
	if resp.statusCode != http.StatusOK {
		t.Fatalf("proxied GET status = %d, want 200", resp.statusCode)
	}
	if !bytes.Equal(resp.body, bytes.Repeat([]byte("R"), bodyLen)) {
		t.Fatalf("client received %d bytes, want the full %d-byte body", len(resp.body), bodyLen)
	}

	streamID := waitRecordCapStream(t, h, path)
	msg := recordCapReceiveMessage(t, h, streamID)
	body, _ := msg["body"].(string)
	if len(body) != recordCap {
		t.Errorf("recorded response body len = %d, want %d", len(body), recordCap)
	}
	if body != strings.Repeat("R", len(body)) {
		t.Errorf("recorded response body is not the leading bytes of the wire body")
	}
	if tr, _ := msg["body_truncated"].(bool); !tr {
		t.Errorf("body_truncated = %v, want true", msg["body_truncated"])
	}
	md, _ := msg["metadata"].(map[string]any)
	if _, ok := md["http_anomaly_raw_body_truncated"]; !ok {
		t.Errorf("metadata http_anomaly_raw_body_truncated absent, want it set (raw bytes exceed the record cap); metadata=%v", md)
	}
}
