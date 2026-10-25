//go:build e2e && !e2e_smoke

// filter.http_version selects a stream by its head HTTP version — the
// value `query resource=flows` shows as flows[].http_version. A live
// WebSocket stream records its Upgrade GET / 101 with a version and its
// frames without one; the "" filter must not select it (it did while the
// predicate matched any row of the stream), and the head version must.
//
// Driven through the production wiring: JSON-RPC harness → proxy_start →
// proxybuild live stack → RecordStep → SQLite → query / manage tools.
package mcptest_test

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// flowIDsForHTTPVersion returns the ids `query resource=flows` lists under
// filter.http_version=v.
func flowIDsForHTTPVersion(t *testing.T, h *mcptest.Harness, v string) map[string]bool {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{
		"resource": "flows",
		"limit":    100,
		"filter":   map[string]any{"http_version": v},
	})
	flows, _ := res.Decoded["flows"].([]any)
	ids := map[string]bool{}
	for _, e := range flows {
		m, _ := e.(map[string]any)
		if id, _ := m["id"].(string); id != "" {
			ids[id] = true
		}
	}
	return ids
}

// exportedIDsForHTTPVersion returns the stream ids an inline JSONL
// `manage export_flows` emits under filter.http_version=v.
func exportedIDsForHTTPVersion(t *testing.T, h *mcptest.Harness, v string) map[string]bool {
	t.Helper()
	res := h.MustOK(t, "manage", map[string]any{
		"action": "export_flows",
		"params": map[string]any{"filter": map[string]any{"http_version": v}},
	})
	data, _ := res.Decoded["data"].(string)
	ids := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var rec struct {
			Stream struct {
				ID string `json:"id"`
			} `json:"stream"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal export line: %v", err)
		}
		if rec.Stream.ID != "" {
			ids[rec.Stream.ID] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan export data: %v", err)
	}
	return ids
}

func TestE2E_FilterHTTPVersion_LiveWSMatchesHeadVersion(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "ws"})
	proxyAddr := startProxyWithPassthrough(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := wsUpstreamHostPort(t, h.UpstreamTLS.URL)
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, upstream)
	if err != nil {
		t.Fatalf("dial WS through proxy: %v", err)
	}
	defer conn.Close()

	if err := writeMaskedClientFrame(conn, wslayer.OpcodeText, []byte("http-version")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if _, err := readServerFrameWithDeadline(conn, 5*time.Second); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := writeMaskedClientFrame(conn, wslayer.OpcodeClose, []byte{0x03, 0xe8}); err != nil {
		t.Fatalf("write close: %v", err)
	}
	_, _ = readServerFrameWithDeadline(conn, 5*time.Second)
	_ = conn.Close()

	id := waitCompleteStreamID(t, h, map[string]any{"url_pattern": "/ws"})
	fl := queryFlowDecoded(t, h, id)
	if p, _ := fl["protocol"].(string); p != "ws" {
		t.Fatalf("protocol = %q, want ws", p)
	}
	if n, _ := fl["message_count"].(float64); n < 3 {
		t.Fatalf("message_count = %v, want the Upgrade pair plus frames", fl["message_count"])
	}
	head, _ := fl["http_version"].(string)
	if head != "http/1.1" {
		t.Fatalf("http_version = %q, want http/1.1 (Upgrade GET head)", head)
	}

	if flowIDsForHTTPVersion(t, h, "")[id] {
		t.Errorf("query http_version=\"\" lists WS stream %s whose head version is %s", id, head)
	}
	if !flowIDsForHTTPVersion(t, h, head)[id] {
		t.Errorf("query http_version=%q does not list WS stream %s", head, id)
	}
	if exportedIDsForHTTPVersion(t, h, "")[id] {
		t.Errorf("export http_version=\"\" exports WS stream %s whose head version is %s", id, head)
	}
	if !exportedIDsForHTTPVersion(t, h, head)[id] {
		t.Errorf("export http_version=%q does not export WS stream %s", head, id)
	}
}
