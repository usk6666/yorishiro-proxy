//go:build e2e

// USK-1189 smoke coverage: a CONNECT request the proxy cuts off at
// request_timeout_ms must be visible to the agent through MCP `query` —
// the failure reason and the bytes the client sent.
package mcptest_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func TestE2E_CONNECTRequestTimeout_RecordedAndQueryable(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":        "127.0.0.1:0",
		"request_timeout_ms": 300,
	})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	payload := "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX-Pa"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, _ := io.ReadAll(conn); len(got) != 0 {
		t.Errorf("proxy replied to a stalled CONNECT: %q", got)
	}

	entry := pollErrorFlow(t, h, "connect_request_timeout")
	tags, _ := entry["tags"].(map[string]any)
	if tags["closed_by"] != "proxy" || tags["phase"] != "connect_request" {
		t.Errorf("tags closed_by/phase = %v/%v, want proxy/connect_request (entry=%v)", tags["closed_by"], tags["phase"], entry)
	}
	if tags["request_timeout_ms"] != "300" {
		t.Errorf("tags.request_timeout_ms = %v, want 300", tags["request_timeout_ms"])
	}

	id, _ := entry["id"].(string)
	detail := pollFlowDetail(t, h, id, "raw_request")
	if got := decodeB64Field(t, detail.Decoded, "raw_request"); got != payload {
		t.Errorf("raw_request = %q, want %q", got, payload)
	}
}
