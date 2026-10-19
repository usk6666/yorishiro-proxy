//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1189 (T3 via MCP): a plain-forward request head under the 4000-byte
// target peek that stalls is answered 400; the agent sees the bytes sent and
// the 400 the proxy returned.
func TestE2E_PlainForwardPeekTimeout_RecordedWithResponse(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	upstream := startHoldingUpstream(t)

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
	payload := "GET http://" + upstream + "/x HTTP/1.1\r\nHo"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(conn)
	if !strings.HasPrefix(string(got), "HTTP/1.1 400 ") {
		t.Fatalf("client read %q, want the 400", got)
	}

	entry := pollErrorFlow(t, h, "request_head_timeout")
	id, _ := entry["id"].(string)
	detail := pollFlowDetail(t, h, id, "raw_request", "raw_response")
	if code, _ := detail.Decoded["response_status_code"].(float64); int(code) != 400 {
		t.Errorf("response_status_code = %v, want 400", detail.Decoded["response_status_code"])
	}
	if req := decodeB64Field(t, detail.Decoded, "raw_request"); req != payload {
		t.Errorf("raw_request = %q, want %q", req, payload)
	}
	if resp := decodeB64Field(t, detail.Decoded, "raw_response"); resp != string(got) {
		t.Errorf("raw_response = %q, want the bytes the client read %q", resp, got)
	}
}
