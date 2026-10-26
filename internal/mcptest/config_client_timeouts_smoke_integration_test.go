//go:build e2e

// USK-1186 smoke coverage: request_timeout_ms in the -config file bounds the
// client request head on the live data path right after startup, with no
// MCP configure / proxy_start override.
package mcptest_test

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// statusClientTimeouts reads request_timeout_ms / client_idle_timeout_ms
// from query(resource).
func statusClientTimeouts(t *testing.T, h *mcptest.Harness, resource string) (req, idle float64) {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": resource})
	r, ok := res.Decoded["request_timeout_ms"].(float64)
	if !ok {
		t.Fatalf("query %s: request_timeout_ms missing: %s", resource, res.Text)
	}
	i, ok := res.Decoded["client_idle_timeout_ms"].(float64)
	if !ok {
		t.Fatalf("query %s: client_idle_timeout_ms missing: %s", resource, res.Text)
	}
	return r, i
}

func TestE2E_ConfigFileRequestTimeout_BoundsHeadAfterBoot(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"request_timeout_ms": 300}`})
	upstream := startHoldingUpstream(t)

	if req, _ := statusClientTimeouts(t, h, "status"); req != 300 {
		t.Errorf("status before proxy_start: request_timeout_ms = %v, want 300 (from the config file)", req)
	}

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}
	if req, _ := statusClientTimeouts(t, h, "status"); req != 300 {
		t.Errorf("status after proxy_start: request_timeout_ms = %v, want 300", req)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	// > 4100 bytes so the request passes the forward handler's target peek.
	head := "GET http://" + upstream + "/stall HTTP/1.1\r\nHost: " + upstream + "\r\nX-Pad: " + strings.Repeat("a", 4100)
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	elapsed := time.Since(start)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("proxy kept a stalled request head open for %v; the config-file 300ms bound did not apply", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("proxy closed the stalled head after %v, want well under 3s", elapsed)
	}
	if len(got) != 0 {
		t.Errorf("proxy replied to a stalled request head: %.120q", got)
	}

	entry := pollErrorFlow(t, h, "request_head_timeout")
	tags, _ := entry["tags"].(map[string]any)
	if tags["request_timeout_ms"] != "300" {
		t.Errorf("tags.request_timeout_ms = %v, want 300", tags["request_timeout_ms"])
	}
}
