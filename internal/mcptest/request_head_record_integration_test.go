//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1181 guard: a keep-alive connection that ends with zero bytes of a
// next request is a normal close and must not leave an error flow. Only the
// completed exchange is recorded. (The idle-deadline variant of the same
// zero-byte rule is pinned at the Layer by
// TestChannelNext_IdleExpiryZeroBytes_NoRequestHeadError: the 120s idle
// bound is not reachable from MCP.)
func TestE2E_KeepAliveZeroByteClose_NotRecorded(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "http://")

	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":        "127.0.0.1:0",
		"request_timeout_ms": 300,
	})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	br := bufio.NewReader(conn)
	if _, err := fmt.Fprintf(conn, "GET http://%s/one HTTP/1.1\r\nHost: %s\r\n\r\n", host, host); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := gohttp.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	// Stay idle (well past request_timeout_ms, under the keep-alive idle
	// bound), then close with zero bytes of a next request.
	time.Sleep(3 * 300 * time.Millisecond)
	_ = conn.Close()

	// Settle: the completed exchange must be recorded first, so the
	// absence check below cannot pass vacuously.
	deadline := time.Now().Add(5 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": map[string]any{"state": "complete"}})
		if n, _ := res.Decoded["count"].(float64); n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("completed exchange not recorded: %s", res.Text)
		}
		time.Sleep(50 * time.Millisecond)
	}
	watch := time.Now().Add(1 * time.Second)
	for time.Now().Before(watch) {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": map[string]any{"state": "error"}})
		if n, _ := res.Decoded["count"].(float64); n != 0 {
			t.Fatalf("zero-byte keep-alive close was recorded as an error flow: %s", res.Text)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
