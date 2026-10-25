//go:build e2e

// USK-1185 smoke coverage: MCP `configure { request_timeout_ms: 0 }`
// disables the client request-head bound on the live data path, even when
// the boot-time config set a short request_timeout (which also seeds the
// plain-HTTP forward peek's static value).
package mcptest_test

import (
	"bufio"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func TestE2E_RequestTimeoutZero_TrickledHeadAnswered(t *testing.T) {
	// request_timeout is a JSON time.Duration (nanoseconds): 200ms.
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"request_timeout": 200000000}`})
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = io.WriteString(w, "path="+r.URL.Path)
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "http://")

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	listenAddr, _ := startRes.Decoded["listen_addr"].(string)
	if listenAddr == "" {
		t.Fatalf("proxy_start did not surface listen_addr; result=%s", startRes.Text)
	}
	h.MustOK(t, "configure", map[string]any{"request_timeout_ms": 0})

	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET http://" + host + "/slow HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	start := time.Now()
	for i := range req {
		time.Sleep(25 * time.Millisecond)
		if _, err := conn.Write([]byte(req[i : i+1])); err != nil {
			t.Fatalf("trickle byte %d after %v: %v (the 200ms bound still applies)", i, time.Since(start), err)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "path=/slow" {
		t.Fatalf("trickled request = %d %q, want 200 path=/slow", resp.StatusCode, body)
	}
}
