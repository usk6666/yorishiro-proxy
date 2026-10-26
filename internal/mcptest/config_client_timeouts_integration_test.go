//go:build e2e && !e2e_smoke

// USK-1186: request_timeout_ms / client_idle_timeout_ms from the -config
// file — 0 disables (distinct from omitted), the idle bound applies to
// keep-alive connections, and an omitted key keeps today's defaults.
package mcptest_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func startPathEchoUpstream(t *testing.T) string {
	t.Helper()
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = io.WriteString(w, "path="+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	return strings.TrimPrefix(upstream.URL, "http://")
}

func startProxyListener(t *testing.T, h *mcptest.Harness) string {
	t.Helper()
	res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	addr, _ := res.Decoded["listen_addr"].(string)
	if addr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", res.Text)
	}
	return addr
}

// trickleGet sends a GET one byte every 25ms (~1.5s+ for the whole head) and
// returns the response status and body, or the error that ended it.
func trickleGet(t *testing.T, proxyAddr, host, path string) (int, string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	req := "GET http://" + host + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	for i := range req {
		time.Sleep(25 * time.Millisecond)
		if _, err := conn.Write([]byte(req[i : i+1])); err != nil {
			return 0, "", err
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, "", err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body), nil
}

// idleProbeGet writes one GET on conn and reads its response.
func idleProbeGet(t *testing.T, conn net.Conn, br *bufio.Reader, host, path string) (int, string) {
	t.Helper()
	req := "GET http://" + host + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := gohttp.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response for %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// TestE2E_ConfigFileRequestTimeoutZero_Disables is USK-1186 T6.
func TestE2E_ConfigFileRequestTimeoutZero_Disables(t *testing.T) {
	t.Run("zero disables", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"request_timeout_ms": 0}`})
		host := startPathEchoUpstream(t)
		addr := startProxyListener(t, h)
		if req, _ := statusClientTimeouts(t, h, "status"); req != 0 {
			t.Errorf("status request_timeout_ms = %v, want 0 (disabled)", req)
		}
		code, body, err := trickleGet(t, addr, host, "/slow")
		if err != nil || code != 200 || body != "path=/slow" {
			t.Fatalf("trickled request = %d %q err=%v, want 200 path=/slow", code, body, err)
		}
	})
	t.Run("positive control 300 cuts the trickle", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"request_timeout_ms": 300}`})
		host := startPathEchoUpstream(t)
		addr := startProxyListener(t, h)
		code, body, err := trickleGet(t, addr, host, "/slow")
		if err == nil && code == 200 {
			t.Fatalf("trickled request = %d %q, want it cut by the 300ms bound", code, body)
		}
	})
}

// TestE2E_ConfigFileClientIdleTimeout is USK-1186 T7.
func TestE2E_ConfigFileClientIdleTimeout(t *testing.T) {
	t.Run("300ms closes an idle keep-alive connection", func(t *testing.T) {
		// The HTTP/1 Layer waits max(idle, request head) for the next
		// request's first byte when both are enabled, so the request bound
		// is shortened too; with the idle key omitted this config waits
		// the default 120s and the connection stays open.
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"request_timeout_ms": 300, "client_idle_timeout_ms": 300}`})
		host := startPathEchoUpstream(t)
		addr := startProxyListener(t, h)
		if _, idle := statusClientTimeouts(t, h, "status"); idle != 300 {
			t.Errorf("status client_idle_timeout_ms = %v, want 300", idle)
		}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		if code, body := idleProbeGet(t, conn, br, host, "/first"); code != 200 || body != "path=/first" {
			t.Fatalf("first request = %d %q, want 200 path=/first", code, body)
		}
		start := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = br.ReadByte()
		elapsed := time.Since(start)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("idle keep-alive connection still open after %v; the config-file 300ms idle bound did not apply", elapsed)
		}
		if err == nil {
			t.Fatal("read a byte from an idle keep-alive connection, want close")
		}
		if elapsed > 3*time.Second {
			t.Errorf("idle connection closed after %v, want well under 3s", elapsed)
		}
	})
	t.Run("0 keeps an idle keep-alive connection open", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"client_idle_timeout_ms": 0, "request_timeout_ms": 300}`})
		host := startPathEchoUpstream(t)
		addr := startProxyListener(t, h)
		if req, idle := statusClientTimeouts(t, h, "status"); req != 300 || idle != 0 {
			t.Errorf("status request_timeout_ms=%v client_idle_timeout_ms=%v, want 300 / 0", req, idle)
		}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		if code, body := idleProbeGet(t, conn, br, host, "/first"); code != 200 || body != "path=/first" {
			t.Fatalf("first request = %d %q, want 200 path=/first", code, body)
		}
		time.Sleep(time.Second)
		if code, body := idleProbeGet(t, conn, br, host, "/second"); code != 200 || body != "path=/second" {
			t.Fatalf("second request after 1s idle = %d %q, want 200 path=/second", code, body)
		}
	})
}

// TestE2E_ConfigFileClientTimeoutsOmitted_Defaults is USK-1186 T8: a config
// file without the keys keeps 60000 / 120000.
func TestE2E_ConfigFileClientTimeoutsOmitted_Defaults(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"socks5_auth": "none"}`})
	check := func(when string) {
		t.Helper()
		for _, resource := range []string{"status", "config"} {
			if req, idle := statusClientTimeouts(t, h, resource); req != 60000 || idle != 120000 {
				t.Errorf("%s %s: request_timeout_ms=%v client_idle_timeout_ms=%v, want 60000 / 120000", when, resource, req, idle)
			}
		}
	}
	check("before proxy_start")
	startProxyListener(t, h)
	check("after proxy_start")
}
