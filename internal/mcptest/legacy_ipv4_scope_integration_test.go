//go:build e2e && !e2e_smoke

// USK-1273: with a policy that allows only 127.0.0.1, a dial host spelled
// as a legacy inet_aton IPv4 form ("0x7f.0.0.1", "2130706433", "127.1",
// "0177.0.0.1") is refused on every live entry point and by resend_http,
// through the production listener wiring and the JSON-RPC MCP transport.
// Go's pure resolver sends the hex spellings to DNS, so admitting them
// under the allow could dial a host the allow list never named. The
// upstream counts received bytes, so a refusal is "zero bytes". A Host
// header carrying such a spelling on a connection dialing 127.0.0.1 is a
// name leg and is still forwarded verbatim.
package mcptest_test

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

const loopbackAllowConfig = `{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1"}]}}`

func TestE2E_LegacyIPv4Scope_LiveAndResend(t *testing.T) {
	target, received, lastHead := byteCountingHTTPUpstream(t)
	_, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: loopbackAllowConfig})
	proxyAddr := startProxyWithPassthrough(t, h)

	legacy := []string{"0x7f.0.0.1", "2130706433", "127.1", "0177.0.0.1"}

	assertNoBytes := func(t *testing.T, what string) {
		t.Helper()
		time.Sleep(200 * time.Millisecond)
		if got := received.Load(); got != 0 {
			t.Fatalf("%s: upstream received %d bytes, want 0", what, got)
		}
	}

	t.Run("plain forward", func(t *testing.T) {
		for _, host := range legacy {
			for _, req := range []string{
				"GET http://" + host + ":" + portStr + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
				"GET / HTTP/1.1\r\nHost: " + host + ":" + portStr + "\r\nConnection: close\r\n\r\n",
			} {
				code, server := rawProxyRequest(t, proxyAddr, req)
				if code != http.StatusForbidden || server != "yorishiro-proxy" {
					t.Errorf("request %q = %d (Server %q), want the proxy's 403", req, code, server)
				}
			}
		}
		assertNoBytes(t, "plain forward")
	})

	t.Run("CONNECT", func(t *testing.T) {
		for _, host := range legacy {
			authority := host + ":" + portStr
			c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(c, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			if line := string(buf[:n]); !strings.HasPrefix(line, "HTTP/1.1 403") {
				t.Errorf("CONNECT %s status = %q, want 403", authority, line)
			}
			_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
			_ = c.Close()
		}
		assertNoBytes(t, "CONNECT")
	})

	t.Run("SOCKS5 domain", func(t *testing.T) {
		for _, host := range legacy {
			if rep := socks5Rep(t, proxyAddr, 0x03, append([]byte{byte(len(host))}, host...), port); rep != 0x02 {
				t.Errorf("SOCKS5 domain %s REP = 0x%02x, want 0x02", host, rep)
			}
		}
		assertNoBytes(t, "SOCKS5")
	})

	t.Run("resend_http", func(t *testing.T) {
		for _, host := range legacy {
			authority := host + ":" + portStr
			res := h.CallTool(t, "resend_http", map[string]any{
				"method": "GET", "scheme": "http", "authority": authority, "path": "/", "timeout_ms": 3000,
			})
			assertToolScopeRefused(t, res, "resend_http authority "+authority)
		}
		assertNoBytes(t, "resend_http")
	})

	// Control: the canonical spelling reaches the upstream, so the zero-byte
	// rows above are not vacuous.
	t.Run("dotted control", func(t *testing.T) {
		code, _ := rawProxyRequest(t, proxyAddr, "GET http://127.0.0.1:"+portStr+"/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if code != http.StatusOK {
			t.Errorf("dotted 127.0.0.1 = %d, want 200", code)
		}
		if got := received.Load(); got == 0 {
			t.Errorf("upstream received 0 bytes for the dotted control")
		}
	})

	// Name-leg control (plan B): a legacy spelling in the Host header on a
	// connection dialing 127.0.0.1 is forwarded, byte-identical.
	t.Run("Host header name leg forwarded verbatim", func(t *testing.T) {
		code, _ := rawProxyRequest(t, proxyAddr, "GET http://127.0.0.1:"+portStr+"/vhost HTTP/1.1\r\nHost: 0x7f.0.0.1\r\nConnection: close\r\n\r\n")
		if code != http.StatusOK {
			t.Fatalf("Host 0x7f.0.0.1 on dial 127.0.0.1 = %d, want 200", code)
		}
		if head := lastHead(); !strings.Contains(head, "\r\nHost: 0x7f.0.0.1\r\n") {
			t.Errorf("upstream request head = %q, want the Host header verbatim", head)
		}
	})
}
