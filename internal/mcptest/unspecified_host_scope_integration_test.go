//go:build e2e && !e2e_smoke

// USK-1312: with a policy that denies the loopback names, an empty host or
// an unspecified address (0.0.0.0 / ::) — which Go's dialer reads as the
// proxy's own host — is refused on every live entry point and by
// resend_http, through the production listener wiring and the JSON-RPC
// MCP transport. The upstream counts received bytes, so a refusal is
// "zero bytes", not merely "some error".
package mcptest_test

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

const loopbackDenyConfig = `{"target_scope_policy":{"denies":[{"hostname":"127.0.0.1"},{"hostname":"localhost"},{"hostname":"::1"}]}}`

// socks5Rep runs a NO_AUTH SOCKS5 CONNECT with the given ATYP and address
// bytes and returns REP (0xff when no reply arrived).
func socks5Rep(t *testing.T, proxyAddr string, atyp byte, addr []byte, port int) byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks5 greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c, sel); err != nil {
		t.Fatalf("socks5 method selection: %v", err)
	}
	req := append([]byte{0x05, 0x01, 0x00, atyp}, addr...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("socks5 CONNECT: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		return 0xff
	}
	return reply[1]
}

func TestE2E_UnspecifiedHostScope_LiveAndResend(t *testing.T) {
	target, received, _ := byteCountingHTTPUpstream(t)
	_, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: loopbackDenyConfig})
	proxyAddr := startProxyWithPassthrough(t, h)

	assertNoBytes := func(t *testing.T, what string) {
		t.Helper()
		time.Sleep(200 * time.Millisecond)
		if got := received.Load(); got != 0 {
			t.Fatalf("%s: upstream received %d bytes, want 0", what, got)
		}
	}

	t.Run("plain forward", func(t *testing.T) {
		for _, req := range []string{
			"GET http://0.0.0.0:" + portStr + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
			"GET http://[::]:" + portStr + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
			"GET / HTTP/1.1\r\nHost: :" + portStr + "\r\nConnection: close\r\n\r\n",
		} {
			code, server := rawProxyRequest(t, proxyAddr, req)
			if code != http.StatusForbidden || server != "yorishiro-proxy" {
				t.Errorf("request %q = %d (Server %q), want the proxy's 403", req, code, server)
			}
		}
		assertNoBytes(t, "plain forward")
	})

	t.Run("CONNECT", func(t *testing.T) {
		for _, authority := range []string{"[::]:" + portStr, "0.0.0.0:" + portStr} {
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

	t.Run("SOCKS5", func(t *testing.T) {
		if rep := socks5Rep(t, proxyAddr, 0x04, make([]byte, 16), port); rep != 0x02 {
			t.Errorf("SOCKS5 ATYP v6 :: REP = 0x%02x, want 0x02", rep)
		}
		if rep := socks5Rep(t, proxyAddr, 0x01, make([]byte, 4), port); rep != 0x02 {
			t.Errorf("SOCKS5 ATYP v4 0.0.0.0 REP = 0x%02x, want 0x02", rep)
		}
		if rep := socks5Rep(t, proxyAddr, 0x03, append([]byte{2}, "::"...), port); rep != 0x02 {
			t.Errorf("SOCKS5 domain :: REP = 0x%02x, want 0x02", rep)
		}
		assertNoBytes(t, "SOCKS5")
	})

	t.Run("resend_http", func(t *testing.T) {
		for _, authority := range []string{"0.0.0.0:" + portStr, "[::]:" + portStr, ":" + portStr} {
			res := h.CallTool(t, "resend_http", map[string]any{
				"method": "GET", "scheme": "http", "authority": authority, "path": "/", "timeout_ms": 3000,
			})
			assertToolScopeRefused(t, res, "resend_http authority "+authority)
		}
		assertNoBytes(t, "resend_http")
	})
}
