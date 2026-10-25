//go:build e2e

package mcptest_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// T20 (USK-1316): config file → runtime. transparent_mode and
// transparent_peek_timeout_ms in the config file make a bare proxy_start
// start a transparent listener (reported by query status), which relays
// a server-first protocol after the configured peek deadline; settings
// transparent mode cannot be combined with are refused by proxy_start.
func TestE2E_Transparent_ConfigToRuntime_Smoke(t *testing.T) {
	const banner = "220 transparent smoke\r\n"
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, banner)
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	upstream := netip.MustParseAddrPort(ln.Addr().String())

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"listen_addr":"127.0.0.1:0","transparent_mode":"redirect","transparent_peek_timeout_ms":100}`,
		OriginalDstResolver: connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
			return upstream, nil
		}),
	})

	res := h.MustOK(t, "proxy_start", map[string]any{})
	if got, _ := res.Decoded["transparent_mode"].(string); got != "redirect" {
		t.Fatalf("proxy_start transparent_mode = %q, want redirect (from the config file); result %s", got, res.Text)
	}
	addr, _ := res.Decoded["listen_addr"].(string)

	status := h.MustOK(t, "query", map[string]any{"resource": "status"})
	var snap struct {
		Listeners []struct {
			Name            string `json:"name"`
			TransparentMode string `json:"transparent_mode"`
		} `json:"listeners"`
	}
	if err := json.Unmarshal([]byte(status.Text), &snap); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if len(snap.Listeners) != 1 || snap.Listeners[0].TransparentMode != "redirect" {
		t.Errorf("status listeners = %+v, want one transparent_mode=redirect listener", snap.Listeners)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != banner {
		t.Fatalf("banner %q, %v; want the server-first banner relayed", line, err)
	}

	h.ExpectError(t, "proxy_start", map[string]any{
		"name": "other", "listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{"19999": "127.0.0.1:9"},
	}, "tcp_forwards")
	h.ExpectError(t, "proxy_start", map[string]any{
		"name": "other2", "listen_addr": "127.0.0.1:0",
		"socks5_auth": "password", "socks5_username": "u", "socks5_password": "p",
	}, "socks5_auth")
	h.ExpectError(t, "proxy_start", map[string]any{
		"name": "other3", "listen_addr": "127.0.0.1:0", "transparent_peek_timeout_ms": 5,
	}, "transparent_peek_timeout_ms")
}
