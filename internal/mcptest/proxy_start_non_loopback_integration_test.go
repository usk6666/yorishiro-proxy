//go:build e2e && !e2e_smoke

// USK-1125 exhaustive coverage for non-loopback proxy listeners. Every
// test that needs a real non-loopback address discovers one via
// mcptest.NonLoopbackIPv4 and skips when the host has none (sandboxed
// runners commonly expose only lo). Client addresses on recorded streams
// are deliberately not asserted.
package mcptest_test

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ProxyStart_WildcardListen_DialViaNonLoopbackIP proves a client
// reaching a 0.0.0.0 listener through a non-loopback interface address is
// proxied and recorded.
func TestE2E_ProxyStart_WildcardListen_DialViaNonLoopbackIP(t *testing.T) {
	ip := mcptest.NonLoopbackIPv4(t)
	upstream := startPlainHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "0.0.0.0:0"})
	port := listenAddrPort(t, res, "0.0.0.0")

	const path = "/usk1125-wildcard-nonloopback"
	if body := getViaProxy(t, net.JoinHostPort(ip, port), upstream, path); body != "ok:"+path {
		t.Errorf("response body = %q, want %q", body, "ok:"+path)
	}
	assertListenFlowRecorded(t, h, path)
}

// TestE2E_ProxyStart_SpecificIPListen proves a listener bound to one
// specific interface address accepts there and only there: the same port
// on 127.0.0.1 refuses the connection.
func TestE2E_ProxyStart_SpecificIPListen(t *testing.T) {
	ip := mcptest.NonLoopbackIPv4(t)
	upstream := startPlainHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": net.JoinHostPort(ip, "0")})
	port := listenAddrPort(t, res, ip)

	const path = "/usk1125-specific-ip"
	if body := getViaProxy(t, net.JoinHostPort(ip, port), upstream, path); body != "ok:"+path {
		t.Errorf("response body = %q, want %q", body, "ok:"+path)
	}
	assertListenFlowRecorded(t, h, path)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("dial 127.0.0.1:%s succeeded; listener bound to %s must not accept on loopback", port, ip)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("dial 127.0.0.1:%s error = %v, want connection refused", port, err)
	}
}

// TestE2E_ProxyStart_ConfigFileWildcardListenAddr proves the config-file
// listen_addr reaches proxy_start as its default: a file carrying
// 0.0.0.0:0 plus an argument-less proxy_start binds the wildcard.
func TestE2E_ProxyStart_ConfigFileWildcardListenAddr(t *testing.T) {
	if ln, err := net.Listen("tcp", "0.0.0.0:0"); err != nil {
		t.Skipf("cannot bind 0.0.0.0 in this environment: %v", err)
	} else {
		_ = ln.Close()
	}
	upstream := startPlainHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"listen_addr":"0.0.0.0:0"}`,
	})

	res := h.MustOK(t, "proxy_start", map[string]any{})
	port := listenAddrPort(t, res, "0.0.0.0")

	const path = "/usk1125-config-file"
	if body := getViaProxy(t, net.JoinHostPort("127.0.0.1", port), upstream, path); body != "ok:"+path {
		t.Errorf("response body = %q, want %q", body, "ok:"+path)
	}
	assertListenFlowRecorded(t, h, path)
}

// TestE2E_ProxyStart_TCPForwardInheritsWildcardHost proves a tcp_forwards
// listener under a 0.0.0.0 parent binds the wildcard as well, so a client
// on a non-loopback interface address reaches the forward target.
func TestE2E_ProxyStart_TCPForwardInheritsWildcardHost(t *testing.T) {
	ip := mcptest.NonLoopbackIPv4(t)
	echoAddr := startTCPEchoServer(t)

	// Free wildcard port for the forward (probe-then-release idiom).
	probe, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("probe wildcard port: %v", err)
	}
	fwdPort := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":  "0.0.0.0:0",
		"tcp_forwards": map[string]any{fwdPort: echoAddr},
	})

	const payload = "usk1125 forward via non-loopback\n"
	if got := tcpEchoRoundTrip(t, net.JoinHostPort(ip, fwdPort), payload, 5*time.Second); got != payload {
		t.Errorf("echo round-trip via %s:%s = %q, want %q", ip, fwdPort, got, payload)
	}
}
