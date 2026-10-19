//go:build e2e

// USK-1161 smoke: proxy_start refuses a tcp_forwards entry whose upstream
// target the operator Policy denies, before anything is bound or dialed,
// and an allowed forward keeps working. Helpers live in
// raw_target_scope_smoke_integration_test.go.
package mcptest_test

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_TCPForwardScope_ProxyStartRejectsDeniedTarget is test-plan 1.
func TestE2E_TCPForwardScope_ProxyStartRejectsDeniedTarget(t *testing.T) {
	target, received, accepts := countingEchoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: denyPolicyConfig(rawAddrPort(t, target)),
	})
	port := strconv.Itoa(pickFreePort(t))
	res := h.CallTool(t, "proxy_start", map[string]any{
		"listen_addr":  "127.0.0.1:0",
		"tcp_forwards": map[string]any{port: map[string]any{"target": target, "protocol": "raw"}},
	})
	if !res.IsError && res.Err == nil {
		t.Fatalf("proxy_start succeeded for a Policy-denied tcp_forwards target: %s", res.Text)
	}
	msg := res.Text
	if res.Err != nil {
		msg += " " + res.Err.Error()
	}
	if !strings.Contains(msg, "scope") || !strings.Contains(msg, port) {
		t.Errorf("proxy_start error %q does not name the scope and forward port %s", msg, port)
	}

	if st := queryStatus(t, h); st.Running || st.ListenerCount != 0 {
		t.Errorf("query(status) = %+v after the rejected proxy_start; want not running, 0 listeners", st)
	}
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second); err == nil {
		_ = c.Close()
		t.Errorf("forward port %s is bound after the rejected proxy_start", port)
	}
	if a, r := accepts.Load(), received.Load(); a != 0 || r != 0 {
		t.Errorf("denied upstream saw %d connections / %d bytes, want 0 / 0", a, r)
	}
}

// TestE2E_TCPForwardScope_AllowedTargetRelays is test-plan 2 (guard): a
// forward to a target the Policy allows starts and relays as before,
// while a sibling port is denied.
func TestE2E_TCPForwardScope_AllowedTargetRelays(t *testing.T) {
	target, _, accepts := countingEchoUpstream(t)
	deniedPort := pickFreePort(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: fmt.Sprintf(`{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1","ports":[%d]}],"denies":[{"hostname":"127.0.0.1","ports":[%d]}]}}`,
			rawAddrPort(t, target), deniedPort),
	})
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw"})[0]

	msg := []byte{0x00, 0x01, 'a', 'l', 'l', 'o', 'w'}
	c := writeRaw(t, fwd, msg)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo = %q, %v; want %q", got, err, msg)
	}
	if a := accepts.Load(); a != 1 {
		t.Errorf("allowed upstream accepted %d connections, want 1", a)
	}
}
