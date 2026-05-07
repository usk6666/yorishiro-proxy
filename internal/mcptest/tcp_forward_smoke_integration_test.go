//go:build e2e

// Package mcptest_test holds USK-757's smoke coverage for the
// proxy_start tcp_forwards parameter.
//
// internal/proxybuild/tcp_forward_integration_test.go covers the
// proxybuild manager directly but is gated behind `e2e &&
// !e2e_smoke`, so the per-PR merge gate never sees the
// proxy_start → proxybuild handoff for tcp_forwards. A regression in
// schema parsing or per-port listener wiring would only surface
// nightly. This file boots the production server and exercises the
// MCP-tool entry path end-to-end.
package mcptest_test

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_TCPForward_EchoRoundTrip proves:
//
//  1. proxy_start accepts a tcp_forwards map keyed by string port → host:port string.
//  2. proxybuild binds the named port for the listener.
//  3. A TCP client connecting to the forward port reaches the
//     upstream — the echo server sees the request bytes and the
//     client sees the response bytes (full bidirectional bridge).
func TestE2E_TCPForward_EchoRoundTrip(t *testing.T) {
	echoAddr := startTCPEchoServer(t)
	forwardPort := pickFreePort(t)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	// proxy_start still requires a primary listen address even when
	// the meaningful work is on the tcp_forwards side. The tool
	// validates listen_addr, then layers tcp_forwards on as additional
	// per-port listeners.
	res := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			strconv.Itoa(forwardPort): echoAddr,
		},
	})
	if _, ok := res.Decoded["tcp_forwards"]; !ok {
		t.Fatalf("proxy_start did not echo back tcp_forwards: %s", res.Text)
	}

	// Drive an echo round-trip through the forward port. If the per-
	// port listener never bound, the dial below fails with
	// connection refused.
	const payload = "hello yorishiro tcp-forward smoke\n"
	got := tcpEchoRoundTrip(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(forwardPort)), payload, 5*time.Second)
	if got != payload {
		t.Errorf("tcp echo round-trip mismatch: got %q, want %q", got, payload)
	}
}

// TestE2E_TCPForward_RejectsInvalidTarget is the negative-path
// companion: malformed forward target (missing port) must fail at
// proxy_start time, not at first connection. This catches regressions
// in validateTCPForwardsConfig wiring through the MCP schema.
func TestE2E_TCPForward_RejectsInvalidTarget(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	// "127.0.0.1" with no port should be rejected as invalid host:port.
	// The tool wraps with the stable "tcp_forwards" prefix.
	h.ExpectError(t, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"9999": "127.0.0.1",
		},
	}, "tcp_forwards")
}

// startTCPEchoServer binds an ephemeral loopback TCP port and serves
// a one-shot echo per accepted connection. Returns the host:port
// suitable for the tcp_forwards target field. The server is torn
// down via t.Cleanup; callers do not manage its lifetime.
func startTCPEchoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo: listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				// Listener closed (expected on test teardown) or a
				// transient accept error. Either way exit the loop;
				// failing tests will surface as round-trip mismatches.
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return l.Addr().String()
}

// tcpEchoRoundTrip dials addr, writes payload, reads exactly
// len(payload) bytes back, and returns them as a string. It enforces
// a per-step deadline so a hung proxy does not stall the test
// indefinitely.
func tcpEchoRoundTrip(t *testing.T, addr, payload string, timeout time.Duration) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		t.Fatalf("dial forward port %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	var buf bytes.Buffer
	tmp := make([]byte, len(payload))
	for buf.Len() < len(payload) {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.String()
}
