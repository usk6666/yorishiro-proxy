//go:build e2e && !e2e_smoke

// USK-1129 T10: a Policy deny written as a bracketed IPv6 literal ("[::1]")
// must block a CONNECT to that address. The CONNECT gate splits the target
// with net.SplitHostPort, which strips the brackets, so pre-fix the rule
// compared "[::1]" with "::1" and never matched — the deny was fail-open.
package mcptest_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func TestE2E_USK1129_BracketedIPv6PolicyDeny_BlocksCONNECT(t *testing.T) {
	deniedAddr, deniedHits := startIPv6SinkholeUpstream(t)
	controlAddr, controlHits := startIPv6SinkholeUpstream(t)
	_, deniedPort, err := net.SplitHostPort(deniedAddr)
	if err != nil {
		t.Fatalf("split denied addr: %v", err)
	}

	// The deny is port-scoped so the second sinkhole on the same address
	// is a positive control: it proves a CONNECT that the scope permits
	// really does reach the upstream, so a zero hit count on the denied
	// sinkhole is evidence of the deny rather than of a dead harness.
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: fmt.Sprintf(
			`{"target_scope_policy":{"denies":[{"hostname":"[::1]","ports":[%s]}]}}`, deniedPort),
	})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	connectDenied(t, proxyAddr, deniedAddr)
	connectAndHandshake(t, proxyAddr, controlAddr)

	deadline := time.Now().Add(5 * time.Second)
	for controlHits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if controlHits.Load() == 0 {
		t.Fatal("control sinkhole on [::1] observed no dial; the harness cannot observe upstream dials")
	}
	if got := deniedHits.Load(); got != 0 {
		t.Errorf("denied sinkhole %s observed %d dial(s); want 0 — Policy deny [::1] was bypassed", deniedAddr, got)
	}
}

// connectAndHandshake opens a CONNECT tunnel to target through the proxy and
// attempts a TLS handshake over it, which is what makes the MITM path dial
// the upstream. The handshake outcome is irrelevant (the sinkhole closes
// every connection); only the upstream dial count is asserted.
func connectAndHandshake(t *testing.T, proxyAddr, target string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT %s status = %q, want 200", target, strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, //nolint:gosec // asserting the scope gate, not cert validity
	})
	_ = tlsConn.Handshake()
}

// connectDenied sends a CONNECT for target through the proxy and requires
// the scope gate to refuse it: "HTTP/1.1 403 Forbidden" naming the scope
// gate, then the proxy closes the connection (USK-1246).
func connectDenied(t *testing.T, proxyAddr, target string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read CONNECT %s reply until EOF: %v (got %q)", target, err, got)
	}
	reply := string(got)
	if !strings.HasPrefix(reply, "HTTP/1.1 403 Forbidden\r\n") {
		t.Errorf("CONNECT %s reply = %q, want 403 Forbidden", target, reply)
	}
	if !strings.Contains(reply, "yorishiro-proxy: target blocked by scope") {
		t.Errorf("CONNECT %s reply = %q, want body naming the scope gate", target, reply)
	}
}

// startIPv6SinkholeUpstream is startSinkholeUpstream on [::1]. It skips the
// test when the host has no IPv6 loopback.
func startIPv6SinkholeUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	var hits atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if ctx.Err() != nil {
				_ = conn.Close()
				return
			}
			hits.Add(1)
			_ = conn.Close()
		}
	}()
	return listener.Addr().String(), &hits
}
