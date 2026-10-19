//go:build e2e && !e2e_smoke

// USK-1083 exhaustive tier: every raw (bytechunk) construction path stamps
// the connection's EnvelopeContext, so HostScopeStep gates it with the
// scheme derived from the client-facing leg's TLS state (RFC-001 §3.5.1),
// capture_scope sees the target, and RecordStep records conn_id and the
// per-leg TLS. Helpers live in raw_target_scope_smoke_integration_test.go.
package mcptest_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// rawProbe is a payload that is neither TLS nor HTTP, so CONNECT / SOCKS5
// inner peek falls back to the bytechunk stack.
var rawProbe = []byte{0x00, 0x01, 'r', 'a', 'w', '-', 'p', 'r', 'o', 'b', 'e'}

// readEcho reads len(want) bytes from c and fails unless they equal want.
func readEcho(t *testing.T, c net.Conn, want []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(want) {
		t.Fatalf("echo = %q, %v; want %q", got, err, want)
	}
	_ = c.SetReadDeadline(time.Time{})
}

// assertBlockedNoBytes waits for the raw audit Stream and checks the
// denied upstream received nothing.
func assertBlockedNoBytes(t *testing.T, h *mcptest.Harness, received *atomic.Int64) {
	t.Helper()
	waitBlockedRawStream(t, h)
	if got := received.Load(); got != 0 {
		t.Errorf("denied upstream received %d bytes, want 0", got)
	}
}

// TestE2E_RawTargetScope_TCPForwardAllowedRecordsConnID is T2: a deny on a
// different port leaves the raw relay working, and the recorded Stream
// carries the connection's conn_id.
func TestE2E_RawTargetScope_TCPForwardAllowedRecordsConnID(t *testing.T) {
	target, _ := echoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(1)})
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw"})[0]

	c := writeRaw(t, fwd, rawProbe)
	readEcho(t, c, rawProbe)
	_ = c.Close()

	st := waitRawFlows(t, h, nil, func(f map[string]any) bool { return f["state"] == "complete" }, 5*time.Second, "allowed raw relay")[0]
	id, _ := st["id"].(string)
	if cid, _ := queryFlowDetail(t, h, id)["conn_id"].(string); cid == "" {
		t.Errorf("raw Stream conn_id is empty; want the connection's conn_id")
	}
}

// TestE2E_RawTargetScope_TCPForwardTLSScheme is T3: with tls=true the
// client-facing leg is TLS, so HostScopeStep derives "https" — a deny on
// schemes ["https"] blocks, a deny on ["http"] does not.
func TestE2E_RawTargetScope_TCPForwardTLSScheme(t *testing.T) {
	dialTLS := func(t *testing.T, addr string) *tls.Conn {
		t.Helper()
		tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1"}) //nolint:gosec // proxy's ephemeral MITM CA
		if err != nil {
			t.Fatalf("TLS dial forward: %v", err)
		}
		t.Cleanup(func() { _ = tc.Close() })
		return tc
	}

	t.Run("deny https blocks", func(t *testing.T) {
		target, received := echoUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(rawAddrPort(t, target), "https")})
		fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw", "tls": true})[0]
		tc := dialTLS(t, fwd)
		if _, err := tc.Write(rawProbe); err != nil {
			t.Fatalf("write: %v", err)
		}
		assertBlockedNoBytes(t, h, received)
	})

	t.Run("deny http relays", func(t *testing.T) {
		target, _ := echoUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(rawAddrPort(t, target), "http")})
		fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw", "tls": true})[0]
		tc := dialTLS(t, fwd)
		if _, err := tc.Write(rawProbe); err != nil {
			t.Fatalf("write: %v", err)
		}
		readEcho(t, tc, rawProbe)
	})
}

// TestE2E_RawTargetScope_TCPForwardAutoRawFallback is T4: protocol=auto
// that falls back to raw on non-HTTP first bytes is gated too.
func TestE2E_RawTargetScope_TCPForwardAutoRawFallback(t *testing.T) {
	target, received := echoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(rawAddrPort(t, target))})
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "auto"})[0]

	writeRaw(t, fwd, []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02})
	assertBlockedNoBytes(t, h, received)
}

// TestE2E_RawTargetScope_SOCKS5PlaintextRaw is T5: the SOCKS5 gate checks
// a blank scheme, so a schemes-bearing deny passes it; the raw envelopes
// then carry TargetHost with TLS=nil and HostScopeStep blocks on "http".
func TestE2E_RawTargetScope_SOCKS5PlaintextRaw(t *testing.T) {
	t.Run("deny http blocks", func(t *testing.T) {
		target, received := echoUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(rawAddrPort(t, target), "http")})
		proxyAddr := startProxyWithPassthrough(t, h)
		c := socks5DialNoAuth(t, proxyAddr, "127.0.0.1", rawAddrPort(t, target))
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Time{})
		if _, err := c.Write(rawProbe); err != nil {
			t.Fatalf("write: %v", err)
		}
		assertBlockedNoBytes(t, h, received)
	})
	t.Run("deny https relays", func(t *testing.T) {
		target, _ := echoUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(rawAddrPort(t, target), "https")})
		proxyAddr := startProxyWithPassthrough(t, h)
		c := socks5DialNoAuth(t, proxyAddr, "127.0.0.1", rawAddrPort(t, target))
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Time{})
		if _, err := c.Write(rawProbe); err != nil {
			t.Fatalf("write: %v", err)
		}
		readEcho(t, c, rawProbe)
	})
}

// TestE2E_RawTargetScope_CONNECTPlaintextRaw is T6: the CONNECT gate
// checks "https", so a deny on ["http"] passes it (200 Established); the
// plaintext raw inner stream is checked as "http" and blocked.
func TestE2E_RawTargetScope_CONNECTPlaintextRaw(t *testing.T) {
	target, received := echoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(rawAddrPort(t, target), "http")})
	proxyAddr := startProxyWithPassthrough(t, h)

	c, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write(rawProbe); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertBlockedNoBytes(t, h, received)
}

// tlsEchoUpstream is a TLS echo server with a certificate for 127.0.0.1.
func tlsEchoUpstream(t *testing.T) string {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	leaf, err := cert.NewIssuer(ca).GetCertificate("127.0.0.1")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestE2E_RawTargetScope_RawPassthroughRecordsPerLegTLS is T7: a CONNECT
// to a raw_passthrough_hosts target is TLS-terminated and relayed as
// bytechunk; the recorded Stream carries conn_id and the upstream leg's
// TLS connection info.
func TestE2E_RawTargetScope_RawPassthroughRecordsPerLegTLS(t *testing.T) {
	target := tlsEchoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: fmt.Sprintf(`{"raw_passthrough_hosts":[%s]}`, strconv.Quote(target)),
	})
	proxyAddr := startProxyWithPassthrough(t, h)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	msg := []byte("raw-over-tls\n")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c.br, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo = %q, %v; want %q", got, err, msg)
	}
	_ = c.Close()

	st := waitRawFlows(t, h, nil, nil, 5*time.Second, "raw passthrough")[0]
	id, _ := st["id"].(string)
	detail := queryFlowDetail(t, h, id)
	if cid, _ := detail["conn_id"].(string); cid == "" {
		t.Errorf("raw-over-TLS Stream conn_id is empty")
	}
	ci, _ := detail["conn_info"].(map[string]any)
	if v, _ := ci["tls_version"].(string); v == "" {
		t.Errorf("raw-over-TLS Stream conn_info.tls_version is empty (conn_info=%v); want the upstream leg's TLS", ci)
	}
}

// bannerUpstream accepts connections, writes banner first, then echoes.
func bannerUpstream(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := c.Write([]byte(banner)); err != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// readBannerAndClose dials addr, reads the banner, and closes.
func readBannerAndClose(t *testing.T, addr, banner string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	readEcho(t, c, []byte(banner))
}

// TestE2E_RawTargetScope_CaptureScopeReceiveFirst is T8: capture_scope's
// per-stream decision is taken on the FIRST envelope, which for a
// server-first protocol is the Receive banner. It must see the target.
func TestE2E_RawTargetScope_CaptureScopeReceiveFirst(t *testing.T) {
	const banner = "220 usk1083 ready\r\n"

	t.Run("include records", func(t *testing.T) {
		target := bannerUpstream(t, banner)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		fwd := startForwards(t, h, map[string]any{
			"capture_scope": map[string]any{"includes": []map[string]any{{"hostname": "127.0.0.1"}}},
		}, map[string]any{"target": target, "protocol": "raw"})[0]
		readBannerAndClose(t, fwd, banner)
		waitRawFlows(t, h, nil, nil, 5*time.Second, "capture_scope include 127.0.0.1")
	})

	t.Run("exclude suppresses", func(t *testing.T) {
		target := bannerUpstream(t, banner)
		port := strconv.Itoa(rawAddrPort(t, target))
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		fwds := startForwards(t, h, map[string]any{
			"capture_scope": map[string]any{"excludes": []map[string]any{{"hostname": "127.0.0.1"}}},
		},
			map[string]any{"target": target, "protocol": "raw"},
			// Barrier: same upstream under a hostname the exclude does
			// not name. Its Stream landing proves the earlier,
			// excluded connection had its chance to be recorded.
			map[string]any{"target": net.JoinHostPort("localhost", port), "protocol": "raw"},
		)
		readBannerAndClose(t, fwds[0], banner)
		readBannerAndClose(t, fwds[1], banner)
		waitRawFlows(t, h, nil, func(f map[string]any) bool { return f["state"] == "complete" }, 5*time.Second, "barrier")
		if got := queryRawFlows(t, h, nil); len(got) != 1 {
			t.Errorf("raw Streams recorded = %d, want 1 (the barrier only; the 127.0.0.1 one is excluded): %v", len(got), got)
		}
	})
}

// TestE2E_RawTargetScope_DenyTearsConnectionDown is T10 (user decision
// U1): a denied raw chunk closes the connection instead of silently
// dropping it — the client reads EOF promptly, and exactly one audit
// Stream exists however often the client keeps writing.
func TestE2E_RawTargetScope_DenyTearsConnectionDown(t *testing.T) {
	target, received := echoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyPolicyConfig(rawAddrPort(t, target))})
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "raw"})[0]

	c := writeRaw(t, fwd, rawProbe)
	assertConnClosedWithin(t, c, c.SetReadDeadline, 5*time.Second)
	for i := 0; i < 3; i++ {
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := c.Write(rawProbe); err != nil && !errors.Is(err, net.ErrClosed) {
			break
		}
	}
	if got := len(waitRawFlows(t, h, map[string]any{"blocked_by": "target_scope"}, nil, 5*time.Second, "audit")); got != 1 {
		t.Errorf("audit Streams = %d, want exactly 1", got)
	}
	if got := received.Load(); got != 0 {
		t.Errorf("denied upstream received %d bytes, want 0", got)
	}
}
