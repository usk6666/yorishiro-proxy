//go:build e2e

// USK-1160: live connections admitted by the CONNECT / SOCKS5 /
// plain-forward gates are re-evaluated when the policy changes, and closed
// when an identical new connection would no longer be admitted. These
// tests drive the production assembly (mcpserver.Run) through the harness:
// the policy file is rewritten and Harness.ReloadPolicy requests the same
// reload SIGHUP does in the binary.
package mcptest_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// startProxyWithPassthrough starts the proxy listener with the given TLS
// passthrough patterns and returns its address.
func startProxyWithPassthrough(t *testing.T, h *mcptest.Harness, passthrough ...string) string {
	t.Helper()
	args := map[string]any{"listen_addr": "127.0.0.1:0"}
	if len(passthrough) > 0 {
		args["tls_passthrough"] = passthrough
	}
	res := h.MustOK(t, "proxy_start", args)
	addr, _ := res.Decoded["listen_addr"].(string)
	if addr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", res.Text)
	}
	return addr
}

// liveTLSConn is a client TLS session over a proxy tunnel.
type liveTLSConn struct {
	*tls.Conn
	br *bufio.Reader
}

// clientTLSOver runs a client TLS handshake over an established tunnel.
// The client does not verify the peer: passthrough presents the upstream's
// certificate, MITM presents the proxy's.
func clientTLSOver(t *testing.T, raw net.Conn) *liveTLSConn {
	t.Helper()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1"}) //nolint:gosec
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		t.Fatalf("client TLS handshake over tunnel: %v", err)
	}
	_ = tc.SetDeadline(time.Time{})
	t.Cleanup(func() { _ = tc.Close() })
	return &liveTLSConn{Conn: tc, br: bufio.NewReader(tc)}
}

// assertPassthrough checks the tunnel reached the upstream without MITM:
// the certificate the client saw is the upstream's own.
func assertPassthrough(t *testing.T, c *liveTLSConn, upstreamCert []byte) {
	t.Helper()
	peer := c.ConnectionState().PeerCertificates
	if len(peer) == 0 || !bytes.Equal(peer[0].Raw, upstreamCert) {
		t.Fatalf("tunnel is not a TLS passthrough: client saw a certificate other than the upstream's")
	}
}

// keepAliveGet sends one keep-alive GET on c and returns the status code.
func keepAliveGet(t *testing.T, c *liveTLSConn, host, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if err := req.Write(c); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		t.Fatalf("read response to %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// assertConnClosedWithin asserts the proxy closed the connection within d:
// a read ends in EOF / reset instead of timing out. Bytes still in flight
// (e.g. pushed frames) are drained.
func assertConnClosedWithin(t *testing.T, r io.Reader, setDeadline func(time.Time) error, d time.Duration) {
	t.Helper()
	_ = setDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	for {
		_, err := r.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("connection still open %v after the policy change; want it closed", d)
		}
		return
	}
}

// TestE2E_LiveConnReconcile_ConnectPassthroughCutOnReload is T1 /
// acceptance criterion 1: a CONNECT TLS-passthrough tunnel to a host the
// reloaded policy denies is closed within 5s, and a request sent on it
// afterwards never reaches the upstream.
func TestE2E_LiveConnReconcile_ConnectPassthroughCutOnReload(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"127.0.0.1"}]}`)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})
	proxyAddr := startProxyWithPassthrough(t, h, "127.0.0.1")

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	assertPassthrough(t, c, upstream.Certificate().Raw)
	if got := keepAliveGet(t, c, target, "/before"); got != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("before reload: status=%d hits=%d, want 200 and 1", got, hits.Load())
	}

	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}

	assertConnClosedWithin(t, c.br, c.SetReadDeadline, 5*time.Second)
	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/after", nil)
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = req.Write(c)
	time.Sleep(200 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after reload = %d, want 1 — the cut tunnel still carried a request", got)
	}
}
