//go:build e2e && !e2e_smoke

// USK-1274: an HTTP/1.x absolute-form request-target names the host a
// server routes on — RFC 9112 §3.2.2 has the server use the URI authority
// and ignore Host. Inside a CONNECT / SOCKS5 MITM tunnel, or on the second
// and later requests of a plain forward-proxy keep-alive connection, the
// proxy forwards the request-target verbatim to the connection's dial
// target, so `GET http://denied.example/ HTTP/1.1` + an allowed Host
// reached a server that may route it to the denied vhost while the scope
// check judged only the Host. The absolute-form authority is now a name
// leg (Option B); the request-target itself stays on the wire verbatim.
package mcptest_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// uriRecordingUpstream is an HTTP upstream (TLS when useTLS) that counts
// requests and records each request-target exactly as received
// (http.Request.RequestURI is the unmodified request-line target).
type uriRecordingUpstream struct {
	addr string
	hits atomic.Int64
	mu   sync.Mutex
	uris []string
}

func startURIRecordingUpstream(t *testing.T, useTLS bool) *uriRecordingUpstream {
	t.Helper()
	u := &uriRecordingUpstream{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.mu.Lock()
		u.uris = append(u.uris, r.RequestURI)
		u.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	})
	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	u.addr = srv.Listener.Addr().String()
	return u
}

func (u *uriRecordingUpstream) requestURIs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.uris...)
}

// writeRawRequest writes one raw HTTP/1.1 request on a keep-alive
// connection and returns the response status code and Server header.
func writeRawRequest(t *testing.T, c net.Conn, br *bufio.Reader, request string) (int, string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Server")
}

// tunnelRawRequest is writeRawRequest on a MITM tunnel's client TLS session.
func tunnelRawRequest(t *testing.T, c *liveTLSConn, request string) (int, string) {
	t.Helper()
	return writeRawRequest(t, c, c.br, request)
}

// openMITMTunnel CONNECTs to target through the proxy and completes the
// client TLS handshake with the proxy's MITM certificate.
func openMITMTunnel(t *testing.T, proxyAddr, target string) *liveTLSConn {
	t.Helper()
	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	return clientTLSOver(t, raw)
}

// T1: CONNECT + TLS MITM to an IP-allowed target. An origin-form request
// is relayed (negative control); an absolute-form request naming a denied
// authority behind an allowed Host is answered 403 by the proxy, never
// reaches the upstream and is recorded as a target_scope block.
func TestE2E_AbsoluteFormScope_TunnelDeniedAuthority(t *testing.T) {
	up := startURIRecordingUpstream(t, true)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})
	proxyAddr := startProxyWithPassthrough(t, h)
	c := openMITMTunnel(t, proxyAddr, up.addr)

	if code, _ := tunnelRawRequest(t, c, "GET /public HTTP/1.1\r\nHost: "+up.addr+"\r\n\r\n"); code != http.StatusOK || up.hits.Load() != 1 {
		t.Fatalf("origin-form GET /public = %d (upstream hits %d), want 200 and 1", code, up.hits.Load())
	}
	code, server := tunnelRawRequest(t, c, "GET http://denied.example/abs HTTP/1.1\r\nHost: "+up.addr+"\r\n\r\n")
	if code != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("absolute-form GET http://denied.example/abs = %d (Server %q), want the proxy's 403", code, server)
	}
	if got := up.hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the denied absolute-form authority reached the upstream (URIs %q)", got, up.requestURIs())
	}
	blocked := waitBlockedHTTPStreams(t, h, 1)
	if s, _ := blocked[0]["scheme"].(string); s != "https" {
		t.Errorf("blocked Stream scheme = %q, want https", s)
	}
}

// T2: plain forward proxy, one keep-alive connection. The first request's
// absolute-form target is the dial target and is relayed; the second names
// a denied authority behind the same allowed Host and is refused before it
// reaches the upstream the connection is bound to.
func TestE2E_AbsoluteFormScope_ForwardKeepAliveSecondRequest(t *testing.T) {
	up := startURIRecordingUpstream(t, false)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})
	proxyAddr := startProxyWithPassthrough(t, h)

	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	br := bufio.NewReader(c)

	if code, _ := writeRawRequest(t, c, br, "GET http://"+up.addr+"/first HTTP/1.1\r\nHost: "+up.addr+"\r\n\r\n"); code != http.StatusOK || up.hits.Load() != 1 {
		t.Fatalf("first request = %d (upstream hits %d), want 200 and 1", code, up.hits.Load())
	}
	code, server := writeRawRequest(t, c, br, "GET http://denied.example/second HTTP/1.1\r\nHost: "+up.addr+"\r\n\r\n")
	if code != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("second keep-alive request to http://denied.example/second = %d (Server %q), want the proxy's 403", code, server)
	}
	if got := up.hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the second request reached the upstream (URIs %q)", got, up.requestURIs())
	}
	waitBlockedHTTPStreams(t, h, 1)
}

// T3 (guard): a non-denied absolute-form authority on an IP-allowed target
// is forwarded, and the request-target reaches the upstream and the
// recorded raw request byte-for-byte — the scope check only reads it.
func TestE2E_AbsoluteFormScope_NonDeniedAuthorityVerbatim(t *testing.T) {
	up := startURIRecordingUpstream(t, true)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})
	proxyAddr := startProxyWithPassthrough(t, h)
	c := openMITMTunnel(t, proxyAddr, up.addr)

	const target = "http://vhost.example/abs-ok"
	if code, _ := tunnelRawRequest(t, c, "GET "+target+" HTTP/1.1\r\nHost: "+up.addr+"\r\n\r\n"); code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", target, code)
	}
	if got := up.requestURIs(); len(got) != 1 || got[0] != target {
		t.Errorf("upstream request-targets = %q, want [%q] verbatim", got, target)
	}

	var id string
	deadline := time.Now().Add(5 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		for _, f := range queryHTTPFlows(t, h, map[string]any{"state": "complete"}) {
			if u, _ := f["url"].(string); strings.Contains(u, "/abs-ok") {
				id, _ = f["id"].(string)
			}
		}
		if id == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if id == "" {
		t.Fatalf("no complete http Stream for /abs-ok within 5s")
	}
	detail := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
	rawB64, _ := detail.Decoded["raw_request"].(string)
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatalf("decode raw_request: %v", err)
	}
	if want := "GET " + target + " HTTP/1.1\r\n"; !strings.HasPrefix(string(raw), want) {
		t.Errorf("recorded raw request %q does not start with the wire request line %q", raw, want)
	}
}

// T4: Option B on the absolute-form leg. Under a domain allow an unlisted
// absolute-form authority is refused; under an IP-literal allow on the
// dial target the same request is forwarded (vhost testing stays possible).
func TestE2E_AbsoluteFormScope_OptionB(t *testing.T) {
	t.Run("domain allow: unlisted authority refused", func(t *testing.T) {
		up := startURIRecordingUpstream(t, true)
		_, port, _ := net.SplitHostPort(up.addr)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			ConfigJSON: `{"target_scope_policy":{"allows":[{"hostname":"localhost"}]}}`,
		})
		proxyAddr := startProxyWithPassthrough(t, h)
		target := net.JoinHostPort("localhost", port)
		c := openMITMTunnel(t, proxyAddr, target)

		if code, _ := tunnelRawRequest(t, c, "GET /same HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); code != http.StatusOK || up.hits.Load() != 1 {
			t.Fatalf("origin-form GET /same = %d (upstream hits %d), want 200 and 1", code, up.hits.Load())
		}
		code, server := tunnelRawRequest(t, c, "GET http://unlisted.example/abs HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		if code != http.StatusForbidden || server != "yorishiro-proxy" {
			t.Errorf("unlisted absolute-form authority on a domain-allowed target = %d (Server %q), want the proxy's 403", code, server)
		}
		if got := up.hits.Load(); got != 1 {
			t.Errorf("upstream hits = %d, want 1", got)
		}
	})
	t.Run("IP-literal allow: unlisted authority forwarded", func(t *testing.T) {
		up := startURIRecordingUpstream(t, true)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			ConfigJSON: `{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1"}]}}`,
		})
		proxyAddr := startProxyWithPassthrough(t, h)
		c := openMITMTunnel(t, proxyAddr, up.addr)
		code, _ := tunnelRawRequest(t, c, fmt.Sprintf("GET http://unlisted.example/abs HTTP/1.1\r\nHost: %s\r\n\r\n", up.addr))
		if code != http.StatusOK || up.hits.Load() != 1 {
			t.Errorf("unlisted absolute-form authority on an IP-allowed target = %d (upstream hits %d), want 200 and 1", code, up.hits.Load())
		}
	})
}
