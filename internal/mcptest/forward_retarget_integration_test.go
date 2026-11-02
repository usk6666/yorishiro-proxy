//go:build e2e && !e2e_smoke

// USK-1410: on one keep-alive connection to the explicit plain-HTTP
// forward proxy, a later request naming another host is routed to that
// host, recorded against it, and judged by TargetScope as a request to it.
package mcptest_test

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// dialForwardProxy opens one keep-alive client connection to proxyAddr.
func dialForwardProxy(t *testing.T, proxyAddr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, bufio.NewReader(c)
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return port
}

// T2: B's Stream, queried through MCP, names B's URL and B's socket as
// server_addr; A's names A.
func TestE2E_ForwardRetarget_RecordsSwitchedDestination(t *testing.T) {
	a := startURIRecordingUpstream(t, false)
	b := startURIRecordingUpstream(t, false)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxyAddr := startProxyWithPassthrough(t, h)
	c, br := dialForwardProxy(t, proxyAddr)

	if code, _ := writeRawRequest(t, c, br, "GET http://"+a.addr+"/one HTTP/1.1\r\nHost: "+a.addr+"\r\n\r\n"); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", code)
	}
	if code, _ := writeRawRequest(t, c, br, "GET http://"+b.addr+"/two HTTP/1.1\r\nHost: "+b.addr+"\r\n\r\n"); code != http.StatusOK {
		t.Fatalf("second request = %d, want 200", code)
	}
	if a.hits.Load() != 1 || b.hits.Load() != 1 {
		t.Errorf("upstream hits A=%d B=%d, want 1 and 1 (A URIs %q)", a.hits.Load(), b.hits.Load(), a.requestURIs())
	}

	for _, want := range []struct{ path, addr string }{{"/one", a.addr}, {"/two", b.addr}} {
		var detail map[string]any
		deadline := time.Now().Add(5 * time.Second)
		for detail == nil && time.Now().Before(deadline) {
			for _, f := range queryHTTPFlows(t, h, map[string]any{"state": "complete"}) {
				if u, _ := f["url"].(string); strings.HasSuffix(u, want.path) {
					id, _ := f["id"].(string)
					detail = h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id}).Decoded
				}
			}
			if detail == nil {
				time.Sleep(50 * time.Millisecond)
			}
		}
		if detail == nil {
			t.Fatalf("no complete http Stream for %s within 5s", want.path)
		}
		if u, _ := detail["url"].(string); !strings.Contains(u, want.addr) {
			t.Errorf("Stream %s url = %q, want host %s", want.path, u, want.addr)
		}
		ci, _ := detail["conn_info"].(map[string]any)
		if got, _ := ci["server_addr"].(string); got != want.addr {
			t.Errorf("Stream %s conn_info.server_addr = %q, want %s", want.path, got, want.addr)
		}
	}
}

// T6: a path-scoped deny on B is judged against B when a later request
// on a connection first bound to A names B: 403 target_scope from the
// proxy, and B never receives the request.
func TestE2E_ForwardRetarget_PathScopedDenyOnSwitchedTarget(t *testing.T) {
	a := startURIRecordingUpstream(t, false)
	b := startURIRecordingUpstream(t, false)
	cfg := fmt.Sprintf(`{"target_scope_policy":{"denies":[{"hostname":"127.0.0.1","ports":[%s],"path_prefix":"/secret"}]}}`, portOf(t, b.addr))
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: cfg})
	proxyAddr := startProxyWithPassthrough(t, h)
	c, br := dialForwardProxy(t, proxyAddr)

	if code, _ := writeRawRequest(t, c, br, "GET http://"+a.addr+"/secret HTTP/1.1\r\nHost: "+a.addr+"\r\n\r\n"); code != http.StatusOK {
		t.Fatalf("A /secret = %d, want 200 (the deny names B's port only)", code)
	}
	code, server := writeRawRequest(t, c, br, "GET /secret HTTP/1.1\r\nHost: "+b.addr+"\r\n\r\n")
	if code != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("B /secret on A's connection = %d (Server %q), want the proxy's 403", code, server)
	}
	if a.hits.Load() != 1 || b.hits.Load() != 0 {
		t.Errorf("upstream hits A=%d B=%d, want 1 and 0 (A URIs %q)", a.hits.Load(), b.hits.Load(), a.requestURIs())
	}
	waitBlockedHTTPStreams(t, h, 1)
}

// T7: a connection admitted by an IP-literal allow does not lend that
// admission to a later request naming an unlisted host: the request is
// judged as a request to that host and refused. Guard: a later request to
// the same IP target with another Host value still reaches A (Option B:
// vhost testing on an IP-allowed target).
func TestE2E_ForwardRetarget_IPAllowDoesNotCoverOtherTarget(t *testing.T) {
	a := startURIRecordingUpstream(t, false)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1"}]}}`,
	})
	proxyAddr := startProxyWithPassthrough(t, h)
	c, br := dialForwardProxy(t, proxyAddr)

	if code, _ := writeRawRequest(t, c, br, "GET http://"+a.addr+"/one HTTP/1.1\r\nHost: "+a.addr+"\r\n\r\n"); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", code)
	}
	if code, _ := writeRawRequest(t, c, br, "GET http://"+a.addr+"/vhost HTTP/1.1\r\nHost: vhost.example\r\n\r\n"); code != http.StatusOK {
		t.Errorf("same IP target with Host: vhost.example = %d, want 200 (vhost testing must keep working)", code)
	}
	unlisted := "unlisted.example:" + portOf(t, a.addr)
	code, server := writeRawRequest(t, c, br, "GET http://"+unlisted+"/x HTTP/1.1\r\nHost: "+unlisted+"\r\n\r\n")
	if code != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("GET http://%s/x on an IP-admitted connection = %d (Server %q), want the proxy's 403", unlisted, code, server)
	}
	if got := a.hits.Load(); got != 2 {
		t.Errorf("A hits = %d, want 2 (URIs %q)", got, a.requestURIs())
	}
	waitBlockedHTTPStreams(t, h, 1)
}
