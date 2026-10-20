//go:build e2e && !e2e_smoke

// USK-1235 exhaustive tier: HTTPScopeStep's default-port inference for a
// port-less Host / :authority must not let a request escape a rule bound to
// the port the connection actually dialed.
package mcptest_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// T1 (Issue case a): CONNECT 127.0.0.1:<port> → TLS MITM → requests whose
// Host is "127.0.0.1" with no port. A path-scoped deny on the dial port
// fires: /admin is answered 403 and never reaches the upstream, and the
// block is recorded. Before the TargetHost check HTTPScopeStep judged the
// authority as 127.0.0.1:443, the deny's port did not match, and
// HostScopeStep (no path) could not match a path-scoped deny either. A
// second /admin request whose Host names a different explicit port
// (127.0.0.1:443) is blocked the same way.
func TestE2E_ScopePortInference_PortlessHostDenyOnDialPort(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split upstream addr %q: %v", target, err)
	}
	if port == "443" {
		t.Fatalf("precondition: upstream bound to 443; the test needs a non-default dial port")
	}
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: fmt.Sprintf(
			`{"target_scope_policy":{"denies":[{"hostname":"127.0.0.1","ports":[%s],"path_prefix":"/admin"}]}}`,
			port),
	})
	proxyAddr := startProxyWithPassthrough(t, h)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)

	// Negative control on the same tunnel: a path outside the deny prefix
	// reaches the upstream, so the 403 below is the path rule, not a
	// connection-level refusal.
	if got := keepAliveGet(t, c, "127.0.0.1", "/public"); got != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("GET /public (Host 127.0.0.1) = %d (upstream hits %d), want 200 and 1", got, hits.Load())
	}
	if got, server := keepAliveGetServer(t, c, "127.0.0.1", "/admin"); got != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("GET /admin (Host 127.0.0.1, dial port %s) = %d (Server %q), want the proxy's 403", port, got, server)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after /admin = %d, want 1 — the port-less Host carried /admin past the deny on port %s", got, port)
	}
	// The block is recorded, and it is the only one: /public was relayed,
	// so the one target_scope Stream belongs to /admin. (A target_scope
	// Stream carries no messages, so its URL cannot be read back.)
	blocked := waitBlockedHTTPStreams(t, h, 1)
	if s, _ := blocked[0]["scheme"].(string); s != "https" {
		t.Errorf("blocked Stream scheme = %q, want https", s)
	}

	// An authority naming an explicit port other than the dial port is the
	// same bypass class: the Host leg judges 127.0.0.1:443, which the deny
	// does not cover, so only the dial-port leg can block it.
	if got, server := keepAliveGetServer(t, c, "127.0.0.1:443", "/admin"); got != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("GET /admin (Host 127.0.0.1:443, dial port %s) = %d (Server %q), want the proxy's 403", port, got, server)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after /admin with Host 127.0.0.1:443 = %d, want 1 — the mismatched-port Host carried /admin past the deny on port %s", got, port)
	}
	waitBlockedHTTPStreams(t, h, 2)
}

// waitBlockedHTTPStreams waits until exactly n http Streams are recorded
// with blocked_by=target_scope and returns them; more than n fails.
func waitBlockedHTTPStreams(t *testing.T, h *mcptest.Harness, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		flows := queryHTTPFlows(t, h, map[string]any{"blocked_by": "target_scope"})
		if len(flows) > n {
			t.Fatalf("%d http Streams with blocked_by=target_scope, want %d", len(flows), n)
		}
		if len(flows) == n {
			return flows
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d http Streams with blocked_by=target_scope after 5s, want %d", len(flows), n)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// keepAliveGetServer is keepAliveGet that also returns the response's
// Server header, so a 403 can be attributed to the proxy rather than the
// upstream.
func keepAliveGetServer(t *testing.T, c *liveTLSConn, host, path string) (int, string) {
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
	return resp.StatusCode, resp.Header.Get("Server")
}
