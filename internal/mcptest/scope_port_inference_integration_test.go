//go:build e2e && !e2e_smoke

// USK-1235 exhaustive tier: HTTPScopeStep's default-port inference for a
// port-less Host / :authority must not let a request escape a rule bound to
// the port the connection actually dialed.
package mcptest_test

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// T1 (Issue case a): CONNECT 127.0.0.1:<port> → TLS MITM → requests whose
// Host is "127.0.0.1" with no port. A path-scoped deny on the dial port
// fires: /admin is answered 403 and never reaches the upstream, and the
// block is recorded. Before the TargetHost check HTTPScopeStep judged the
// authority as 127.0.0.1:443, the deny's port did not match, and
// HostScopeStep (no path) could not match a path-scoped deny either.
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
	if got := keepAliveGet(t, c, "127.0.0.1", "/admin"); got != http.StatusForbidden {
		t.Errorf("GET /admin (Host 127.0.0.1, dial port %s) = %d, want 403", port, got)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after /admin = %d, want 1 — the port-less Host carried /admin past the deny on port %s", got, port)
	}
	waitBlockedHTTPStream(t, h)
}
