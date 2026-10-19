//go:build e2e && !e2e_smoke

// USK-1130 exhaustive tier: a path-scoped allow
// ({hostname: X, path_prefix: "/api/"}) through the production server.
//
// Every connection-level gate checks TargetScope without a request path, so
// before USK-1130 such an allow never matched there and every connection to
// X was refused "not in policy allow list" before HTTPScopeStep saw a path.
// Now routes on which HTTPScopeStep checks every request path admit X
// provisionally, the Pipeline enforces the prefix per request, and routes
// that never yield a path (raw bytes, TLS passthrough, tcp_forwards raw)
// stay refused.
package mcptest_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// pathAllowPolicyConfig is a config document whose Policy allows only
// 127.0.0.1 under path_prefix "/api/".
const pathAllowPolicyConfig = `{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1","path_prefix":"/api/"}]}}`

// queryHTTPFlows returns the http-protocol Streams matching filter.
func queryHTTPFlows(t *testing.T, h *mcptest.Harness, filter map[string]any) []map[string]any {
	t.Helper()
	f := map[string]any{"protocol": "http"}
	for k, v := range filter {
		f[k] = v
	}
	res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": f})
	raw, _ := res.Decoded["flows"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// waitBlockedHTTPStream waits for an http Stream recorded with
// blocked_by=target_scope.
func waitBlockedHTTPStream(t *testing.T, h *mcptest.Harness) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if flows := queryHTTPFlows(t, h, map[string]any{"blocked_by": "target_scope"}); len(flows) > 0 {
			return flows[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no http Stream with blocked_by=target_scope within 5s")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// T1: plain HTTP forward. An in-prefix request reaches the upstream; an
// out-of-prefix one is answered 403 by the proxy and recorded as blocked.
func TestE2E_PathScopeAllow_PlainHTTPForward(t *testing.T) {
	target, hits := countingHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: pathAllowPolicyConfig})
	proxyAddr := startProxyWithPassthrough(t, h)

	pURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pURL), DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := client.Get("http://" + target + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header.Get("Server")
	}

	if code, _ := get("/api/x"); code != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("GET /api/x = %d (upstream hits %d), want 200 and 1", code, hits.Load())
	}
	code, server := get("/other")
	if code != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("GET /other = %d (Server %q), want the proxy's 403", code, server)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after /other = %d, want 1", got)
	}
	blocked := waitBlockedHTTPStream(t, h)
	if s, _ := blocked["state"].(string); s != "error" && s != "complete" {
		t.Errorf("blocked Stream state = %q", s)
	}
}

// T2: CONNECT + TLS MITM. The tunnel is admitted; the Pipeline enforces the
// prefix per request.
func TestE2E_PathScopeAllow_CONNECTMITM(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: pathAllowPolicyConfig})
	proxyAddr := startProxyWithPassthrough(t, h)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	if got := keepAliveGet(t, c, target, "/api/ok"); got != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("GET /api/ok = %d (upstream hits %d), want 200 and 1", got, hits.Load())
	}
	if got := keepAliveGet(t, c, target, "/other"); got != http.StatusForbidden {
		t.Errorf("GET /other = %d, want 403", got)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after /other = %d, want 1", got)
	}
	waitBlockedHTTPStream(t, h)
}

// T3: a CONNECT to the path-allowed host carrying non-HTTP bytes never
// yields a path, so HostScopeStep closes it: the upstream receives no
// client byte and the block is recorded as a raw audit Stream.
func TestE2E_PathScopeAllow_CONNECTRawBytesBlocked(t *testing.T) {
	target, received := echoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: pathAllowPolicyConfig})
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

// T4 (e2e): a TLS passthrough target is never admitted by a path-scoped
// allow — the relay would carry X traffic with no path check.
func TestE2E_PathScopeAllow_CONNECTPassthroughRefused(t *testing.T) {
	target, _, accepts := countingEchoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: pathAllowPolicyConfig})
	proxyAddr := startProxyWithPassthrough(t, h, "127.0.0.1")

	c, err := dialCONNECTTunnel(proxyAddr, target)
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
		_, _ = c.Write([]byte("\x16\x03\x01 not a ClientHello"))
		assertConnClosedWithin(t, c, c.SetReadDeadline, 5*time.Second)
	}
	time.Sleep(200 * time.Millisecond)
	if n := accepts.Load(); n != 0 {
		t.Errorf("passthrough target accepted %d connections, want 0", n)
	}
}

// T5 / U2: a path deny on the dial target fires even when the inner
// request names another host. Before USK-1130 HostScopeStep (no path) and
// HTTPScopeStep (Host header only) both let it through.
func TestE2E_PathScopeAllow_HostSpoofDoesNotBypassPathDeny(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"target_scope_policy":{"denies":[{"hostname":"127.0.0.1","path_prefix":"/admin"}]}}`,
	})
	proxyAddr := startProxyWithPassthrough(t, h)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	if got := keepAliveGet(t, c, "y.example.com", "/admin"); got != http.StatusForbidden {
		t.Errorf("GET /admin with Host y.example.com = %d, want 403", got)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("upstream hits = %d, want 0 — the spoofed Host carried /admin to the denied host", got)
	}
}

// T8: tcp_forwards. protocol raw never yields a path, so proxy_start
// refuses it; protocol http starts and the Pipeline enforces the prefix.
func TestE2E_PathScopeAllow_TCPForwards(t *testing.T) {
	t.Run("raw refused at proxy_start", func(t *testing.T) {
		target, _ := echoUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: pathAllowPolicyConfig})
		res := h.CallTool(t, "proxy_start", map[string]any{
			"listen_addr": "127.0.0.1:0",
			"tcp_forwards": map[string]any{
				strconv.Itoa(pickFreePort(t)): map[string]any{"target": target, "protocol": "raw"},
			},
		})
		if !res.IsError && res.Err == nil {
			t.Fatalf("proxy_start accepted a raw forward under a path-scoped allow: %s", res.Text)
		}
	})

	t.Run("http enforced per request", func(t *testing.T) {
		target, hits := countingHTTPUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: pathAllowPolicyConfig})
		// startForwards fails the test if proxy_start refuses the forward.
		fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "http"})[0]

		c, err := net.DialTimeout("tcp", fwd, 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		br := bufio.NewReader(c)
		if got := forwardGET(t, c, br, target, "/api/x"); got != http.StatusOK || hits.Load() != 1 {
			t.Fatalf("GET /api/x = %d (upstream hits %d), want 200 and 1", got, hits.Load())
		}
		if got := forwardGET(t, c, br, target, "/other"); got != http.StatusForbidden {
			t.Errorf("GET /other = %d, want 403", got)
		}
		if got := hits.Load(); got != 1 {
			t.Errorf("upstream hits after /other = %d, want 1", got)
		}
	})
}
