//go:build e2e && !e2e_smoke

// USK-1264 / USK-1304 / USK-1306: name-leg parsing hardening, through the
// real listener and the real MCP tools.
//
//   - USK-1264: a plain-forward Host / absolute-form authority with colons
//     that is not an IPv6 literal ("db.internal:5432:x") is refused 400 and
//     never reaches an upstream proxy; resend_http refuses it before dial.
//   - USK-1304: a comma-bearing Host value ("ok.example, denied.example")
//     is refused when any part names a denied host; a non-denied comma
//     value is forwarded with the header unchanged.
//   - USK-1306: a port-scoped deny on a name matches the dial target's
//     port as well as the port written in the name.
package mcptest_test

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// denyOnlyConfig returns a config document whose policy has only denies.
func denyOnlyConfig(denies string) string {
	return `{"target_scope_policy":{"denies":[` + denies + `]}}`
}

// portDenyConfig denies portd.example on port, with an optional allow.
func portDenyConfig(port int, allows string) string {
	return `{"target_scope_policy":{"allows":[` + allows + `],"denies":[{"hostname":"portd.example","ports":[` + strconv.Itoa(port) + `]}]}}`
}

// TestE2E_HostNameLegParsing_MultiColonHostUpstreamProxy: a multi-colon
// non-IPv6 Host (origin-form) or authority (absolute-form) is refused 400
// by the plain-forward handler and no CONNECT reaches the upstream proxy.
func TestE2E_HostNameLegParsing_MultiColonHostUpstreamProxy(t *testing.T) {
	proxyUpstream, received, _ := byteCountingHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: denyOnlyConfig(`{"hostname":"db.internal"}`)})
	res := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":    "127.0.0.1:0",
		"upstream_proxy": "http://" + proxyUpstream,
	})
	proxyAddr, _ := res.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", res.Text)
	}

	for _, req := range []string{
		"GET / HTTP/1.1\r\nHost: db.internal:5432:x\r\nConnection: close\r\n\r\n",
		"GET http://db.internal:5432:80/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: [db.internal:5432]:80\r\nConnection: close\r\n\r\n",
	} {
		code, server := rawProxyRequest(t, proxyAddr, req)
		if code != http.StatusBadRequest || server != "yorishiro-proxy" {
			t.Errorf("request %q = %d (Server %q), want the proxy's 400", req, code, server)
		}
	}
	if got := received.Load(); got != 0 {
		t.Errorf("upstream proxy received %d bytes, want 0 — the multi-colon target was tunnelled", got)
	}
}

// TestE2E_HostNameLegParsing_CommaHostLive: a live plain-forward request
// whose Host value has a denied comma part is refused 403 with no byte
// upstream, under a deny-only policy and on an IP-literal-allowed
// connection. A non-denied comma value is forwarded and the upstream sees
// the Host line byte-identical.
func TestE2E_HostNameLegParsing_CommaHostLive(t *testing.T) {
	for name, cfg := range map[string]string{
		"deny-only":  denyOnlyConfig(`{"hostname":"denied.example"}`),
		"IP-allowed": hostScopePolicyConfig,
	} {
		t.Run(name, func(t *testing.T) {
			target, received, lastHead := byteCountingHTTPUpstream(t)
			h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: cfg})
			proxyAddr := startProxyWithPassthrough(t, h)

			code, server := rawProxyRequest(t, proxyAddr, "GET http://"+target+"/comma HTTP/1.1\r\nHost: ok.example, denied.example\r\nConnection: close\r\n\r\n")
			if code != http.StatusForbidden || server != "yorishiro-proxy" {
				t.Errorf("comma Host with a denied part = %d (Server %q), want the proxy's 403", code, server)
			}
			if got := received.Load(); got != 0 {
				t.Errorf("upstream received %d bytes, want 0 — the denied comma part reached the upstream", got)
			}
			waitBlockedHTTPStream(t, h)

			code, _ = rawProxyRequest(t, proxyAddr, "GET http://"+target+"/comma-ok HTTP/1.1\r\nHost: a.example, b.example\r\nConnection: close\r\n\r\n")
			if code != http.StatusOK {
				t.Fatalf("non-denied comma Host = %d, want 200", code)
			}
			if head := lastHead(); !strings.Contains(head, "\r\nHost: a.example, b.example\r\n") {
				t.Errorf("upstream request head %q does not carry the comma Host line verbatim", head)
			}
		})
	}
}

// TestE2E_HostNameLegParsing_DialPortDenyLive: deny {portd.example,
// ports:[P]}; an absolute-form request to 127.0.0.1:P naming
// "portd.example:1" in Host is refused — the dial port P matches.
func TestE2E_HostNameLegParsing_DialPortDenyLive(t *testing.T) {
	target, received, _ := byteCountingHTTPUpstream(t)
	_, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: portDenyConfig(port, `{"hostname":"127.0.0.1"}`)})
	proxyAddr := startProxyWithPassthrough(t, h)

	code, server := rawProxyRequest(t, proxyAddr, "GET http://"+target+"/portd HTTP/1.1\r\nHost: portd.example:1\r\nConnection: close\r\n\r\n")
	if code != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("Host portd.example:1 on dial port %d = %d (Server %q), want the proxy's 403", port, code, server)
	}
	if got := received.Load(); got != 0 {
		t.Errorf("upstream received %d bytes, want 0", got)
	}

	// Guard: another name on the same connection is forwarded.
	code, _ = rawProxyRequest(t, proxyAddr, "GET http://"+target+"/other HTTP/1.1\r\nHost: other.example:1\r\nConnection: close\r\n\r\n")
	if code != http.StatusOK {
		t.Errorf("Host other.example:1 = %d, want 200", code)
	}
}

// assertToolScopeRefused requires a tool-level target scope rejection.
func assertToolScopeRefused(t *testing.T, res mcptest.ToolResult, what string) {
	t.Helper()
	if res.Err != nil {
		t.Fatalf("%s: transport error: %v", what, res.Err)
	}
	if !res.IsError || !strings.Contains(res.Text, "target scope") {
		t.Errorf("%s: IsError=%v text=%q, want a target scope rejection", what, res.IsError, res.Text)
	}
}

// TestE2E_HostNameLegParsing_ResendFuzzCommaHost: resend_http and
// fuzz_http refuse a Host value whose comma part is denied, on an
// IP-literal-allowed dial address.
func TestE2E_HostNameLegParsing_ResendFuzzCommaHost(t *testing.T) {
	target, received, _ := byteCountingHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})

	assertToolScopeRefused(t, h.CallTool(t, "resend_http", map[string]any{
		"method": "GET", "scheme": "http", "authority": target, "path": "/resend-comma",
		"headers": []map[string]any{{"name": "Host", "value": "ok.example, denied.example"}},
	}), "resend_http comma Host")
	if got := received.Load(); got != 0 {
		t.Fatalf("upstream received %d bytes after resend_http, want 0", got)
	}

	out := decodeFuzzScopeRecheckResult(t, h.CallTool(t, "fuzz_http", map[string]any{
		"method": "GET", "scheme": "http", "authority": target, "path": "/fuzz-comma",
		"headers":    []map[string]any{{"name": "Host", "value": "seed.example"}},
		"positions":  []map[string]any{{"path": "headers[0].value", "payloads": []string{"vhost.example", "ok.example, denied.example"}}},
		"timeout_ms": 10000,
	}))
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	if v := out.Variants[0]; v.StatusCode != http.StatusOK || v.Error != "" {
		t.Errorf("variants[0] = status %d error %q, want 200", v.StatusCode, v.Error)
	}
	if v := out.Variants[1]; v.StatusCode != 0 || !strings.Contains(v.Error, "request blocked by target scope") {
		t.Errorf("variants[1] = status %d error %q, want a target scope rejection", v.StatusCode, v.Error)
	}
}

// TestE2E_HostNameLegParsing_ResendFuzzDialPortDeny: resend_http and
// fuzz_http refuse Host "portd.example:1" when the dial port is the
// denied one; h2c resend with override_host refuses the same name, and a
// denied comma part, in :authority.
func TestE2E_HostNameLegParsing_ResendFuzzDialPortDeny(t *testing.T) {
	target, received, _ := byteCountingHTTPUpstream(t)
	_, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"target_scope_policy":{"denies":[{"hostname":"portd.example","ports":[` + portStr + `]},{"hostname":"denied.example"}]}}`,
	})

	assertToolScopeRefused(t, h.CallTool(t, "resend_http", map[string]any{
		"method": "GET", "scheme": "http", "authority": target, "path": "/resend-portd",
		"headers": []map[string]any{{"name": "Host", "value": "portd.example:1"}},
	}), "resend_http Host portd.example:1")

	out := decodeFuzzScopeRecheckResult(t, h.CallTool(t, "fuzz_http", map[string]any{
		"method": "GET", "scheme": "http", "authority": target, "path": "/fuzz-portd",
		"headers":    []map[string]any{{"name": "Host", "value": "seed.example"}},
		"positions":  []map[string]any{{"path": "headers[0].value", "payloads": []string{"other.example:1", "portd.example:1"}}},
		"timeout_ms": 10000,
	}))
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	if v := out.Variants[1]; v.StatusCode != 0 || !strings.Contains(v.Error, "request blocked by target scope") {
		t.Errorf("variants[1] = status %d error %q, want a target scope rejection", v.StatusCode, v.Error)
	}
	afterFuzz := received.Load()
	if afterFuzz == 0 {
		t.Fatalf("variants[0] did not reach the upstream (guard)")
	}

	for _, authority := range []string{"portd.example:1", "ok.example, denied.example"} {
		assertToolScopeRefused(t, h.CallTool(t, "resend_http", map[string]any{
			"method": "GET", "scheme": "http", "authority": authority, "path": "/h2c",
			"http_version": "h2c", "override_host": target,
		}), fmt.Sprintf("h2c resend :authority %q on dial port %d", authority, port))
	}
	if got := received.Load(); got != afterFuzz {
		t.Errorf("upstream received %d more bytes after the h2c resends, want 0", got-afterFuzz)
	}
}

// TestE2E_HostNameLegParsing_ResendMultiColonAuthority: resend_http with
// authority "db.internal:5432:80" errors before dial, even in open mode
// (no scope rule to refuse it); with an upstream
// proxy override, no CONNECT reaches it.
func TestE2E_HostNameLegParsing_ResendMultiColonAuthority(t *testing.T) {
	proxyUpstream, received, _ := byteCountingHTTPUpstream(t)
	// Open mode: no scope check runs, so the resolver itself must refuse.
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	res := h.CallTool(t, "resend_http", map[string]any{
		"method": "GET", "scheme": "http", "authority": "db.internal:5432:80", "path": "/",
		"upstream_proxy": map[string]any{"url_template": "http://" + proxyUpstream},
	})
	if res.Err != nil {
		t.Fatalf("resend_http transport error: %v", res.Err)
	}
	if !res.IsError {
		t.Errorf("resend_http with a multi-colon authority succeeded: %s", res.Text)
	}
	if got := received.Load(); got != 0 {
		t.Errorf("upstream proxy received %d bytes, want 0 — the multi-colon authority was dialled", got)
	}
}
