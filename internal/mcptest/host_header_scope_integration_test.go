//go:build e2e && !e2e_smoke

// USK-1167: TargetScope judges every Host header value, not only the
// authority. The HTTP/1 serializer writes the Host line from the header
// list and never writes msg.Authority, so a request whose Host header
// alone was rewritten — by intercept modify_and_forward, resend_http,
// fuzz_http, a Transform rule, or by the client sending two Host headers —
// reached a denied vhost on an allowed TCP target.
//
// Name legs (authority and Host values) follow "Option B": deny rules
// always apply; an allow layer that admitted the dial target through an
// IP-literal rule does not also require the name to be allow-listed, so
// same-IP different-vhost testing and Host-header injection still work.
package mcptest_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// hostScopePolicyFile allows the loopback upstream and denies one vhost.
const hostScopePolicyFile = `{"allows":[{"hostname":"127.0.0.1"}],"denies":[{"hostname":"denied.example"}]}`

// hostScopePolicyConfig is hostScopePolicyFile as a config document.
const hostScopePolicyConfig = `{"target_scope_policy":` + hostScopePolicyFile + `}`

// rawProxyRequest writes one raw HTTP/1.1 request to the forward proxy and
// returns the response status code and Server header.
func rawProxyRequest(t *testing.T, proxyAddr, request string) (int, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("Server")
}

// byteCountingHTTPUpstream is an upstream that does not parse HTTP: it counts the
// bytes it receives and answers every read with a fixed 200. Unlike a
// net/http server it neither rejects duplicate Host headers before
// counting nor hides that bytes arrived. The plain-forward handler dials
// the upstream before the Pipeline runs, so received bytes — not accepted
// connections — tell whether a request reached it. lastHead returns the
// request head (request line and header lines, verbatim) of the most
// recent request.
func byteCountingHTTPUpstream(t *testing.T) (string, *atomic.Int64, func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var (
		received atomic.Int64
		last     atomic.Pointer[string]
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				br := bufio.NewReader(c)
				var head strings.Builder
				for {
					line, err := br.ReadString('\n')
					received.Add(int64(len(line)))
					head.WriteString(line)
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				s := head.String()
				last.Store(&s)
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	lastHead := func() string {
		if p := last.Load(); p != nil {
			return *p
		}
		return ""
	}
	return ln.Addr().String(), &received, lastHead
}

// TestE2E_HostHeaderScope_InterceptModifyHostOnly:modify_and_forward that
// replaces only the header list with a denied Host is refused 403 and never
// reaches the upstream. A non-denied Host is forwarded (guard).
func TestE2E_HostHeaderScope_InterceptModifyHostOnly(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	h, _, client := startScopeRecheckProxy(t, hostScopePolicyFile)

	modifyHost := func(host string) proxiedResponse {
		t.Helper()
		respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/held-host", upstreamAddr), nil, nil)
		entry := waitForHeldEntry(t, h, 5*time.Second)
		h.MustOK(t, "intercept", map[string]any{
			"action": "modify_and_forward",
			"params": map[string]any{"intercept_id": entry["id"]},
			"http": map[string]any{"headers": []map[string]any{
				{"name": "Host", "value": host},
			}},
		})
		return awaitResponse(t, respCh)
	}

	if resp := modifyHost("vhost.example"); resp.err != nil || resp.statusCode != http.StatusOK {
		t.Fatalf("non-denied Host rewrite: status=%d err=%v, want 200", resp.statusCode, resp.err)
	}
	if got := upstream.hitCount(); got != 1 {
		t.Fatalf("upstream hits after non-denied rewrite = %d, want 1", got)
	}

	assertScopeBlockedResponse(t, modifyHost("denied.example"))
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the Host-only rewrite reached the denied vhost", got)
	}
	assertBlockedFlowRecorded(t, h)
}

// TestE2E_HostHeaderScope_ResendHTTP: resend_http with an allowed
// authority and a denied Host header is rejected before dialing.
func TestE2E_HostHeaderScope_ResendHTTP(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})

	resend := func(host string) mcptest.ToolResult {
		t.Helper()
		return h.CallTool(t, "resend_http", map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": upstreamAddr,
			"path":      "/resend-host",
			"headers":   []map[string]any{{"name": "Host", "value": host}},
		})
	}

	if res := resend("vhost.example"); res.Err != nil || res.IsError {
		t.Fatalf("resend with non-denied Host: err=%v text=%s", res.Err, res.Text)
	}
	if got := upstream.hitCount(); got != 1 {
		t.Fatalf("upstream hits after non-denied resend = %d, want 1", got)
	}

	res := resend("denied.example")
	if res.Err != nil {
		t.Fatalf("resend_http transport error: %v", res.Err)
	}
	if !res.IsError || !strings.Contains(res.Text, "target scope") {
		t.Errorf("resend with denied Host: IsError=%v text=%q, want a target scope rejection", res.IsError, res.Text)
	}
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — resend_http put the denied Host on the wire", got)
	}
}

// TestE2E_HostHeaderScope_FuzzHTTP: fuzz_http judges the Host values of
// each variant after position substitution — a value position and a name
// position that renames a header to Host.
func TestE2E_HostHeaderScope_FuzzHTTP(t *testing.T) {
	tests := []struct {
		name     string
		headers  []map[string]any
		position map[string]any
	}{
		{
			name:     "headers[0].value",
			headers:  []map[string]any{{"name": "Host", "value": "seed.example"}},
			position: map[string]any{"path": "headers[0].value", "payloads": []string{"vhost.example", "denied.example"}},
		},
		{
			name:     "headers[0].name renamed to Host",
			headers:  []map[string]any{{"name": "X-Alt", "value": "denied.example"}},
			position: map[string]any{"path": "headers[0].name", "payloads": []string{"X-Other", "Host"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamAddr, upstream := startObservedUpstream(t)
			h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})

			out := decodeFuzzScopeRecheckResult(t, h.CallTool(t, "fuzz_http", map[string]any{
				"method":     "GET",
				"scheme":     "http",
				"authority":  upstreamAddr,
				"path":       "/fuzz-host",
				"headers":    tt.headers,
				"positions":  []map[string]any{tt.position},
				"timeout_ms": 10000,
			}))

			if got := upstream.hitCount(); got != 1 {
				t.Errorf("upstream hits = %d, want 1 — the denied-Host variant was sent", got)
			}
			if len(out.Variants) != 2 {
				t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
			}
			if v := out.Variants[0]; v.StatusCode != http.StatusOK || v.Error != "" {
				t.Errorf("variants[0] = status %d error %q, want 200 and no error", v.StatusCode, v.Error)
			}
			if v := out.Variants[1]; v.StatusCode != 0 || !strings.Contains(v.Error, "request blocked by target scope") {
				t.Errorf("variants[1] = status %d error %q, want status 0 and a target scope rejection", v.StatusCode, v.Error)
			}
		})
	}
}

// TestE2E_HostHeaderScope_FuzzHTTPDomainAllowPlaceholderHost: under a
// domain allow, a base Host placeholder that a headers[0].value position
// replaces does not abort the run at plan time; the allowed variant is
// sent and the out-of-allow variant is refused per variant, before send.
func TestE2E_HostHeaderScope_FuzzHTTPDomainAllowPlaceholderHost(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	_, port, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"target_scope_policy":{"allows":[{"hostname":"localhost"}]}}`,
	})

	out := decodeFuzzScopeRecheckResult(t, h.CallTool(t, "fuzz_http", map[string]any{
		"method":     "GET",
		"scheme":     "http",
		"authority":  net.JoinHostPort("localhost", port),
		"path":       "/fuzz-host-placeholder",
		"headers":    []map[string]any{{"name": "Host", "value": "placeholder.invalid"}},
		"positions":  []map[string]any{{"path": "headers[0].value", "payloads": []string{"localhost", "other.example"}}},
		"timeout_ms": 10000,
	}))

	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	if v := out.Variants[0]; v.StatusCode != http.StatusOK || v.Error != "" {
		t.Errorf("variants[0] = status %d error %q, want 200 and no error", v.StatusCode, v.Error)
	}
	if v := out.Variants[1]; v.StatusCode != 0 || !strings.Contains(v.Error, "request blocked by target scope") {
		t.Errorf("variants[1] = status %d error %q, want status 0 and a target scope rejection", v.StatusCode, v.Error)
	}
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
}

// TestE2E_HostHeaderScope_DuplicateHostLive: a live plain-forward request
// carrying an allowed Host and a second, denied, `host` header is refused
// and recorded as a blocked audit Stream. A pipeline-blocked request is
// recorded without Flow rows by design (buildPipelineDropRecorder), so the
// read-only guarantee — the scope check never rewrites the header list —
// is asserted on a duplicate-Host request whose values are both allowed:
// it is forwarded, and both the upstream and the recorded raw request see
// both Host lines verbatim (casing and order).
func TestE2E_HostHeaderScope_DuplicateHostLive(t *testing.T) {
	target, received, lastHead := byteCountingHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})
	proxyAddr := startProxyWithPassthrough(t, h)

	dupRequest := func(second, path string) string {
		return "GET http://" + target + path + " HTTP/1.1\r\n" +
			"Host: " + target + "\r\n" +
			"host: " + second + "\r\n" +
			"Connection: close\r\n\r\n"
	}

	code, server := rawProxyRequest(t, proxyAddr, dupRequest("denied.example", "/dup-denied"))
	if code != http.StatusForbidden || server != "yorishiro-proxy" {
		t.Errorf("duplicate Host request = %d (Server %q), want the proxy's 403", code, server)
	}
	if got := received.Load(); got != 0 {
		t.Errorf("upstream received %d bytes, want 0 — the second Host header reached the denied vhost", got)
	}
	waitBlockedHTTPStream(t, h)

	// Guard + wire fidelity: both values allowed (vhost.example is not
	// denied; the IP-literal allow on the dial target exempts it from the
	// allow list).
	code, _ = rawProxyRequest(t, proxyAddr, dupRequest("vhost.example", "/dup-allowed"))
	if code != http.StatusOK {
		t.Fatalf("duplicate allowed Host request = %d, want 200", code)
	}
	wantLines := "Host: " + target + "\r\nhost: vhost.example\r\n"
	if head := lastHead(); !strings.Contains(head, wantLines) {
		t.Errorf("upstream request head %q does not carry both Host lines verbatim (%q)", head, wantLines)
	}
	var id string
	deadline := time.Now().Add(5 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		for _, f := range queryHTTPFlows(t, h, map[string]any{"state": "complete"}) {
			if u, _ := f["url"].(string); strings.Contains(u, "/dup-allowed") {
				id, _ = f["id"].(string)
			}
		}
		if id == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if id == "" {
		t.Fatalf("no complete http Stream for /dup-allowed within 5s")
	}
	detail := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
	rawB64, _ := detail.Decoded["raw_request"].(string)
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatalf("decode raw_request: %v", err)
	}
	if !strings.Contains(string(raw), wantLines) {
		t.Errorf("recorded raw request %q does not contain both Host lines verbatim (%q)", raw, wantLines)
	}
}

// TestE2E_HostHeaderScope_TransformSetHost: a Transform set_header Host rule
// runs after the head-of-pipeline scope check; it must be re-checked.
func TestE2E_HostHeaderScope_TransformSetHost(t *testing.T) {
	tests := []struct {
		host      string
		wantBlock bool
	}{
		{"vhost.example", false},
		{"denied.example", true},
		// USK-1304: a denied comma part is refused too.
		{"ok.example, denied.example", true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			upstreamAddr, upstream := startObservedUpstream(t)
			h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: hostScopePolicyConfig})
			proxyAddr := startProxyWithRules(t, h, nil, []map[string]any{{
				"id":           "set-host",
				"enabled":      true,
				"priority":     1,
				"direction":    "request",
				"path_pattern": ".*",
				"action_type":  "set_header",
				"header_name":  "Host",
				"header_value": tt.host,
			}})
			resp := awaitResponse(t, requestThroughProxy(t, proxyHTTPClient(t, proxyAddr), "GET",
				fmt.Sprintf("http://%s/transform-host", upstreamAddr), nil, nil))
			if !tt.wantBlock {
				if resp.err != nil || resp.statusCode != http.StatusOK {
					t.Fatalf("status=%d err=%v, want 200", resp.statusCode, resp.err)
				}
				if got := upstream.hitCount(); got != 1 {
					t.Errorf("upstream hits = %d, want 1", got)
				}
				return
			}
			assertScopeBlockedResponse(t, resp)
			if got := upstream.hitCount(); got != 0 {
				t.Errorf("upstream hits = %d, want 0 — the transformed Host reached the denied vhost", got)
			}
			assertBlockedFlowRecorded(t, h)
		})
	}
}

// TestE2E_HostHeaderScope_OptionB: with an IP-literal allow on the dial
// target, a Host naming an unlisted (not denied) vhost is forwarded — the
// same-IP different-vhost technique. Before USK-1167 the authority leg
// refused it. A domain allow keeps the full check.
func TestE2E_HostHeaderScope_OptionB(t *testing.T) {
	t.Run("IP-literal allow: unlisted vhost forwarded", func(t *testing.T) {
		target, hits := countingHTTPUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			ConfigJSON: `{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1"}]}}`,
		})
		proxyAddr := startProxyWithPassthrough(t, h)
		code, _ := rawProxyRequest(t, proxyAddr, "GET http://"+target+"/vhost HTTP/1.1\r\nHost: vhost.example\r\nConnection: close\r\n\r\n")
		if code != http.StatusOK || hits.Load() != 1 {
			t.Errorf("unlisted vhost on IP-allowed target = %d (upstream hits %d), want 200 and 1", code, hits.Load())
		}
	})
	t.Run("domain allow: unlisted vhost refused", func(t *testing.T) {
		target, hits := countingHTTPUpstream(t)
		_, port, _ := net.SplitHostPort(target)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{
			ConfigJSON: `{"target_scope_policy":{"allows":[{"hostname":"localhost"}]}}`,
		})
		proxyAddr := startProxyWithPassthrough(t, h)
		code, _ := rawProxyRequest(t, proxyAddr, "GET http://localhost:"+port+"/same HTTP/1.1\r\nHost: localhost:"+port+"\r\nConnection: close\r\n\r\n")
		if code != http.StatusOK || hits.Load() != 1 {
			t.Fatalf("allowed domain = %d (upstream hits %d), want 200 and 1", code, hits.Load())
		}
		code, server := rawProxyRequest(t, proxyAddr, "GET http://localhost:"+port+"/vhost HTTP/1.1\r\nHost: vhost.example\r\nConnection: close\r\n\r\n")
		if code != http.StatusForbidden || server != "yorishiro-proxy" {
			t.Errorf("unlisted vhost on domain-allowed target = %d (Server %q), want the proxy's 403", code, server)
		}
		if got := hits.Load(); got != 1 {
			t.Errorf("upstream hits = %d, want 1", got)
		}
	})
}
