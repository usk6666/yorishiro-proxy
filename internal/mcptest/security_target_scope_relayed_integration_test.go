//go:build e2e && !e2e_smoke

// USK-879: regression coverage for "security set_target_scope is ignored
// for proxy-relayed traffic". Pre-USK-879, when no target_scope_policy was
// configured at boot (the common case for an AI-agent / dev user), the
// MCP control plane and the live data path held *separate* TargetScope
// pointers — InitTargetScope returned nil for nil-policy boot, then
// mcp.NewServer.finalizeDefaults synthesised a fresh per-MCP empty scope.
// `security set_target_scope` mutations therefore reached the MCP-only
// instance (so test_target / resend_* / fuzz_* enforced the rules) while
// every connector handler gate (CONNECT, plain-HTTP forward, SOCKS5) and
// every pipeline scope step continued to hold nil, letting traffic flow
// freely to denied hosts.
//
// The fix in internal/mcpserver/init.go guarantees InitTargetScope always
// returns a non-nil instance so the same pointer threads through both
// surfaces. This test boots the production server with NO policy file
// (mirroring the Issue's repro environment), calls `security
// set_target_scope` over the MCP wire, then drives proxy-relayed traffic
// through CONNECT and plain-HTTP forward paths and asserts the upstream
// never receives the request.
package mcptest_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_USK879_AgentScope_BlocksCONNECTRelayedTraffic exercises the
// HTTPS-via-CONNECT path. Spec wire shape (help_security.md): the proxy
// sends "HTTP/1.1 200 Connection Established" (the tunnel acknowledgement
// is sent before the scope check) and then closes the tunnel; no upstream
// dial occurs.
func TestE2E_USK879_AgentScope_BlocksCONNECTRelayedTraffic(t *testing.T) {
	// Sinkhole upstream: records every TCP connect attempt. The proxy must
	// NOT reach this listener once the scope rejects the target.
	sinkAddr, sinkHits := startSinkholeUpstream(t)
	denyHost, denyPort, err := net.SplitHostPort(sinkAddr)
	if err != nil {
		t.Fatalf("split sinkhole addr: %v", err)
	}

	// Boot with no policy file — InitTargetScope returns a fresh empty
	// scope post-fix. Pre-fix this would have been nil.
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	// Agent-layer scope: allow only an unrelated host. The sinkhole's
	// hostname is therefore implicitly denied via "not in agent allow
	// list".
	h.MustOK(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{
			"allows": []map[string]any{
				{"hostname": "allowed.example.invalid"},
			},
		},
	})

	// Sanity: test_target via MCP returns allowed:false. If this fails
	// the bug is in the MCP-side enforcement and the assertion below
	// would not isolate the real regression.
	testRes := h.MustOK(t, "security", map[string]any{
		"action": "test_target",
		"params": map[string]any{
			"url": "https://" + sinkAddr + "/",
		},
	})
	if allowed, _ := testRes.Decoded["allowed"].(bool); allowed {
		t.Fatalf("test_target unexpectedly returned allowed=true: %s", testRes.Text)
	}

	// Issue an HTTPS request through the proxy via CONNECT. The client
	// uses InsecureSkipVerify because it doesn't have the proxy's MITM CA
	// — but the scope deny means the inner TLS handshake should EOF
	// before any cert is presented.
	rawConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := fmt.Fprintf(rawConn,
		"CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n",
		denyHost, denyPort, denyHost, denyPort,
	); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(rawConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200") {
		t.Errorf("CONNECT response status = %q, want 200 prefix per help_security.md spec", strings.TrimSpace(statusLine))
	}
	// Consume the rest of the response headers up to "\r\n\r\n".
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT response headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Attempt an inner TLS handshake over the tunnel. Per spec the
	// handshake must fail with EOF because the proxy closed the
	// connection after the 200.
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         denyHost,
		InsecureSkipVerify: true, //nolint:gosec — we're asserting the deny mechanism, not cert validity
	})
	hsErr := tlsConn.Handshake()
	if hsErr == nil {
		t.Error("inner TLS handshake completed; want EOF after 200 per help_security.md deny manifestation")
		_ = tlsConn.Close()
	}

	// Durable assertion: the sinkhole upstream MUST NOT have observed any
	// connect attempt. If hits > 0 the scope gate was bypassed.
	if got := sinkHits.Load(); got != 0 {
		t.Errorf("sinkhole upstream observed %d connect attempt(s); want 0 — scope deny was bypassed", got)
	}
}

// TestE2E_USK879_AgentScope_BlocksPlainHTTPForwardRelayedTraffic exercises
// the plain-HTTP forward proxy path. Spec wire shape: the proxy returns
// "HTTP/1.1 403 Forbidden" with body "yorishiro-proxy: target blocked by
// scope" (help_security.md deny manifestation).
func TestE2E_USK879_AgentScope_BlocksPlainHTTPForwardRelayedTraffic(t *testing.T) {
	sinkAddr, sinkHits := startSinkholeUpstream(t)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	// Allow an unrelated host; sinkhole is denied via "not in agent allow list".
	h.MustOK(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{
			"allows": []map[string]any{
				{"hostname": "allowed.example.invalid"},
			},
		},
	})

	client := proxyHTTPClient(t, proxyAddr)

	resp, err := client.Get("http://" + sinkAddr + "/some/path")
	if err != nil {
		t.Fatalf("plain HTTP forward request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("plain HTTP forward status = %d, want %d per help_security.md spec",
			resp.StatusCode, gohttp.StatusForbidden)
	}

	body, _ := io.ReadAll(resp.Body)
	wantBody := "yorishiro-proxy: target blocked by scope"
	if !strings.Contains(string(body), wantBody) {
		t.Errorf("plain HTTP forward body = %q, want substring %q", string(body), wantBody)
	}

	// Durable assertion: sinkhole upstream must NOT have been dialled.
	if got := sinkHits.Load(); got != 0 {
		t.Errorf("sinkhole upstream observed %d connect attempt(s); want 0 — scope deny was bypassed", got)
	}
}

// TestE2E_USK879_AgentScope_AllowsPermittedHost is the positive control:
// when set_target_scope explicitly allows a host, traffic to that host
// passes (proving the scope evaluator works after the agent-rules path,
// not just that the gate blocks unconditionally).
func TestE2E_USK879_AgentScope_AllowsPermittedHost(t *testing.T) {
	upstreamAddr, upstreamObs := startObservedUpstream(t)
	host, _, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	// Allow the upstream host explicitly.
	h.MustOK(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{
			"allows": []map[string]any{
				{"hostname": host},
			},
		},
	})

	client := proxyHTTPClient(t, proxyAddr)
	resp, err := client.Get("http://" + upstreamAddr + "/")
	if err != nil {
		t.Fatalf("allowed-host GET: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("allowed-host status = %d, want 200", resp.StatusCode)
	}
	if upstreamObs.hitCount() != 1 {
		t.Errorf("upstream hits = %d, want 1 — allowed traffic did not reach upstream",
			upstreamObs.hitCount())
	}
}

// startSinkholeUpstream returns the address of a TCP listener that
// accepts connections and immediately closes them, while incrementing
// a hit counter. The proxy must NOT reach this listener when scope
// denies the target. Returns (addr, hitCounter).
func startSinkholeUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sinkhole: %v", err)
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
