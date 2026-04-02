//go:build e2e

package proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// scopeBypassTestEnv holds components for target scope bypass resistance tests.
type scopeBypassTestEnv struct {
	listener *proxy.Listener
	store    flow.Store
	handler  *protohttp.Handler
	cancel   context.CancelFunc
}

// setupScopeBypassEnv creates a proxy with the given target scope for bypass testing.
func setupScopeBypassEnv(t *testing.T, ts *proxy.TargetScope) *scopeBypassTestEnv {
	t.Helper()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "scope-bypass.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	httpHandler := protohttp.NewHandler(store, issuer, logger)
	httpHandler.SetTargetScope(ts)
	detector := protocol.NewDetector(httpHandler)

	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			// Expected on shutdown.
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	t.Cleanup(func() {
		proxyCancel()
	})

	return &scopeBypassTestEnv{
		listener: listener,
		store:    store,
		handler:  httpHandler,
		cancel:   proxyCancel,
	}
}

// blockedResponse represents the JSON response body from a blocked request.
type blockedResponse struct {
	Error  string `json:"error"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// sendHTTPViaProxy sends a raw HTTP request through the proxy and returns the response.
func sendHTTPViaProxy(t *testing.T, proxyAddr, rawRequest string) (*gohttp.Response, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	return resp, body
}

// sendCONNECTViaProxy sends a CONNECT request through the proxy and returns the response.
func sendCONNECTViaProxy(t *testing.T, proxyAddr, connectHost string) (*gohttp.Response, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectHost, connectHost)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	return resp, body
}

// assertBlocked verifies the response is a 403 with the expected block reason.
func assertBlocked(t *testing.T, resp *gohttp.Response, body []byte, wantReason string) {
	t.Helper()
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d; body = %s", resp.StatusCode, gohttp.StatusForbidden, body)
		return
	}
	var br blockedResponse
	if err := json.Unmarshal(body, &br); err != nil {
		t.Fatalf("parse blocked response: %v; raw = %s", err, body)
	}
	if br.Error != "blocked by target scope" {
		t.Errorf("error = %q, want %q", br.Error, "blocked by target scope")
	}
	if br.Reason != wantReason {
		t.Errorf("reason = %q, want %q", br.Reason, wantReason)
	}
}

// assertAllowed verifies the response is a 200 OK.
func assertAllowed(t *testing.T, resp *gohttp.Response, body []byte) {
	t.Helper()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", resp.StatusCode, gohttp.StatusOK, body)
	}
}

// assertFlowBlocked verifies that a blocked flow was recorded in the store.
func assertFlowBlocked(t *testing.T, ctx context.Context, store flow.Store, wantBlockedBy string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	flows, err := store.ListFlows(ctx, flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	found := false
	for _, f := range flows {
		if f.BlockedBy == wantBlockedBy {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no flow found with BlockedBy=%q among %d flows", wantBlockedBy, len(flows))
	}
}

// --- IP Address Bypass Resistance ---

func TestBypass_IPAddressDirect_HostnameDenyRule(t *testing.T) {
	// Scenario: Hostname-based deny rule (evil.com) should NOT prevent access
	// to an IP address (127.0.0.1) because they are different identifiers.
	// This verifies the proxy does NOT over-block but correctly scopes by hostname.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ip-ok")
	}))
	defer upstream.Close()

	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "evil.com"},
	})

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// Request via IP address should pass (deny is for evil.com hostname only).
	req := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertAllowed(t, resp, body)
	if string(body) != "ip-ok" {
		t.Errorf("body = %q, want %q", body, "ip-ok")
	}
}

func TestBypass_IPAddressDirect_HostnameAllowRule(t *testing.T) {
	// Scenario: Hostname-based allow rule only allows "target.example.com".
	// Accessing the upstream via raw IP address should be BLOCKED because
	// 127.0.0.1 is not in the allow list.
	// This is the critical IP bypass vector: attacker resolves hostname to IP
	// and tries to access via IP directly.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	}))
	defer upstream.Close()

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "target.example.com"},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// Request via IP address should be blocked (not in allow list).
	req := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertBlocked(t, resp, body, "not in agent allow list")

	// Verify blocked flow is recorded.
	assertFlowBlocked(t, context.Background(), env.store, "target_scope")
}

func TestBypass_IPAddressDirect_CONNECTTunnel(t *testing.T) {
	// Scenario: Allow rule for "target.example.com" only. Attacker tries
	// CONNECT to 127.0.0.1:443 directly. Should be blocked.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "target.example.com"},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	resp, body := sendCONNECTViaProxy(t, proxyAddr, "127.0.0.1:443")
	assertBlocked(t, resp, body, "not in agent allow list")
}

// --- HTTPS CONNECT Tunnel Bypass Resistance ---

func TestBypass_CONNECT_BlockedHost(t *testing.T) {
	// Scenario: CONNECT to an explicitly denied host must be rejected.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "blocked.internal"},
	})

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	resp, body := sendCONNECTViaProxy(t, proxyAddr, "blocked.internal:443")
	assertBlocked(t, resp, body, "blocked by agent deny rule")

	// Verify blocked CONNECT is recorded.
	assertFlowBlocked(t, context.Background(), env.store, "target_scope")
}

func TestBypass_CONNECT_NotInAllowList(t *testing.T) {
	// Scenario: Only target.com:443 is allowed. CONNECT to other.com:443
	// should be blocked even though the port matches.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "target.com", Ports: []int{443}},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	resp, body := sendCONNECTViaProxy(t, proxyAddr, "other.com:443")
	assertBlocked(t, resp, body, "not in agent allow list")
}

// --- Port-Based Scope Bypass Resistance ---

func TestBypass_PortRestriction_DifferentPort(t *testing.T) {
	// Scenario: allow target.com:443 -> target.com:8443 should be blocked.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "127.0.0.1", Ports: []int{9999}}, // different from upstream port
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// Request to actual upstream port should be blocked.
	req := fmt.Sprintf("GET http://127.0.0.1:%s/test HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n",
		upstreamPort, upstreamPort)
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertBlocked(t, resp, body, "not in agent allow list")
}

func TestBypass_PortRestriction_CONNECT_DifferentPort(t *testing.T) {
	// Scenario: allow example.com:443 -> CONNECT example.com:8443 should be blocked.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com", Ports: []int{443}},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	resp, body := sendCONNECTViaProxy(t, proxyAddr, "example.com:8443")
	assertBlocked(t, resp, body, "not in agent allow list")
}

func TestBypass_PortRestriction_NoPortInRule_AllPortsAllowed(t *testing.T) {
	// Scenario: allow example.com (no port restriction) should allow all ports.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "any-port-ok")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "127.0.0.1"}, // no port restriction
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// Request to any port should be allowed.
	req := fmt.Sprintf("GET http://127.0.0.1:%s/test HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n",
		upstreamPort, upstreamPort)
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertAllowed(t, resp, body)
	if string(body) != "any-port-ok" {
		t.Errorf("body = %q, want %q", body, "any-port-ok")
	}
}

// --- Wildcard Pattern Bypass Resistance ---

func TestBypass_Wildcard_SubdomainMatch(t *testing.T) {
	// Scenario: *.example.com should match sub.example.com.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "wildcard-ok")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "*.example.com"},
		{Hostname: "127.0.0.1"}, // allow upstream for actual connection
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// sub.example.com should match wildcard.
	// We use the upstream IP for the actual connection, with Host header of sub.example.com.
	// However, the scope check is against the URL hostname, so we need to
	// verify the matching logic at the TargetScope level.
	allowed, _ := ts.CheckTarget("http", "sub.example.com", 80, "/")
	if !allowed {
		t.Error("sub.example.com should match *.example.com allow rule")
	}

	// Verify actual proxy request to upstream IP with allow rule is allowed.
	req := fmt.Sprintf("GET http://127.0.0.1:%s/test HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n",
		upstreamPort, upstreamPort)
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertAllowed(t, resp, body)
}

func TestBypass_Wildcard_BareDomainNoMatch(t *testing.T) {
	// Scenario: *.example.com should NOT match example.com (bare domain).
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "*.example.com"},
	}, nil)

	// Bare domain check.
	allowed, reason := ts.CheckTarget("http", "example.com", 80, "/")
	if allowed {
		t.Error("example.com should NOT match *.example.com (bare domain)")
	}
	if reason != "not in agent allow list" {
		t.Errorf("reason = %q, want %q", reason, "not in agent allow list")
	}

	// Verify via proxy: CONNECT to example.com should be blocked.
	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	resp, body := sendCONNECTViaProxy(t, proxyAddr, "example.com:443")
	assertBlocked(t, resp, body, "not in agent allow list")
}

func TestBypass_Wildcard_NestedSubdomainMatch(t *testing.T) {
	// Scenario: *.example.com should match a.b.example.com (nested subdomain).
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "*.example.com"},
	}, nil)

	tests := []struct {
		name    string
		host    string
		allowed bool
	}{
		{"single subdomain", "sub.example.com", true},
		{"nested subdomain", "a.b.example.com", true},
		{"deeply nested", "x.y.z.example.com", true},
		{"bare domain", "example.com", false},
		{"unrelated domain", "example.org", false},
		{"suffix attack", "notexample.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ts.CheckTarget("http", tt.host, 80, "/")
			if allowed != tt.allowed {
				t.Errorf("CheckTarget(%q) allowed = %v, want %v (reason: %s)",
					tt.host, allowed, tt.allowed, reason)
			}
		})
	}
}

// --- Host Header Manipulation (SSRF Pattern) ---

func TestBypass_HostHeaderSSRF_ForwardProxy(t *testing.T) {
	// Scenario: Attacker connects to allowed upstream via IP but sets Host
	// header to a different (denied) hostname. The scope check should be
	// based on the URL host (where the connection actually goes), not the
	// Host header.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ssrf-test-ok")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "127.0.0.1"},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// Send request to allowed IP, but with Host header pointing to different host.
	// Since the URL hostname (127.0.0.1) is in the allow list, this should
	// pass through. The proxy checks the URL target, not the Host header.
	req := fmt.Sprintf("GET http://127.0.0.1:%s/test HTTP/1.1\r\nHost: evil.internal\r\nConnection: close\r\n\r\n",
		upstreamPort)
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertAllowed(t, resp, body)
	if string(body) != "ssrf-test-ok" {
		t.Errorf("body = %q, want %q", body, "ssrf-test-ok")
	}
}

func TestBypass_HostHeaderSSRF_DeniedURL(t *testing.T) {
	// Scenario: Attacker sets URL to denied host but Host header to allowed host.
	// The scope check MUST use the URL, so the request should be blocked.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	}))
	defer upstream.Close()

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "allowed.example.com"},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// URL points to upstream IP (not allowed), Host header says allowed.example.com.
	// Scope check must use the URL hostname, so this should be blocked.
	req := fmt.Sprintf("GET %s/steal HTTP/1.1\r\nHost: allowed.example.com\r\nConnection: close\r\n\r\n",
		upstream.URL)
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertBlocked(t, resp, body, "not in agent allow list")
}

// --- Policy Layer Immutability Bypass Resistance ---

func TestBypass_PolicyDeny_CannotOverrideViaAgent(t *testing.T) {
	// Scenario: Policy denies internal.corp. Agent tries to add it to allow list.
	// Policy deny must take priority regardless of agent rules.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ts := proxy.NewTargetScope()
	// Policy: deny internal.corp (immutable)
	ts.SetPolicyRules(nil, []proxy.TargetRule{
		{Hostname: "internal.corp"},
	})
	// Agent: try to allow internal.corp
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "internal.corp"},
		{Hostname: "127.0.0.1"},
	}, nil)

	// Verify CheckTarget blocks despite agent allow.
	allowed, reason := ts.CheckTarget("http", "internal.corp", 80, "/")
	if allowed {
		t.Fatal("internal.corp should be blocked by policy deny despite agent allow")
	}
	if reason != "blocked by policy deny rule" {
		t.Errorf("reason = %q, want %q", reason, "blocked by policy deny rule")
	}

	// Verify via CONNECT.
	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	resp, body := sendCONNECTViaProxy(t, proxyAddr, "internal.corp:443")
	assertBlocked(t, resp, body, "blocked by policy deny rule")

	_ = upstreamPort
}

func TestBypass_PolicyAllow_AgentCannotExpandBeyond(t *testing.T) {
	// Scenario: Policy allows only *.target.com. Agent tries to set allow
	// for *.other.com which is outside policy boundary. Should be rejected.
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules([]proxy.TargetRule{
		{Hostname: "*.target.com"},
	}, nil)

	err := ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "*.other.com"},
	}, nil)
	if err == nil {
		t.Fatal("expected error when agent tries to expand beyond policy allow boundary")
	}

	// Agent within boundary should succeed.
	err = ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "api.target.com"},
	}, nil)
	if err != nil {
		t.Fatalf("agent within policy boundary should succeed: %v", err)
	}
}

// --- Edge Cases ---

func TestBypass_CaseInsensitiveHostname(t *testing.T) {
	// Scenario: Deny "EVIL.COM" but request uses "evil.com". Should still block.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "EVIL.COM"},
	})

	tests := []struct {
		name     string
		hostname string
		blocked  bool
	}{
		{"lowercase", "evil.com", true},
		{"uppercase", "EVIL.COM", true},
		{"mixed case", "Evil.Com", true},
		{"different host", "good.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ts.CheckTarget("http", tt.hostname, 80, "/")
			if tt.blocked && allowed {
				t.Errorf("%q should be blocked", tt.hostname)
			}
			if !tt.blocked && !allowed {
				t.Errorf("%q should be allowed, got: %s", tt.hostname, reason)
			}
		})
	}
}

func TestBypass_EmptyHostname(t *testing.T) {
	// Scenario: Request with empty hostname should be blocked by allow list.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "target.com"},
	}, nil)

	allowed, _ := ts.CheckTarget("http", "", 80, "/")
	if allowed {
		t.Error("empty hostname should be blocked when allow list is configured")
	}
}

func TestBypass_SchemeRestriction(t *testing.T) {
	// Scenario: Allow rule restricted to HTTPS scheme only. HTTP request
	// to the same host should be blocked.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "target.com", Schemes: []string{"https"}},
	}, nil)

	tests := []struct {
		name    string
		scheme  string
		allowed bool
	}{
		{"https allowed", "https", true},
		{"http blocked", "http", false},
		{"empty scheme blocked", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ts.CheckTarget(tt.scheme, "target.com", 443, "/")
			if allowed != tt.allowed {
				t.Errorf("scheme %q: allowed = %v, want %v (reason: %s)",
					tt.scheme, allowed, tt.allowed, reason)
			}
		})
	}
}

func TestBypass_MultipleBypassVectorsSimultaneous(t *testing.T) {
	// Scenario: Comprehensive test combining multiple bypass vectors.
	// Policy: allow *.target.com, deny internal.corp.
	// Agent: further restrict to api.target.com and web.target.com.
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		[]proxy.TargetRule{{Hostname: "internal.corp"}},
	)
	ts.SetAgentRules(
		[]proxy.TargetRule{
			{Hostname: "api.target.com"},
			{Hostname: "web.target.com"},
		},
		nil,
	)

	tests := []struct {
		name       string
		hostname   string
		port       int
		wantAllow  bool
		wantReason string
	}{
		{
			name:      "allowed by agent (api)",
			hostname:  "api.target.com",
			port:      443,
			wantAllow: true,
		},
		{
			name:      "allowed by agent (web)",
			hostname:  "web.target.com",
			port:      443,
			wantAllow: true,
		},
		{
			name:       "in policy but not agent allow",
			hostname:   "other.target.com",
			port:       443,
			wantAllow:  false,
			wantReason: "not in agent allow list",
		},
		{
			name:       "outside policy entirely",
			hostname:   "evil.com",
			port:       443,
			wantAllow:  false,
			wantReason: "not in policy allow list",
		},
		{
			name:       "policy denied host",
			hostname:   "internal.corp",
			port:       443,
			wantAllow:  false,
			wantReason: "blocked by policy deny rule",
		},
		{
			name:       "IP bypass attempt",
			hostname:   "10.0.0.1",
			port:       443,
			wantAllow:  false,
			wantReason: "not in policy allow list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := ts.CheckTarget("https", tt.hostname, tt.port, "/")
			if allowed != tt.wantAllow {
				t.Errorf("allowed = %v, want %v", allowed, tt.wantAllow)
			}
			if !tt.wantAllow && reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestBypass_CONNECT_FlowRecordingOnBlock(t *testing.T) {
	// Verify that all blocked CONNECT attempts are properly recorded in the
	// flow store with the correct protocol and BlockedBy fields.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	ctx := context.Background()
	proxyAddr := env.listener.Addr()

	// Send multiple blocked CONNECT requests.
	targets := []string{
		"blocked1.com:443",
		"blocked2.com:443",
		"127.0.0.1:443",
	}

	for _, target := range targets {
		resp, body := sendCONNECTViaProxy(t, proxyAddr, target)
		assertBlocked(t, resp, body, "not in agent allow list")
	}

	// Wait for flow recording.
	time.Sleep(500 * time.Millisecond)

	flows, err := env.store.ListFlows(ctx, flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}

	if len(flows) < len(targets) {
		t.Fatalf("expected at least %d blocked flows, got %d", len(targets), len(flows))
	}

	for _, f := range flows {
		if f.BlockedBy != "target_scope" {
			t.Errorf("flow %s: BlockedBy = %q, want %q", f.ID, f.BlockedBy, "target_scope")
		}
	}
}

func TestBypass_PathPrefix_ScopeEnforcement(t *testing.T) {
	// Scenario: Allow rule with path prefix /api/. Request to /admin/ should
	// be blocked even though the hostname matches.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "path-ok")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "127.0.0.1", PathPrefix: "/api/"},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"allowed path", "/api/data", gohttp.StatusOK},
		{"blocked path", "/admin/secret", gohttp.StatusForbidden},
		{"root path", "/", gohttp.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := fmt.Sprintf("GET http://127.0.0.1:%s%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n",
				upstreamPort, tt.path, upstreamPort)
			resp, _ := sendHTTPViaProxy(t, proxyAddr, req)
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestBypass_WildcardDenyWithSubdomain(t *testing.T) {
	// Scenario: Wildcard deny *.internal.corp should block all subdomains
	// but not unrelated hosts.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(nil, []proxy.TargetRule{
		{Hostname: "*.internal.corp"},
	})

	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		{"subdomain blocked", "api.internal.corp", true},
		{"nested sub blocked", "a.b.internal.corp", true},
		{"bare domain not blocked", "internal.corp", false},
		{"unrelated allowed", "external.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := ts.CheckTarget("http", tt.host, 80, "/")
			if tt.blocked && allowed {
				t.Errorf("%q should be blocked by wildcard deny", tt.host)
			}
			if !tt.blocked && !allowed {
				t.Errorf("%q should be allowed", tt.host)
			}
		})
	}
}

func TestBypass_AgentDenyOverridesAgentAllow(t *testing.T) {
	// Scenario: Agent allows *.target.com but also denies secret.target.com.
	// The deny should take priority.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		[]proxy.TargetRule{{Hostname: "secret.target.com"}},
	)

	allowed, reason := ts.CheckTarget("https", "secret.target.com", 443, "/")
	if allowed {
		t.Error("secret.target.com should be blocked by agent deny despite agent allow")
	}
	if reason != "blocked by agent deny rule" {
		t.Errorf("reason = %q, want %q", reason, "blocked by agent deny rule")
	}

	// Non-denied subdomain should still be allowed.
	allowed, _ = ts.CheckTarget("https", "api.target.com", 443, "/")
	if !allowed {
		t.Error("api.target.com should be allowed")
	}
}

func TestBypass_ProxyURL_vs_HostHeader_Mismatch(t *testing.T) {
	// Scenario: In HTTP forward proxy mode, the URL determines the target.
	// If URL has http://allowed-host/path but Host header says denied-host,
	// the proxy should use the URL for scope checking, not the Host header.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "mismatch-ok")
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Host

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "127.0.0.1"},
	}, nil)

	env := setupScopeBypassEnv(t, ts)
	proxyAddr := env.listener.Addr()

	// URL points to 127.0.0.1 (allowed), Host header says denied-host.
	// Scope check is on URL, so request should pass.
	req := fmt.Sprintf("GET http://%s/test HTTP/1.1\r\nHost: denied-host.example.com\r\nConnection: close\r\n\r\n",
		upstreamHost)
	resp, body := sendHTTPViaProxy(t, proxyAddr, req)
	assertAllowed(t, resp, body)
	if string(body) != "mismatch-ok" {
		t.Errorf("body = %q, want %q", body, "mismatch-ok")
	}
}
