package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// policyTestEnv holds all the components needed for a Target Scope Policy
// integration test. It extends testEnv with TargetScope for policy-layer testing.
type policyTestEnv struct {
	cs          *gomcp.ClientSession
	store       session.Store
	manager     *proxy.Manager
	targetScope *proxy.TargetScope
	httpHandler *protohttp.Handler
}

// setupPolicyTestEnv creates a fully-wired MCP test environment with a
// pre-configured TargetScope. The TargetScope is shared between the MCP server
// and the HTTP handler so that Policy and Agent Layer rules affect proxy traffic.
func setupPolicyTestEnv(t *testing.T, ts *proxy.TargetScope) *policyTestEnv {
	t.Helper()
	ctx := context.Background()

	// Create a temporary SQLite store.
	dbPath := filepath.Join(t.TempDir(), "policy-integration.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Generate an ephemeral CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	// Build protocol handlers and detector.
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	if ts != nil {
		httpHandler.SetTargetScope(ts)
	}
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager.
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	// Create MCP server with all components wired, including TargetScope.
	var opts []ServerOption
	if ts != nil {
		opts = append(opts, WithTargetScope(ts))
	}
	opts = append(opts, WithTargetScopeSetter(httpHandler))

	mcpServer := NewServer(ctx, ca, store, manager, opts...)

	// Connect server and client via in-memory transport.
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "policy-integration-test",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return &policyTestEnv{
		cs:          cs,
		store:       store,
		manager:     manager,
		targetScope: ts,
		httpHandler: httpHandler,
	}
}

// callSecurityTool is a helper that calls the security MCP tool with structured input.
func callSecurityTool(t *testing.T, cs *gomcp.ClientSession, input securityInput) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "security",
		Arguments: securityMarshal(t, input),
	})
	if err != nil {
		t.Fatalf("CallTool(security): %v", err)
	}
	return result
}

// callSecurityToolExpectError calls the security tool and expects an error result.
func callSecurityToolExpectError(t *testing.T, cs *gomcp.ClientSession, input securityInput) string {
	t.Helper()
	result := callSecurityTool(t, cs, input)
	if !result.IsError {
		t.Fatal("expected security tool to return error, got success")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	return text.Text
}

// sendProxyRequest sends an HTTP request through the proxy and returns the response.
// If the request fails (e.g., connection refused), it returns the error.
func sendProxyRequest(t *testing.T, proxyAddr, targetURL string) (*gohttp.Response, error) {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
	t.Cleanup(client.CloseIdleConnections)
	return client.Get(targetURL)
}

// waitForSessions waits briefly for sessions to be persisted to the store.
func waitForSessions() {
	time.Sleep(200 * time.Millisecond)
}

// --- Scenario 1: Policy denies cannot be removed by agent ---

func TestPolicyIntegration_PolicyDenyCannotBeOverridden(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		nil,
		[]proxy.TargetRule{{Hostname: "blocked.example.com"}},
	)

	env := setupPolicyTestEnv(t, ts)

	// Step 1: Add blocked.example.com to agent allows.
	// Since there are no policy allows, the validation passes (no boundary restriction).
	// However, the policy deny still takes precedence at evaluation time.
	setResult := callSecurityTool(t, env.cs, securityInput{
		Action: "set_target_scope",
		Params: securityParams{
			Allows: []targetRuleInput{
				{Hostname: "blocked.example.com"},
			},
		},
	})
	if setResult.IsError {
		// set_target_scope should succeed because no policy allows boundary exists.
		text := setResult.Content[0].(*gomcp.TextContent)
		t.Fatalf("unexpected error from set_target_scope: %s", text.Text)
	}

	// Step 2: Verify via test_target that blocked.example.com is still blocked by policy deny.
	testResult := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://blocked.example.com/api/test",
		},
	})
	var testRes testTargetResult
	securityUnmarshalResult(t, testResult, &testRes)

	if testRes.Allowed {
		t.Error("expected blocked.example.com to be blocked by policy deny despite agent allow")
	}
	if testRes.Layer != "policy" {
		t.Errorf("layer = %q, want %q", testRes.Layer, "policy")
	}
	if testRes.Reason != "blocked by policy deny rule" {
		t.Errorf("reason = %q, want %q", testRes.Reason, "blocked by policy deny rule")
	}

	// Step 3: Start proxy and send actual request to blocked.example.com.
	// This should return 403.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	resp, err := sendProxyRequest(t, startResult.ListenAddr,
		"http://blocked.example.com/api/test")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Step 4: Verify resend of blocked session is also blocked.
	waitForSessions()

	// Find the blocked session.
	sessResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
		"filter": map[string]any{
			"blocked_by": "target_scope",
		},
	})
	if sessResult.Count == 0 {
		t.Fatal("expected at least one blocked session")
	}

	// Try to resend the blocked session via execute.
	resendResult, err := env.cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "execute",
		Arguments: map[string]any{
			"action": "resend",
			"params": map[string]any{
				"session_id": sessResult.Sessions[0].ID,
			},
		},
	})
	if err != nil {
		t.Fatalf("execute resend: %v", err)
	}
	if !resendResult.IsError {
		t.Error("expected resend of policy-blocked session to fail")
	}
}

// --- Scenario 2: Policy allows as upper boundary ---

func TestPolicyIntegration_PolicyAllowsAsUpperBoundary(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)

	upstreamAddr := startUpstreamServer(t)
	env := setupPolicyTestEnv(t, ts)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Step 1: Request to upstream (which is on 127.0.0.1) will be blocked
	// because 127.0.0.1 is NOT in the policy allow list (*.target.com).
	resp, err := sendProxyRequest(t, startResult.ListenAddr,
		fmt.Sprintf("http://%s/api/test", upstreamAddr))
	if err != nil {
		t.Fatalf("proxy request to upstream: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("upstream request status = %d, want %d (not in policy allow list)",
			resp.StatusCode, gohttp.StatusForbidden)
	}

	// Step 2: Verify test_target shows api.target.com is allowed.
	testResult := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://api.target.com/api/test",
		},
	})
	var testRes testTargetResult
	securityUnmarshalResult(t, testResult, &testRes)
	if !testRes.Allowed {
		t.Error("expected api.target.com to be allowed by policy allows")
	}

	// Step 3: Verify test_target shows evil.com is blocked.
	testResult2 := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://evil.com/api/test",
		},
	})
	var testRes2 testTargetResult
	securityUnmarshalResult(t, testResult2, &testRes2)
	if testRes2.Allowed {
		t.Error("expected evil.com to be blocked (not in policy allow list)")
	}
	if testRes2.Layer != "policy" {
		t.Errorf("evil.com layer = %q, want %q", testRes2.Layer, "policy")
	}

	// Step 4: Try to add evil.com to agent allows (outside policy boundary).
	errText := callSecurityToolExpectError(t, env.cs, securityInput{
		Action: "set_target_scope",
		Params: securityParams{
			Allows: []targetRuleInput{
				{Hostname: "evil.com"},
			},
		},
	})
	if !strings.Contains(errText, "outside policy") {
		t.Errorf("error should mention policy boundary, got: %s", errText)
	}

	// Step 5: Adding api.target.com to agent allows should succeed (within policy).
	setResult := callSecurityTool(t, env.cs, securityInput{
		Action: "set_target_scope",
		Params: securityParams{
			Allows: []targetRuleInput{
				{Hostname: "api.target.com"},
			},
		},
	})
	if setResult.IsError {
		t.Fatalf("expected success adding api.target.com to agent allows, got error")
	}
}

// --- Scenario 3: Agent Layer adds restriction within Policy ---

func TestPolicyIntegration_AgentLayerAddsRestriction(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)

	env := setupPolicyTestEnv(t, ts)

	// Step 1: Add agent deny for admin.target.com.
	updateResult := callSecurityTool(t, env.cs, securityInput{
		Action: "update_target_scope",
		Params: securityParams{
			AddDenies: []targetRuleInput{
				{Hostname: "admin.target.com"},
			},
		},
	})
	if updateResult.IsError {
		t.Fatal("expected success adding agent deny for admin.target.com")
	}

	// Step 2: Verify api.target.com is still allowed.
	testResult := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://api.target.com/test",
		},
	})
	var apiRes testTargetResult
	securityUnmarshalResult(t, testResult, &apiRes)
	if !apiRes.Allowed {
		t.Error("expected api.target.com to be allowed")
	}

	// Step 3: Verify admin.target.com is blocked by agent deny.
	testResult2 := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://admin.target.com/test",
		},
	})
	var adminRes testTargetResult
	securityUnmarshalResult(t, testResult2, &adminRes)
	if adminRes.Allowed {
		t.Error("expected admin.target.com to be blocked by agent deny")
	}
	if adminRes.Layer != "agent" {
		t.Errorf("admin.target.com layer = %q, want %q", adminRes.Layer, "agent")
	}

	// Step 4: Remove agent deny for admin.target.com.
	removeResult := callSecurityTool(t, env.cs, securityInput{
		Action: "update_target_scope",
		Params: securityParams{
			RemoveDenies: []targetRuleInput{
				{Hostname: "admin.target.com"},
			},
		},
	})
	if removeResult.IsError {
		t.Fatal("expected success removing agent deny for admin.target.com")
	}

	// Step 5: Verify admin.target.com is now allowed.
	testResult3 := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://admin.target.com/test",
		},
	})
	var adminRes2 testTargetResult
	securityUnmarshalResult(t, testResult3, &adminRes2)
	if !adminRes2.Allowed {
		t.Error("expected admin.target.com to be allowed after removing agent deny")
	}
}

// --- Scenario 3b: Agent Layer adds restriction with proxy listener ---

func TestPolicyIntegration_AgentDenyEnforcedByProxy(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)

	upstreamAddr := startUpstreamServer(t)
	env := setupPolicyTestEnv(t, ts)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Note: The upstream server is on 127.0.0.1 which does NOT match *.target.com.
	// For proxy listener tests with actual HTTP traffic, we can't use *.target.com
	// as the upstream since DNS won't resolve to our test server.
	// Instead, we verify that the proxy blocks requests to out-of-scope hosts.

	// Request to 127.0.0.1 should be blocked (not in *.target.com).
	resp, err := sendProxyRequest(t, startResult.ListenAddr,
		fmt.Sprintf("http://%s/api/test", upstreamAddr))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	waitForSessions()

	// Verify the session was recorded with blocked_by.
	sessResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
		"filter": map[string]any{
			"blocked_by": "target_scope",
		},
	})
	if sessResult.Count == 0 {
		t.Error("expected at least one blocked session recorded")
	}
}

// --- Scenario 4: proxy_stop -> proxy_start preserves Policy ---

func TestPolicyIntegration_PolicyPreservedAcrossRestart(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		[]proxy.TargetRule{{Hostname: "blocked.target.com"}},
	)

	env := setupPolicyTestEnv(t, ts)

	// Step 1: Start the proxy.
	_ = callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Step 2: Verify policy is present.
	getResult := callSecurityTool(t, env.cs, securityInput{
		Action: "get_target_scope",
	})
	var beforeStop getTargetScopeResult
	securityUnmarshalResult(t, getResult, &beforeStop)

	if len(beforeStop.Policy.Allows) != 1 || beforeStop.Policy.Allows[0].Hostname != "*.target.com" {
		t.Errorf("before stop: policy allows = %v, want [{*.target.com}]", beforeStop.Policy.Allows)
	}
	if len(beforeStop.Policy.Denies) != 1 || beforeStop.Policy.Denies[0].Hostname != "blocked.target.com" {
		t.Errorf("before stop: policy denies = %v, want [{blocked.target.com}]", beforeStop.Policy.Denies)
	}

	// Step 3: Stop the proxy.
	_ = callTool[proxyStopResult](t, env.cs, "proxy_stop", nil)

	// Step 4: Restart the proxy.
	_ = callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Step 5: Verify policy is still present after restart.
	getResult2 := callSecurityTool(t, env.cs, securityInput{
		Action: "get_target_scope",
	})
	var afterRestart getTargetScopeResult
	securityUnmarshalResult(t, getResult2, &afterRestart)

	if len(afterRestart.Policy.Allows) != 1 || afterRestart.Policy.Allows[0].Hostname != "*.target.com" {
		t.Errorf("after restart: policy allows = %v, want [{*.target.com}]", afterRestart.Policy.Allows)
	}
	if len(afterRestart.Policy.Denies) != 1 || afterRestart.Policy.Denies[0].Hostname != "blocked.target.com" {
		t.Errorf("after restart: policy denies = %v, want [{blocked.target.com}]", afterRestart.Policy.Denies)
	}
	if !afterRestart.Policy.Immutable {
		t.Error("after restart: policy.immutable should be true")
	}

	// Step 6: Verify blocked.target.com is still blocked after restart.
	testResult := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://blocked.target.com/test",
		},
	})
	var testRes testTargetResult
	securityUnmarshalResult(t, testResult, &testRes)
	if testRes.Allowed {
		t.Error("expected blocked.target.com to still be blocked after restart")
	}
	if testRes.Layer != "policy" {
		t.Errorf("after restart: layer = %q, want %q", testRes.Layer, "policy")
	}
}

// --- Scenario 5: get_target_scope distinguishes two layers ---

func TestPolicyIntegration_GetTargetScopeTwoLayers(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		[]proxy.TargetRule{{Hostname: "blocked.internal"}},
	)
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "api.target.com"}},
		[]proxy.TargetRule{{Hostname: "admin.target.com"}},
	)

	env := setupPolicyTestEnv(t, ts)

	getResult := callSecurityTool(t, env.cs, securityInput{
		Action: "get_target_scope",
	})
	var got getTargetScopeResult
	securityUnmarshalResult(t, getResult, &got)

	// Verify Policy layer.
	if len(got.Policy.Allows) != 1 {
		t.Fatalf("policy.allows count = %d, want 1", len(got.Policy.Allows))
	}
	if got.Policy.Allows[0].Hostname != "*.target.com" {
		t.Errorf("policy.allows[0].hostname = %q, want %q", got.Policy.Allows[0].Hostname, "*.target.com")
	}
	if len(got.Policy.Denies) != 1 {
		t.Fatalf("policy.denies count = %d, want 1", len(got.Policy.Denies))
	}
	if got.Policy.Denies[0].Hostname != "blocked.internal" {
		t.Errorf("policy.denies[0].hostname = %q, want %q", got.Policy.Denies[0].Hostname, "blocked.internal")
	}
	if got.Policy.Source != "config file" {
		t.Errorf("policy.source = %q, want %q", got.Policy.Source, "config file")
	}
	if !got.Policy.Immutable {
		t.Error("policy.immutable should be true")
	}

	// Verify Agent layer.
	if len(got.Agent.Allows) != 1 {
		t.Fatalf("agent.allows count = %d, want 1", len(got.Agent.Allows))
	}
	if got.Agent.Allows[0].Hostname != "api.target.com" {
		t.Errorf("agent.allows[0].hostname = %q, want %q", got.Agent.Allows[0].Hostname, "api.target.com")
	}
	if len(got.Agent.Denies) != 1 {
		t.Fatalf("agent.denies count = %d, want 1", len(got.Agent.Denies))
	}
	if got.Agent.Denies[0].Hostname != "admin.target.com" {
		t.Errorf("agent.denies[0].hostname = %q, want %q", got.Agent.Denies[0].Hostname, "admin.target.com")
	}

	// Verify effective mode.
	if got.EffectiveMode != "enforcing" {
		t.Errorf("effective_mode = %q, want %q", got.EffectiveMode, "enforcing")
	}
}

// --- Scenario 6: Blocked session recording ---

func TestPolicyIntegration_BlockedSessionRecording(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.allowed.com"}},
		[]proxy.TargetRule{{Hostname: "policy-blocked.allowed.com"}},
	)

	upstreamAddr := startUpstreamServer(t)
	env := setupPolicyTestEnv(t, ts)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Step 1: Request to a host blocked by policy denies.
	// policy-blocked.allowed.com is in policy denies, so it should be blocked.
	// However, DNS won't resolve this hostname. Instead, let's use the upstream
	// server address which is not in *.allowed.com, so it's blocked by policy allows.
	resp1, err := sendProxyRequest(t, startResult.ListenAddr,
		fmt.Sprintf("http://%s/api/test", upstreamAddr))
	if err != nil {
		t.Fatalf("proxy request 1: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != gohttp.StatusForbidden {
		t.Errorf("request 1 status = %d, want %d", resp1.StatusCode, gohttp.StatusForbidden)
	}

	waitForSessions()

	// Step 2: Verify blocked sessions are recorded with blocked_by = "target_scope".
	sessResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
		"filter": map[string]any{
			"blocked_by": "target_scope",
		},
	})
	if sessResult.Count == 0 {
		t.Fatal("expected at least one blocked session")
	}

	// Verify the blocked_by field is populated.
	for _, s := range sessResult.Sessions {
		if s.BlockedBy != "target_scope" {
			t.Errorf("session %s blocked_by = %q, want %q", s.ID, s.BlockedBy, "target_scope")
		}
	}

	// Step 3: Verify query can filter by blocked_by.
	normalResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	// All sessions should have blocked_by set since all requests are blocked.
	for _, s := range normalResult.Sessions {
		if s.BlockedBy != "target_scope" {
			t.Errorf("session %s blocked_by = %q, want %q", s.ID, s.BlockedBy, "target_scope")
		}
	}

	// Step 4: Verify session detail also has blocked_by.
	if sessResult.Count > 0 {
		sessionDetail := callTool[querySessionResult](t, env.cs, "query", map[string]any{
			"resource": "session",
			"id":       sessResult.Sessions[0].ID,
		})
		if sessionDetail.BlockedBy != "target_scope" {
			t.Errorf("session detail blocked_by = %q, want %q", sessionDetail.BlockedBy, "target_scope")
		}
	}
}

// --- Scenario 6b: Agent deny blocked sessions ---

func TestPolicyIntegration_AgentDenyBlockedSessionRecording(t *testing.T) {
	ts := proxy.NewTargetScope()
	// No policy rules -- open mode. Only agent denies.
	ts.SetAgentRules(nil, []proxy.TargetRule{{Hostname: "*.evil.test"}})

	upstreamAddr := startUpstreamServer(t)
	env := setupPolicyTestEnv(t, ts)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Request to upstream (127.0.0.1) should succeed since it's not in agent denies.
	resp, err := sendProxyRequest(t, startResult.ListenAddr,
		fmt.Sprintf("http://%s/api/test", upstreamAddr))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("allowed request status = %d, want %d (body: %s)",
			resp.StatusCode, gohttp.StatusOK, body)
	}

	waitForSessions()

	// Verify the allowed session has no blocked_by.
	allowedSessions := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if allowedSessions.Count == 0 {
		t.Fatal("expected at least one session")
	}
	for _, s := range allowedSessions.Sessions {
		if s.BlockedBy != "" {
			t.Errorf("allowed session %s blocked_by = %q, want empty", s.ID, s.BlockedBy)
		}
	}
}

// --- Scenario 7: Backward compatibility -- no Policy ---

func TestPolicyIntegration_BackwardCompatibility_NoPolicy(t *testing.T) {
	// Create TargetScope without policy rules.
	ts := proxy.NewTargetScope()
	env := setupPolicyTestEnv(t, ts)

	// Step 1: Verify get_target_scope returns empty policy.
	getResult := callSecurityTool(t, env.cs, securityInput{
		Action: "get_target_scope",
	})
	var got getTargetScopeResult
	securityUnmarshalResult(t, getResult, &got)

	if got.EffectiveMode != "open" {
		t.Errorf("effective_mode = %q, want %q", got.EffectiveMode, "open")
	}
	if len(got.Policy.Allows) != 0 {
		t.Errorf("policy.allows = %v, want empty", got.Policy.Allows)
	}
	if len(got.Policy.Denies) != 0 {
		t.Errorf("policy.denies = %v, want empty", got.Policy.Denies)
	}
	if got.Policy.Source != "none" {
		t.Errorf("policy.source = %q, want %q", got.Policy.Source, "none")
	}
	if !got.Policy.Immutable {
		t.Error("policy.immutable should always be true")
	}

	// Step 2: set_target_scope should work normally.
	setResult := callSecurityTool(t, env.cs, securityInput{
		Action: "set_target_scope",
		Params: securityParams{
			Allows: []targetRuleInput{
				{Hostname: "example.com"},
			},
			Denies: []targetRuleInput{
				{Hostname: "evil.com"},
			},
		},
	})
	if setResult.IsError {
		t.Fatal("expected success for set_target_scope without policy")
	}
	var setRes setTargetScopeResult
	securityUnmarshalResult(t, setResult, &setRes)
	if setRes.Mode != "enforcing" {
		t.Errorf("mode = %q, want %q", setRes.Mode, "enforcing")
	}
	if len(setRes.Allows) != 1 || setRes.Allows[0].Hostname != "example.com" {
		t.Errorf("allows = %v, want [{example.com}]", setRes.Allows)
	}
	if len(setRes.Denies) != 1 || setRes.Denies[0].Hostname != "evil.com" {
		t.Errorf("denies = %v, want [{evil.com}]", setRes.Denies)
	}

	// Step 3: update_target_scope should work normally.
	updateResult := callSecurityTool(t, env.cs, securityInput{
		Action: "update_target_scope",
		Params: securityParams{
			AddAllows: []targetRuleInput{
				{Hostname: "new.com"},
			},
			RemoveDenies: []targetRuleInput{
				{Hostname: "evil.com"},
			},
		},
	})
	if updateResult.IsError {
		t.Fatal("expected success for update_target_scope without policy")
	}
	var updateRes setTargetScopeResult
	securityUnmarshalResult(t, updateResult, &updateRes)
	if len(updateRes.Allows) != 2 {
		t.Errorf("allows count = %d, want 2", len(updateRes.Allows))
	}
	if len(updateRes.Denies) != 0 {
		t.Errorf("denies count = %d, want 0", len(updateRes.Denies))
	}

	// Step 4: test_target should work normally.
	testResult := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "https://example.com/api",
		},
	})
	var testRes testTargetResult
	securityUnmarshalResult(t, testResult, &testRes)
	if !testRes.Allowed {
		t.Error("expected example.com to be allowed")
	}
}

// --- Scenario 7b: Backward compatibility with proxy listener ---

func TestPolicyIntegration_BackwardCompatibility_ProxyWorks(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	ts := proxy.NewTargetScope()
	env := setupPolicyTestEnv(t, ts)

	// Start proxy without any policy or agent rules.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Request to upstream should succeed (no rules = open mode).
	resp, err := sendProxyRequest(t, startResult.ListenAddr,
		fmt.Sprintf("http://%s/api/test", upstreamAddr))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d (body: %s)", resp.StatusCode, gohttp.StatusOK, body)
	}
	if !strings.Contains(string(body), "hello from upstream") {
		t.Errorf("response body = %q, want to contain %q", body, "hello from upstream")
	}

	waitForSessions()

	// Verify session was recorded normally.
	sessResult := callTool[querySessionsResult](t, env.cs, "query", map[string]any{
		"resource": "sessions",
	})
	if sessResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", sessResult.Count)
	}
	if sessResult.Sessions[0].BlockedBy != "" {
		t.Errorf("session blocked_by = %q, want empty", sessResult.Sessions[0].BlockedBy)
	}
}

// --- Scenario: Policy denies override agent allows in evaluation ---

func TestPolicyIntegration_PolicyDenyTakesPrecedenceOverAllLayers(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.example.com"}},
		[]proxy.TargetRule{{Hostname: "blocked.example.com"}},
	)
	// Agent allows blocked.example.com, but policy deny should win.
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "blocked.example.com"}},
		nil,
	)

	env := setupPolicyTestEnv(t, ts)

	// Verify policy deny takes precedence.
	testResult := callSecurityTool(t, env.cs, securityInput{
		Action: "test_target",
		Params: securityParams{
			URL: "http://blocked.example.com/test",
		},
	})
	var res testTargetResult
	securityUnmarshalResult(t, testResult, &res)

	if res.Allowed {
		t.Error("expected blocked.example.com to be blocked by policy deny despite agent allow")
	}
	if res.Layer != "policy" {
		t.Errorf("layer = %q, want %q", res.Layer, "policy")
	}
	if res.Reason != "blocked by policy deny rule" {
		t.Errorf("reason = %q, want %q", res.Reason, "blocked by policy deny rule")
	}
}

// --- Scenario: execute resend with Policy enforcement ---

func TestPolicyIntegration_ExecuteResendBlockedByPolicy(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	// Create a session targeting a host not in the policy allow list.
	u, _ := url.Parse("http://evil.com/api/test")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)
	_ = echoServer

	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": entry.Session.ID,
		},
	})

	if !result.IsError {
		t.Fatal("expected error for resend to host outside policy allow list")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

func TestPolicyIntegration_ExecuteResendAllowedByPolicy(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	serverURL, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       serverURL,
			Headers:   map[string][]string{},
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	ts := proxy.NewTargetScope()
	// Policy allows the echo server's hostname (127.0.0.1).
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: serverURL.Hostname()}},
		nil,
	)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": entry.Session.ID,
		},
	})

	if result.IsError {
		t.Fatalf("expected success for resend to policy-allowed host, got error: %v", result.Content)
	}
}

// --- Scenario: Combined policy allows + policy denies + agent rules ---

func TestPolicyIntegration_FullLayeredEvaluation(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		[]proxy.TargetRule{{Hostname: "forbidden.target.com"}},
	)
	ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "api.target.com"}},
		[]proxy.TargetRule{{Hostname: "staging.target.com"}},
	)

	env := setupPolicyTestEnv(t, ts)

	tests := []struct {
		name          string
		url           string
		wantAllowed   bool
		wantLayer     string
		wantReason    string
	}{
		{
			name:        "policy deny blocks",
			url:         "http://forbidden.target.com/api",
			wantAllowed: false,
			wantLayer:   "policy",
			wantReason:  "blocked by policy deny rule",
		},
		{
			name:        "agent deny blocks within policy",
			url:         "http://staging.target.com/api",
			wantAllowed: false,
			wantLayer:   "agent",
			wantReason:  "blocked by agent deny rule",
		},
		{
			name:        "outside policy allows",
			url:         "http://evil.com/api",
			wantAllowed: false,
			wantLayer:   "policy",
			wantReason:  "not in policy allow list",
		},
		{
			name:        "in policy allows but not in agent allows",
			url:         "http://other.target.com/api",
			wantAllowed: false,
			wantLayer:   "agent",
			wantReason:  "not in agent allow list",
		},
		{
			name:        "fully allowed",
			url:         "http://api.target.com/api",
			wantAllowed: true,
			wantLayer:   "agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testResult := callSecurityTool(t, env.cs, securityInput{
				Action: "test_target",
				Params: securityParams{
					URL: tt.url,
				},
			})
			var res testTargetResult
			securityUnmarshalResult(t, testResult, &res)

			if res.Allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v", res.Allowed, tt.wantAllowed)
			}
			if res.Layer != tt.wantLayer {
				t.Errorf("layer = %q, want %q", res.Layer, tt.wantLayer)
			}
			if tt.wantReason != "" && res.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", res.Reason, tt.wantReason)
			}
		})
	}
}

// --- Scenario: Agent Layer boundary validation ---

func TestPolicyIntegration_AgentBoundaryValidation(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)

	env := setupPolicyTestEnv(t, ts)

	tests := []struct {
		name      string
		input     securityInput
		wantError bool
		errSubstr string
	}{
		{
			name: "set_target_scope with allows inside policy",
			input: securityInput{
				Action: "set_target_scope",
				Params: securityParams{
					Allows: []targetRuleInput{{Hostname: "api.target.com"}},
				},
			},
			wantError: false,
		},
		{
			name: "set_target_scope with allows outside policy",
			input: securityInput{
				Action: "set_target_scope",
				Params: securityParams{
					Allows: []targetRuleInput{{Hostname: "evil.com"}},
				},
			},
			wantError: true,
			errSubstr: "outside policy",
		},
		{
			name: "set_target_scope with wildcard subdomain inside policy",
			input: securityInput{
				Action: "set_target_scope",
				Params: securityParams{
					Allows: []targetRuleInput{{Hostname: "*.api.target.com"}},
				},
			},
			wantError: false,
		},
		{
			name: "update_target_scope add_allows inside policy",
			input: securityInput{
				Action: "update_target_scope",
				Params: securityParams{
					AddAllows: []targetRuleInput{{Hostname: "new.target.com"}},
				},
			},
			wantError: false,
		},
		{
			name: "update_target_scope add_allows outside policy",
			input: securityInput{
				Action: "update_target_scope",
				Params: securityParams{
					AddAllows: []targetRuleInput{{Hostname: "evil.com"}},
				},
			},
			wantError: true,
			errSubstr: "outside policy",
		},
		{
			name: "set_target_scope with denies (unrestricted)",
			input: securityInput{
				Action: "set_target_scope",
				Params: securityParams{
					Denies: []targetRuleInput{{Hostname: "anything.com"}},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset agent rules before each test to avoid state leaking.
			ts.SetAgentRules(nil, nil)

			result := callSecurityTool(t, env.cs, tt.input)

			if tt.wantError {
				if !result.IsError {
					t.Fatalf("expected error, got success")
				}
				text, ok := result.Content[0].(*gomcp.TextContent)
				if ok && tt.errSubstr != "" && !strings.Contains(text.Text, tt.errSubstr) {
					t.Errorf("error text = %q, want to contain %q", text.Text, tt.errSubstr)
				}
			} else {
				if result.IsError {
					text := result.Content[0].(*gomcp.TextContent)
					t.Fatalf("expected success, got error: %s", text.Text)
				}
			}
		})
	}
}

// --- Scenario: Policy with port and path restrictions ---

func TestPolicyIntegration_PolicyWithPortAndPath(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{
			Hostname:   "api.target.com",
			Ports:      []int{443, 8443},
			PathPrefix: "/api/",
			Schemes:    []string{"https"},
		}},
		nil,
	)

	env := setupPolicyTestEnv(t, ts)

	tests := []struct {
		name        string
		url         string
		wantAllowed bool
	}{
		{
			name:        "matching URL",
			url:         "https://api.target.com:443/api/v1/data",
			wantAllowed: true,
		},
		{
			name:        "wrong port",
			url:         "https://api.target.com:9090/api/v1/data",
			wantAllowed: false,
		},
		{
			name:        "wrong path",
			url:         "https://api.target.com:443/admin/panel",
			wantAllowed: false,
		},
		{
			name:        "wrong scheme",
			url:         "http://api.target.com:443/api/v1/data",
			wantAllowed: false,
		},
		{
			name:        "wrong hostname",
			url:         "https://evil.com:443/api/v1/data",
			wantAllowed: false,
		},
		{
			name:        "alternative allowed port",
			url:         "https://api.target.com:8443/api/v1/data",
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testResult := callSecurityTool(t, env.cs, securityInput{
				Action: "test_target",
				Params: securityParams{
					URL: tt.url,
				},
			})
			var res testTargetResult
			securityUnmarshalResult(t, testResult, &res)

			if res.Allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v (reason: %s, layer: %s)",
					res.Allowed, tt.wantAllowed, res.Reason, res.Layer)
			}
		})
	}
}

// --- Scenario: update_target_scope cannot remove policy deny rules ---

func TestPolicyIntegration_CannotRemovePolicyDenyViaUpdate(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		nil,
		[]proxy.TargetRule{{Hostname: "policy-blocked.com"}},
	)

	env := setupPolicyTestEnv(t, ts)

	// Try to remove a policy deny rule via update_target_scope.
	errText := callSecurityToolExpectError(t, env.cs, securityInput{
		Action: "update_target_scope",
		Params: securityParams{
			RemoveDenies: []targetRuleInput{
				{Hostname: "policy-blocked.com"},
			},
		},
	})
	if !strings.Contains(errText, "policy") || !strings.Contains(errText, "immutable") {
		t.Errorf("error should mention policy immutability, got: %s", errText)
	}
}

// --- Scenario: nil TargetScope defaults to open ---

func TestPolicyIntegration_NilTargetScopeDefaultsToOpen(t *testing.T) {
	// Create environment without explicit TargetScope -- NewServer creates a
	// default empty one.
	env := setupPolicyTestEnv(t, nil)

	// get_target_scope should work (auto-initialized TargetScope).
	getResult := callSecurityTool(t, env.cs, securityInput{
		Action: "get_target_scope",
	})
	var got getTargetScopeResult
	securityUnmarshalResult(t, getResult, &got)

	if got.EffectiveMode != "open" {
		t.Errorf("effective_mode = %q, want %q", got.EffectiveMode, "open")
	}
	if got.Policy.Source != "none" {
		t.Errorf("policy.source = %q, want %q", got.Policy.Source, "none")
	}
}

// --- Scenario: Execute fuzz blocked by policy ---

func TestPolicyIntegration_ExecuteFuzzBlockedByPolicy(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://evil.com/api/test")
	saveTestEntry(t, store,
		&session.Session{
			ID:        "fuzz-policy-blocked",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)

	cs := setupExecuteWithTargetScope(t, store, ts)
	result := executeCallTool(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"session_id":  "fuzz-policy-blocked",
			"attack_type": "sequential",
			"positions": []map[string]any{
				{
					"id":          "pos-0",
					"location":    "header",
					"name":        "Content-Type",
					"payload_set": "types",
				},
			},
			"payload_sets": map[string]any{
				"types": map[string]any{
					"type":   "list",
					"values": []string{"text/html"},
				},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error for fuzz with host outside policy allow list")
	}
	text := result.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// --- Scenario: Execute macro blocked by policy ---

func TestPolicyIntegration_ExecuteMacroBlockedByPolicy(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://evil.com/api/login")
	saveTestEntry(t, store,
		&session.Session{
			ID:        "macro-policy-blocked",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"user":"admin"}`),
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte(`{"token":"abc"}`),
		},
	)

	ts := proxy.NewTargetScope()
	ts.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "*.target.com"}},
		nil,
	)

	ctx := context.Background()
	s := NewServer(ctx, nil, store, nil, WithTargetScope(ts))
	s.replayDoer = newPermissiveClient()
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	// Define the macro.
	defineResult := executeCallTool(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "test-policy-blocked-macro",
			"steps": []map[string]any{
				{
					"id":         "step-1",
					"session_id": "macro-policy-blocked",
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Run the macro -- should be blocked by policy.
	runResult := executeCallTool(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "test-policy-blocked-macro",
		},
	})

	if !runResult.IsError {
		t.Fatal("expected error for macro with host outside policy allow list")
	}
	text := runResult.Content[0].(*gomcp.TextContent).Text
	if !strings.Contains(text, "target scope") {
		t.Errorf("error message should mention target scope, got: %s", text)
	}
}

// executeCallToolRaw is a convenience wrapper for calling the execute tool.
func executeCallToolRaw(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal execute args: %v", err)
	}
	var argMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &argMap); err != nil {
		t.Fatalf("unmarshal execute args: %v", err)
	}
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "execute",
		Arguments: argMap,
	})
	if err != nil {
		t.Fatalf("CallTool(execute): %v", err)
	}
	return result
}
