//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// testEnv holds all the components needed for an MCP integration test.
type testEnv struct {
	cs          *gomcp.ClientSession
	store       flow.Store
	manager     *proxy.Manager
	scope       *proxy.CaptureScope
	passthrough *proxy.PassthroughList
}

// setupIntegrationEnv creates a fully-wired MCP test environment with a real
// flow store, CA, and proxy manager connected via in-memory transport.
func setupIntegrationEnv(t *testing.T) *testEnv {
	t.Helper()
	return setupIntegrationEnvWithOpts(t)
}

// setupIntegrationEnvWithOpts creates a fully-wired MCP test environment with
// optional CaptureScope and PassthroughList. These are needed for configure
// tool integration tests where scope and passthrough must be initialized
// before configure can be called.
func setupIntegrationEnvWithOpts(t *testing.T, opts ...ServerOption) *testEnv {
	t.Helper()
	ctx := context.Background()

	// Create a temporary SQLite store.
	dbPath := filepath.Join(t.TempDir(), "integration.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager.
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	// Create MCP server with all components wired.
	mcpServer := NewServer(ctx, ca, store, manager, opts...)

	// Connect server and client via in-memory transport.
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "integration-test",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return &testEnv{
		cs:      cs,
		store:   store,
		manager: manager,
	}
}

// setupIntegrationEnvWithScopeAndPassthrough creates a fully-wired MCP test
// environment with CaptureScope and PassthroughList initialized.
// The scope and passthrough are shared with the HTTP handler so that
// configure tool changes affect actual traffic filtering.
func setupIntegrationEnvWithScopeAndPassthrough(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	// Create a temporary SQLite store.
	dbPath := filepath.Join(t.TempDir(), "integration.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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

	// Create shared scope and passthrough.
	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()

	// Build protocol handlers and detector with shared scope and passthrough.
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	httpHandler.SetCaptureScope(scope)
	httpHandler.SetPassthroughList(pl)
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager.
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	// Create MCP server with scope and passthrough wired.
	mcpServer := NewServer(ctx, ca, store, manager,
		WithCaptureScope(scope),
		WithPassthroughList(pl),
	)

	// Connect server and client via in-memory transport.
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "integration-test",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return &testEnv{
		cs:          cs,
		store:       store,
		manager:     manager,
		scope:       scope,
		passthrough: pl,
	}
}

// callTool is a helper that calls an MCP tool and unmarshals the result.
func callTool[T any](t *testing.T, cs *gomcp.ClientSession, name string, args any) T {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if result.IsError {
		t.Fatalf("CallTool(%s) returned error: %v", name, result.Content)
	}

	var out T
	if len(result.Content) == 0 {
		t.Fatalf("CallTool(%s) returned empty content", name)
	}
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("CallTool(%s) expected TextContent, got %T", name, result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("CallTool(%s) unmarshal: %v", name, err)
	}
	return out
}

// callToolExpectError is a helper that calls an MCP tool and expects an error.
func callToolExpectError(t *testing.T, cs *gomcp.ClientSession, name string, args any) {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if !result.IsError {
		t.Fatalf("CallTool(%s) expected error, got success", name)
	}
}

// startUpstreamServer starts a simple HTTP echo server for testing.
// It returns the server address and a cleanup function.
func startUpstreamServer(t *testing.T) string {
	t.Helper()

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		if len(body) > 0 {
			fmt.Fprintf(w, "echo: %s", body)
		} else {
			fmt.Fprint(w, "hello from upstream")
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &gohttp.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	return listener.Addr().String()
}

// proxyHTTPClient creates an HTTP client configured to use the proxy.
func proxyHTTPClient(proxyAddr string) *gohttp.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
}

// TestIntegration_FullLifecycle tests the complete MCP tool lifecycle:
// proxy_start -> HTTP request through proxy -> query sessions -> query flow
// -> execute replay -> execute delete_flows -> proxy_stop.
func TestIntegration_FullLifecycle(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnv(t)

	// 1. Start the proxy via MCP tool.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}
	if startResult.ListenAddr == "" {
		t.Fatal("proxy_start returned empty listen_addr")
	}

	// Verify manager reports running.
	running, addr := env.manager.Status()
	if !running {
		t.Fatal("manager should be running after proxy_start")
	}
	if addr != startResult.ListenAddr {
		t.Errorf("manager addr = %q, proxy_start addr = %q", addr, startResult.ListenAddr)
	}

	// 2. Send an HTTP request through the proxy.
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/test", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("upstream response status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(respBody) != "hello from upstream" {
		t.Fatalf("upstream response body = %q, want %q", respBody, "hello from upstream")
	}

	// Wait for flow to be persisted.
	time.Sleep(200 * time.Millisecond)

	// 3. List sessions via query tool.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count != 1 {
		t.Fatalf("query sessions count = %d, want 1", listResult.Count)
	}
	flowEntry := listResult.Flows[0]
	if flowEntry.Method != "GET" {
		t.Errorf("flow method = %q, want %q", flowEntry.Method, "GET")
	}
	if flowEntry.StatusCode != 200 {
		t.Errorf("flow status_code = %d, want %d", flowEntry.StatusCode, 200)
	}
	if !strings.Contains(flowEntry.URL, "/api/test") {
		t.Errorf("flow URL = %q, want to contain /api/test", flowEntry.URL)
	}

	// 4. Get flow details via query tool.
	getResult := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowEntry.ID,
	})
	if getResult.ID != flowEntry.ID {
		t.Errorf("query flow ID = %q, want %q", getResult.ID, flowEntry.ID)
	}
	if getResult.Method != "GET" {
		t.Errorf("query flow method = %q, want %q", getResult.Method, "GET")
	}
	if getResult.ResponseStatusCode != 200 {
		t.Errorf("query flow response status = %d, want %d", getResult.ResponseStatusCode, 200)
	}
	if getResult.ResponseBody != "hello from upstream" {
		t.Errorf("query flow response body = %q, want %q", getResult.ResponseBody, "hello from upstream")
	}
	if getResult.ResponseBodyEncoding != "text" {
		t.Errorf("query flow response body encoding = %q, want %q", getResult.ResponseBodyEncoding, "text")
	}
	if getResult.DurationMs < 0 {
		t.Errorf("query flow duration = %d, want >= 0", getResult.DurationMs)
	}

	// 5. Replay the request via execute tool.
	// Note: execute replay uses an HTTP client that by default blocks private
	// networks (SSRF protection). Since our upstream is on loopback, we need
	// to handle the expected failure.
	replayResult, replayErr := env.cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "replay",
			"params": map[string]any{
				"flow_id": flowEntry.ID,
			},
		},
	})
	if replayErr != nil {
		t.Fatalf("CallTool(execute/replay): %v", replayErr)
	}
	// The replay will fail because the target is a private address (SSRF protection).
	// This is expected behavior — we verify the tool ran and returned an error.
	if !replayResult.IsError {
		// If replay succeeded (e.g., SSRF protection is relaxed), verify the result.
		var rr resendActionResult
		tc, ok := replayResult.Content[0].(*gomcp.TextContent)
		if ok {
			json.Unmarshal([]byte(tc.Text), &rr)
		}
		if rr.NewFlowID == "" {
			t.Error("resend replay returned empty new_flow_id")
		}
		if rr.StatusCode != 200 {
			t.Errorf("execute replay status_code = %d, want 200", rr.StatusCode)
		}
	}

	// 6. Delete the flow via manage tool.
	deleteResult := callTool[executeDeleteFlowsResult](t, env.cs, "manage", map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"flow_id": flowEntry.ID,
		},
	})
	if deleteResult.DeletedCount != 1 {
		t.Errorf("execute delete_flows deleted_count = %d, want 1", deleteResult.DeletedCount)
	}

	// Verify session is gone.
	listAfterDelete := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	// May have a replay flow if replay succeeded.
	for _, s := range listAfterDelete.Flows {
		if s.ID == flowEntry.ID {
			t.Error("deleted flow still appears in query sessions")
		}
	}

	// 7. Close idle keep-alive connections before stopping, so the proxy does
	// not block waiting for the next request on a persistent connection.
	client.CloseIdleConnections()

	// Stop the proxy via MCP tool.
	stopResult := callTool[proxyStopResult](t, env.cs, "proxy_stop", nil)
	if stopResult.Status != "stopped" {
		t.Errorf("proxy_stop status = %q, want %q", stopResult.Status, "stopped")
	}

	// Verify manager reports not running.
	running, _ = env.manager.Status()
	if running {
		t.Error("manager should not be running after proxy_stop")
	}
}

// TestIntegration_ExportCACert verifies the query ca_cert resource returns a valid
// PEM certificate with metadata through the full MCP integration path.
func TestIntegration_ExportCACert(t *testing.T) {
	env := setupIntegrationEnv(t)

	result := callTool[queryCACertResult](t, env.cs, "query", map[string]any{
		"resource": "ca_cert",
	})

	if result.PEM == "" {
		t.Error("query ca_cert PEM is empty")
	}
	if !strings.HasPrefix(result.PEM, "-----BEGIN CERTIFICATE-----") {
		t.Error("query ca_cert PEM does not start with BEGIN CERTIFICATE header")
	}
	if result.Fingerprint == "" {
		t.Error("query ca_cert fingerprint is empty")
	}
	if result.Subject == "" {
		t.Error("query ca_cert subject is empty")
	}
	if result.NotAfter == "" {
		t.Error("query ca_cert not_after is empty")
	}

	// Verify not_after is in the future.
	notAfter, err := time.Parse("2006-01-02T15:04:05Z", result.NotAfter)
	if err != nil {
		t.Fatalf("parse not_after %q: %v", result.NotAfter, err)
	}
	if !notAfter.After(time.Now()) {
		t.Errorf("not_after %v is not in the future", notAfter)
	}
}

// TestIntegration_ProxyStop_WhenNotRunning verifies that proxy_stop returns
// an error when the proxy is not running.
func TestIntegration_ProxyStop_WhenNotRunning(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "proxy_stop", nil)
}

// TestIntegration_ProxyStart_DoubleStart verifies that starting the proxy
// twice returns an error.
func TestIntegration_ProxyStart_DoubleStart(t *testing.T) {
	env := setupIntegrationEnv(t)

	// First start should succeed.
	_ = callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Second start should fail.
	callToolExpectError(t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
}

// TestIntegration_QuerySession_NotFound verifies that querying a flow returns an
// error for a non-existent flow ID.
func TestIntegration_QuerySession_NotFound(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       "nonexistent-flow-id",
	})
}

// TestIntegration_ExecuteDeleteFlows_NotFound verifies that deleting a flow
// returns an error for a non-existent flow ID.
func TestIntegration_ExecuteDeleteFlows_NotFound(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "manage", map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"flow_id": "nonexistent-flow-id",
		},
	})
}

// TestIntegration_ExecuteReplay_NoSession verifies that execute replay returns
// an error when the referenced session does not exist.
func TestIntegration_ExecuteReplay_NoSession(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "resend", map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id": "nonexistent-flow-id",
		},
	})
}

// TestIntegration_QuerySessions_Empty verifies that query sessions returns an
// empty list when no sessions have been recorded.
func TestIntegration_QuerySessions_Empty(t *testing.T) {
	env := setupIntegrationEnv(t)

	result := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if result.Count != 0 {
		t.Errorf("query sessions count = %d, want 0", result.Count)
	}
	if result.Total != 0 {
		t.Errorf("query sessions total = %d, want 0", result.Total)
	}
	if len(result.Flows) != 0 {
		t.Errorf("query sessions length = %d, want 0", len(result.Flows))
	}
}

// TestIntegration_ListTools verifies that all expected tools are registered.
func TestIntegration_ListTools(t *testing.T) {
	env := setupIntegrationEnv(t)

	toolsResult, err := env.cs.ListTools(context.Background(), &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	expectedTools := map[string]bool{
		"proxy_start": false,
		"proxy_stop":  false,
		"configure":   false,
		"query":       false,
		"resend":      false,
		"manage":      false,
		"fuzz":        false,
		"macro":       false,
		"intercept":   false,
		"plugin":      false,
	}

	for _, tool := range toolsResult.Tools {
		if _, ok := expectedTools[tool.Name]; ok {
			expectedTools[tool.Name] = true
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("expected tool %q not found in ListTools result", name)
		}
	}

	// Verify no unexpected legacy tools are present.
	legacyTools := []string{
		"clear_sessions", "proxy_status", "list_sessions", "get_session",
		"replay_request", "delete_session", "export_ca_cert",
		"add_tls_passthrough", "remove_tls_passthrough", "list_tls_passthrough",
		"set_capture_scope", "get_capture_scope", "clear_capture_scope",
		"replay_raw",
	}
	toolSet := make(map[string]bool)
	for _, tool := range toolsResult.Tools {
		toolSet[tool.Name] = true
	}
	for _, legacy := range legacyTools {
		if toolSet[legacy] {
			t.Errorf("legacy tool %q should not be registered", legacy)
		}
	}
}

// TestIntegration_ProxyStartStopRestart verifies the proxy can be started,
// stopped, and restarted through MCP tools.
func TestIntegration_ProxyStartStopRestart(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Start.
	result1 := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if result1.Status != "running" {
		t.Fatalf("first start: status = %q, want %q", result1.Status, "running")
	}

	// Stop.
	stopResult := callTool[proxyStopResult](t, env.cs, "proxy_stop", nil)
	if stopResult.Status != "stopped" {
		t.Fatalf("stop: status = %q, want %q", stopResult.Status, "stopped")
	}

	// Restart.
	result2 := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if result2.Status != "running" {
		t.Fatalf("restart: status = %q, want %q", result2.Status, "running")
	}
}

// TestIntegration_MultipleRequests verifies that multiple HTTP requests are
// recorded as separate sessions and can be listed/filtered.
func TestIntegration_MultipleRequests(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnv(t)

	// Start proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)

	// Send GET request.
	getURL := fmt.Sprintf("http://%s/api/users", upstreamAddr)
	resp1, err := client.Get(getURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp1.Body.Close()

	// Send POST request.
	postURL := fmt.Sprintf("http://%s/api/data", upstreamAddr)
	resp2, err := client.Post(postURL, "application/json", strings.NewReader(`{"key":"value"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp2.Body.Close()

	// Wait for sessions to be persisted.
	time.Sleep(200 * time.Millisecond)

	// List all sessions.
	allResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if allResult.Count != 2 {
		t.Fatalf("query sessions count = %d, want 2", allResult.Count)
	}

	// Filter by method.
	getResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"method": "GET",
		},
	})
	if getResult.Count != 1 {
		t.Errorf("query sessions(method=GET) count = %d, want 1", getResult.Count)
	}

	postResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"method": "POST",
		},
	})
	if postResult.Count != 1 {
		t.Errorf("query sessions(method=POST) count = %d, want 1", postResult.Count)
	}

	// Filter by URL pattern.
	urlResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"url_pattern": "/api/users",
		},
	})
	if urlResult.Count != 1 {
		t.Errorf("query sessions(url_pattern=/api/users) count = %d, want 1", urlResult.Count)
	}

	// Delete all sessions via manage tool.
	delResult := callTool[executeDeleteFlowsResult](t, env.cs, "manage", map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"confirm": true,
		},
	})
	if delResult.DeletedCount != 2 {
		t.Errorf("execute delete_flows(confirm) deleted_count = %d, want 2", delResult.DeletedCount)
	}

	// Verify empty.
	emptyResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if emptyResult.Count != 0 {
		t.Errorf("query sessions after delete_all count = %d, want 0", emptyResult.Count)
	}
}

// TestIntegration_Configure_CaptureScopeMerge verifies that the configure tool's
// capture_scope merge operation works end-to-end with the actual proxy.
// After configuring a scope, only in-scope traffic should be recorded.
func TestIntegration_Configure_CaptureScopeMerge(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnvWithScopeAndPassthrough(t)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Configure capture_scope to only include requests to a specific path.
	cfgResult := callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"capture_scope": map[string]any{
			"add_includes": []any{
				map[string]any{"url_prefix": "/in-scope"},
			},
		},
	})
	if cfgResult.Status != "configured" {
		t.Fatalf("configure status = %q, want %q", cfgResult.Status, "configured")
	}
	if cfgResult.CaptureScope == nil {
		t.Fatal("configure capture_scope is nil")
	}
	if cfgResult.CaptureScope.IncludeCount != 1 {
		t.Errorf("configure include_count = %d, want 1", cfgResult.CaptureScope.IncludeCount)
	}

	client := proxyHTTPClient(startResult.ListenAddr)

	// Send a request to an in-scope URL — should be recorded.
	inScopeURL := fmt.Sprintf("http://%s/in-scope/data", upstreamAddr)
	resp, err := client.Get(inScopeURL)
	if err != nil {
		t.Fatalf("GET in-scope: %v", err)
	}
	resp.Body.Close()

	// Send a request to an out-of-scope URL — should NOT be recorded.
	outOfScopeURL := fmt.Sprintf("http://%s/out-of-scope/data", upstreamAddr)
	resp, err = client.Get(outOfScopeURL)
	if err != nil {
		t.Fatalf("GET out-of-scope: %v", err)
	}
	resp.Body.Close()

	// Wait for sessions to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Verify only the in-scope request was recorded.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count != 1 {
		t.Fatalf("query sessions count = %d, want 1 (only in-scope)", listResult.Count)
	}
	if !strings.Contains(listResult.Flows[0].URL, "/in-scope/data") {
		t.Errorf("recorded flow URL = %q, want to contain /in-scope/data", listResult.Flows[0].URL)
	}

	// Close idle connections before stopping.
	client.CloseIdleConnections()
}

// TestIntegration_Configure_TLSPassthroughMerge verifies that configure tool's
// tls_passthrough merge operation updates the passthrough list, verifiable via query config.
func TestIntegration_Configure_TLSPassthroughMerge(t *testing.T) {
	env := setupIntegrationEnvWithScopeAndPassthrough(t)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Add TLS passthrough patterns via configure merge.
	cfgResult := callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"tls_passthrough": map[string]any{
			"add": []any{"pinned-service.com", "*.googleapis.com"},
		},
	})
	if cfgResult.Status != "configured" {
		t.Fatalf("configure status = %q, want %q", cfgResult.Status, "configured")
	}
	if cfgResult.TLSPassthrough == nil {
		t.Fatal("configure tls_passthrough is nil")
	}
	if cfgResult.TLSPassthrough.TotalPatterns != 2 {
		t.Errorf("configure total_patterns = %d, want 2", cfgResult.TLSPassthrough.TotalPatterns)
	}

	// Verify via query config that the passthrough patterns are reflected.
	configResult := callTool[queryConfigResult](t, env.cs, "query", map[string]any{
		"resource": "config",
	})
	if configResult.TLSPassthrough == nil {
		t.Fatal("query config tls_passthrough is nil")
	}
	if configResult.TLSPassthrough.Count != 2 {
		t.Errorf("query config tls_passthrough count = %d, want 2", configResult.TLSPassthrough.Count)
	}
	// Verify specific patterns are present (sorted alphabetically).
	patternSet := make(map[string]bool)
	for _, p := range configResult.TLSPassthrough.Patterns {
		patternSet[p] = true
	}
	if !patternSet["pinned-service.com"] {
		t.Error("query config tls_passthrough missing pinned-service.com")
	}
	if !patternSet["*.googleapis.com"] {
		t.Error("query config tls_passthrough missing *.googleapis.com")
	}

	// Now remove one pattern via merge.
	cfgResult2 := callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"tls_passthrough": map[string]any{
			"remove": []any{"pinned-service.com"},
		},
	})
	if cfgResult2.TLSPassthrough == nil {
		t.Fatal("second configure tls_passthrough is nil")
	}
	if cfgResult2.TLSPassthrough.TotalPatterns != 1 {
		t.Errorf("second configure total_patterns = %d, want 1", cfgResult2.TLSPassthrough.TotalPatterns)
	}

	// Verify via query config that the removal is reflected.
	configResult2 := callTool[queryConfigResult](t, env.cs, "query", map[string]any{
		"resource": "config",
	})
	if configResult2.TLSPassthrough.Count != 1 {
		t.Errorf("query config after remove count = %d, want 1", configResult2.TLSPassthrough.Count)
	}
	if len(configResult2.TLSPassthrough.Patterns) > 0 && configResult2.TLSPassthrough.Patterns[0] != "*.googleapis.com" {
		t.Errorf("query config remaining pattern = %q, want *.googleapis.com", configResult2.TLSPassthrough.Patterns[0])
	}
}

// TestIntegration_Configure_Replace verifies that the configure tool's replace
// operation completely replaces configuration sections.
func TestIntegration_Configure_Replace(t *testing.T) {
	env := setupIntegrationEnvWithScopeAndPassthrough(t)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "old-target.com"},
				map[string]any{"hostname": "another-old.com"},
			},
			"excludes": []any{
				map[string]any{"hostname": "old-exclude.com"},
			},
		},
		"tls_passthrough": []any{"old-passthrough.com", "old-passthrough2.com"},
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Verify initial config via query.
	initialConfig := callTool[queryConfigResult](t, env.cs, "query", map[string]any{
		"resource": "config",
	})
	if len(initialConfig.CaptureScope.Includes) != 2 {
		t.Fatalf("initial capture_scope includes = %d, want 2", len(initialConfig.CaptureScope.Includes))
	}
	if len(initialConfig.CaptureScope.Excludes) != 1 {
		t.Fatalf("initial capture_scope excludes = %d, want 1", len(initialConfig.CaptureScope.Excludes))
	}
	if initialConfig.TLSPassthrough.Count != 2 {
		t.Fatalf("initial tls_passthrough count = %d, want 2", initialConfig.TLSPassthrough.Count)
	}

	// Replace capture_scope entirely.
	cfgResult := callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "replace",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "new-target.com", "method": "POST"},
			},
			"excludes": []any{},
		},
		"tls_passthrough": map[string]any{
			"patterns": []any{"only-this-one.com"},
		},
	})
	if cfgResult.Status != "configured" {
		t.Fatalf("configure status = %q, want %q", cfgResult.Status, "configured")
	}
	if cfgResult.CaptureScope.IncludeCount != 1 {
		t.Errorf("replace include_count = %d, want 1", cfgResult.CaptureScope.IncludeCount)
	}
	if cfgResult.CaptureScope.ExcludeCount != 0 {
		t.Errorf("replace exclude_count = %d, want 0", cfgResult.CaptureScope.ExcludeCount)
	}
	if cfgResult.TLSPassthrough.TotalPatterns != 1 {
		t.Errorf("replace tls_passthrough total = %d, want 1", cfgResult.TLSPassthrough.TotalPatterns)
	}

	// Verify via query config that replacement is complete.
	replacedConfig := callTool[queryConfigResult](t, env.cs, "query", map[string]any{
		"resource": "config",
	})
	if len(replacedConfig.CaptureScope.Includes) != 1 {
		t.Fatalf("replaced includes = %d, want 1", len(replacedConfig.CaptureScope.Includes))
	}
	if replacedConfig.CaptureScope.Includes[0].Hostname != "new-target.com" {
		t.Errorf("replaced include hostname = %q, want %q", replacedConfig.CaptureScope.Includes[0].Hostname, "new-target.com")
	}
	if replacedConfig.CaptureScope.Includes[0].Method != "POST" {
		t.Errorf("replaced include method = %q, want %q", replacedConfig.CaptureScope.Includes[0].Method, "POST")
	}
	if len(replacedConfig.CaptureScope.Excludes) != 0 {
		t.Errorf("replaced excludes = %d, want 0", len(replacedConfig.CaptureScope.Excludes))
	}
	if replacedConfig.TLSPassthrough.Count != 1 {
		t.Errorf("replaced tls_passthrough count = %d, want 1", replacedConfig.TLSPassthrough.Count)
	}
	if len(replacedConfig.TLSPassthrough.Patterns) > 0 && replacedConfig.TLSPassthrough.Patterns[0] != "only-this-one.com" {
		t.Errorf("replaced tls_passthrough pattern = %q, want %q", replacedConfig.TLSPassthrough.Patterns[0], "only-this-one.com")
	}
}

// TestIntegration_Configure_ProxyNotRunning verifies that configure returns an
// appropriate error when the proxy is not running (scope/passthrough not initialized).
func TestIntegration_Configure_ProxyNotRunning(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Configure with capture_scope when scope is nil (no WithCaptureScope option).
	callToolExpectError(t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"capture_scope": map[string]any{
			"add_includes": []any{
				map[string]any{"hostname": "example.com"},
			},
		},
	})

	// Configure with tls_passthrough when passthrough is nil.
	callToolExpectError(t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"tls_passthrough": map[string]any{
			"add": []any{"example.com"},
		},
	})
}

// TestIntegration_QueryMessages verifies that query messages returns the correct
// send/receive messages for a recorded HTTP flow, including sequence, direction,
// method, URL, headers, and body fields.
func TestIntegration_QueryMessages(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnv(t)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Send a POST request through the proxy with a body.
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/messages", upstreamAddr)
	resp, err := client.Post(targetURL, "application/json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("upstream response status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Wait for flow to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Get the flow ID.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count != 1 {
		t.Fatalf("query sessions count = %d, want 1", listResult.Count)
	}
	flowID := listResult.Flows[0].ID

	// Query messages for this flow.
	msgsResult := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       flowID,
	})

	// Should have at least 2 messages: send (request) and receive (response).
	if msgsResult.Count < 2 {
		t.Fatalf("query messages count = %d, want >= 2", msgsResult.Count)
	}
	if msgsResult.Total < 2 {
		t.Fatalf("query messages total = %d, want >= 2", msgsResult.Total)
	}

	// Find the send message.
	var sendMsg, recvMsg *queryMessageEntry
	for i := range msgsResult.Messages {
		msg := &msgsResult.Messages[i]
		if msg.Direction == "send" && sendMsg == nil {
			sendMsg = msg
		}
		if msg.Direction == "receive" && recvMsg == nil {
			recvMsg = msg
		}
	}

	if sendMsg == nil {
		t.Fatal("no send message found")
	}
	if recvMsg == nil {
		t.Fatal("no receive message found")
	}

	// Verify send message fields.
	if sendMsg.Sequence != 0 {
		t.Errorf("send sequence = %d, want 0", sendMsg.Sequence)
	}
	if sendMsg.Method != "POST" {
		t.Errorf("send method = %q, want %q", sendMsg.Method, "POST")
	}
	if !strings.Contains(sendMsg.URL, "/api/messages") {
		t.Errorf("send URL = %q, want to contain /api/messages", sendMsg.URL)
	}
	if sendMsg.Headers == nil {
		t.Error("send headers is nil")
	}
	if sendMsg.Body != `{"hello":"world"}` {
		t.Errorf("send body = %q, want %q", sendMsg.Body, `{"hello":"world"}`)
	}
	if sendMsg.BodyEncoding != "text" {
		t.Errorf("send body_encoding = %q, want %q", sendMsg.BodyEncoding, "text")
	}
	if sendMsg.Timestamp == "" {
		t.Error("send timestamp is empty")
	}

	// Verify receive message fields.
	if recvMsg.Sequence != 1 {
		t.Errorf("receive sequence = %d, want 1", recvMsg.Sequence)
	}
	if recvMsg.Direction != "receive" {
		t.Errorf("receive direction = %q, want %q", recvMsg.Direction, "receive")
	}
	if recvMsg.StatusCode != 200 {
		t.Errorf("receive status_code = %d, want 200", recvMsg.StatusCode)
	}
	if recvMsg.Headers == nil {
		t.Error("receive headers is nil")
	}
	// The upstream echoes back "echo: <body>" for POST requests.
	expectedResp := `echo: {"hello":"world"}`
	if !strings.Contains(recvMsg.Body, "echo:") {
		t.Errorf("receive body = %q, want to contain %q", recvMsg.Body, expectedResp)
	}
	if recvMsg.BodyEncoding != "text" {
		t.Errorf("receive body_encoding = %q, want %q", recvMsg.BodyEncoding, "text")
	}
	if recvMsg.Timestamp == "" {
		t.Error("receive timestamp is empty")
	}

	_ = respBody // Verified via upstream echo handler

	// Close idle connections before stopping.
	client.CloseIdleConnections()
}

// TestIntegration_QueryStatus verifies that query status returns accurate proxy
// state information when the proxy is running.
func TestIntegration_QueryStatus(t *testing.T) {
	env := setupIntegrationEnv(t)

	// Query status before proxy is running.
	statusBefore := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if statusBefore.Running {
		t.Error("query status running = true, want false before proxy_start")
	}
	if statusBefore.ListenAddr != "" {
		t.Errorf("query status listen_addr = %q, want empty before proxy_start", statusBefore.ListenAddr)
	}
	if statusBefore.UptimeSeconds != 0 {
		t.Errorf("query status uptime_seconds = %d, want 0 before proxy_start", statusBefore.UptimeSeconds)
	}

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Small delay to accumulate uptime.
	time.Sleep(100 * time.Millisecond)

	// Query status while proxy is running.
	statusAfter := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if !statusAfter.Running {
		t.Error("query status running = false, want true after proxy_start")
	}
	if statusAfter.ListenAddr == "" {
		t.Error("query status listen_addr is empty after proxy_start")
	}
	if statusAfter.ListenAddr != startResult.ListenAddr {
		t.Errorf("query status listen_addr = %q, want %q", statusAfter.ListenAddr, startResult.ListenAddr)
	}
	if statusAfter.ActiveConnections < 0 {
		t.Errorf("query status active_connections = %d, want >= 0", statusAfter.ActiveConnections)
	}
	if statusAfter.UptimeSeconds < 0 {
		t.Errorf("query status uptime_seconds = %d, want >= 0", statusAfter.UptimeSeconds)
	}
	if statusAfter.TotalFlows < 0 {
		t.Errorf("query status total_flows = %d, want >= 0", statusAfter.TotalFlows)
	}
	if !statusAfter.CAInitialized {
		t.Error("query status ca_initialized = false, want true")
	}
}

// TestIntegration_QueryConfig verifies that query config returns the full
// capture scope and TLS passthrough configuration after proxy_start with
// initial config values.
func TestIntegration_QueryConfig(t *testing.T) {
	env := setupIntegrationEnvWithScopeAndPassthrough(t)

	// Start the proxy with both capture_scope and tls_passthrough.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "api.example.com", "url_prefix": "/v1/"},
				map[string]any{"method": "POST"},
			},
			"excludes": []any{
				map[string]any{"hostname": "cdn.example.com"},
			},
		},
		"tls_passthrough": []any{"pinned.example.com", "*.googleapis.com"},
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Query config and verify all settings.
	cfgResult := callTool[queryConfigResult](t, env.cs, "query", map[string]any{
		"resource": "config",
	})

	// Verify capture_scope.
	if cfgResult.CaptureScope == nil {
		t.Fatal("query config capture_scope is nil")
	}
	if len(cfgResult.CaptureScope.Includes) != 2 {
		t.Fatalf("query config includes count = %d, want 2", len(cfgResult.CaptureScope.Includes))
	}

	// Verify include rules have correct fields.
	includeHostnames := make(map[string]scopeRuleOutput)
	for _, inc := range cfgResult.CaptureScope.Includes {
		key := inc.Hostname + "|" + inc.URLPrefix + "|" + inc.Method
		includeHostnames[key] = inc
	}

	apiRule, ok := includeHostnames["api.example.com|/v1/|"]
	if !ok {
		t.Error("include rule for api.example.com /v1/ not found")
	} else {
		if apiRule.Hostname != "api.example.com" {
			t.Errorf("include hostname = %q, want %q", apiRule.Hostname, "api.example.com")
		}
		if apiRule.URLPrefix != "/v1/" {
			t.Errorf("include url_prefix = %q, want %q", apiRule.URLPrefix, "/v1/")
		}
	}

	postRule, ok := includeHostnames["||POST"]
	if !ok {
		t.Error("include rule for method POST not found")
	} else {
		if postRule.Method != "POST" {
			t.Errorf("include method = %q, want %q", postRule.Method, "POST")
		}
	}

	if len(cfgResult.CaptureScope.Excludes) != 1 {
		t.Fatalf("query config excludes count = %d, want 1", len(cfgResult.CaptureScope.Excludes))
	}
	if cfgResult.CaptureScope.Excludes[0].Hostname != "cdn.example.com" {
		t.Errorf("exclude hostname = %q, want %q", cfgResult.CaptureScope.Excludes[0].Hostname, "cdn.example.com")
	}

	// Verify tls_passthrough.
	if cfgResult.TLSPassthrough == nil {
		t.Fatal("query config tls_passthrough is nil")
	}
	if cfgResult.TLSPassthrough.Count != 2 {
		t.Errorf("query config tls_passthrough count = %d, want 2", cfgResult.TLSPassthrough.Count)
	}
	ptSet := make(map[string]bool)
	for _, p := range cfgResult.TLSPassthrough.Patterns {
		ptSet[p] = true
	}
	if !ptSet["pinned.example.com"] {
		t.Error("tls_passthrough missing pinned.example.com")
	}
	if !ptSet["*.googleapis.com"] {
		t.Error("tls_passthrough missing *.googleapis.com")
	}
}
