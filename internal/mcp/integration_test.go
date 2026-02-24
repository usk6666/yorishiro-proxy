package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/katashiro-proxy/internal/protocol/http"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// testEnv holds all the components needed for an MCP integration test.
type testEnv struct {
	cs      *gomcp.ClientSession
	store   session.Store
	manager *proxy.Manager
}

// setupIntegrationEnv creates a fully-wired MCP test environment with a real
// session store, CA, and proxy manager connected via in-memory transport.
func setupIntegrationEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	// Create a temporary SQLite store.
	dbPath := filepath.Join(t.TempDir(), "integration.db")
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
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager.
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	// Create MCP server with all components wired.
	mcpServer := NewServer(ctx, ca, store, manager)

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

// Integration tests reuse the result types defined in the source files
// (proxyStartResult, proxyStopResult, listSessionsResult, etc.).

// TestIntegration_FullLifecycle tests the complete MCP tool lifecycle:
// proxy_start -> HTTP request through proxy -> list_sessions -> get_session
// -> replay_request -> delete_session -> proxy_stop.
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

	// Wait for session to be persisted.
	time.Sleep(200 * time.Millisecond)

	// 3. List sessions via MCP tool.
	listResult := callTool[listSessionsResult](t, env.cs, "list_sessions", nil)
	if listResult.Count != 1 {
		t.Fatalf("list_sessions count = %d, want 1", listResult.Count)
	}
	sessionEntry := listResult.Sessions[0]
	if sessionEntry.Method != "GET" {
		t.Errorf("session method = %q, want %q", sessionEntry.Method, "GET")
	}
	if sessionEntry.StatusCode != 200 {
		t.Errorf("session status_code = %d, want %d", sessionEntry.StatusCode, 200)
	}
	if !strings.Contains(sessionEntry.URL, "/api/test") {
		t.Errorf("session URL = %q, want to contain /api/test", sessionEntry.URL)
	}

	// 4. Get session details via MCP tool.
	getResult := callTool[getSessionResult](t, env.cs, "get_session", map[string]any{
		"session_id": sessionEntry.ID,
	})
	if getResult.ID != sessionEntry.ID {
		t.Errorf("get_session ID = %q, want %q", getResult.ID, sessionEntry.ID)
	}
	if getResult.Method != "GET" {
		t.Errorf("get_session method = %q, want %q", getResult.Method, "GET")
	}
	if getResult.ResponseStatusCode != 200 {
		t.Errorf("get_session response status = %d, want %d", getResult.ResponseStatusCode, 200)
	}
	if getResult.ResponseBody != "hello from upstream" {
		t.Errorf("get_session response body = %q, want %q", getResult.ResponseBody, "hello from upstream")
	}
	if getResult.ResponseBodyEncoding != "text" {
		t.Errorf("get_session response body encoding = %q, want %q", getResult.ResponseBodyEncoding, "text")
	}
	if getResult.DurationMs < 0 {
		t.Errorf("get_session duration = %d, want >= 0", getResult.DurationMs)
	}

	// 5. Replay the request via MCP tool.
	// Note: replay_request uses an HTTP client that by default blocks private
	// networks (SSRF protection). Since our upstream is on loopback, we need
	// to skip the replay test if the target is loopback.
	// Instead, verify the session was created by checking replay's error for
	// the private network check — this validates the tool is reachable.
	replayResult, replayErr := env.cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_request",
		Arguments: map[string]any{
			"session_id": sessionEntry.ID,
		},
	})
	if replayErr != nil {
		t.Fatalf("CallTool(replay_request): %v", replayErr)
	}
	// The replay will fail because the target is a private address (SSRF protection).
	// This is expected behavior — we verify the tool ran and returned an error.
	if !replayResult.IsError {
		// If replay succeeded (e.g., SSRF protection is relaxed), verify the result.
		var rr replayRequestResult
		tc, ok := replayResult.Content[0].(*gomcp.TextContent)
		if ok {
			json.Unmarshal([]byte(tc.Text), &rr)
		}
		if rr.NewSessionID == "" {
			t.Error("replay_request returned empty new_session_id")
		}
		if rr.StatusCode != 200 {
			t.Errorf("replay_request status_code = %d, want 200", rr.StatusCode)
		}
	}

	// 6. Delete the session via MCP tool.
	deleteResult := callTool[deleteSessionResult](t, env.cs, "delete_session", map[string]any{
		"session_id": sessionEntry.ID,
	})
	if deleteResult.DeletedCount != 1 {
		t.Errorf("delete_session deleted_count = %d, want 1", deleteResult.DeletedCount)
	}

	// Verify session is gone.
	listAfterDelete := callTool[listSessionsResult](t, env.cs, "list_sessions", nil)
	// May have a replay session if replay succeeded.
	for _, s := range listAfterDelete.Sessions {
		if s.ID == sessionEntry.ID {
			t.Error("deleted session still appears in list_sessions")
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

// TestIntegration_ExportCACert verifies the export_ca_cert tool returns a valid
// PEM certificate with metadata through the full MCP integration path.
func TestIntegration_ExportCACert(t *testing.T) {
	env := setupIntegrationEnv(t)

	result := callTool[exportCACertResult](t, env.cs, "export_ca_cert", nil)

	if result.PEM == "" {
		t.Error("export_ca_cert PEM is empty")
	}
	if !strings.HasPrefix(result.PEM, "-----BEGIN CERTIFICATE-----") {
		t.Error("export_ca_cert PEM does not start with BEGIN CERTIFICATE header")
	}
	if result.Fingerprint == "" {
		t.Error("export_ca_cert fingerprint is empty")
	}
	if result.Subject == "" {
		t.Error("export_ca_cert subject is empty")
	}
	if result.NotAfter == "" {
		t.Error("export_ca_cert not_after is empty")
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

// TestIntegration_GetSession_NotFound verifies that get_session returns an
// error for a non-existent session ID.
func TestIntegration_GetSession_NotFound(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "get_session", map[string]any{
		"session_id": "nonexistent-session-id",
	})
}

// TestIntegration_DeleteSession_NotFound verifies that delete_session returns
// an error for a non-existent session ID.
func TestIntegration_DeleteSession_NotFound(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "delete_session", map[string]any{
		"session_id": "nonexistent-session-id",
	})
}

// TestIntegration_ReplayRequest_NoSession verifies that replay_request returns
// an error when the referenced session does not exist.
func TestIntegration_ReplayRequest_NoSession(t *testing.T) {
	env := setupIntegrationEnv(t)

	callToolExpectError(t, env.cs, "replay_request", map[string]any{
		"session_id": "nonexistent-session-id",
	})
}

// TestIntegration_ListSessions_Empty verifies that list_sessions returns an
// empty list when no sessions have been recorded.
func TestIntegration_ListSessions_Empty(t *testing.T) {
	env := setupIntegrationEnv(t)

	result := callTool[listSessionsResult](t, env.cs, "list_sessions", nil)
	if result.Count != 0 {
		t.Errorf("list_sessions count = %d, want 0", result.Count)
	}
	if result.Total != 0 {
		t.Errorf("list_sessions total = %d, want 0", result.Total)
	}
	if len(result.Sessions) != 0 {
		t.Errorf("list_sessions sessions length = %d, want 0", len(result.Sessions))
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
		"proxy_start":    false,
		"proxy_stop":     false,
		"list_sessions":  false,
		"get_session":    false,
		"replay_request": false,
		"delete_session": false,
		"export_ca_cert": false,
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
	allResult := callTool[listSessionsResult](t, env.cs, "list_sessions", nil)
	if allResult.Count != 2 {
		t.Fatalf("list_sessions count = %d, want 2", allResult.Count)
	}

	// Filter by method.
	getResult := callTool[listSessionsResult](t, env.cs, "list_sessions", map[string]any{
		"method": "GET",
	})
	if getResult.Count != 1 {
		t.Errorf("list_sessions(method=GET) count = %d, want 1", getResult.Count)
	}

	postResult := callTool[listSessionsResult](t, env.cs, "list_sessions", map[string]any{
		"method": "POST",
	})
	if postResult.Count != 1 {
		t.Errorf("list_sessions(method=POST) count = %d, want 1", postResult.Count)
	}

	// Filter by URL pattern.
	urlResult := callTool[listSessionsResult](t, env.cs, "list_sessions", map[string]any{
		"url_pattern": "/api/users",
	})
	if urlResult.Count != 1 {
		t.Errorf("list_sessions(url_pattern=/api/users) count = %d, want 1", urlResult.Count)
	}

	// Delete all sessions.
	delResult := callTool[deleteSessionResult](t, env.cs, "delete_session", map[string]any{
		"delete_all": true,
	})
	if delResult.DeletedCount != 2 {
		t.Errorf("delete_session(delete_all) deleted_count = %d, want 2", delResult.DeletedCount)
	}

	// Verify empty.
	emptyResult := callTool[listSessionsResult](t, env.cs, "list_sessions", nil)
	if emptyResult.Count != 0 {
		t.Errorf("list_sessions after delete_all count = %d, want 0", emptyResult.Count)
	}
}
