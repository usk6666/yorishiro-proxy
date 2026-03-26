//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// clientTestEnv holds the components for a CLI client e2e test.
type clientTestEnv struct {
	addr    string
	token   string
	cancel  context.CancelFunc
	errCh   chan error
	store   flow.Store
	manager *proxy.Manager
}

// setupClientTestEnv creates an MCP server for CLI client e2e tests.
// It starts the HTTP MCP transport on a dynamically-allocated port.
func setupClientTestEnv(t *testing.T) *clientTestEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	dbPath := filepath.Join(t.TempDir(), "client-e2e.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		cancel()
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		cancel()
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	httpHandler := protohttp.NewHandler(store, issuer, logger)
	detector := protocol.NewDetector(httpHandler)
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	token := "test-e2e-token"
	opts := []mcp.ServerOption{
		mcp.WithDBPath(dbPath),
		mcp.WithMiddleware(func(next http.Handler) http.Handler {
			return mcp.BearerAuthMiddleware(next, token)
		}),
	}
	mcpServer := mcp.NewServer(ctx, ca, store, manager, opts...)

	// Use :0 and the onListening callback to avoid port race conditions.
	// RunHTTP binds the listener internally, so there is no window where
	// another process could steal the port.
	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- mcpServer.RunHTTP(ctx, "127.0.0.1:0", func(addr string) {
			addrCh <- addr
		})
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		cancel()
		t.Fatalf("server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("server did not start within 5s")
	}

	env := &clientTestEnv{
		addr:    addr,
		token:   token,
		cancel:  cancel,
		errCh:   errCh,
		store:   store,
		manager: manager,
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
		}
	})
	return env
}

// setupTempServerJSON creates a temp server.json with the given entries and
// overrides the serverJSONPathFunc to point to it.
func setupTempServerJSON(t *testing.T, entries []ServerJSON) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshal server.json: %v", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatalf("write server.json: %v", err)
	}
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return path, nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })
	return path
}

// newMCPSession creates an MCP client session connected to the test server.
func newMCPSession(t *testing.T, ctx context.Context, addr, token string) *gomcp.ClientSession {
	t.Helper()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &bearerRoundTripper{
			token: token,
			base:  http.DefaultTransport,
		},
	}
	transport := &gomcp.StreamableClientTransport{
		Endpoint:   fmt.Sprintf("http://%s/mcp", addr),
		HTTPClient: httpClient,
	}
	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "client-e2e-test",
		Version: "0.1",
	}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("MCP client connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

// --- e2e Test: Server Startup + server.json ---

func TestClientE2E_ServerStartup_ServerJSON(t *testing.T) {
	env := setupClientTestEnv(t)

	// Write server.json mimicking what startServers does.
	path := setupTempServerJSON(t, []ServerJSON{
		{
			Addr:      env.addr,
			Token:     env.token,
			PID:       os.Getpid(),
			StartedAt: time.Now().UTC(),
		},
	})

	// Verify server.json contents.
	entries, err := readServerJSONSlice(path)
	if err != nil {
		t.Fatalf("readServerJSONSlice: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Addr != env.addr {
		t.Errorf("Addr = %q, want %q", entries[0].Addr, env.addr)
	}
	if entries[0].Token != env.token {
		t.Errorf("Token = %q, want %q", entries[0].Token, env.token)
	}
}

// --- e2e Test: Client Connection + ListTools ---

func TestClientE2E_ClientConnect_ListTools(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if result == nil || len(result.Tools) == 0 {
		t.Fatal("ListTools returned no tools")
	}

	// Verify essential tools are present.
	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}
	requiredTools := []string{"query", "proxy_start", "proxy_stop", "configure", "resend"}
	for _, name := range requiredTools {
		if !toolNames[name] {
			t.Errorf("expected tool %q in ListTools result", name)
		}
	}
}

// --- e2e Test: Client Query Status ---

func TestClientE2E_QueryStatus(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool query status: %v", err)
	}
	if result.IsError {
		t.Fatalf("query status returned error: %+v", result)
	}

	// Extract text content and verify it contains expected status fields.
	text := extractTextFromResult(t, result)
	if !strings.Contains(text, "running") {
		t.Errorf("status response missing 'running' field: %s", text)
	}
}

// --- e2e Test: proxy_start + query flows ---

func TestClientE2E_ProxyStart_QueryFlows(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	// Start the proxy.
	startResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool proxy_start: %v", err)
	}
	if startResult.IsError {
		t.Fatalf("proxy_start returned error: %s", extractTextFromResult(t, startResult))
	}

	// Query flows (should be empty initially).
	flowsResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "flows",
		},
	})
	if err != nil {
		t.Fatalf("CallTool query flows: %v", err)
	}
	if flowsResult.IsError {
		t.Fatalf("query flows returned error: %s", extractTextFromResult(t, flowsResult))
	}

	// Stop the proxy.
	stopResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool proxy_stop: %v", err)
	}
	if stopResult.IsError {
		t.Fatalf("proxy_stop returned error: %s", extractTextFromResult(t, stopResult))
	}
}

// --- e2e Test: configure + query config ---

func TestClientE2E_Configure_QueryConfig(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	// Configure upstream proxy (merge mode).
	configResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"operation":      "merge",
			"upstream_proxy": "http://proxy.example.com:8888",
		},
	})
	if err != nil {
		t.Fatalf("CallTool configure: %v", err)
	}
	if configResult.IsError {
		t.Fatalf("configure returned error: %s", extractTextFromResult(t, configResult))
	}

	// Query config to verify the change.
	queryResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "config",
		},
	})
	if err != nil {
		t.Fatalf("CallTool query config: %v", err)
	}
	if queryResult.IsError {
		t.Fatalf("query config returned error: %s", extractTextFromResult(t, queryResult))
	}

	text := extractTextFromResult(t, queryResult)
	if !strings.Contains(text, "proxy.example.com") {
		t.Errorf("config response should contain configured upstream_proxy, got: %s", text)
	}
}

// --- e2e Test: Auto-detection via server.json ---

func TestClientE2E_AutoDetection_ServerJSON(t *testing.T) {
	env := setupClientTestEnv(t)

	// Write a server.json with the live server's address and token.
	setupTempServerJSON(t, []ServerJSON{
		{
			Addr:      env.addr,
			Token:     env.token,
			PID:       os.Getpid(),
			StartedAt: time.Now().UTC(),
		},
	})

	// Clear env vars to force server.json auto-detection.
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	// resolveClientConn should detect the server from server.json.
	addr, token, err := resolveClientConn("", "")
	if err != nil {
		t.Fatalf("resolveClientConn auto-detect: %v", err)
	}
	if addr != env.addr {
		t.Errorf("addr = %q, want %q", addr, env.addr)
	}
	if token != env.token {
		t.Errorf("token = %q, want %q", token, env.token)
	}
}

// --- e2e Test: Explicit --addr / --token flags ---

func TestClientE2E_ExplicitFlags(t *testing.T) {
	env := setupClientTestEnv(t)

	// Point server.json to a different (wrong) address.
	setupTempServerJSON(t, []ServerJSON{
		{
			Addr:      "127.0.0.1:1",
			Token:     "wrong-token",
			PID:       os.Getpid(),
			StartedAt: time.Now().UTC(),
		},
	})

	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	// Explicit flags should override server.json.
	addr, token, err := resolveClientConn(env.addr, env.token)
	if err != nil {
		t.Fatalf("resolveClientConn: %v", err)
	}
	if addr != env.addr {
		t.Errorf("addr = %q, want %q", addr, env.addr)
	}
	if token != env.token {
		t.Errorf("token = %q, want %q", token, env.token)
	}

	// Verify actual MCP connection works with these resolved values.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, addr, token)
	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool query status with explicit flags: %v", err)
	}
	if result.IsError {
		t.Fatalf("query status returned error: %s", extractTextFromResult(t, result))
	}
}

// --- e2e Test: Invalid Tool Name ---

func TestClientE2E_InvalidToolName(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "nonexistent_tool_xyz",
		Arguments: map[string]any{
			"resource": "flows",
		},
	})
	// The MCP SDK may return an error or a result with IsError=true.
	if err != nil {
		// Expected: server returns an error for unknown tool.
		return
	}
	if result != nil && !result.IsError {
		t.Error("expected error or IsError=true for unknown tool, got success")
	}
}

// --- e2e Test: Invalid Parameters ---

func TestClientE2E_InvalidParameters(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	// Call query with an invalid resource name.
	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "invalid_resource_xyz",
		},
	})
	if err != nil {
		// Error is acceptable for invalid params.
		return
	}
	if result != nil && !result.IsError {
		// The server may accept unknown resources gracefully;
		// the important thing is it does not crash.
		// Verify the server is still responding.
		statusResult, err := session.CallTool(ctx, &gomcp.CallToolParams{
			Name: "query",
			Arguments: map[string]any{
				"resource": "status",
			},
		})
		if err != nil {
			t.Fatalf("server became unhealthy after invalid params: %v", err)
		}
		if statusResult.IsError {
			t.Fatalf("server returned error for status after invalid params")
		}
	}
}

// --- e2e Test: Server Not Running ---

func TestClientE2E_ServerNotRunning(t *testing.T) {
	// Point to a port that no one is listening on.
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	dir := t.TempDir()
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) {
		return filepath.Join(dir, "server.json"), nil
	}
	t.Cleanup(func() { serverJSONPathFunc = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := runClientTool(ctx, "query", []string{"-server-addr=127.0.0.1:1", "resource=status"})
	if err == nil {
		t.Error("expected error when server is not running, got nil")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("error should mention connection failure, got: %v", err)
	}
}

// --- e2e Test: resend tool (basic call) ---

func TestClientE2E_Resend_NoFlowID(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	// Call resend with a non-existent flow_id; should return an error.
	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action":  "resend",
			"flow_id": "nonexistent-flow-id",
		},
	})
	if err != nil {
		// Error is acceptable for invalid flow_id.
		return
	}
	if result != nil && !result.IsError {
		t.Error("expected error for resend with nonexistent flow_id, got success")
	}
}

// --- e2e Test: formatResult output modes ---

func TestClientE2E_FormatResult_JSONAndTable(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	// Get a status result.
	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool query status: %v", err)
	}

	// Test JSON format.
	var jsonBuf bytes.Buffer
	if err := printToolResult(&jsonBuf, "query", result, "json", false, false); err != nil {
		t.Fatalf("printToolResult json: %v", err)
	}
	if jsonBuf.Len() == 0 {
		t.Error("JSON output is empty")
	}

	// Test table format.
	var tableBuf bytes.Buffer
	if err := printToolResult(&tableBuf, "query", result, "table", false, false); err != nil {
		t.Fatalf("printToolResult table: %v", err)
	}
	if tableBuf.Len() == 0 {
		t.Error("table output is empty")
	}

	// Test raw format.
	var rawBuf bytes.Buffer
	if err := printToolResult(&rawBuf, "query", result, "raw", false, false); err != nil {
		t.Fatalf("printToolResult raw: %v", err)
	}
	if rawBuf.Len() == 0 {
		t.Error("raw output is empty")
	}

	// Test quiet mode suppresses output on success.
	var quietBuf bytes.Buffer
	if err := printToolResult(&quietBuf, "query", result, "json", true, false); err != nil {
		t.Fatalf("printToolResult quiet: %v", err)
	}
	if quietBuf.Len() != 0 {
		t.Errorf("quiet mode should suppress output, got %d bytes", quietBuf.Len())
	}
}

// --- e2e Test: query ca_cert ---

func TestClientE2E_QueryCACert(t *testing.T) {
	env := setupClientTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	session := newMCPSession(t, ctx, env.addr, env.token)

	result, err := session.CallTool(ctx, &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "ca_cert",
		},
	})
	if err != nil {
		t.Fatalf("CallTool query ca_cert: %v", err)
	}
	if result.IsError {
		t.Fatalf("query ca_cert returned error: %s", extractTextFromResult(t, result))
	}

	text := extractTextFromResult(t, result)
	if !strings.Contains(text, "BEGIN CERTIFICATE") {
		t.Errorf("ca_cert response should contain PEM certificate, got: %.100s...", text)
	}
}

// --- Helper functions ---

// extractTextFromResult extracts the first TextContent from a CallToolResult.
func extractTextFromResult(t *testing.T, result *gomcp.CallToolResult) string {
	t.Helper()
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}
