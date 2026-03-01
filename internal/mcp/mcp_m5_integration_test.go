package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// --- M5 Integration Test Helpers ---

// m5HTTPEnv holds the components needed for an HTTP-transport MCP integration test.
type m5HTTPEnv struct {
	mcpServer *Server
	store     session.Store
	manager   *proxy.Manager
	addr      string // HTTP server listen address (127.0.0.1:<port>)
	token     string // Bearer token for authentication
	cancel    context.CancelFunc
	errCh     chan error
	stopped   sync.Once // ensures cancel+drain only happens once
}

// setupM5HTTPEnv creates a fully-wired MCP server environment and starts
// the Streamable HTTP transport on a dynamically-allocated loopback port.
// If token is non-empty, Bearer token authentication is enabled.
func setupM5HTTPEnv(t *testing.T, token string) *m5HTTPEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	// Create a temporary SQLite store.
	dbPath := filepath.Join(t.TempDir(), "m5-integration.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		cancel()
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Generate an ephemeral CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		cancel()
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	// Build protocol handlers and detector.
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager.
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	// Build MCP server options.
	opts := []ServerOption{
		WithDBPath(dbPath),
	}
	if token != "" {
		opts = append(opts, WithMiddleware(func(next http.Handler) http.Handler {
			return BearerAuthMiddleware(next, token)
		}))
	}

	mcpServer := NewServer(ctx, ca, store, manager, opts...)

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// Start the HTTP server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- mcpServer.RunHTTP(ctx, addr)
	}()

	// Wait for the server to start.
	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		cancel()
		t.Fatalf("HTTP server did not start: %v", err)
	}

	env := &m5HTTPEnv{
		mcpServer: mcpServer,
		store:     store,
		manager:   manager,
		addr:      addr,
		token:     token,
		cancel:    cancel,
		errCh:     errCh,
	}

	t.Cleanup(func() {
		env.shutdown()
	})

	return env
}

// shutdown cancels the server context and drains the error channel exactly once.
func (e *m5HTTPEnv) shutdown() {
	e.stopped.Do(func() {
		e.cancel()
		select {
		case <-e.errCh:
		case <-time.After(10 * time.Second):
		}
	})
}

// bearerRoundTripper adds a Bearer token to every outgoing HTTP request.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (t *bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

// newHTTPMCPClient creates an MCP ClientSession connected via Streamable HTTP.
// If token is non-empty, Bearer token authentication is injected.
func newHTTPMCPClient(t *testing.T, ctx context.Context, addr, token string) *gomcp.ClientSession {
	t.Helper()

	httpClient := &http.Client{Timeout: 10 * time.Second}
	if token != "" {
		httpClient.Transport = &bearerRoundTripper{
			token: token,
			base:  http.DefaultTransport,
		}
	}

	transport := &gomcp.StreamableClientTransport{
		Endpoint:            fmt.Sprintf("http://%s/mcp", addr),
		HTTPClient:          httpClient,
		MaxRetries:          -1,   // disable retries for tests
		DisableStandaloneSSE: true, // simpler for tests
	}

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "m5-test-client",
		Version: "0.1",
	}, nil)

	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("MCP client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// --- Test: HTTP Transport Basic Operations ---

// TestM5_HTTPTransport_BasicOperations tests the full lifecycle over Streamable HTTP:
// connect -> proxy_start -> HTTP request -> query sessions -> verify.
func TestM5_HTTPTransport_BasicOperations(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)
	ctx := context.Background()

	// Connect MCP client via Streamable HTTP.
	cs := newHTTPMCPClient(t, ctx, env.addr, token)

	// List tools to verify connection works.
	toolsResult, err := cs.ListTools(ctx, &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	expectedTools := []string{"proxy_start", "proxy_stop", "configure", "query", "execute"}
	toolSet := make(map[string]bool)
	for _, tool := range toolsResult.Tools {
		toolSet[tool.Name] = true
	}
	for _, name := range expectedTools {
		if !toolSet[name] {
			t.Errorf("expected tool %q not found", name)
		}
	}

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}
	if startResult.ListenAddr == "" {
		t.Fatal("proxy_start returned empty listen_addr")
	}

	// Send an HTTP request through the proxy.
	upstreamAddr := startUpstreamServer(t)
	proxyClient := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/m5-test", upstreamAddr)
	resp, err := proxyClient.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upstream status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Wait for session persistence.
	time.Sleep(200 * time.Millisecond)

	// Query sessions via HTTP MCP client.
	listResult := callTool[querySessionsResult](t, cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("query sessions count = %d, want 1", listResult.Count)
	}
	entry := listResult.Sessions[0]
	if entry.Method != "GET" {
		t.Errorf("session method = %q, want %q", entry.Method, "GET")
	}
	if !strings.Contains(entry.URL, "/api/m5-test") {
		t.Errorf("session URL = %q, want to contain /api/m5-test", entry.URL)
	}

	// Query session detail.
	detailResult := callTool[querySessionResult](t, cs, "query", map[string]any{
		"resource": "session",
		"id":       entry.ID,
	})
	if detailResult.ID != entry.ID {
		t.Errorf("session detail ID = %q, want %q", detailResult.ID, entry.ID)
	}
	if detailResult.ResponseStatusCode != 200 {
		t.Errorf("session response status = %d, want 200", detailResult.ResponseStatusCode)
	}

	// Query status.
	statusResult := callTool[queryStatusResult](t, cs, "query", map[string]any{
		"resource": "status",
	})
	if !statusResult.Running {
		t.Error("query status running = false, want true")
	}
	if statusResult.ListenAddr != startResult.ListenAddr {
		t.Errorf("status listen_addr = %q, want %q", statusResult.ListenAddr, startResult.ListenAddr)
	}

	// Close idle connections before stopping.
	proxyClient.CloseIdleConnections()

	// Stop the proxy.
	stopResult := callTool[proxyStopResult](t, cs, "proxy_stop", nil)
	if stopResult.Status != "stopped" {
		t.Errorf("proxy_stop status = %q, want %q", stopResult.Status, "stopped")
	}
}

// --- Test: Multi-Client Concurrent Access ---

// TestM5_MultiClient_ConcurrentAccess tests that multiple MCP clients can
// connect simultaneously via Streamable HTTP and perform independent operations.
func TestM5_MultiClient_ConcurrentAccess(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)
	ctx := context.Background()

	// Create two independent MCP clients.
	cs1 := newHTTPMCPClient(t, ctx, env.addr, token)
	cs2 := newHTTPMCPClient(t, ctx, env.addr, token)

	// Client 1: Start proxy.
	startResult := callTool[proxyStartResult](t, cs1, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Set up upstream and proxy client for generating traffic.
	upstreamAddr := startUpstreamServer(t)
	proxyClient := proxyHTTPClient(startResult.ListenAddr)

	// Send some traffic through the proxy.
	targetURL := fmt.Sprintf("http://%s/api/multi-client", upstreamAddr)
	resp, err := proxyClient.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	// Wait for session persistence.
	time.Sleep(200 * time.Millisecond)

	// Both clients should see the same sessions (shared DB).
	var wg sync.WaitGroup
	var result1, result2 querySessionsResult
	var err1, err2 error

	wg.Add(2)
	go func() {
		defer wg.Done()
		r, e := callToolSafe[querySessionsResult](cs1, "query", map[string]any{
			"resource": "sessions",
		})
		result1 = r
		err1 = e
	}()
	go func() {
		defer wg.Done()
		r, e := callToolSafe[querySessionsResult](cs2, "query", map[string]any{
			"resource": "sessions",
		})
		result2 = r
		err2 = e
	}()
	wg.Wait()

	if err1 != nil {
		t.Fatalf("client1 query sessions: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("client2 query sessions: %v", err2)
	}

	if result1.Count != 1 {
		t.Errorf("client1 sessions count = %d, want 1", result1.Count)
	}
	if result2.Count != 1 {
		t.Errorf("client2 sessions count = %d, want 1", result2.Count)
	}

	// Both clients should return the same session ID.
	if result1.Count > 0 && result2.Count > 0 {
		if result1.Sessions[0].ID != result2.Sessions[0].ID {
			t.Errorf("clients see different session IDs: %q vs %q",
				result1.Sessions[0].ID, result2.Sessions[0].ID)
		}
	}

	// Client 2: Query status while client 1 started the proxy.
	statusResult := callTool[queryStatusResult](t, cs2, "query", map[string]any{
		"resource": "status",
	})
	if !statusResult.Running {
		t.Error("client2 sees proxy as not running")
	}

	// Close idle connections before stopping.
	proxyClient.CloseIdleConnections()
}

// --- Test: Bearer Token Authentication ---

// TestM5_BearerTokenAuth tests Bearer token authentication scenarios via raw HTTP.
func TestM5_BearerTokenAuth(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)

	// Valid MCP initialize request payload.
	initPayload := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}`

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "valid token succeeds",
			authHeader: "Bearer " + token,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing token returns 401",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token returns 401",
			authHeader: "Bearer wrongtoken123456",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong scheme returns 401",
			authHeader: "Basic dXNlcjpwYXNz",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "bearer lowercase returns 401",
			authHeader: "bearer " + token,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty bearer value returns 401",
			authHeader: "Bearer ",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token with extra space returns 401",
			authHeader: "Bearer  " + token,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost,
				fmt.Sprintf("http://%s/mcp", env.addr),
				strings.NewReader(initPayload))
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("HTTP request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("status = %d, want %d; body = %s",
					resp.StatusCode, tt.wantStatus, body)
			}
		})
	}
}

// TestM5_BearerTokenAuth_MCPClientConnect tests that an MCP client with valid
// credentials can connect and call tools, while invalid credentials fail.
func TestM5_BearerTokenAuth_MCPClientConnect(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)
	ctx := context.Background()

	// Valid token: client should connect and call ListTools.
	cs := newHTTPMCPClient(t, ctx, env.addr, token)
	toolsResult, err := cs.ListTools(ctx, &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools with valid token: %v", err)
	}
	if len(toolsResult.Tools) == 0 {
		t.Error("expected at least one tool with valid token")
	}

	// Invalid token: client.Connect should fail.
	badHTTPClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &bearerRoundTripper{
			token: "definitely-wrong-token",
			base:  http.DefaultTransport,
		},
	}
	badTransport := &gomcp.StreamableClientTransport{
		Endpoint:            fmt.Sprintf("http://%s/mcp", env.addr),
		HTTPClient:          badHTTPClient,
		MaxRetries:          -1,
		DisableStandaloneSSE: true,
	}
	badClient := gomcp.NewClient(&gomcp.Implementation{
		Name:    "bad-client",
		Version: "0.1",
	}, nil)

	_, err = badClient.Connect(ctx, badTransport, nil)
	if err == nil {
		t.Fatal("Connect with invalid token should fail")
	}
}

// TestM5_NoAuthMiddleware_NoTokenRequired tests that the HTTP transport
// works without any authentication middleware when no token is configured.
func TestM5_NoAuthMiddleware_NoTokenRequired(t *testing.T) {
	env := setupM5HTTPEnv(t, "") // no token
	ctx := context.Background()

	// Client without any auth header should connect successfully.
	cs := newHTTPMCPClient(t, ctx, env.addr, "")
	toolsResult, err := cs.ListTools(ctx, &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools without auth: %v", err)
	}
	if len(toolsResult.Tools) == 0 {
		t.Error("expected at least one tool")
	}
}

// --- Test: Graceful Shutdown ---

// TestM5_GracefulShutdown tests that the HTTP server shuts down gracefully
// when the context is cancelled.
func TestM5_GracefulShutdown(t *testing.T) {
	// Override shutdown timeout for faster test.
	origTimeout := shutdownTimeout
	shutdownTimeout = 2 * time.Second
	t.Cleanup(func() { shutdownTimeout = origTimeout })

	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)
	ctx := context.Background()

	// Connect MCP client and verify it works.
	cs := newHTTPMCPClient(t, ctx, env.addr, token)
	_, err = cs.ListTools(ctx, &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	// Cancel the server context to trigger shutdown.
	env.shutdown()

	// Server should no longer accept connections.
	_, err = net.DialTimeout("tcp", env.addr, 1*time.Second)
	if err == nil {
		t.Error("server still accepting connections after shutdown")
	}
}

// TestM5_GracefulShutdown_WithActiveProxy tests shutdown with an active proxy.
func TestM5_GracefulShutdown_WithActiveProxy(t *testing.T) {
	origTimeout := shutdownTimeout
	shutdownTimeout = 2 * time.Second
	t.Cleanup(func() { shutdownTimeout = origTimeout })

	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)
	ctx := context.Background()

	// Start proxy via MCP.
	cs := newHTTPMCPClient(t, ctx, env.addr, token)
	startResult := callTool[proxyStartResult](t, cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Cancel the server context and wait for shutdown.
	env.shutdown()
}

// --- Test: HTTP Transport Without Auth (Optional Middleware) ---

// TestM5_HTTPTransport_ToolOperations tests various tool operations over HTTP
// transport: configure, execute delete_sessions.
func TestM5_HTTPTransport_ToolOperations(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)
	ctx := context.Background()

	cs := newHTTPMCPClient(t, ctx, env.addr, token)

	// Query status before proxy start.
	statusBefore := callTool[queryStatusResult](t, cs, "query", map[string]any{
		"resource": "status",
	})
	if statusBefore.Running {
		t.Error("proxy should not be running before start")
	}

	// Start proxy.
	startResult := callTool[proxyStartResult](t, cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Send traffic.
	upstreamAddr := startUpstreamServer(t)
	proxyClient := proxyHTTPClient(startResult.ListenAddr)
	resp, err := proxyClient.Post(
		fmt.Sprintf("http://%s/api/tool-test", upstreamAddr),
		"application/json",
		strings.NewReader(`{"test":"data"}`),
	)
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	resp.Body.Close()

	time.Sleep(200 * time.Millisecond)

	// Verify session exists.
	listResult := callTool[querySessionsResult](t, cs, "query", map[string]any{
		"resource": "sessions",
	})
	if listResult.Count != 1 {
		t.Fatalf("sessions count = %d, want 1", listResult.Count)
	}

	sessionID := listResult.Sessions[0].ID

	// Query messages.
	msgsResult := callTool[queryMessagesResult](t, cs, "query", map[string]any{
		"resource": "messages",
		"id":       sessionID,
	})
	if msgsResult.Count < 2 {
		t.Fatalf("messages count = %d, want >= 2", msgsResult.Count)
	}

	// Delete session.
	delResult := callTool[executeDeleteSessionsResult](t, cs, "execute", map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"session_id": sessionID,
		},
	})
	if delResult.DeletedCount != 1 {
		t.Errorf("deleted count = %d, want 1", delResult.DeletedCount)
	}

	// Verify deleted.
	emptyResult := callTool[querySessionsResult](t, cs, "query", map[string]any{
		"resource": "sessions",
	})
	if emptyResult.Count != 0 {
		t.Errorf("sessions after delete = %d, want 0", emptyResult.Count)
	}

	// Close idle connections before stopping.
	proxyClient.CloseIdleConnections()

	// Stop proxy.
	stopResult := callTool[proxyStopResult](t, cs, "proxy_stop", nil)
	if stopResult.Status != "stopped" {
		t.Errorf("proxy_stop status = %q, want %q", stopResult.Status, "stopped")
	}
}

// --- Test: Multiple Clients with Independent Tool Calls ---

// TestM5_MultiClient_IndependentToolCalls tests that multiple clients can
// independently call MCP tools without interference.
func TestM5_MultiClient_IndependentToolCalls(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	env := setupM5HTTPEnv(t, token)
	ctx := context.Background()

	const numClients = 3
	clients := make([]*gomcp.ClientSession, numClients)
	for i := range numClients {
		clients[i] = newHTTPMCPClient(t, ctx, env.addr, token)
	}

	// All clients call ListTools concurrently.
	var wg sync.WaitGroup
	errs := make([]error, numClients)

	for i := range numClients {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = clients[idx].ListTools(ctx, &gomcp.ListToolsParams{})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("client %d ListTools: %v", i, err)
		}
	}

	// All clients query status concurrently.
	statusResults := make([]queryStatusResult, numClients)
	statusErrs := make([]error, numClients)

	for i := range numClients {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r, e := callToolSafe[queryStatusResult](clients[idx], "query", map[string]any{
				"resource": "status",
			})
			statusResults[idx] = r
			statusErrs[idx] = e
		}(i)
	}
	wg.Wait()

	for i, err := range statusErrs {
		if err != nil {
			t.Errorf("client %d query status: %v", i, err)
		}
	}

	// All clients should report the same proxy state.
	for i := range numClients {
		if statusResults[i].Running {
			t.Errorf("client %d: proxy should not be running", i)
		}
	}
}

// --- Test: stdio + HTTP Simultaneous Operation ---

// TestM5_StdioAndHTTP_SharedState tests that stdio and HTTP transports share
// state correctly. We simulate this by connecting one client via in-memory
// transport (simulating stdio) and another via HTTP transport, then verifying
// they share the same MCP server state.
func TestM5_StdioAndHTTP_SharedState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create shared components.
	dbPath := filepath.Join(t.TempDir(), "m5-dual.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
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
	detector := protocol.NewDetector(httpHandler)
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	mcpServer := NewServer(ctx, ca, store, manager,
		WithDBPath(dbPath),
		WithMiddleware(func(next http.Handler) http.Handler {
			return BearerAuthMiddleware(next, token)
		}),
	)

	// Start the stdio (in-memory) transport.
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	stdioClient := gomcp.NewClient(&gomcp.Implementation{
		Name:    "stdio-client",
		Version: "0.1",
	}, nil)
	stdioCS, err := stdioClient.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("stdio client connect: %v", err)
	}
	t.Cleanup(func() { stdioCS.Close() })

	// Start the HTTP transport.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpAddr := ln.Addr().String()
	ln.Close()

	httpErrCh := make(chan error, 1)
	go func() {
		httpErrCh <- mcpServer.RunHTTP(ctx, httpAddr)
	}()
	if err := waitForServer(t, httpAddr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// Connect HTTP MCP client.
	httpCS := newHTTPMCPClient(t, ctx, httpAddr, token)

	// stdio client: Start proxy.
	startResult := callTool[proxyStartResult](t, stdioCS, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// HTTP client: Query status and verify proxy is running.
	statusResult := callTool[queryStatusResult](t, httpCS, "query", map[string]any{
		"resource": "status",
	})
	if !statusResult.Running {
		t.Error("HTTP client: proxy not running after stdio client started it")
	}
	if statusResult.ListenAddr != startResult.ListenAddr {
		t.Errorf("HTTP client: listen_addr = %q, want %q",
			statusResult.ListenAddr, startResult.ListenAddr)
	}

	// Generate traffic.
	upstreamAddr := startUpstreamServer(t)
	proxyClient := proxyHTTPClient(startResult.ListenAddr)
	resp, err := proxyClient.Get(fmt.Sprintf("http://%s/api/dual-test", upstreamAddr))
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	time.Sleep(200 * time.Millisecond)

	// HTTP client: Query sessions (should see the session created via stdio proxy).
	httpSessions := callTool[querySessionsResult](t, httpCS, "query", map[string]any{
		"resource": "sessions",
	})
	if httpSessions.Count != 1 {
		t.Fatalf("HTTP client sessions = %d, want 1", httpSessions.Count)
	}

	// stdio client: Also sees the same session.
	stdioSessions := callTool[querySessionsResult](t, stdioCS, "query", map[string]any{
		"resource": "sessions",
	})
	if stdioSessions.Count != 1 {
		t.Fatalf("stdio client sessions = %d, want 1", stdioSessions.Count)
	}

	if httpSessions.Sessions[0].ID != stdioSessions.Sessions[0].ID {
		t.Errorf("session IDs differ: HTTP=%q, stdio=%q",
			httpSessions.Sessions[0].ID, stdioSessions.Sessions[0].ID)
	}

	// Close idle connections before stopping.
	proxyClient.CloseIdleConnections()

	// HTTP client: Stop proxy.
	stopResult := callTool[proxyStopResult](t, httpCS, "proxy_stop", nil)
	if stopResult.Status != "stopped" {
		t.Errorf("proxy_stop status = %q, want %q", stopResult.Status, "stopped")
	}

	// stdio client: Verify proxy is stopped.
	stdioStatus := callTool[queryStatusResult](t, stdioCS, "query", map[string]any{
		"resource": "status",
	})
	if stdioStatus.Running {
		t.Error("stdio client: proxy still running after HTTP client stopped it")
	}
}

// --- Test: HTTP Server Address Validation ---

// TestM5_HTTPServer_RejectsNonLoopback tests that RunHTTP rejects non-loopback
// addresses. This is tested at the unit level already but we verify integration.
func TestM5_HTTPServer_RejectsNonLoopback(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tests := []struct {
		name string
		addr string
	}{
		{"all_interfaces", ":3000"},
		{"explicit_all", "0.0.0.0:3000"},
		{"external_ip", "10.0.0.1:3000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.RunHTTP(ctx, tt.addr)
			if err == nil {
				t.Fatalf("RunHTTP(%q) should reject non-loopback address", tt.addr)
			}
		})
	}
}

// --- Test: Generate Token ---

// TestM5_GenerateToken_Integration tests that GenerateToken produces usable
// tokens for the auth middleware.
func TestM5_GenerateToken_Integration(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	env := setupM5HTTPEnv(t, token)

	// Connect with the generated token.
	ctx := context.Background()
	cs := newHTTPMCPClient(t, ctx, env.addr, token)

	_, err = cs.ListTools(ctx, &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools with generated token: %v", err)
	}
}

// --- Helper: callToolSafe ---

// callToolSafe is a non-fatal variant of callTool for use in goroutines.
func callToolSafe[T any](cs *gomcp.ClientSession, name string, args any) (T, error) {
	var zero T
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		return zero, fmt.Errorf("CallTool(%s): %w", name, err)
	}
	if result.IsError {
		return zero, fmt.Errorf("CallTool(%s) returned error: %v", name, result.Content)
	}
	if len(result.Content) == 0 {
		return zero, fmt.Errorf("CallTool(%s) returned empty content", name)
	}
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		return zero, fmt.Errorf("CallTool(%s) expected TextContent, got %T", name, result.Content[0])
	}
	var out T
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		return zero, fmt.Errorf("CallTool(%s) unmarshal: %w", name, err)
	}
	return out, nil
}
