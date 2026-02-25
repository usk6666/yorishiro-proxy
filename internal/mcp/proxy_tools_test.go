package mcp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// stubDetector is a minimal ProtocolDetector for testing.
type stubDetector struct{}

func (d *stubDetector) Detect(_ []byte) proxy.ProtocolHandler { return nil }

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setupTestSessionWithManager creates an MCP client session with a ProxyManager for testing.
func setupTestSessionWithManager(t *testing.T, manager *proxy.Manager) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, nil, manager)
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

	return cs
}

func TestProxyStart_Success(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	cs := setupTestSessionWithManager(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: map[string]any{"listen_addr": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	// Parse result.
	var out proxyStartResult
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
	if out.ListenAddr == "" {
		t.Error("expected non-empty listen_addr")
	}
}

func TestProxyStart_DefaultAddr(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	cs := setupTestSessionWithManager(t, manager)

	// Call without listen_addr to use default.
	// Note: This will try to bind to 127.0.0.1:8080. If that port is in use,
	// the test may fail, which is acceptable in CI environments.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if result.IsError {
		// Port 127.0.0.1:8080 might be in use; skip the test.
		t.Skipf("proxy_start with default addr failed (port likely in use): %v", result.Content)
	}

	var out proxyStartResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
}

func TestProxyStart_AlreadyRunning(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	cs := setupTestSessionWithManager(t, manager)

	// First start.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: map[string]any{"listen_addr": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("first CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected first start to succeed: %v", result.Content)
	}

	// Second start should fail.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: map[string]any{"listen_addr": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("second CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for double start")
	}
}

func TestProxyStop_Success(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionWithManager(t, manager)

	// Start first.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: map[string]any{"listen_addr": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("CallTool start: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected start to succeed: %v", result.Content)
	}

	// Now stop.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool stop: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected stop to succeed: %v", result.Content)
	}

	var out proxyStopResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Status != "stopped" {
		t.Errorf("status = %q, want %q", out.Status, "stopped")
	}
}

func TestProxyStop_NotRunning(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionWithManager(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for stop when not running")
	}
}

func TestProxyStart_NilManager(t *testing.T) {
	cs := setupTestSessionWithManager(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: map[string]any{"listen_addr": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil manager")
	}
}

func TestProxyStop_NilManager(t *testing.T) {
	cs := setupTestSessionWithManager(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil manager")
	}
}

func TestProxyStartStop_FullCycle(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionWithManager(t, manager)

	// Start.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: map[string]any{"listen_addr": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("CallTool start: %v", err)
	}
	if result.IsError {
		t.Fatalf("start failed: %v", result.Content)
	}

	// Verify running.
	running, _ := manager.Status()
	if !running {
		t.Error("expected manager to be running")
	}

	// Stop.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool stop: %v", err)
	}
	if result.IsError {
		t.Fatalf("stop failed: %v", result.Content)
	}

	// Verify stopped.
	running, _ = manager.Status()
	if running {
		t.Error("expected manager to not be running")
	}

	// Restart.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: map[string]any{"listen_addr": "127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("CallTool restart: %v", err)
	}
	if result.IsError {
		t.Fatalf("restart failed: %v", result.Content)
	}

	// Cleanup.
	manager.Stop(context.Background())
}

// setupTestSessionForStatus creates an MCP client session with all dependencies for proxy_status testing.
func setupTestSessionForStatus(t *testing.T, ca *cert.CA, store session.Store, manager *proxy.Manager, opts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), ca, store, manager, opts...)
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

	return cs
}

func TestProxyStatus_NotRunning(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionForStatus(t, nil, nil, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Running {
		t.Error("expected running = false")
	}
	if out.ListenAddr != "" {
		t.Errorf("expected empty listen_addr, got %q", out.ListenAddr)
	}
	if out.ActiveConnections != 0 {
		t.Errorf("expected active_connections = 0, got %d", out.ActiveConnections)
	}
	if out.UptimeSeconds != 0 {
		t.Errorf("expected uptime_seconds = 0, got %d", out.UptimeSeconds)
	}
}

func TestProxyStatus_Running(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	// Wait briefly so uptime is measurable.
	time.Sleep(50 * time.Millisecond)

	cs := setupTestSessionForStatus(t, nil, nil, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !out.Running {
		t.Error("expected running = true")
	}
	if out.ListenAddr == "" {
		t.Error("expected non-empty listen_addr")
	}
	if out.ActiveConnections != 0 {
		t.Errorf("expected active_connections = 0 (no conns), got %d", out.ActiveConnections)
	}
	// Uptime should be at least 0 (could be 0 if less than 1 second).
	if out.UptimeSeconds < 0 {
		t.Errorf("expected uptime_seconds >= 0, got %d", out.UptimeSeconds)
	}
}

func TestProxyStatus_WithCA(t *testing.T) {
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionForStatus(t, ca, nil, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !out.CAInitialized {
		t.Error("expected ca_initialized = true")
	}
}

func TestProxyStatus_WithoutCA(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionForStatus(t, nil, nil, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.CAInitialized {
		t.Error("expected ca_initialized = false")
	}
}

func TestProxyStatus_WithUninitializedCA(t *testing.T) {
	// CA struct exists but has no certificate generated/loaded.
	ca := &cert.CA{}

	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionForStatus(t, ca, nil, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.CAInitialized {
		t.Error("expected ca_initialized = false for uninitialized CA")
	}
}

func TestProxyStatus_WithSessionCount(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := newTestLogger()
	store, err := session.NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Save some sessions.
	for i := 0; i < 3; i++ {
		u, _ := url.Parse("http://example.com/test")
		sess := &session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		}
		if err := store.SaveSession(context.Background(), sess); err != nil {
			t.Fatalf("SaveSession: %v", err)
		}
		if err := store.AppendMessage(context.Background(), &session.Message{
			SessionID: sess.ID,
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Host": {"example.com"}},
		}); err != nil {
			t.Fatalf("AppendMessage(send): %v", err)
		}
		if err := store.AppendMessage(context.Background(), &session.Message{
			SessionID:  sess.ID,
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
		}); err != nil {
			t.Fatalf("AppendMessage(recv): %v", err)
		}
	}

	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionForStatus(t, nil, store, manager, WithDBPath(dbPath))

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.TotalSessions != 3 {
		t.Errorf("total_sessions = %d, want 3", out.TotalSessions)
	}
	if out.DBSizeBytes <= 0 {
		t.Errorf("db_size_bytes = %d, want > 0", out.DBSizeBytes)
	}
}

func TestProxyStatus_DBSizeUnavailable(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// No dbPath set — should return -1 for db_size_bytes.
	cs := setupTestSessionForStatus(t, nil, nil, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.DBSizeBytes != -1 {
		t.Errorf("db_size_bytes = %d, want -1 (unavailable)", out.DBSizeBytes)
	}
}

func TestProxyStatus_DBPathNonexistent(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// Set a non-existent dbPath — should return -1.
	cs := setupTestSessionForStatus(t, nil, nil, manager, WithDBPath("/nonexistent/path/db.sqlite"))

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.DBSizeBytes != -1 {
		t.Errorf("db_size_bytes = %d, want -1 (nonexistent path)", out.DBSizeBytes)
	}
}

func TestProxyStatus_NilManagerAndStore(t *testing.T) {
	// All nil dependencies — should still succeed with zero/default values.
	cs := setupTestSessionForStatus(t, nil, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out proxyStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Running {
		t.Error("expected running = false")
	}
	if out.ListenAddr != "" {
		t.Errorf("expected empty listen_addr, got %q", out.ListenAddr)
	}
	if out.ActiveConnections != 0 {
		t.Errorf("expected active_connections = 0, got %d", out.ActiveConnections)
	}
	if out.TotalSessions != 0 {
		t.Errorf("expected total_sessions = 0, got %d", out.TotalSessions)
	}
	if out.DBSizeBytes != -1 {
		t.Errorf("expected db_size_bytes = -1, got %d", out.DBSizeBytes)
	}
	if out.UptimeSeconds != 0 {
		t.Errorf("expected uptime_seconds = 0, got %d", out.UptimeSeconds)
	}
	if out.CAInitialized {
		t.Error("expected ca_initialized = false")
	}
}

func TestProxyStatus_ResponseFields(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	cs := setupTestSessionForStatus(t, nil, nil, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_status",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	textContent := result.Content[0].(*gomcp.TextContent)

	// Verify all expected fields are present in the JSON response.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(textContent.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	expectedFields := []string{
		"running",
		"listen_addr",
		"active_connections",
		"total_sessions",
		"db_size_bytes",
		"uptime_seconds",
		"ca_initialized",
	}
	for _, field := range expectedFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("response JSON does not contain %q field", field)
		}
	}
}
