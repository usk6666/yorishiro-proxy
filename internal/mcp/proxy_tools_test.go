package mcp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
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
