package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

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
