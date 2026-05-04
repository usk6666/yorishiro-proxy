package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// setupMultiListenerTestSession creates an MCP client flow with a Manager for
// testing multi-listener features.
func setupMultiListenerTestSession(t *testing.T, manager proxyManager) *gomcp.ClientSession {
	t.Helper()
	return setupTestSessionWithManager(t, manager)
}

func TestProxyStart_WithName(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "http-proxy",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStartResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Name != "http-proxy" {
		t.Errorf("name = %q, want %q", out.Name, "http-proxy")
	}
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
	if out.ListenAddr == "" {
		t.Error("expected non-empty listen_addr")
	}
}

func TestProxyStart_DefaultNameWhenOmitted(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStartResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Name != connector.DefaultListenerName {
		t.Errorf("name = %q, want %q", out.Name, connector.DefaultListenerName)
	}
}

func TestProxyStart_MultipleNamedListeners(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start first listener.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "http",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(http): %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success for http: %v", result.Content)
	}

	// Start second listener on a different name and port.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "grpc",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(grpc): %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success for grpc: %v", result.Content)
	}

	// Verify both are running.
	if got := manager.ListenerCount(); got != 2 {
		t.Errorf("ListenerCount = %d, want 2", got)
	}
}

func TestProxyStart_DuplicateName_Error(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start first.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "myproxy",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool first: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected first start to succeed: %v", result.Content)
	}

	// Duplicate name should fail.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "myproxy",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool duplicate: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for duplicate name")
	}
}

func TestProxyStop_WithName(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	// Start two listeners.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "listener-a",
			"listen_addr": "127.0.0.1:0",
		},
	})
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "listener-b",
			"listen_addr": "127.0.0.1:0",
		},
	})
	defer manager.StopAll(context.Background())

	if got := manager.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	// Stop specific listener by name.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
		Arguments: map[string]any{
			"name": "listener-a",
		},
	})
	if err != nil {
		t.Fatalf("CallTool stop: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStopResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Status != "stopped" {
		t.Errorf("status = %q, want %q", out.Status, "stopped")
	}
	if len(out.Stopped) != 1 || out.Stopped[0] != "listener-a" {
		t.Errorf("stopped = %v, want [listener-a]", out.Stopped)
	}

	// Only listener-b should remain.
	if got := manager.ListenerCount(); got != 1 {
		t.Errorf("ListenerCount after stop = %d, want 1", got)
	}
}

func TestProxyStop_WithoutName_StopsAll(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	// Start multiple listeners.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "a",
			"listen_addr": "127.0.0.1:0",
		},
	})
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "b",
			"listen_addr": "127.0.0.1:0",
		},
	})

	if got := manager.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	// Stop without name should stop all.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStopResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Status != "stopped" {
		t.Errorf("status = %q, want %q", out.Status, "stopped")
	}
	if len(out.Stopped) != 2 {
		t.Errorf("stopped count = %d, want 2", len(out.Stopped))
	}

	if got := manager.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after StopAll = %d, want 0", got)
	}
}

func TestProxyStop_NamedNotFound_Error(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
		Arguments: map[string]any{
			"name": "nonexistent",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent listener")
	}
}

func TestQueryStatus_MultipleListeners(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start two named listeners.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "http",
			"listen_addr": "127.0.0.1:0",
		},
	})
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "grpc",
			"listen_addr": "127.0.0.1:0",
		},
	})

	// Query status.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !out.Running {
		t.Error("expected running=true")
	}
	if out.ListenerCount != 2 {
		t.Errorf("listener_count = %d, want 2", out.ListenerCount)
	}
	if len(out.Listeners) != 2 {
		t.Fatalf("listeners len = %d, want 2", len(out.Listeners))
	}

	// Verify listener names.
	names := make(map[string]bool)
	for _, l := range out.Listeners {
		names[l.Name] = true
		if l.ListenAddr == "" {
			t.Errorf("listener %q has empty listen_addr", l.Name)
		}
	}
	if !names["http"] {
		t.Error("expected 'http' listener in status")
	}
	if !names["grpc"] {
		t.Error("expected 'grpc' listener in status")
	}
}

func TestQueryStatus_NoListeners(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Running {
		t.Error("expected running=false when no listeners")
	}
	if out.ListenerCount != 0 {
		t.Errorf("listener_count = %d, want 0", out.ListenerCount)
	}
}

func TestQueryStatus_OnlyNamedListeners_RunningTrue(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start a non-default listener.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "custom",
			"listen_addr": "127.0.0.1:0",
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var out queryStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Running should be true even without a "default" listener.
	if !out.Running {
		t.Error("expected running=true with a named listener")
	}
	if out.ListenerCount != 1 {
		t.Errorf("listener_count = %d, want 1", out.ListenerCount)
	}
}
