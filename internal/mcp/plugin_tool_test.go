package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// setupTestSessionWithPluginEngine creates a connected MCP client session with a plugin engine.
func setupTestSessionWithPluginEngine(t *testing.T, engine *plugin.Engine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, nil, nil, WithPluginEngine(engine))
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

// writeStarlarkScript writes a simple Starlark script to a temp directory and returns its path.
func writeStarlarkScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write script %s: %v", name, err)
	}
	return path
}

func TestPlugin_List_Empty(t *testing.T) {
	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)

	cs := setupTestSessionWithPluginEngine(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "list", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	tc, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}

	var out pluginListResult
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Count != 0 {
		t.Errorf("expected 0 plugins, got %d", out.Count)
	}
}

func TestPlugin_List_WithPlugins(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "test_plugin.star", `
def on_receive_from_client(data):
    return {"action": action.CONTINUE}
`)

	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	cs := setupTestSessionWithPluginEngine(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "list", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	tc := result.Content[0].(*gomcp.TextContent)
	var out pluginListResult
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Count != 1 {
		t.Errorf("expected 1 plugin, got %d", out.Count)
	}
	if out.Plugins[0].Name != "test_plugin" {
		t.Errorf("expected name 'test_plugin', got %q", out.Plugins[0].Name)
	}
	if !out.Plugins[0].Enabled {
		t.Error("expected plugin to be enabled")
	}
}

func TestPlugin_EnableDisable(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "toggle_plugin.star", `
def on_receive_from_client(data):
    return {"action": action.CONTINUE}
`)

	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	cs := setupTestSessionWithPluginEngine(t, engine)

	// Disable the plugin.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "disable", "params": map[string]any{"name": "toggle_plugin"}},
	})
	if err != nil {
		t.Fatalf("CallTool disable: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected disable success: %v", result.Content)
	}

	tc := result.Content[0].(*gomcp.TextContent)
	var toggleOut pluginToggleResult
	if err := json.Unmarshal([]byte(tc.Text), &toggleOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if toggleOut.Enabled {
		t.Error("expected Enabled=false after disable")
	}

	// Verify it shows as disabled in list.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "list", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool list: %v", err)
	}
	tc = result.Content[0].(*gomcp.TextContent)
	var listOut pluginListResult
	if err := json.Unmarshal([]byte(tc.Text), &listOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if listOut.Plugins[0].Enabled {
		t.Error("expected plugin to be disabled in list")
	}

	// Re-enable.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "enable", "params": map[string]any{"name": "toggle_plugin"}},
	})
	if err != nil {
		t.Fatalf("CallTool enable: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected enable success: %v", result.Content)
	}

	tc = result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(tc.Text), &toggleOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !toggleOut.Enabled {
		t.Error("expected Enabled=true after enable")
	}
}

func TestPlugin_Reload(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "reload_plugin.star", `
def on_receive_from_client(data):
    return {"action": action.CONTINUE}
`)

	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	cs := setupTestSessionWithPluginEngine(t, engine)

	// Reload the specific plugin.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "reload", "params": map[string]any{"name": "reload_plugin"}},
	})
	if err != nil {
		t.Fatalf("CallTool reload: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected reload success: %v", result.Content)
	}

	tc := result.Content[0].(*gomcp.TextContent)
	var reloadOut pluginReloadResult
	if err := json.Unmarshal([]byte(tc.Text), &reloadOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if reloadOut.Reloaded != "reload_plugin" {
		t.Errorf("expected reloaded='reload_plugin', got %q", reloadOut.Reloaded)
	}
}

func TestPlugin_ReloadAll(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeStarlarkScript(t, dir, "reload_all.star", `
def on_receive_from_client(data):
    return {"action": action.CONTINUE}
`)

	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)
	err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	cs := setupTestSessionWithPluginEngine(t, engine)

	// Reload all (empty name).
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "reload", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool reload all: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected reload all success: %v", result.Content)
	}

	tc := result.Content[0].(*gomcp.TextContent)
	var reloadOut pluginReloadResult
	if err := json.Unmarshal([]byte(tc.Text), &reloadOut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if reloadOut.Reloaded != "all" {
		t.Errorf("expected reloaded='all', got %q", reloadOut.Reloaded)
	}
}

func TestPlugin_MissingAction(t *testing.T) {
	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)

	cs := setupTestSessionWithPluginEngine(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for missing action")
	}
}

func TestPlugin_InvalidAction(t *testing.T) {
	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)

	cs := setupTestSessionWithPluginEngine(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "unknown", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for invalid action")
	}
}

func TestPlugin_NilEngine(t *testing.T) {
	cs := setupTestSessionWithPluginEngine(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "list", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error when plugin engine is nil")
	}
}

func TestPlugin_EnableNotFound(t *testing.T) {
	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)

	cs := setupTestSessionWithPluginEngine(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "enable", "params": map[string]any{"name": "nonexistent"}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for nonexistent plugin")
	}
}

func TestPlugin_EnableMissingName(t *testing.T) {
	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)

	cs := setupTestSessionWithPluginEngine(t, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "plugin",
		Arguments: map[string]any{"action": "enable", "params": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for missing name in enable")
	}
}
