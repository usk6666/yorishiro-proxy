package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write script %s: %v", name, err)
	}
	return path
}

func TestEngine_LoadPlugins_BasicHook(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "basic.star", `
def on_receive_from_client(data):
    data["plugin_ran"] = True
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
			OnError:  "skip",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	if e.PluginCount() != 1 {
		t.Errorf("PluginCount() = %d, want 1", e.PluginCount())
	}

	data := map[string]any{"method": "GET", "url": "http://example.com"}
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil {
		t.Fatal("Dispatch() returned nil result")
	}
	if result.Action != ActionContinue {
		t.Errorf("result.Action = %v, want CONTINUE", result.Action)
	}
}

func TestEngine_LoadPlugins_DropAction(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "drop.star", `
def on_receive_from_client(data):
    if data.get("url", "").endswith("/blocked"):
        return {"action": action.DROP}
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Test blocked URL.
	data := map[string]any{"url": "http://example.com/blocked"}
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result.Action != ActionDrop {
		t.Errorf("expected DROP for /blocked, got %v", result.Action)
	}

	// Test allowed URL.
	data = map[string]any{"url": "http://example.com/ok"}
	result, err = e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result.Action != ActionContinue {
		t.Errorf("expected CONTINUE for /ok, got %v", result.Action)
	}
}

func TestEngine_LoadPlugins_RespondAction(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "respond.star", `
def on_receive_from_client(data):
    return {
        "action": action.RESPOND,
        "response": {
            "status": 403,
            "body": "Forbidden",
        },
    }
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	data := map[string]any{"url": "http://example.com"}
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result.Action != ActionRespond {
		t.Errorf("expected RESPOND, got %v", result.Action)
	}
	if result.ResponseData == nil {
		t.Fatal("expected response data, got nil")
	}
	if status, ok := result.ResponseData["status"]; !ok || status != int64(403) {
		t.Errorf("response status = %v, want 403", result.ResponseData["status"])
	}
}

func TestEngine_LoadPlugins_NoneReturn(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "none.star", `
def on_connect(data):
    pass  # returns None
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_connect"},
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	result, err := e.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil {
		t.Fatal("Dispatch() returned nil result")
	}
	if result.Action != ActionContinue {
		t.Errorf("expected CONTINUE for None return, got %v", result.Action)
	}
}

func TestEngine_LoadPlugins_MultiplePlugins_Order(t *testing.T) {
	dir := t.TempDir()

	path1 := writeScript(t, dir, "first.star", `
def on_connect(data):
    order = data.get("order", [])
    order.append("first")
    data["order"] = order
    return {"action": action.CONTINUE, "data": data}
`)

	path2 := writeScript(t, dir, "second.star", `
def on_connect(data):
    order = data.get("order", [])
    order.append("second")
    data["order"] = order
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: path1, Protocol: "http", Hooks: []string{"on_connect"}},
		{Path: path2, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	if e.PluginCount() != 2 {
		t.Fatalf("PluginCount() = %d, want 2", e.PluginCount())
	}

	data := map[string]any{}
	result, err := e.Dispatch(context.Background(), HookOnConnect, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil {
		t.Fatal("Dispatch() returned nil result")
	}
}

func TestEngine_LoadPlugins_ScriptError_Skip(t *testing.T) {
	dir := t.TempDir()
	badPath := writeScript(t, dir, "bad.star", `this is not valid starlark`)
	goodPath := writeScript(t, dir, "good.star", `
def on_connect(data):
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: badPath, Protocol: "http", Hooks: []string{"on_connect"}, OnError: "skip"},
		{Path: goodPath, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() should not error with skip, got %v", err)
	}
	if e.PluginCount() != 1 {
		t.Errorf("PluginCount() = %d, want 1 (bad plugin skipped)", e.PluginCount())
	}
}

func TestEngine_LoadPlugins_ScriptError_Abort(t *testing.T) {
	dir := t.TempDir()
	badPath := writeScript(t, dir, "bad.star", `this is not valid starlark`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: badPath, Protocol: "http", Hooks: []string{"on_connect"}, OnError: "abort"},
	})
	if err == nil {
		t.Fatal("LoadPlugins() should error with abort for bad script")
	}
}

func TestEngine_LoadPlugins_FileNotFound(t *testing.T) {
	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: "/nonexistent/script.star", Protocol: "http", Hooks: []string{"on_connect"}, OnError: "abort"},
	})
	if err == nil {
		t.Fatal("LoadPlugins() should error for missing file")
	}
}

func TestEngine_LoadPlugins_InvalidConfig(t *testing.T) {
	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: "", Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err == nil {
		t.Fatal("LoadPlugins() should error for invalid config")
	}
}

func TestEngine_LoadPlugins_MissingHookFunction(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "nohook.star", `
x = 42
`)

	e := NewEngine(nil)
	defer e.Close()

	// The hook function is not defined in the script - should just skip it
	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() should succeed even if hook not found, got %v", err)
	}

	// Dispatch should return nil since no handlers registered.
	result, err := e.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for no handlers, got %v", result)
	}
}

func TestEngine_LoadPlugins_RuntimeError_Skip(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "runtime_err.star", `
def on_connect(data):
    return 1 / 0  # runtime error
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}, OnError: "skip"},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Dispatch should skip the error.
	result, err := e.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() should skip runtime error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestEngine_LoadPlugins_RuntimeError_Abort(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "runtime_err.star", `
def on_connect(data):
    return 1 / 0  # runtime error
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}, OnError: "abort"},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	_, err = e.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err == nil {
		t.Fatal("Dispatch() should return error with abort on runtime error")
	}
}

func TestEngine_LoadPlugins_ActionModule(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "action_module.star", `
# Verify action module constants are accessible
def on_connect(data):
    data["continue"] = action.CONTINUE
    data["drop"] = action.DROP
    data["respond"] = action.RESPOND
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	data := map[string]any{}
	result, err := e.Dispatch(context.Background(), HookOnConnect, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil || result.Data == nil {
		t.Fatal("expected result with data")
	}
}

func TestEngine_Close(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "close.star", `
def on_connect(data):
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	if err := e.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if e.PluginCount() != 0 {
		t.Errorf("PluginCount() after Close() = %d, want 0", e.PluginCount())
	}
}

func TestEngine_LoadPlugins_InvalidDropInNonDroppableHook(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "invalid_drop.star", `
def on_connect(data):
    return {"action": "DROP"}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}, OnError: "abort"},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Should error because DROP is not valid in on_connect.
	_, err = e.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err == nil {
		t.Fatal("expected error for DROP action in on_connect hook")
	}
}

func TestEngine_LoadPlugins_EmptyConfigs(t *testing.T) {
	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), nil)
	if err != nil {
		t.Fatalf("LoadPlugins(nil) error = %v", err)
	}
	if e.PluginCount() != 0 {
		t.Errorf("PluginCount() = %d, want 0", e.PluginCount())
	}

	err = e.LoadPlugins(context.Background(), []PluginConfig{})
	if err != nil {
		t.Fatalf("LoadPlugins([]) error = %v", err)
	}
}

func TestEngine_LoadPlugins_PrintFunction(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "print.star", `
def on_connect(data):
    print("hello from plugin")
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	_, err = e.Dispatch(context.Background(), HookOnConnect, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
}

func TestEngine_Plugins(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "info_plugin.star", `
def on_connect(data):
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	infos := e.Plugins()
	if len(infos) != 1 {
		t.Fatalf("Plugins() len = %d, want 1", len(infos))
	}
	if infos[0].Name != "info_plugin" {
		t.Errorf("Name = %q, want 'info_plugin'", infos[0].Name)
	}
	if infos[0].Protocol != "http" {
		t.Errorf("Protocol = %q, want 'http'", infos[0].Protocol)
	}
	if !infos[0].Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestEngine_SetPluginEnabled(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "toggle.star", `
def on_receive_from_client(data):
    data["toggled"] = True
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Disable the plugin.
	if err := e.SetPluginEnabled("toggle", false); err != nil {
		t.Fatalf("SetPluginEnabled(false) error = %v", err)
	}

	infos := e.Plugins()
	if infos[0].Enabled {
		t.Error("expected Enabled=false after disable")
	}

	// Dispatch should skip the disabled plugin.
	data := map[string]any{}
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	// With no active handlers, dispatch returns the CONTINUE result but without the toggled key.
	if result != nil && result.Data != nil {
		if _, ok := result.Data["toggled"]; ok {
			t.Error("disabled plugin should not have run")
		}
	}

	// Re-enable.
	if err := e.SetPluginEnabled("toggle", true); err != nil {
		t.Fatalf("SetPluginEnabled(true) error = %v", err)
	}

	data = map[string]any{}
	result, err = e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil || result.Data == nil {
		t.Fatal("expected result with data after re-enable")
	}
}

func TestEngine_SetPluginEnabled_NotFound(t *testing.T) {
	e := NewEngine(nil)
	defer e.Close()

	err := e.SetPluginEnabled("nonexistent", true)
	if err == nil {
		t.Fatal("expected error for nonexistent plugin")
	}
}

func TestEngine_ReloadPlugin(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "reloadable.star", `
def on_receive_from_client(data):
    data["version"] = "v1"
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Update the script.
	writeScript(t, dir, "reloadable.star", `
def on_receive_from_client(data):
    data["version"] = "v2"
    return {"action": action.CONTINUE, "data": data}
`)

	// Reload.
	if err := e.ReloadPlugin(context.Background(), "reloadable"); err != nil {
		t.Fatalf("ReloadPlugin() error = %v", err)
	}

	data := map[string]any{}
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil || result.Data == nil {
		t.Fatal("expected result with data")
	}
	if v, ok := result.Data["version"]; !ok || v != "v2" {
		t.Errorf("version = %v, want 'v2'", v)
	}
}

func TestEngine_ReloadPlugin_NotFound(t *testing.T) {
	e := NewEngine(nil)
	defer e.Close()

	err := e.ReloadPlugin(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent plugin")
	}
}

func TestEngine_ReloadAll(t *testing.T) {
	dir := t.TempDir()
	path1 := writeScript(t, dir, "plugin_a.star", `
def on_connect(data):
    return {"action": action.CONTINUE}
`)
	path2 := writeScript(t, dir, "plugin_b.star", `
def on_connect(data):
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: path1, Protocol: "http", Hooks: []string{"on_connect"}},
		{Path: path2, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	if err := e.ReloadAll(context.Background()); err != nil {
		t.Fatalf("ReloadAll() error = %v", err)
	}

	if e.PluginCount() != 2 {
		t.Errorf("PluginCount() after reload = %d, want 2", e.PluginCount())
	}
}

func TestEngine_ReloadPlugin_PreservesEnabledState(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "preserve.star", `
def on_connect(data):
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_connect"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Disable then reload.
	e.SetPluginEnabled("preserve", false)
	if err := e.ReloadPlugin(context.Background(), "preserve"); err != nil {
		t.Fatalf("ReloadPlugin() error = %v", err)
	}

	infos := e.Plugins()
	if len(infos) != 1 {
		t.Fatalf("expected 1 plugin after reload, got %d", len(infos))
	}
	if infos[0].Enabled {
		t.Error("expected Enabled=false to be preserved after reload")
	}
}

func TestPluginName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/path/to/add_auth_header.star", "add_auth_header"},
		{"script.star", "script"},
		{"/a/b/c/plugin.py", "plugin"},
		{"noext", "noext"},
	}
	for _, tt := range tests {
		got := pluginName(tt.path)
		if got != tt.want {
			t.Errorf("pluginName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
