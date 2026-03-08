package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNewTxCtx(t *testing.T) {
	txCtx := NewTxCtx()
	if txCtx == nil {
		t.Fatal("NewTxCtx() returned nil")
	}
	if len(txCtx) != 0 {
		t.Errorf("NewTxCtx() returned non-empty map: %v", txCtx)
	}
}

func TestInjectTxCtx(t *testing.T) {
	data := map[string]any{"method": "GET"}
	txCtx := NewTxCtx()
	txCtx["key"] = "value"

	InjectTxCtx(data, txCtx)

	got, ok := data[txCtxKey]
	if !ok {
		t.Fatal("InjectTxCtx did not set ctx in data")
	}
	gotMap, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("ctx is not map[string]any: %T", got)
	}
	if gotMap["key"] != "value" {
		t.Errorf("ctx[key] = %v, want %q", gotMap["key"], "value")
	}
}

func TestExtractTxCtx_NilResult(t *testing.T) {
	txCtx := NewTxCtx()
	txCtx["existing"] = "preserved"

	got := ExtractTxCtx(nil, txCtx)
	if got["existing"] != "preserved" {
		t.Error("ExtractTxCtx should preserve existing txCtx for nil result")
	}
}

func TestExtractTxCtx_NilData(t *testing.T) {
	txCtx := NewTxCtx()
	txCtx["existing"] = "preserved"

	result := &HookResult{Action: ActionContinue}
	got := ExtractTxCtx(result, txCtx)
	if got["existing"] != "preserved" {
		t.Error("ExtractTxCtx should preserve existing txCtx for nil Data")
	}
}

func TestExtractTxCtx_NoCtxKey(t *testing.T) {
	txCtx := NewTxCtx()
	txCtx["existing"] = "preserved"

	result := &HookResult{
		Action: ActionContinue,
		Data:   map[string]any{"method": "POST"},
	}
	got := ExtractTxCtx(result, txCtx)
	if got["existing"] != "preserved" {
		t.Error("ExtractTxCtx should preserve existing txCtx when ctx key missing")
	}
}

func TestExtractTxCtx_MergesChanges(t *testing.T) {
	txCtx := NewTxCtx()
	txCtx["existing"] = "preserved"

	result := &HookResult{
		Action: ActionContinue,
		Data: map[string]any{
			txCtxKey: map[string]any{
				"existing": "updated",
				"new_key":  "new_value",
			},
		},
	}
	got := ExtractTxCtx(result, txCtx)
	if got["existing"] != "updated" {
		t.Errorf("ctx[existing] = %v, want %q", got["existing"], "updated")
	}
	if got["new_key"] != "new_value" {
		t.Errorf("ctx[new_key] = %v, want %q", got["new_key"], "new_value")
	}
}

func TestExtractTxCtx_InvalidType(t *testing.T) {
	txCtx := NewTxCtx()
	txCtx["existing"] = "preserved"

	result := &HookResult{
		Action: ActionContinue,
		Data: map[string]any{
			txCtxKey: "not a map",
		},
	}
	got := ExtractTxCtx(result, txCtx)
	if got["existing"] != "preserved" {
		t.Error("ExtractTxCtx should ignore invalid ctx type")
	}
}

func TestIsDataHook(t *testing.T) {
	tests := []struct {
		name string
		hook Hook
		want bool
	}{
		{"on_receive_from_client", HookOnReceiveFromClient, true},
		{"on_before_send_to_server", HookOnBeforeSendToServer, true},
		{"on_receive_from_server", HookOnReceiveFromServer, true},
		{"on_before_send_to_client", HookOnBeforeSendToClient, true},
		{"on_connect", HookOnConnect, false},
		{"on_tls_handshake", HookOnTLSHandshake, false},
		{"on_disconnect", HookOnDisconnect, false},
		{"on_socks5_connect", HookOnSOCKS5Connect, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDataHook(tt.hook); got != tt.want {
				t.Errorf("IsDataHook(%q) = %v, want %v", tt.hook, got, tt.want)
			}
		})
	}
}

// writeTestScript creates a Starlark script file and returns its path.
func writeTestScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write script %s: %v", name, err)
	}
	return path
}

func TestTxCtx_SinglePlugin_SharedAcrossHooks(t *testing.T) {
	// Plugin stores a value in ctx during on_receive_from_client and reads
	// it in on_before_send_to_server.
	dir := t.TempDir()
	scriptPath := writeTestScript(t, dir, "txctx_share.star", `
def on_receive_from_client(data):
    ctx = data["ctx"]
    ctx["captured_method"] = data.get("method", "unknown")
    return {"action": action.CONTINUE}

def on_before_send_to_server(data):
    ctx = data["ctx"]
    captured = ctx.get("captured_method", "")
    if captured == "":
        fail("ctx did not preserve captured_method")
    data["method"] = captured + "_modified"
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client", "on_before_send_to_server"},
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	txCtx := NewTxCtx()

	// First hook: on_receive_from_client
	data1 := map[string]any{"method": "GET", "url": "http://example.com"}
	InjectTxCtx(data1, txCtx)
	result1, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data1)
	if err != nil {
		t.Fatalf("Dispatch on_receive_from_client error = %v", err)
	}
	txCtx = ExtractTxCtx(result1, txCtx)

	// Verify ctx was populated.
	if txCtx["captured_method"] != "GET" {
		t.Errorf("txCtx[captured_method] = %v, want %q", txCtx["captured_method"], "GET")
	}

	// Second hook: on_before_send_to_server
	data2 := map[string]any{"method": "GET", "url": "http://example.com"}
	InjectTxCtx(data2, txCtx)
	result2, err := e.Dispatch(context.Background(), HookOnBeforeSendToServer, data2)
	if err != nil {
		t.Fatalf("Dispatch on_before_send_to_server error = %v", err)
	}

	// Verify the plugin successfully read from ctx.
	if result2 == nil || result2.Data == nil {
		t.Fatal("expected result with data from on_before_send_to_server")
	}
	if result2.Data["method"] != "GET_modified" {
		t.Errorf("method = %v, want %q", result2.Data["method"], "GET_modified")
	}
}

func TestTxCtx_MultiplePlugins_SharedCtx(t *testing.T) {
	// Two plugins both write to ctx during the same hook. The second plugin
	// should see what the first plugin wrote.
	dir := t.TempDir()
	path1 := writeTestScript(t, dir, "plugin_a.star", `
def on_receive_from_client(data):
    ctx = data["ctx"]
    ctx["from_a"] = "hello"
    return {"action": action.CONTINUE}
`)
	path2 := writeTestScript(t, dir, "plugin_b.star", `
def on_receive_from_client(data):
    ctx = data["ctx"]
    from_a = ctx.get("from_a", "")
    if from_a != "hello":
        fail("plugin_b did not see from_a: got " + str(from_a))
    ctx["from_b"] = "world"
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     path1,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
			OnError:  "abort",
		},
		{
			Path:     path2,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	txCtx := NewTxCtx()
	data := map[string]any{"method": "GET"}
	InjectTxCtx(data, txCtx)

	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch error = %v", err)
	}

	txCtx = ExtractTxCtx(result, txCtx)

	if txCtx["from_a"] != "hello" {
		t.Errorf("txCtx[from_a] = %v, want %q", txCtx["from_a"], "hello")
	}
	if txCtx["from_b"] != "world" {
		t.Errorf("txCtx[from_b] = %v, want %q", txCtx["from_b"], "world")
	}
}

func TestTxCtx_TypePreservation(t *testing.T) {
	// Verify that ctx preserves different Go/Starlark types.
	dir := t.TempDir()
	scriptPath := writeTestScript(t, dir, "types.star", `
def on_receive_from_client(data):
    ctx = data["ctx"]
    ctx["str_val"] = "hello"
    ctx["int_val"] = 42
    ctx["float_val"] = 3.14
    ctx["bool_val"] = True
    ctx["list_val"] = [1, 2, 3]
    ctx["dict_val"] = {"nested": "value"}
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	txCtx := NewTxCtx()
	data := map[string]any{"method": "GET"}
	InjectTxCtx(data, txCtx)

	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch error = %v", err)
	}

	txCtx = ExtractTxCtx(result, txCtx)

	if txCtx["str_val"] != "hello" {
		t.Errorf("str_val = %v (%T), want %q", txCtx["str_val"], txCtx["str_val"], "hello")
	}
	if txCtx["int_val"] != int64(42) {
		t.Errorf("int_val = %v (%T), want int64(42)", txCtx["int_val"], txCtx["int_val"])
	}
	if txCtx["float_val"] != float64(3.14) {
		t.Errorf("float_val = %v (%T), want float64(3.14)", txCtx["float_val"], txCtx["float_val"])
	}
	if txCtx["bool_val"] != true {
		t.Errorf("bool_val = %v (%T), want true", txCtx["bool_val"], txCtx["bool_val"])
	}
	listVal, ok := txCtx["list_val"].([]any)
	if !ok {
		t.Fatalf("list_val type = %T, want []any", txCtx["list_val"])
	}
	if len(listVal) != 3 {
		t.Errorf("list_val length = %d, want 3", len(listVal))
	}
	dictVal, ok := txCtx["dict_val"].(map[string]any)
	if !ok {
		t.Fatalf("dict_val type = %T, want map[string]any", txCtx["dict_val"])
	}
	if dictVal["nested"] != "value" {
		t.Errorf("dict_val[nested] = %v, want %q", dictVal["nested"], "value")
	}
}

func TestTxCtx_LifecycleHook_NoCtx(t *testing.T) {
	// Lifecycle hooks should not receive ctx. When ctx is not injected,
	// the plugin should not find it in data.
	dir := t.TempDir()
	scriptPath := writeTestScript(t, dir, "lifecycle.star", `
def on_connect(data):
    if "ctx" in data:
        fail("lifecycle hook should not receive ctx")
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_connect"},
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Dispatch without injecting txCtx.
	data := map[string]any{"client_addr": "127.0.0.1:1234"}
	_, err = e.Dispatch(context.Background(), HookOnConnect, data)
	if err != nil {
		t.Fatalf("Dispatch error = %v (lifecycle hook should not see ctx)", err)
	}
}

func TestTxCtx_FullTransaction_FourHooks(t *testing.T) {
	// Simulate a full HTTP transaction across all four data hooks.
	// Each hook adds one value to ctx. The last hook verifies all
	// previous values are present.
	dir := t.TempDir()
	scriptPath := writeTestScript(t, dir, "full_tx.star", `
def on_receive_from_client(data):
    ctx = data["ctx"]
    ctx["step1"] = "receive_client"
    return {"action": action.CONTINUE}

def on_before_send_to_server(data):
    ctx = data["ctx"]
    if ctx.get("step1") != "receive_client":
        fail("step1 not found in on_before_send_to_server")
    ctx["step2"] = "before_server"
    return {"action": action.CONTINUE}

def on_receive_from_server(data):
    ctx = data["ctx"]
    if ctx.get("step1") != "receive_client":
        fail("step1 not found in on_receive_from_server")
    if ctx.get("step2") != "before_server":
        fail("step2 not found in on_receive_from_server")
    ctx["step3"] = "receive_server"
    return {"action": action.CONTINUE}

def on_before_send_to_client(data):
    ctx = data["ctx"]
    if ctx.get("step1") != "receive_client":
        fail("step1 not found in on_before_send_to_client")
    if ctx.get("step2") != "before_server":
        fail("step2 not found in on_before_send_to_client")
    if ctx.get("step3") != "receive_server":
        fail("step3 not found in on_before_send_to_client")
    ctx["step4"] = "before_client"
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client", "on_before_send_to_server", "on_receive_from_server", "on_before_send_to_client"},
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	txCtx := NewTxCtx()
	hooks := []Hook{HookOnReceiveFromClient, HookOnBeforeSendToServer, HookOnReceiveFromServer, HookOnBeforeSendToClient}

	for _, hook := range hooks {
		data := map[string]any{"method": "GET"}
		InjectTxCtx(data, txCtx)
		result, err := e.Dispatch(context.Background(), hook, data)
		if err != nil {
			t.Fatalf("Dispatch(%s) error = %v", hook, err)
		}
		txCtx = ExtractTxCtx(result, txCtx)
	}

	// Verify all 4 steps were recorded.
	expectedKeys := map[string]string{
		"step1": "receive_client",
		"step2": "before_server",
		"step3": "receive_server",
		"step4": "before_client",
	}
	for k, v := range expectedKeys {
		if txCtx[k] != v {
			t.Errorf("txCtx[%s] = %v, want %q", k, txCtx[k], v)
		}
	}
}

func TestTxCtx_CtxNotReturnedExplicitly_StillPreserved(t *testing.T) {
	// Plugin modifies ctx but returns {"action": action.CONTINUE} without
	// explicitly including data or ctx in the return value.
	// The engine's extractTxCtxFromStarlark should still capture the changes.
	dir := t.TempDir()
	scriptPath := writeTestScript(t, dir, "implicit.star", `
def on_receive_from_client(data):
    ctx = data["ctx"]
    ctx["implicit_key"] = "implicit_value"
    # Note: NOT returning data or ctx in the result dict.
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	txCtx := NewTxCtx()
	data := map[string]any{"method": "GET"}
	InjectTxCtx(data, txCtx)

	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data)
	if err != nil {
		t.Fatalf("Dispatch error = %v", err)
	}

	txCtx = ExtractTxCtx(result, txCtx)

	if txCtx["implicit_key"] != "implicit_value" {
		t.Errorf("txCtx[implicit_key] = %v, want %q", txCtx["implicit_key"], "implicit_value")
	}
}

func TestTxCtx_IsolatedBetweenTransactions(t *testing.T) {
	// Verify that separate transactions have isolated ctx dicts.
	dir := t.TempDir()
	scriptPath := writeTestScript(t, dir, "isolation.star", `
def on_receive_from_client(data):
    ctx = data["ctx"]
    ctx["count"] = ctx.get("count", 0) + 1
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
			OnError:  "abort",
		},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Transaction 1
	txCtx1 := NewTxCtx()
	data1 := map[string]any{"method": "GET"}
	InjectTxCtx(data1, txCtx1)
	result1, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data1)
	if err != nil {
		t.Fatalf("Dispatch tx1 error = %v", err)
	}
	txCtx1 = ExtractTxCtx(result1, txCtx1)

	// Transaction 2 (separate txCtx)
	txCtx2 := NewTxCtx()
	data2 := map[string]any{"method": "POST"}
	InjectTxCtx(data2, txCtx2)
	result2, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, data2)
	if err != nil {
		t.Fatalf("Dispatch tx2 error = %v", err)
	}
	txCtx2 = ExtractTxCtx(result2, txCtx2)

	// Both should have count=1 (not accumulated).
	if txCtx1["count"] != int64(1) {
		t.Errorf("tx1 count = %v, want 1", txCtx1["count"])
	}
	if txCtx2["count"] != int64(1) {
		t.Errorf("tx2 count = %v, want 1", txCtx2["count"])
	}
}
