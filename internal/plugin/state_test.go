package plugin

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"go.starlark.net/starlark"
)

func TestPluginState_GetSet(t *testing.T) {
	ps := NewPluginState()

	tests := []struct {
		name  string
		key   string
		value starlark.Value
	}{
		{"string", "str_key", starlark.String("hello")},
		{"bytes", "bytes_key", starlark.Bytes("raw")},
		{"int", "int_key", starlark.MakeInt(42)},
		{"float", "float_key", starlark.Float(3.14)},
		{"bool_true", "bool_key", starlark.Bool(true)},
		{"bool_false", "bool_f", starlark.Bool(false)},
	}

	thread := &starlark.Thread{Name: "test"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set value.
			_, err := ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
				starlark.Tuple{starlark.String(tt.key), tt.value}, nil)
			if err != nil {
				t.Fatalf("stateSet() error = %v", err)
			}

			// Get value.
			got, err := ps.stateGet(thread, starlark.NewBuiltin("state.get", nil),
				starlark.Tuple{starlark.String(tt.key)}, nil)
			if err != nil {
				t.Fatalf("stateGet() error = %v", err)
			}

			if got != tt.value {
				t.Errorf("stateGet() = %v, want %v", got, tt.value)
			}
		})
	}
}

func TestPluginState_GetMissing(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	got, err := ps.stateGet(thread, starlark.NewBuiltin("state.get", nil),
		starlark.Tuple{starlark.String("nonexistent")}, nil)
	if err != nil {
		t.Fatalf("stateGet() error = %v", err)
	}
	if got != starlark.None {
		t.Errorf("stateGet() = %v, want None", got)
	}
}

func TestPluginState_Delete(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	// Set then delete.
	ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("key"), starlark.String("val")}, nil)
	ps.stateDelete(thread, starlark.NewBuiltin("state.delete", nil),
		starlark.Tuple{starlark.String("key")}, nil)

	got, _ := ps.stateGet(thread, starlark.NewBuiltin("state.get", nil),
		starlark.Tuple{starlark.String("key")}, nil)
	if got != starlark.None {
		t.Errorf("after delete, stateGet() = %v, want None", got)
	}

	// Deleting non-existent key should not error.
	_, err := ps.stateDelete(thread, starlark.NewBuiltin("state.delete", nil),
		starlark.Tuple{starlark.String("nonexistent")}, nil)
	if err != nil {
		t.Fatalf("stateDelete(nonexistent) error = %v", err)
	}
}

func TestPluginState_Keys(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	// Empty state.
	got, err := ps.stateKeys(thread, starlark.NewBuiltin("state.keys", nil),
		starlark.Tuple{}, nil)
	if err != nil {
		t.Fatalf("stateKeys() error = %v", err)
	}
	list := got.(*starlark.List)
	if list.Len() != 0 {
		t.Errorf("empty state keys len = %d, want 0", list.Len())
	}

	// Add keys.
	ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("a"), starlark.MakeInt(1)}, nil)
	ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("b"), starlark.MakeInt(2)}, nil)

	got, _ = ps.stateKeys(thread, starlark.NewBuiltin("state.keys", nil),
		starlark.Tuple{}, nil)
	list = got.(*starlark.List)
	if list.Len() != 2 {
		t.Errorf("keys len = %d, want 2", list.Len())
	}
}

func TestPluginState_Clear(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("a"), starlark.MakeInt(1)}, nil)
	ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("b"), starlark.MakeInt(2)}, nil)

	_, err := ps.stateClear(thread, starlark.NewBuiltin("state.clear", nil),
		starlark.Tuple{}, nil)
	if err != nil {
		t.Fatalf("stateClear() error = %v", err)
	}

	got, _ := ps.stateKeys(thread, starlark.NewBuiltin("state.keys", nil),
		starlark.Tuple{}, nil)
	list := got.(*starlark.List)
	if list.Len() != 0 {
		t.Errorf("after clear, keys len = %d, want 0", list.Len())
	}
}

func TestPluginState_RejectUnsupportedTypes(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	tests := []struct {
		name  string
		value starlark.Value
	}{
		{"list", starlark.NewList([]starlark.Value{starlark.MakeInt(1)})},
		{"dict", starlark.NewDict(1)},
		{"tuple", starlark.Tuple{starlark.MakeInt(1)}},
		{"none", starlark.None},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
				starlark.Tuple{starlark.String("key"), tt.value}, nil)
			if err == nil {
				t.Errorf("stateSet(%s) should reject %s type", tt.name, tt.value.Type())
			}
		})
	}
}

func TestPluginState_ConcurrentAccess(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := starlark.String("key")
			for j := 0; j < iterations; j++ {
				ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
					starlark.Tuple{key, starlark.MakeInt(j)}, nil)
				ps.stateGet(thread, starlark.NewBuiltin("state.get", nil),
					starlark.Tuple{key}, nil)
				ps.stateKeys(thread, starlark.NewBuiltin("state.keys", nil),
					starlark.Tuple{}, nil)
				if j%10 == 0 {
					ps.stateDelete(thread, starlark.NewBuiltin("state.delete", nil),
						starlark.Tuple{key}, nil)
				}
			}
		}(i)
	}
	wg.Wait()
}

// Integration tests: test state module through the Engine.

func TestEngine_StateModule_SharedAcrossHooks(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "state_shared.star", `
def on_receive_from_client(data):
    state.set("counter", (state.get("counter") or 0) + 1)
    data["counter"] = state.get("counter")
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

	// Call twice — state should persist between calls.
	for i := 1; i <= 3; i++ {
		result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
		if err != nil {
			t.Fatalf("Dispatch() call %d error = %v", i, err)
		}
		if result == nil || result.Data == nil {
			t.Fatalf("call %d: expected result with data", i)
		}
		got := result.Data["counter"]
		if got != int64(i) {
			t.Errorf("call %d: counter = %v, want %d", i, got, i)
		}
	}
}

func TestEngine_StateModule_IsolatedBetweenPlugins(t *testing.T) {
	dir := t.TempDir()
	path1 := writeScript(t, dir, "plugin_a.star", `
def on_receive_from_client(data):
    state.set("source", "plugin_a")
    data["a_source"] = state.get("source")
    data["a_other"] = state.get("other_key")
    return {"action": action.CONTINUE, "data": data}
`)
	path2 := writeScript(t, dir, "plugin_b.star", `
def on_receive_from_client(data):
    state.set("other_key", "from_b")
    data["b_source"] = state.get("source")
    data["b_other"] = state.get("other_key")
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: path1, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
		{Path: path2, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result == nil || result.Data == nil {
		t.Fatal("expected result with data")
	}

	// plugin_a set "source" in its own state, should see it.
	if v := result.Data["a_source"]; v != "plugin_a" {
		t.Errorf("a_source = %v, want 'plugin_a'", v)
	}
	// plugin_a should NOT see plugin_b's "other_key".
	if v := result.Data["a_other"]; v != nil {
		t.Errorf("a_other = %v, want nil (isolated)", v)
	}
	// plugin_b set "other_key" in its own state, should see it.
	if v := result.Data["b_other"]; v != "from_b" {
		t.Errorf("b_other = %v, want 'from_b'", v)
	}
	// plugin_b should NOT see plugin_a's "source".
	if v := result.Data["b_source"]; v != nil {
		t.Errorf("b_source = %v, want nil (isolated)", v)
	}
}

func TestEngine_StateModule_SurvivesReload(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "state_reload.star", `
def on_receive_from_client(data):
    val = state.get("persist")
    if val == None:
        state.set("persist", "initial")
        data["value"] = "initial"
    else:
        data["value"] = val
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

	// First call sets the value.
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result.Data["value"] != "initial" {
		t.Errorf("first call value = %v, want 'initial'", result.Data["value"])
	}

	// Reload the plugin.
	if err := e.ReloadPlugin(context.Background(), "state_reload"); err != nil {
		t.Fatalf("ReloadPlugin() error = %v", err)
	}

	// Second call after reload should see the persisted value.
	result, err = e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() after reload error = %v", err)
	}
	if result.Data["value"] != "initial" {
		t.Errorf("after reload value = %v, want 'initial'", result.Data["value"])
	}
}

func TestEngine_StateModule_ClearResetsState(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "state_clear.star", `
def on_receive_from_client(data):
    if data.get("do_clear"):
        state.clear()
        data["cleared"] = True
    else:
        state.set("key", "value")
        data["has_key"] = state.get("key") != None
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

	// Set a value.
	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if result.Data["has_key"] != true {
		t.Error("expected has_key=true after set")
	}

	// Clear.
	_, err = e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{"do_clear": true})
	if err != nil {
		t.Fatalf("Dispatch() clear error = %v", err)
	}
}

func TestEngine_StateModule_KeysAndDelete(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "state_keys.star", `
def on_receive_from_client(data):
    state.set("a", 1)
    state.set("b", 2)
    state.set("c", 3)
    data["keys_before"] = len(state.keys())
    state.delete("b")
    data["keys_after"] = len(state.keys())
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

	result, err := e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if v := result.Data["keys_before"]; v != int64(3) {
		t.Errorf("keys_before = %v, want 3", v)
	}
	if v := result.Data["keys_after"]; v != int64(2) {
		t.Errorf("keys_after = %v, want 2", v)
	}
}

func TestPluginState_MaxKeysLimit(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	// Fill to the limit.
	for i := 0; i < maxStateKeys; i++ {
		key := starlark.String(fmt.Sprintf("key_%d", i))
		_, err := ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
			starlark.Tuple{key, starlark.MakeInt(i)}, nil)
		if err != nil {
			t.Fatalf("stateSet() at key %d: unexpected error = %v", i, err)
		}
	}

	// One more should fail.
	_, err := ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("overflow"), starlark.MakeInt(0)}, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max keys limit")
	}

	// Updating an existing key should still succeed.
	_, err = ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("key_0"), starlark.MakeInt(999)}, nil)
	if err != nil {
		t.Fatalf("stateSet() update existing key: unexpected error = %v", err)
	}
}

func TestPluginState_MaxValueSizeLimit(t *testing.T) {
	ps := NewPluginState()
	thread := &starlark.Thread{Name: "test"}

	// String at exactly the limit should succeed.
	exactStr := starlark.String(strings.Repeat("x", maxStateValueSize))
	_, err := ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("exact"), exactStr}, nil)
	if err != nil {
		t.Fatalf("stateSet() at limit: unexpected error = %v", err)
	}

	// String exceeding the limit should fail.
	overStr := starlark.String(strings.Repeat("x", maxStateValueSize+1))
	_, err = ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("over"), overStr}, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max value size for string")
	}

	// Bytes exceeding the limit should fail.
	overBytes := starlark.Bytes(strings.Repeat("x", maxStateValueSize+1))
	_, err = ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("over_bytes"), overBytes}, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max value size for bytes")
	}

	// Int values should not be affected by size limit.
	_, err = ps.stateSet(thread, starlark.NewBuiltin("state.set", nil),
		starlark.Tuple{starlark.String("int_key"), starlark.MakeInt(999999)}, nil)
	if err != nil {
		t.Fatalf("stateSet() int: unexpected error = %v", err)
	}
}

func TestEngine_Close_ClearsState(t *testing.T) {
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "state_close.star", `
def on_receive_from_client(data):
    state.set("secret", "sensitive_data")
    data["value"] = state.get("secret")
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)

	err := e.LoadPlugins(context.Background(), []PluginConfig{
		{Path: scriptPath, Protocol: "http", Hooks: []string{"on_receive_from_client"}},
	})
	if err != nil {
		t.Fatalf("LoadPlugins() error = %v", err)
	}

	// Populate state.
	_, err = e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	// Close should clear states.
	e.Close()

	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.states != nil {
		t.Error("expected e.states to be nil after Close()")
	}
}

func TestValidateStateValue(t *testing.T) {
	tests := []struct {
		name    string
		value   starlark.Value
		wantErr bool
	}{
		{"string", starlark.String("ok"), false},
		{"bytes", starlark.Bytes("ok"), false},
		{"int", starlark.MakeInt(1), false},
		{"float", starlark.Float(1.0), false},
		{"bool", starlark.Bool(true), false},
		{"none", starlark.None, true},
		{"list", starlark.NewList(nil), true},
		{"dict", starlark.NewDict(0), true},
		{"tuple", starlark.Tuple{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStateValue(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateStateValue(%s) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}
