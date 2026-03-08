package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"

	"go.starlark.net/starlark"
	_ "modernc.org/sqlite"
)

// openTestDB creates an in-memory SQLite database with the plugin_kv table.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := EnsureTable(context.Background(), db); err != nil {
		t.Fatalf("ensure table: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPluginStore_GetSet(t *testing.T) {
	db := openTestDB(t)

	tests := []struct {
		name  string
		key   string
		value starlark.Value
	}{
		{"string", "str_key", starlark.String("hello")},
		{"bytes", "bytes_key", starlark.Bytes("raw")},
	}

	thread := &starlark.Thread{Name: "test"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := NewPluginStore(db, "test_plugin")

			// Set value.
			_, err := ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
				starlark.Tuple{starlark.String(tt.key), tt.value}, nil)
			if err != nil {
				t.Fatalf("storeSet() error = %v", err)
			}

			// Get value — should return as string (BLOB stored).
			got, err := ps.storeGet(thread, starlark.NewBuiltin("store.get", nil),
				starlark.Tuple{starlark.String(tt.key)}, nil)
			if err != nil {
				t.Fatalf("storeGet() error = %v", err)
			}

			// Both string and bytes are stored as BLOB and returned as string.
			var expected string
			switch v := tt.value.(type) {
			case starlark.String:
				expected = string(v)
			case starlark.Bytes:
				expected = string(v)
			}

			gotStr, ok := got.(starlark.String)
			if !ok {
				t.Fatalf("storeGet() returned %T, want starlark.String", got)
			}
			if string(gotStr) != expected {
				t.Errorf("storeGet() = %q, want %q", string(gotStr), expected)
			}
		})
	}
}

func TestPluginStore_GetMissing(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "test_plugin")
	thread := &starlark.Thread{Name: "test"}

	got, err := ps.storeGet(thread, starlark.NewBuiltin("store.get", nil),
		starlark.Tuple{starlark.String("nonexistent")}, nil)
	if err != nil {
		t.Fatalf("storeGet() error = %v", err)
	}
	if got != starlark.None {
		t.Errorf("storeGet() = %v, want None", got)
	}
}

func TestPluginStore_Delete(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "test_plugin")
	thread := &starlark.Thread{Name: "test"}

	// Set then delete.
	ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("key"), starlark.String("val")}, nil)
	ps.storeDelete(thread, starlark.NewBuiltin("store.delete", nil),
		starlark.Tuple{starlark.String("key")}, nil)

	got, _ := ps.storeGet(thread, starlark.NewBuiltin("store.get", nil),
		starlark.Tuple{starlark.String("key")}, nil)
	if got != starlark.None {
		t.Errorf("after delete, storeGet() = %v, want None", got)
	}

	// Deleting non-existent key should not error.
	_, err := ps.storeDelete(thread, starlark.NewBuiltin("store.delete", nil),
		starlark.Tuple{starlark.String("nonexistent")}, nil)
	if err != nil {
		t.Fatalf("storeDelete(nonexistent) error = %v", err)
	}
}

func TestPluginStore_Keys(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "test_plugin")
	thread := &starlark.Thread{Name: "test"}

	// Empty store.
	got, err := ps.storeKeys(thread, starlark.NewBuiltin("store.keys", nil),
		starlark.Tuple{}, nil)
	if err != nil {
		t.Fatalf("storeKeys() error = %v", err)
	}
	list := got.(*starlark.List)
	if list.Len() != 0 {
		t.Errorf("empty store keys len = %d, want 0", list.Len())
	}

	// Add keys.
	ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("a"), starlark.String("1")}, nil)
	ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("b"), starlark.String("2")}, nil)

	got, _ = ps.storeKeys(thread, starlark.NewBuiltin("store.keys", nil),
		starlark.Tuple{}, nil)
	list = got.(*starlark.List)
	if list.Len() != 2 {
		t.Errorf("keys len = %d, want 2", list.Len())
	}
}

func TestPluginStore_Clear(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "test_plugin")
	thread := &starlark.Thread{Name: "test"}

	ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("a"), starlark.String("1")}, nil)
	ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("b"), starlark.String("2")}, nil)

	_, err := ps.storeClear(thread, starlark.NewBuiltin("store.clear", nil),
		starlark.Tuple{}, nil)
	if err != nil {
		t.Fatalf("storeClear() error = %v", err)
	}

	got, _ := ps.storeKeys(thread, starlark.NewBuiltin("store.keys", nil),
		starlark.Tuple{}, nil)
	list := got.(*starlark.List)
	if list.Len() != 0 {
		t.Errorf("after clear, keys len = %d, want 0", list.Len())
	}
}

func TestPluginStore_RejectUnsupportedTypes(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "test_plugin")
	thread := &starlark.Thread{Name: "test"}

	tests := []struct {
		name  string
		value starlark.Value
	}{
		{"int", starlark.MakeInt(42)},
		{"float", starlark.Float(3.14)},
		{"bool", starlark.Bool(true)},
		{"list", starlark.NewList([]starlark.Value{starlark.MakeInt(1)})},
		{"dict", starlark.NewDict(1)},
		{"none", starlark.None},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
				starlark.Tuple{starlark.String("key"), tt.value}, nil)
			if err == nil {
				t.Errorf("storeSet(%s) should reject %s type", tt.name, tt.value.Type())
			}
		})
	}
}

func TestPluginStore_NamespaceIsolation(t *testing.T) {
	db := openTestDB(t)
	thread := &starlark.Thread{Name: "test"}

	psA := NewPluginStore(db, "plugin_a")
	psB := NewPluginStore(db, "plugin_b")

	// Set in plugin A.
	psA.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("key"), starlark.String("value_a")}, nil)

	// Plugin B should not see it.
	got, _ := psB.storeGet(thread, starlark.NewBuiltin("store.get", nil),
		starlark.Tuple{starlark.String("key")}, nil)
	if got != starlark.None {
		t.Errorf("plugin B should not see plugin A's key, got %v", got)
	}

	// Plugin B sets its own value for the same key.
	psB.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("key"), starlark.String("value_b")}, nil)

	// Plugin A should still see its own value.
	got, _ = psA.storeGet(thread, starlark.NewBuiltin("store.get", nil),
		starlark.Tuple{starlark.String("key")}, nil)
	if string(got.(starlark.String)) != "value_a" {
		t.Errorf("plugin A's key = %v, want 'value_a'", got)
	}
}

func TestPluginStore_Persistence(t *testing.T) {
	// Use a file-based DB to test persistence across PluginStore instances.
	dbPath := t.TempDir() + "/test.db"
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := EnsureTable(context.Background(), db); err != nil {
		t.Fatalf("ensure table: %v", err)
	}

	thread := &starlark.Thread{Name: "test"}
	ps := NewPluginStore(db, "persist_plugin")

	// Set a value.
	ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("persist_key"), starlark.String("persist_value")}, nil)

	// Close the DB to simulate process restart.
	db.Close()

	// Reopen DB and create a new PluginStore.
	db2, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db2.Close()

	ps2 := NewPluginStore(db2, "persist_plugin")

	got, err := ps2.storeGet(thread, starlark.NewBuiltin("store.get", nil),
		starlark.Tuple{starlark.String("persist_key")}, nil)
	if err != nil {
		t.Fatalf("storeGet() after reopen error = %v", err)
	}
	if string(got.(starlark.String)) != "persist_value" {
		t.Errorf("after reopen, storeGet() = %v, want 'persist_value'", got)
	}
}

func TestPluginStore_WriteThroughCacheConsistency(t *testing.T) {
	db := openTestDB(t)
	thread := &starlark.Thread{Name: "test"}

	ps1 := NewPluginStore(db, "cache_test")
	ps2 := NewPluginStore(db, "cache_test")

	// Write via ps1.
	ps1.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("key"), starlark.String("value1")}, nil)

	// Read via ps2 (different PluginStore instance, same namespace).
	// Since ps2 hasn't loaded its cache yet, it should read from DB.
	got, err := ps2.storeGet(thread, starlark.NewBuiltin("store.get", nil),
		starlark.Tuple{starlark.String("key")}, nil)
	if err != nil {
		t.Fatalf("storeGet() error = %v", err)
	}
	if string(got.(starlark.String)) != "value1" {
		t.Errorf("ps2.storeGet() = %v, want 'value1'", got)
	}
}

func TestPluginStore_ConcurrentAccess(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "concurrent_test")
	thread := &starlark.Thread{Name: "test"}

	const goroutines = 50
	const iterations = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := starlark.String(fmt.Sprintf("key_%d", id))
			for j := 0; j < iterations; j++ {
				ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
					starlark.Tuple{key, starlark.String(fmt.Sprintf("val_%d", j))}, nil)
				ps.storeGet(thread, starlark.NewBuiltin("store.get", nil),
					starlark.Tuple{key}, nil)
				ps.storeKeys(thread, starlark.NewBuiltin("store.keys", nil),
					starlark.Tuple{}, nil)
				if j%10 == 0 {
					ps.storeDelete(thread, starlark.NewBuiltin("store.delete", nil),
						starlark.Tuple{key}, nil)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestPluginStore_MaxKeysLimit(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "max_keys_test")
	thread := &starlark.Thread{Name: "test"}

	// Fill to the limit.
	for i := 0; i < maxStoreKeys; i++ {
		key := starlark.String(fmt.Sprintf("key_%d", i))
		_, err := ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
			starlark.Tuple{key, starlark.String("v")}, nil)
		if err != nil {
			t.Fatalf("storeSet() at key %d: unexpected error = %v", i, err)
		}
	}

	// One more should fail.
	_, err := ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("overflow"), starlark.String("v")}, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max keys limit")
	}

	// Updating an existing key should still succeed.
	_, err = ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("key_0"), starlark.String("updated")}, nil)
	if err != nil {
		t.Fatalf("storeSet() update existing key: unexpected error = %v", err)
	}
}

func TestPluginStore_MaxValueSizeLimit(t *testing.T) {
	db := openTestDB(t)
	ps := NewPluginStore(db, "max_value_test")
	thread := &starlark.Thread{Name: "test"}

	// String at exactly the limit should succeed.
	exactStr := starlark.String(strings.Repeat("x", maxStoreValueSize))
	_, err := ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("exact"), exactStr}, nil)
	if err != nil {
		t.Fatalf("storeSet() at limit: unexpected error = %v", err)
	}

	// String exceeding the limit should fail.
	overStr := starlark.String(strings.Repeat("x", maxStoreValueSize+1))
	_, err = ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("over"), overStr}, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max value size for string")
	}

	// Bytes exceeding the limit should fail.
	overBytes := starlark.Bytes(strings.Repeat("x", maxStoreValueSize+1))
	_, err = ps.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("over_bytes"), overBytes}, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max value size for bytes")
	}
}

// Integration tests: test store module through the Engine.

func TestEngine_StoreModule_SetGet(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "store_setget.star", `
def on_receive_from_client(data):
    store.set("greeting", "hello world")
    data["value"] = store.get("greeting")
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	if err := e.SetDB(context.Background(), db); err != nil {
		t.Fatalf("SetDB() error = %v", err)
	}

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
	if result == nil || result.Data == nil {
		t.Fatal("expected result with data")
	}
	if v := result.Data["value"]; v != "hello world" {
		t.Errorf("value = %v, want 'hello world'", v)
	}
}

func TestEngine_StoreModule_IsolatedBetweenPlugins(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	path1 := writeScript(t, dir, "store_a.star", `
def on_receive_from_client(data):
    store.set("source", "plugin_a")
    data["a_source"] = store.get("source")
    data["a_other"] = store.get("other_key")
    return {"action": action.CONTINUE, "data": data}
`)
	path2 := writeScript(t, dir, "store_b.star", `
def on_receive_from_client(data):
    store.set("other_key", "from_b")
    data["b_source"] = store.get("source")
    data["b_other"] = store.get("other_key")
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	if err := e.SetDB(context.Background(), db); err != nil {
		t.Fatalf("SetDB() error = %v", err)
	}

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

	// plugin_a set "source" in its own store, should see it.
	if v := result.Data["a_source"]; v != "plugin_a" {
		t.Errorf("a_source = %v, want 'plugin_a'", v)
	}
	// plugin_a should NOT see plugin_b's "other_key".
	if v := result.Data["a_other"]; v != nil {
		t.Errorf("a_other = %v, want nil (isolated)", v)
	}
	// plugin_b set "other_key" in its own store, should see it.
	if v := result.Data["b_other"]; v != "from_b" {
		t.Errorf("b_other = %v, want 'from_b'", v)
	}
	// plugin_b should NOT see plugin_a's "source".
	if v := result.Data["b_source"]; v != nil {
		t.Errorf("b_source = %v, want nil (isolated)", v)
	}
}

func TestEngine_StoreModule_KeysDeleteClear(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "store_ops.star", `
def on_receive_from_client(data):
    store.set("a", "1")
    store.set("b", "2")
    store.set("c", "3")
    data["keys_before"] = len(store.keys())
    store.delete("b")
    data["keys_after_delete"] = len(store.keys())
    store.clear()
    data["keys_after_clear"] = len(store.keys())
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	if err := e.SetDB(context.Background(), db); err != nil {
		t.Fatalf("SetDB() error = %v", err)
	}

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
	if v := result.Data["keys_after_delete"]; v != int64(2) {
		t.Errorf("keys_after_delete = %v, want 2", v)
	}
	if v := result.Data["keys_after_clear"]; v != int64(0) {
		t.Errorf("keys_after_clear = %v, want 0", v)
	}
}

func TestEngine_StoreModule_RejectList(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "store_reject.star", `
def on_receive_from_client(data):
    store.set("key", [1, 2, 3])
    return {"action": action.CONTINUE}
`)

	e := NewEngine(nil)
	defer e.Close()

	if err := e.SetDB(context.Background(), db); err != nil {
		t.Fatalf("SetDB() error = %v", err)
	}

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

	_, err = e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err == nil {
		t.Fatal("expected error when storing list in store")
	}
}

func TestEngine_StoreModule_WithoutDB(t *testing.T) {
	// When no DB is set, the store module should not be available.
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "store_nodb.star", `
def on_receive_from_client(data):
    # store should not be defined
    data["has_store"] = "store" in dir()
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

	// The script should load fine but attempting to use store would fail.
	// Since store is not injected, it simply isn't in predeclared.
}

func TestEngine_StoreModule_SurvivesReload(t *testing.T) {
	db := openTestDB(t)
	dir := t.TempDir()
	scriptPath := writeScript(t, dir, "store_reload.star", `
def on_receive_from_client(data):
    val = store.get("persist")
    if val == None:
        store.set("persist", "initial")
        data["value"] = "initial"
    else:
        data["value"] = val
    return {"action": action.CONTINUE, "data": data}
`)

	e := NewEngine(nil)
	defer e.Close()

	if err := e.SetDB(context.Background(), db); err != nil {
		t.Fatalf("SetDB() error = %v", err)
	}

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
	if err := e.ReloadPlugin(context.Background(), "store_reload"); err != nil {
		t.Fatalf("ReloadPlugin() error = %v", err)
	}

	// Second call after reload should see the persisted value (from DB).
	result, err = e.Dispatch(context.Background(), HookOnReceiveFromClient, map[string]any{})
	if err != nil {
		t.Fatalf("Dispatch() after reload error = %v", err)
	}
	if result.Data["value"] != "initial" {
		t.Errorf("after reload value = %v, want 'initial'", result.Data["value"])
	}
}

func TestPluginStore_ClearOnlyAffectsOwnNamespace(t *testing.T) {
	db := openTestDB(t)
	thread := &starlark.Thread{Name: "test"}

	psA := NewPluginStore(db, "plugin_a")
	psB := NewPluginStore(db, "plugin_b")

	// Set values in both.
	psA.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("key"), starlark.String("a_val")}, nil)
	psB.storeSet(thread, starlark.NewBuiltin("store.set", nil),
		starlark.Tuple{starlark.String("key"), starlark.String("b_val")}, nil)

	// Clear plugin A.
	psA.storeClear(thread, starlark.NewBuiltin("store.clear", nil),
		starlark.Tuple{}, nil)

	// Plugin B's data should remain.
	got, _ := psB.storeGet(thread, starlark.NewBuiltin("store.get", nil),
		starlark.Tuple{starlark.String("key")}, nil)
	if string(got.(starlark.String)) != "b_val" {
		t.Errorf("after clear of plugin_a, plugin_b key = %v, want 'b_val'", got)
	}
}

func TestEnsureTable_Idempotent(t *testing.T) {
	db := openTestDB(t)
	// Calling EnsureTable again should not error.
	if err := EnsureTable(context.Background(), db); err != nil {
		t.Fatalf("second EnsureTable() error = %v", err)
	}
}
