package pluginv2

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

const (
	// maxStoreKeys is the maximum number of keys allowed per plugin store.
	maxStoreKeys = 10_000
	// maxStoreValueSize is the maximum size in bytes for a single value.
	maxStoreValueSize = 1 << 20 // 1 MB
)

const createPluginV2KVSQL = `
CREATE TABLE IF NOT EXISTS pluginv2_kv (
    plugin_name TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       BLOB NOT NULL,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plugin_name, key)
);
`

// PluginStore provides a per-plugin persistent key-value store backed by SQLite.
// Values are stored as BLOBs and exposed as Starlark string or bytes.
// An in-memory cache (write-through) avoids a DB round-trip on every read.
//
// It is safe for concurrent use from multiple goroutines.
//
// Resource limits match the state module:
//   - Maximum of 10,000 keys per plugin
//   - Maximum of 1 MB per value
//
// The pluginv2 store uses table `pluginv2_kv` to coexist alongside legacy
// internal/plugin's `plugin_kv` until N9. Migration of legacy rows is out
// of scope for USK-665.
type PluginStore struct {
	mu         sync.RWMutex
	db         *sql.DB
	pluginName string
	cache      map[string][]byte
	loaded     bool
}

// NewPluginStore creates a PluginStore for the given plugin name.
// The db must already have the pluginv2_kv table created (see EnsureTable).
func NewPluginStore(db *sql.DB, pluginName string) *PluginStore {
	return &PluginStore{
		db:         db,
		pluginName: pluginName,
		cache:      make(map[string][]byte),
	}
}

// EnsureTable creates the pluginv2_kv table if it does not exist.
// This should be called once during initialization.
func EnsureTable(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, createPluginV2KVSQL); err != nil {
		return fmt.Errorf("create pluginv2_kv table: %w", err)
	}
	return nil
}

// loadCache populates the in-memory cache from the database.
// Must be called with ps.mu held for writing.
func (ps *PluginStore) loadCache(ctx context.Context) error {
	if ps.loaded {
		return nil
	}

	rows, err := ps.db.QueryContext(ctx,
		"SELECT key, value FROM pluginv2_kv WHERE plugin_name = ?", ps.pluginName)
	if err != nil {
		return fmt.Errorf("load plugin store: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return fmt.Errorf("scan plugin store row: %w", err)
		}
		ps.cache[k] = v
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate plugin store rows: %w", err)
	}

	ps.loaded = true
	return nil
}

// newStoreModule creates a Starlark "store" module bound to the given PluginStore.
// Each plugin gets its own module instance backed by its own PluginStore,
// ensuring namespace isolation between plugins.
func newStoreModule(ps *PluginStore) *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "store",
		Members: starlark.StringDict{
			"get":    starlark.NewBuiltin("store.get", ps.storeGet),
			"set":    starlark.NewBuiltin("store.set", ps.storeSet),
			"delete": starlark.NewBuiltin("store.delete", ps.storeDelete),
			"keys":   starlark.NewBuiltin("store.keys", ps.storeKeys),
			"clear":  starlark.NewBuiltin("store.clear", ps.storeClear),
		},
	}
}

// storeGet implements store.get(key) -> string or None.
func (ps *PluginStore) storeGet(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}

	ps.mu.Lock()
	if err := ps.loadCache(context.Background()); err != nil {
		ps.mu.Unlock()
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	ps.mu.Unlock()

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	v, ok := ps.cache[string(key)]
	if !ok {
		return starlark.None, nil
	}
	return starlark.String(v), nil
}

// storeSet implements store.set(key, value). Returns None.
// Only string and bytes values are accepted (stored as BLOB in SQLite).
func (ps *PluginStore) storeSet(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &key, &value); err != nil {
		return nil, err
	}

	var raw []byte
	switch v := value.(type) {
	case starlark.String:
		raw = []byte(string(v))
	case starlark.Bytes:
		raw = []byte(string(v))
	default:
		return nil, fmt.Errorf("%s: unsupported value type %q; only string and bytes are allowed", fn.Name(), value.Type())
	}

	if len(raw) > maxStoreValueSize {
		return nil, fmt.Errorf("%s: value size %d exceeds limit %d", fn.Name(), len(raw), maxStoreValueSize)
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	if err := ps.loadCache(context.Background()); err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	k := string(key)
	if _, exists := ps.cache[k]; !exists && len(ps.cache) >= maxStoreKeys {
		return nil, fmt.Errorf("%s: key count %d exceeds limit %d", fn.Name(), len(ps.cache), maxStoreKeys)
	}

	// Write-through: persist to DB first, then update cache.
	_, err := ps.db.ExecContext(context.Background(),
		`INSERT INTO pluginv2_kv (plugin_name, key, value, updated_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT (plugin_name, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		ps.pluginName, k, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: persist to db: %w", fn.Name(), err)
	}

	ps.cache[k] = raw
	return starlark.None, nil
}

// storeDelete implements store.delete(key). Returns None.
// Deleting a non-existent key is a no-op.
func (ps *PluginStore) storeDelete(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	if err := ps.loadCache(context.Background()); err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	k := string(key)
	_, err := ps.db.ExecContext(context.Background(),
		"DELETE FROM pluginv2_kv WHERE plugin_name = ? AND key = ?",
		ps.pluginName, k)
	if err != nil {
		return nil, fmt.Errorf("%s: delete from db: %w", fn.Name(), err)
	}

	delete(ps.cache, k)
	return starlark.None, nil
}

// storeKeys implements store.keys() -> list of key strings.
func (ps *PluginStore) storeKeys(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}

	ps.mu.Lock()
	if err := ps.loadCache(context.Background()); err != nil {
		ps.mu.Unlock()
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	ps.mu.Unlock()

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	keys := make([]starlark.Value, 0, len(ps.cache))
	for k := range ps.cache {
		keys = append(keys, starlark.String(k))
	}
	return starlark.NewList(keys), nil
}

// storeClear implements store.clear(). Removes all keys for this plugin. Returns None.
func (ps *PluginStore) storeClear(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	_, err := ps.db.ExecContext(context.Background(),
		"DELETE FROM pluginv2_kv WHERE plugin_name = ?", ps.pluginName)
	if err != nil {
		return nil, fmt.Errorf("%s: clear db: %w", fn.Name(), err)
	}

	ps.cache = make(map[string][]byte)
	ps.loaded = true
	return starlark.None, nil
}
