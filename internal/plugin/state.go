package plugin

import (
	"fmt"
	"sync"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

const (
	// maxStateKeys is the maximum number of keys allowed per plugin state.
	maxStateKeys = 10_000
	// maxStateValueSize is the maximum size in bytes for a single string or bytes value.
	maxStateValueSize = 1 << 20 // 1 MB
)

// PluginState provides a per-plugin in-memory key-value store.
// It is safe for concurrent use from multiple goroutines.
// Values are limited to primitive types: string, bytes, int, float, bool.
// The state is volatile (lost on process restart) but survives plugin reloads.
//
// Resource limits are enforced to prevent unbounded memory growth:
//   - Maximum of 10,000 keys per plugin
//   - Maximum of 1 MB per string/bytes value
type PluginState struct {
	mu   sync.RWMutex
	data map[string]starlark.Value
}

// NewPluginState creates a new empty PluginState.
func NewPluginState() *PluginState {
	return &PluginState{
		data: make(map[string]starlark.Value),
	}
}

// newStateModule creates a Starlark "state" module bound to the given PluginState.
// Each plugin gets its own module instance backed by its own PluginState,
// ensuring namespace isolation between plugins.
func newStateModule(ps *PluginState) *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "state",
		Members: starlark.StringDict{
			"get":    starlark.NewBuiltin("state.get", ps.stateGet),
			"set":    starlark.NewBuiltin("state.set", ps.stateSet),
			"delete": starlark.NewBuiltin("state.delete", ps.stateDelete),
			"keys":   starlark.NewBuiltin("state.keys", ps.stateKeys),
			"clear":  starlark.NewBuiltin("state.clear", ps.stateClear),
		},
	}
}

// stateGet implements state.get(key) -> value or None.
func (ps *PluginState) stateGet(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	v, ok := ps.data[string(key)]
	if !ok {
		return starlark.None, nil
	}
	return v, nil
}

// stateSet implements state.set(key, value). Returns None.
// Only primitive types are accepted: string, bytes, int, float, bool.
func (ps *PluginState) stateSet(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	var value starlark.Value
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &key, &value); err != nil {
		return nil, err
	}

	if err := validateStateValue(value); err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}

	// Check value size for string and bytes types.
	switch v := value.(type) {
	case starlark.String:
		if len(v) > maxStateValueSize {
			return nil, fmt.Errorf("%s: value size %d exceeds limit %d", fn.Name(), len(v), maxStateValueSize)
		}
	case starlark.Bytes:
		if len(v) > maxStateValueSize {
			return nil, fmt.Errorf("%s: value size %d exceeds limit %d", fn.Name(), len(v), maxStateValueSize)
		}
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Check key count limit (only when adding a new key).
	k := string(key)
	if _, exists := ps.data[k]; !exists && len(ps.data) >= maxStateKeys {
		return nil, fmt.Errorf("%s: key count %d exceeds limit %d", fn.Name(), len(ps.data), maxStateKeys)
	}

	ps.data[k] = value
	return starlark.None, nil
}

// stateDelete implements state.delete(key). Returns None.
// Deleting a non-existent key is a no-op.
func (ps *PluginState) stateDelete(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	delete(ps.data, string(key))
	return starlark.None, nil
}

// stateKeys implements state.keys() -> list of key strings.
func (ps *PluginState) stateKeys(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	keys := make([]starlark.Value, 0, len(ps.data))
	for k := range ps.data {
		keys = append(keys, starlark.String(k))
	}
	return starlark.NewList(keys), nil
}

// stateClear implements state.clear(). Removes all keys. Returns None.
func (ps *PluginState) stateClear(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.data = make(map[string]starlark.Value)
	return starlark.None, nil
}

// validateStateValue checks that a Starlark value is a supported primitive type.
// Supported types: string, bytes, int, float, bool.
// Lists, dicts, and other complex types are rejected for safety.
func validateStateValue(v starlark.Value) error {
	switch v.(type) {
	case starlark.String, starlark.Bytes, starlark.Int, starlark.Float, starlark.Bool:
		return nil
	default:
		return fmt.Errorf("unsupported value type %q; only string, bytes, int, float, bool are allowed", v.Type())
	}
}
