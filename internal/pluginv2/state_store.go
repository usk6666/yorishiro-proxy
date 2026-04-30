package pluginv2

import (
	"fmt"
	"log/slog"
	"sync"

	"go.starlark.net/starlark"
)

// StateReleaser is the narrow interface a Layer needs in order to fire
// per-transaction / per-stream cleanup at terminal-state transitions.
// *Engine satisfies this interface; Layers store it as an Option (see
// internal/layer/http2.WithStateReleaser etc.).
//
// USK-671 cross-issue contract: the Pipeline dispatch path must run any
// lifecycle/terminal hook (e.g. grpc.on_end, ws.on_close) synchronously to
// completion BEFORE the owning Layer's terminal path invokes ReleaseStream
// or ReleaseTransaction here. Otherwise the hook would observe an empty
// dict for the very transaction/stream it is reporting on.
type StateReleaser interface {
	ReleaseTransaction(connID, flowID string)
	ReleaseStream(connID, streamID string)
}

const (
	// maxScopedStateKeys mirrors PluginState's per-plugin cap so a plugin
	// author sees the same envelope regardless of which scoped dict they
	// touch.
	maxScopedStateKeys = 10_000

	// maxScopedStateValueSize mirrors PluginState's per-value cap.
	maxScopedStateValueSize = 1 << 20 // 1 MiB

	// scopeStoreCap caps the number of in-flight scopes per store.
	// Defends against a runaway plugin that creates an unbounded number
	// of scope entries (e.g., one set per fake stream id). 100k handles
	// thousands of long-lived connections × tens of streams per
	// connection comfortably.
	scopeStoreCap = 100_000
)

// scopeKey identifies a single transaction or stream scope. ConnID is
// always populated; the second component is FlowID (transaction) or
// StreamID (stream).
type scopeKey struct {
	connID string
	id     string
}

// ScopedState is the per-scope KV backing ctx.transaction_state and
// ctx.stream_state. Values are restricted to the same primitive set as
// PluginState (string, bytes, int, float, bool); per-key + per-value
// caps mirror PluginState's. Safe for concurrent use.
type ScopedState struct {
	mu   sync.RWMutex
	data map[string]starlark.Value
}

func newScopedState() *ScopedState {
	return &ScopedState{data: make(map[string]starlark.Value)}
}

// reset zeros the underlying map. Called by the store when the scope is
// released so any goroutine that still holds a *ScopedState pointer (a
// hook that captured one before release) cannot accumulate new entries
// against the dropped scope.
func (s *ScopedState) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = nil
}

func (s *ScopedState) get(key string) starlark.Value {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.data[key]; ok {
		return v
	}
	return starlark.None
}

func (s *ScopedState) set(key string, v starlark.Value) error {
	if err := validateStateValue(v); err != nil {
		return err
	}
	switch x := v.(type) {
	case starlark.String:
		if len(x) > maxScopedStateValueSize {
			return fmt.Errorf("value size %d exceeds limit %d", len(x), maxScopedStateValueSize)
		}
	case starlark.Bytes:
		if len(x) > maxScopedStateValueSize {
			return fmt.Errorf("value size %d exceeds limit %d", len(x), maxScopedStateValueSize)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		// Released between hook firing and set. Drop the write so a stale
		// reference does not resurrect a freed scope.
		return nil
	}
	if _, exists := s.data[key]; !exists && len(s.data) >= maxScopedStateKeys {
		return fmt.Errorf("key count %d exceeds limit %d", len(s.data), maxScopedStateKeys)
	}
	s.data[key] = v
	return nil
}

func (s *ScopedState) del(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		delete(s.data, key)
	}
}

func (s *ScopedState) keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.data))
	for k := range s.data {
		out = append(out, k)
	}
	return out
}

func (s *ScopedState) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		s.data = make(map[string]starlark.Value)
	}
}

// scopeStore is the concurrent map of (ConnID, ID) → *ScopedState.
// One instance backs transaction scopes, another backs stream scopes.
type scopeStore struct {
	mu     sync.Mutex
	scopes map[scopeKey]*ScopedState
	logger *slog.Logger
	label  string // "transaction" / "stream"; used in log lines
}

func newScopeStore(logger *slog.Logger, label string) *scopeStore {
	return &scopeStore{
		scopes: make(map[scopeKey]*ScopedState),
		logger: logger,
		label:  label,
	}
}

// getOrCreate returns the *ScopedState for (connID, id), creating a fresh
// one if absent. Returns nil — and logs a Warn — when connID is empty (a
// fail-safe against cross-connection collisions on a Layer construction
// bug), when id is empty (release() rejects empty ids, so an entry inserted
// here would leak until Engine.Close), or when the store has reached its
// outer cap.
func (s *scopeStore) getOrCreate(connID, id string) *ScopedState {
	if connID == "" {
		s.logger.Warn("pluginv2: refusing scope with empty ConnID",
			slog.String("scope", s.label),
			slog.String("id", id))
		return nil
	}
	if id == "" {
		// Symmetric with release(): an empty-id entry could not be
		// released by ReleaseTransaction/ReleaseStream and would leak
		// until shutdown. Refuse the insert at the store boundary so the
		// invariant holds regardless of caller discipline.
		s.logger.Warn("pluginv2: refusing scope with empty id",
			slog.String("scope", s.label),
			slog.String("conn_id", connID))
		return nil
	}
	k := scopeKey{connID: connID, id: id}
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.scopes[k]; ok {
		return v
	}
	if len(s.scopes) >= scopeStoreCap {
		s.logger.Warn("pluginv2: scope store full; refusing new scope",
			slog.String("scope", s.label),
			slog.Int("cap", scopeStoreCap),
			slog.String("conn_id", connID),
			slog.String("id", id))
		return nil
	}
	v := newScopedState()
	s.scopes[k] = v
	return v
}

// release removes the entry for (connID, id) and zeros its data. Idempotent.
func (s *scopeStore) release(connID, id string) {
	if connID == "" || id == "" {
		return
	}
	k := scopeKey{connID: connID, id: id}
	s.mu.Lock()
	v, ok := s.scopes[k]
	if ok {
		delete(s.scopes, k)
	}
	s.mu.Unlock()
	if v != nil {
		v.reset()
	}
}

// size reports the number of in-flight scopes. Used by tests to assert
// that release fires for every Layer terminal transition.
func (s *scopeStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.scopes)
}

// purge zeros every scope and clears the map. Engine.Close calls this at
// shutdown so no per-connection state lingers after the proxy stops.
func (s *scopeStore) purge() {
	s.mu.Lock()
	scopes := s.scopes
	s.scopes = make(map[scopeKey]*ScopedState)
	s.mu.Unlock()
	for _, v := range scopes {
		v.reset()
	}
}
