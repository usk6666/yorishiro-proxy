package pluginv2

import (
	"sync"

	"go.starlark.net/starlark"
)

// Hook is a single registered handler keyed by the RFC §9.3 3-axis identity
// (Protocol, Event, Phase) plus the originating plugin name for attribution.
type Hook struct {
	Protocol   string
	Event      string
	Phase      Phase
	Fn         starlark.Callable
	PluginName string
}

// Registry stores plugin hooks indexed by (Protocol, Event, Phase) and
// returns them in registration order on Lookup. Safe for concurrent use.
//
// Registration happens at engine load time (write); Lookup is read-only at
// runtime. Multiple plugins registering for the same key append entries in
// load order; PluginStepPre / PluginStepPost (USK-671) fire them in that
// same order.
type Registry struct {
	mu    sync.RWMutex
	hooks map[registryKey][]Hook
}

type registryKey struct {
	Protocol string
	Event    string
	Phase    Phase
}

// NewRegistry constructs an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		hooks: make(map[registryKey][]Hook),
	}
}

// Register appends h to the registry. The caller must have already
// validated h.Protocol, h.Event, and h.Phase against the surface table —
// the Registry does not re-validate.
func (r *Registry) Register(h Hook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := registryKey{Protocol: h.Protocol, Event: h.Event, Phase: h.Phase}
	r.hooks[key] = append(r.hooks[key], h)
}

// Lookup returns the hooks registered for (protocol, event, phase) in
// registration order, or nil if none are registered. The returned slice is
// a snapshot copy: callers may iterate it without holding the registry
// lock and without affecting subsequent registrations.
//
// For lifecycle entries (PhaseSupportNone), callers pass PhaseNone.
func (r *Registry) Lookup(protocol, event string, phase Phase) []Hook {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := r.hooks[registryKey{Protocol: protocol, Event: event, Phase: phase}]
	if len(entries) == 0 {
		return nil
	}
	out := make([]Hook, len(entries))
	copy(out, entries)
	return out
}

// Count returns the total number of registered hooks across all keys.
// Used by tests and by future plugin_introspect.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, entries := range r.hooks {
		n += len(entries)
	}
	return n
}
