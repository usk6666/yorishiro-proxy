package plugin

import "sync"

// hookEntry represents a single plugin's handler for a specific hook.
type hookEntry struct {
	// pluginName is the identifier of the plugin (typically the script path).
	pluginName string

	// handler is the hook function to call.
	handler HookHandler

	// onError controls what to do when this handler returns an error.
	onError OnErrorBehavior
}

// HookHandler is a function that handles a hook invocation.
// It receives hook data as a map and returns a HookResult.
type HookHandler func(data map[string]any) (*HookResult, error)

// Registry manages hook registrations for all loaded plugins.
// It dispatches hooks in registration order and is safe for concurrent use.
type Registry struct {
	mu    sync.RWMutex
	hooks map[Hook][]hookEntry
}

// NewRegistry creates a new empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		hooks: make(map[Hook][]hookEntry),
	}
}

// Register adds a hook handler for the given plugin and hook.
// Handlers are called in registration order during dispatch.
func (r *Registry) Register(pluginName string, hook Hook, handler HookHandler, onError OnErrorBehavior) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.hooks[hook] = append(r.hooks[hook], hookEntry{
		pluginName: pluginName,
		handler:    handler,
		onError:    onError,
	})
}

// Dispatch calls all registered handlers for the given hook in registration
// order. The data map is passed to each handler and may be modified by handlers
// (modifications are visible to subsequent handlers in the chain).
//
// If a handler returns ActionDrop or ActionRespond, dispatch stops immediately
// and returns that result. If a handler returns an error, the behavior depends
// on the plugin's OnError setting:
//   - OnErrorSkip: the error is collected and the next handler is called.
//   - OnErrorAbort: dispatch stops and the error is returned.
//
// Returns nil HookResult and nil error if no handlers are registered for the hook.
func (r *Registry) Dispatch(hook Hook, data map[string]any) (*HookResult, error) {
	r.mu.RLock()
	entries := r.hooks[hook]
	// Copy the slice under lock to allow concurrent modifications.
	if len(entries) == 0 {
		r.mu.RUnlock()
		return nil, nil
	}
	snapshot := make([]hookEntry, len(entries))
	copy(snapshot, entries)
	r.mu.RUnlock()

	for _, entry := range snapshot {
		result, err := entry.handler(data)
		if err != nil {
			switch entry.onError {
			case OnErrorAbort:
				return nil, &DispatchError{
					PluginName: entry.pluginName,
					Hook:       hook,
					Err:        err,
				}
			default: // OnErrorSkip
				continue
			}
		}
		if result == nil {
			continue
		}

		// Update data from result for subsequent handlers.
		if result.Data != nil {
			for k, v := range result.Data {
				data[k] = v
			}
		}

		// ActionDrop and ActionRespond stop the chain.
		if result.Action == ActionDrop || result.Action == ActionRespond {
			return result, nil
		}
	}

	// All handlers returned CONTINUE.
	return &HookResult{
		Action: ActionContinue,
		Data:   data,
	}, nil
}

// HasHandlers returns true if any handlers are registered for the given hook.
func (r *Registry) HasHandlers(hook Hook) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.hooks[hook]) > 0
}

// Clear removes all registered handlers.
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = make(map[Hook][]hookEntry)
}
