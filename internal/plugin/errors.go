package plugin

import "fmt"

// DispatchError wraps an error from a plugin hook handler with context
// about which plugin and hook caused the error.
type DispatchError struct {
	// PluginName is the identifier of the plugin that errored.
	PluginName string
	// Hook is the hook that was being dispatched.
	Hook Hook
	// Err is the underlying error.
	Err error
}

// Error returns a human-readable error message.
func (e *DispatchError) Error() string {
	return fmt.Sprintf("plugin %q hook %q: %v", e.PluginName, string(e.Hook), e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *DispatchError) Unwrap() error {
	return e.Err
}
