package plugin

import "fmt"

// OnErrorBehavior controls what happens when a plugin hook returns an error.
type OnErrorBehavior string

const (
	// OnErrorSkip logs the error and continues to the next plugin.
	OnErrorSkip OnErrorBehavior = "skip"

	// OnErrorAbort stops the hook chain and returns the error to the caller.
	OnErrorAbort OnErrorBehavior = "abort"
)

// DefaultMaxSteps is the default maximum number of Starlark execution steps
// per hook invocation. This prevents infinite loops from causing DoS.
const DefaultMaxSteps uint64 = 1_000_000

// PluginConfig defines the configuration for a single plugin.
type PluginConfig struct {
	// Path is the filesystem path to the Starlark script file.
	Path string `json:"path"`

	// Protocol is the protocol this plugin applies to (e.g. "http", "grpc").
	// Used by protocol handlers to filter relevant plugins.
	Protocol string `json:"protocol"`

	// Hooks lists the hook names this plugin subscribes to.
	Hooks []string `json:"hooks"`

	// OnError controls the behavior when the plugin's hook returns an error.
	// Valid values: "skip" (default), "abort".
	OnError string `json:"on_error"`

	// MaxSteps limits the number of Starlark execution steps per hook call.
	// 0 means use DefaultMaxSteps. Set to a positive value to override.
	MaxSteps uint64 `json:"max_steps,omitempty"`
}

// Validate checks the PluginConfig for invalid values.
func (c *PluginConfig) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("plugin path must not be empty")
	}
	if c.Protocol == "" {
		return fmt.Errorf("plugin protocol must not be empty")
	}
	if len(c.Hooks) == 0 {
		return fmt.Errorf("plugin must specify at least one hook")
	}
	for _, h := range c.Hooks {
		if err := ValidateHook(Hook(h)); err != nil {
			return fmt.Errorf("plugin %q: %w", c.Path, err)
		}
	}
	behavior := c.onErrorBehavior()
	if behavior != OnErrorSkip && behavior != OnErrorAbort {
		return fmt.Errorf("plugin %q: invalid on_error value: %q (must be \"skip\" or \"abort\")", c.Path, c.OnError)
	}
	return nil
}

// onErrorBehavior returns the parsed OnErrorBehavior, defaulting to OnErrorSkip.
func (c *PluginConfig) onErrorBehavior() OnErrorBehavior {
	if c.OnError == "" {
		return OnErrorSkip
	}
	return OnErrorBehavior(c.OnError)
}

// maxSteps returns the configured max execution steps, or DefaultMaxSteps if not set.
func (c *PluginConfig) maxSteps() uint64 {
	if c.MaxSteps == 0 {
		return DefaultMaxSteps
	}
	return c.MaxSteps
}
