package pluginv2

import "fmt"

// OnErrorBehavior controls the dispatch chain when a plugin hook returns
// an error. Carried forward from legacy semantics unchanged.
type OnErrorBehavior string

const (
	// OnErrorSkip logs and continues to the next hook in the chain.
	OnErrorSkip OnErrorBehavior = "skip"

	// OnErrorAbort stops the chain and returns the error.
	OnErrorAbort OnErrorBehavior = "abort"
)

// DefaultMaxSteps caps Starlark execution per hook call (DoS guard).
// Carried forward from legacy unchanged.
const DefaultMaxSteps uint64 = 1_000_000

// legacyFieldRemovedMessage is the verbatim error returned when YAML/JSON
// configuration still carries the legacy `protocol:` or `hooks:` fields.
// Per USK-665 acceptance criterion U1.
const legacyFieldRemovedMessage = "field hooks/protocol removed in RFC-001; use register_hook() in your script. See docs/rfc/plugin-migration.md"

// PluginConfig configures one Starlark plugin. RFC §9.3 makes Hook
// registration script-driven (register_hook calls inside the .star file),
// so unlike legacy there is no Hooks slice on the config.
type PluginConfig struct {
	// Name is a stable identifier for the plugin. Used for error attribution
	// and for keying the per-plugin state / store. If empty, the engine
	// derives one from Path.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Path is the filesystem path to the .star script.
	Path string `json:"path" yaml:"path"`

	// Vars is a map of arbitrary primitive values exposed to the script as
	// the predeclared `config` dict. Values are converted to Starlark
	// primitives at engine load (string, int, float, bool, bytes); other
	// types are rejected at conversion time.
	Vars map[string]any `json:"vars,omitempty" yaml:"vars,omitempty"`

	// OnError controls behavior when a hook returns an error: "skip" or
	// "abort". Empty defaults to "skip".
	OnError string `json:"on_error,omitempty" yaml:"on_error,omitempty"`

	// MaxSteps overrides the per-call Starlark execution-step budget.
	// Zero means use DefaultMaxSteps.
	MaxSteps uint64 `json:"max_steps,omitempty" yaml:"max_steps,omitempty"`

	// RedactKeys lists Vars keys whose values must be hidden from the
	// future plugin_introspect MCP tool (USK-676). Stored verbatim by
	// USK-665; consumed downstream.
	RedactKeys []string `json:"redact_keys,omitempty" yaml:"redact_keys,omitempty"`

	// Protocol — REMOVED IN RFC-001. Field retained ONLY so YAML/JSON
	// unmarshal of legacy configs lands here and can be rejected by
	// Validate(). Do not read this field at runtime.
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Hooks — REMOVED IN RFC-001. Field retained ONLY so YAML/JSON
	// unmarshal of legacy configs lands here and can be rejected by
	// Validate(). Do not read this field at runtime.
	Hooks []string `json:"hooks,omitempty" yaml:"hooks,omitempty"`
}

// Validate rejects the legacy `protocol:` / `hooks:` tripwire fields with
// the migration message. It also normalizes / verifies the live fields.
func (c *PluginConfig) Validate() error {
	if c.Protocol != "" || len(c.Hooks) > 0 {
		return &LoadError{
			Kind:   LoadErrLegacyField,
			Path:   c.Path,
			Detail: legacyFieldRemovedMessage,
		}
	}
	if c.Path == "" {
		return fmt.Errorf("pluginv2: plugin path must not be empty")
	}
	switch OnErrorBehavior(c.OnError) {
	case "", OnErrorSkip, OnErrorAbort:
		// OK
	default:
		return fmt.Errorf("pluginv2: invalid on_error %q (must be %q or %q)", c.OnError, OnErrorSkip, OnErrorAbort)
	}
	for i, k := range c.RedactKeys {
		if k == "" {
			return fmt.Errorf("pluginv2: redact_keys[%d] must not be empty", i)
		}
	}
	return nil
}

// onErrorBehavior returns the parsed OnErrorBehavior, defaulting to
// OnErrorSkip. Validate() guarantees a parseable value.
func (c *PluginConfig) onErrorBehavior() OnErrorBehavior {
	if c.OnError == "" {
		return OnErrorSkip
	}
	return OnErrorBehavior(c.OnError)
}

// maxSteps returns the configured cap, defaulting to DefaultMaxSteps.
func (c *PluginConfig) maxSteps() uint64 {
	if c.MaxSteps == 0 {
		return DefaultMaxSteps
	}
	return c.MaxSteps
}
