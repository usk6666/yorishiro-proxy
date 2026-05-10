package pluginv2

import (
	"errors"
	"fmt"
)

// ErrChunkTooLarge is returned by Engine.Dispatch when a (raw, on_chunk)
// hook returns chunk bytes whose size exceeds maxTCPPluginChunkSize
// (1 MiB — mirrors config.MaxTCPPluginChunkSize; the bytechunk Layer's
// 32 KiB relay buffer × 32 expansion budget, CWE-400 mitigation). The
// cap fires for either path the plugin can use to inject raw TCP bytes:
//
//   - msg["raw"] = b"..." → outcome.NewRaw (MutationRawOnly / MutationBoth)
//   - msg["bytes"] = b"..." → (*envelope.RawMessage).Bytes via outcome.NewMessage
//
// Mirrors the ErrDisallowedAction fail-soft contract: the Pipeline
// dispatcher in internal/pipeline/plugin_dispatch.go catches this
// sentinel, logs slog.Warn, and continues with the previous (un-mutated)
// envelope so the original chunk reaches the wire untouched. The cap is
// gated by hook identity so HTTP / WS / gRPC plugins (which legitimately
// produce up to MaxBodySize) are not affected.
//
// The cap is layered on top of maxPluginRawSize (raw_field.go = 16 MiB)
// — the SetKey-time ceiling applies to msg["raw"] for ALL protocols; this
// dispatch-time cap is more restrictive and only applies to the raw TCP
// egress path because that path multiplies a small relay buffer by the
// per-connection × per-direction factor.
var ErrChunkTooLarge = errors.New("pluginv2: (raw, on_chunk) hook chunk exceeds size cap")

// LoadErrorKind classifies a plugin load failure for callers that want to
// react programmatically. Use errors.As to extract a *LoadError, then
// inspect Kind.
type LoadErrorKind int

const (
	// LoadErrUnknownProtocol — register_hook called with a protocol string
	// not in the RFC §9.3 surface (e.g. typo "htttp").
	LoadErrUnknownProtocol LoadErrorKind = iota + 1

	// LoadErrUnknownEvent — register_hook called with an event name not
	// valid for the given protocol.
	LoadErrUnknownEvent

	// LoadErrPhaseNotSupported — register_hook passed phase= explicitly
	// for a lifecycle entry (PhaseSupportNone), or passed an unknown phase
	// value.
	LoadErrPhaseNotSupported

	// LoadErrInvalidPhase — phase= argument was not "pre_pipeline" or
	// "post_pipeline".
	LoadErrInvalidPhase

	// LoadErrNotCallable — fn argument was not a Starlark callable.
	LoadErrNotCallable

	// LoadErrLegacyField — PluginConfig.Validate detected a non-empty
	// legacy field (Protocol or Hooks) that was removed in RFC-001.
	LoadErrLegacyField
)

// String returns a stable lowercase token for telemetry and tests.
func (k LoadErrorKind) String() string {
	switch k {
	case LoadErrUnknownProtocol:
		return "unknown_protocol"
	case LoadErrUnknownEvent:
		return "unknown_event"
	case LoadErrPhaseNotSupported:
		return "phase_not_supported"
	case LoadErrInvalidPhase:
		return "invalid_phase"
	case LoadErrNotCallable:
		return "not_callable"
	case LoadErrLegacyField:
		return "legacy_field"
	default:
		return fmt.Sprintf("LoadErrorKind(%d)", int(k))
	}
}

// LoadError is a typed plugin load error. Fields not relevant to a given
// kind are left zero-valued.
type LoadError struct {
	Kind       LoadErrorKind
	Protocol   string
	Event      string
	Phase      string
	PluginName string
	Path       string
	// Detail is a free-form human-readable message appended to Error().
	Detail string
}

// Error renders a load error suitable for surfacing in plugin load logs
// or returning from PluginConfig.Validate.
func (e *LoadError) Error() string {
	switch e.Kind {
	case LoadErrUnknownProtocol:
		return fmt.Sprintf("pluginv2: unknown protocol %q (plugin %q): %s", e.Protocol, e.pluginContext(), e.Detail)
	case LoadErrUnknownEvent:
		return fmt.Sprintf("pluginv2: unknown event %q for protocol %q (plugin %q): %s", e.Event, e.Protocol, e.pluginContext(), e.Detail)
	case LoadErrPhaseNotSupported:
		return fmt.Sprintf("pluginv2: phase argument not supported for (%q, %q) (plugin %q): %s", e.Protocol, e.Event, e.pluginContext(), e.Detail)
	case LoadErrInvalidPhase:
		return fmt.Sprintf("pluginv2: invalid phase %q (plugin %q): %s", e.Phase, e.pluginContext(), e.Detail)
	case LoadErrNotCallable:
		return fmt.Sprintf("pluginv2: register_hook fn for (%q, %q) is not callable (plugin %q)", e.Protocol, e.Event, e.pluginContext())
	case LoadErrLegacyField:
		return fmt.Sprintf("pluginv2: %s", e.Detail)
	default:
		return fmt.Sprintf("pluginv2: load error (kind=%s): %s", e.Kind, e.Detail)
	}
}

func (e *LoadError) pluginContext() string {
	switch {
	case e.PluginName != "":
		return e.PluginName
	case e.Path != "":
		return e.Path
	default:
		return "<unknown>"
	}
}
