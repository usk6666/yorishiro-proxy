package pluginv2

import "time"

// FailOpenKind classifies a hook outcome the engine could not honour and
// therefore treated as CONTINUE (fail-open). The string values are stable
// tokens surfaced verbatim by the plugin_introspect MCP tool.
type FailOpenKind string

const (
	// FailOpenActionNotAllowed — the hook returned DROP / RESPOND for a
	// (protocol, event) whose surface ActionMask forbids it (e.g. DROP from
	// grpc.on_data, RESPOND from ws.on_message, DROP from ws.on_close).
	FailOpenActionNotAllowed FailOpenKind = "action_not_allowed"

	// FailOpenRespondShapeMismatch — a RESPOND whose shape the hook's Layer
	// cannot render: action.RESPOND on a gRPC / gRPC-Web hook, or
	// action.RESPOND_GRPC on an HTTP-family hook.
	FailOpenRespondShapeMismatch FailOpenKind = "respond_shape_mismatch"

	// FailOpenRespondOnInformational — a RESPOND on a Receive-direction
	// informational response (1xx other than 101).
	FailOpenRespondOnInformational FailOpenKind = "respond_on_informational"

	// FailOpenHookError — the hook raised a Starlark runtime error
	// (fail(), an exception, the step budget). In-place msg edits made
	// before the error are still committed (RFC-001 §9.3 D2).
	FailOpenHookError FailOpenKind = "hook_error"

	// FailOpenInvalidReturn — the hook returned a value that is not an
	// action: a bare "RESPOND" string, an unrecognized string, or a value
	// of an unsupported type.
	FailOpenInvalidReturn FailOpenKind = "invalid_return"

	// FailOpenInvalidMutation — the hook's msg edits could not be read
	// back into a message (e.g. an out-of-range field value); every edit
	// of that call is discarded.
	FailOpenInvalidMutation FailOpenKind = "invalid_mutation"

	// FailOpenChunkTooLarge — a (raw, on_chunk) hook produced bytes over
	// the 1 MiB TCP chunk cap (ErrChunkTooLarge).
	FailOpenChunkTooLarge FailOpenKind = "chunk_too_large"

	// FailOpenBodyTooLarge — the message body exceeded the 1 MiB plugin
	// view cap (ErrBodyTooLarge), so the hook was not run at all.
	FailOpenBodyTooLarge FailOpenKind = "body_too_large"

	// FailOpenUnsupportedMessage — the envelope's Message type has no
	// plugin schema (ErrUnsupportedMessageType); the hook was not run.
	FailOpenUnsupportedMessage FailOpenKind = "unsupported_message"

	// FailOpenDispatchError — any other dispatch error that made the
	// engine skip the hook.
	FailOpenDispatchError FailOpenKind = "dispatch_error"
)

// FailOpenRecord describes the most recent fail-open outcome of a plugin.
type FailOpenRecord struct {
	// Kind classifies the outcome.
	Kind FailOpenKind
	// Action is the refused action ("DROP" / "RESPOND") for the
	// action_not_allowed / respond_* kinds; empty otherwise.
	Action string
	// Protocol, Event and Phase identify the hook ("none" for lifecycle
	// hooks).
	Protocol string
	Event    string
	Phase    string
	// Reason is the engine's error text, truncated to failOpenReasonCap
	// bytes. For FailOpenHookError it is the plugin's own error message
	// and may carry data the plugin read from traffic: callers exposing
	// it outside the process must apply their output masking first.
	Reason string
	// At is when the outcome happened.
	At time.Time
}

// FailOpenStats is a point-in-time snapshot of a plugin's fail-open
// counters.
type FailOpenStats struct {
	// Total counts every fail-open outcome since the plugin was loaded.
	Total int64
	// ByKind breaks Total down per FailOpenKind; nil when Total is 0.
	ByKind map[FailOpenKind]int64
	// Last is the most recent outcome; nil when Total is 0.
	Last *FailOpenRecord
}

// FailOpenReasonCap bounds FailOpenRecord.Reason in bytes. The cut lands on
// a UTF-8 rune boundary.
const FailOpenReasonCap = 1024
