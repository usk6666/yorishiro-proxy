package pluginv2

import (
	"errors"
	"sync"
	"time"
	"unicode/utf8"
)

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

// pluginStats holds one loaded plugin's fail-open counters. A pointer is
// shared by the loadedPlugin (read by Introspect) and every Hook it
// registered (written by Dispatch / FireLifecycle), so counters follow the
// plugin instance rather than its name — names are not unique. The record
// path takes only the per-plugin mutex, never Engine.mu. Counters live
// for the process lifetime (the engine is never reloaded).
type pluginStats struct {
	mu     sync.Mutex
	total  int64
	byKind map[FailOpenKind]int64
	last   *FailOpenRecord
}

// record counts one fail-open outcome of hook. nil-safe: hooks registered
// directly via Registry.Register (tests) carry no stats.
func (s *pluginStats) record(hook Hook, kind FailOpenKind, action Action, reason string) {
	if s == nil {
		return
	}
	rec := &FailOpenRecord{
		Kind:     kind,
		Protocol: hook.Protocol,
		Event:    hook.Event,
		Phase:    string(hook.Phase),
		Reason:   truncateUTF8(reason, FailOpenReasonCap),
		At:       time.Now(),
	}
	if action != ActionContinue {
		rec.Action = action.String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	if s.byKind == nil {
		s.byKind = make(map[FailOpenKind]int64)
	}
	s.byKind[kind]++
	s.last = rec
}

// snapshot returns a copy of the counters safe to hand to callers.
func (s *pluginStats) snapshot() FailOpenStats {
	if s == nil {
		return FailOpenStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := FailOpenStats{Total: s.total}
	if len(s.byKind) > 0 {
		out.ByKind = make(map[FailOpenKind]int64, len(s.byKind))
		for k, v := range s.byKind {
			out.ByKind[k] = v
		}
	}
	if s.last != nil {
		last := *s.last
		out.Last = &last
	}
	return out
}

// failOpenKindError tags a refusal with its FailOpenKind while keeping the
// wrapped error's text and errors.Is chain (ErrDisallowedAction) intact.
type failOpenKindError struct {
	kind FailOpenKind
	err  error
}

func (e *failOpenKindError) Error() string { return e.err.Error() }
func (e *failOpenKindError) Unwrap() error { return e.err }

// failOpenKindOf classifies an error Engine.Dispatch / dispatchLifecycleHook
// returns. Classification is by type / sentinel, never by message text.
func failOpenKindOf(err error) FailOpenKind {
	var ke *failOpenKindError
	switch {
	case errors.As(err, &ke):
		return ke.kind
	case errors.Is(err, ErrDisallowedAction):
		return FailOpenActionNotAllowed
	case errors.Is(err, ErrChunkTooLarge):
		return FailOpenChunkTooLarge
	case errors.Is(err, ErrBodyTooLarge):
		return FailOpenBodyTooLarge
	case errors.Is(err, ErrUnsupportedMessageType):
		return FailOpenUnsupportedMessage
	default:
		return FailOpenDispatchError
	}
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
