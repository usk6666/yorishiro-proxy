package pluginv2

// PhaseSupport describes which Phase values are accepted for a surface entry.
type PhaseSupport uint8

const (
	// PhaseSupportPrePost means register_hook accepts phase="pre_pipeline"
	// (default) or phase="post_pipeline". Used for transaction events that
	// participate in the Pipeline Step chain.
	PhaseSupportPrePost PhaseSupport = iota

	// PhaseSupportNone means the entry is a lifecycle / observation hook
	// that does not run through PluginStepPre / PluginStepPost. Passing
	// phase= explicitly to register_hook for such an entry is a load-time
	// error (USK-665 strict-reject decision).
	PhaseSupportNone
)

// EntrySpec describes one (Protocol, Event) row of the RFC §9.3 hook surface.
type EntrySpec struct {
	// Phases controls which Phase values register_hook will accept.
	Phases PhaseSupport
	// Actions enumerates the actions a Starlark hook may return for this
	// entry. ActionContinue is always implicitly permitted.
	Actions ActionMask
}

// Plugin protocol vocabulary.
//
// Plugin protocol strings are a SEPARATE vocabulary from envelope.Protocol.
// They are RFC §9.3 normative; do not unify with envelope constants.
//
//   - Plugin "tls" vs envelope.ProtocolTLSHandshake "tls-handshake"
//   - Plugin "connection" / "socks5" have NO envelope.Protocol equivalent
//     (they are lifecycle namespaces, not Message types)
//   - Plugin "http" / "ws" / "grpc" / "grpc-web" / "sse" / "raw" happen to
//     match envelope.Protocol* values, but they are independently authoritative
//
// Future protocols (HTTP/3, MQTT, etc.) extend the surface table; they are not
// added by alias from envelope.Protocol.
const (
	ProtoHTTP       = "http"
	ProtoWS         = "ws"
	ProtoGRPC       = "grpc"
	ProtoGRPCWeb    = "grpc-web"
	ProtoSSE        = "sse"
	ProtoRaw        = "raw"
	ProtoTLS        = "tls"
	ProtoConnection = "connection"
	ProtoSOCKS5     = "socks5"
)

// Hook event names. Each event is namespaced under exactly one protocol;
// the same string (e.g. "on_start") may appear under multiple protocols
// with distinct semantics.
const (
	EventOnRequest    = "on_request"
	EventOnResponse   = "on_response"
	EventOnUpgrade    = "on_upgrade"
	EventOnMessage    = "on_message"
	EventOnClose      = "on_close"
	EventOnStart      = "on_start"
	EventOnData       = "on_data"
	EventOnEnd        = "on_end"
	EventOnEvent      = "on_event"
	EventOnChunk      = "on_chunk"
	EventOnHandshake  = "on_handshake"
	EventOnConnect    = "on_connect"
	EventOnDisconnect = "on_disconnect"
)

// surface is the RFC §9.3 17-entry hook enumeration.
//
// Lookup is keyed first by protocol, then by event. Reject any
// (protocol, event) pair not present in this table at load time.
//
// Action surface:
//   - DROP/RESPOND only on transaction-start events.
//   - Mid-stream events (on_data, on_message, on_event, on_chunk) accept
//     CONTINUE only — terminating a stateful stream uses native termination
//     (gRPC RST_STREAM, WS close frame), not an action enum.
//   - Lifecycle / observation events (on_close, on_end, on_handshake,
//     on_disconnect) accept CONTINUE only. (connection.on_connect and
//     socks5.on_connect accept DROP for connection-level allowlists.)
//   - http.on_response accepts RESPOND-replace but not DROP — dropping a
//     response yields a hung client; replace with a synthetic 502 instead.
var surface = map[string]map[string]EntrySpec{
	ProtoHTTP: {
		EventOnRequest:  {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
		EventOnResponse: {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue | ActionMaskRespond},
	},
	ProtoWS: {
		EventOnUpgrade: {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
		EventOnMessage: {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue},
		EventOnClose:   {Phases: PhaseSupportNone, Actions: ActionMaskContinue},
	},
	ProtoGRPC: {
		EventOnStart: {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
		EventOnData:  {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue},
		EventOnEnd:   {Phases: PhaseSupportNone, Actions: ActionMaskContinue},
	},
	ProtoGRPCWeb: {
		EventOnStart: {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue | ActionMaskDrop | ActionMaskRespond},
		EventOnData:  {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue},
		EventOnEnd:   {Phases: PhaseSupportNone, Actions: ActionMaskContinue},
	},
	ProtoSSE: {
		EventOnEvent: {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue},
	},
	ProtoRaw: {
		EventOnChunk: {Phases: PhaseSupportPrePost, Actions: ActionMaskContinue},
	},
	ProtoTLS: {
		EventOnHandshake: {Phases: PhaseSupportNone, Actions: ActionMaskContinue},
	},
	ProtoConnection: {
		EventOnConnect:    {Phases: PhaseSupportNone, Actions: ActionMaskContinue | ActionMaskDrop},
		EventOnDisconnect: {Phases: PhaseSupportNone, Actions: ActionMaskContinue},
	},
	ProtoSOCKS5: {
		EventOnConnect: {Phases: PhaseSupportNone, Actions: ActionMaskContinue | ActionMaskDrop},
	},
}

// LookupEntry returns the EntrySpec for the given (protocol, event) pair,
// or false if the pair is not enumerated by RFC §9.3.
func LookupEntry(protocol, event string) (EntrySpec, bool) {
	events, ok := surface[protocol]
	if !ok {
		return EntrySpec{}, false
	}
	spec, ok := events[event]
	return spec, ok
}

// SurfaceEntries returns every (protocol, event) pair enumerated by the
// surface table, in lexicographic protocol+event order. Used by tests and
// by the future plugin_introspect MCP tool (USK-676).
func SurfaceEntries() []SurfaceRow {
	rows := make([]SurfaceRow, 0, 17)
	// Protocol iteration order is deterministic via sorted keys. Tests rely
	// on the count, not the order, but tools may rely on stable output.
	for _, proto := range sortedKeys(surface) {
		for _, event := range sortedKeys(surface[proto]) {
			rows = append(rows, SurfaceRow{
				Protocol: proto,
				Event:    event,
				Spec:     surface[proto][event],
			})
		}
	}
	return rows
}

// SurfaceRow is one entry of the surface table.
type SurfaceRow struct {
	Protocol string
	Event    string
	Spec     EntrySpec
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Insertion-sort: tiny slices, no allocation.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
