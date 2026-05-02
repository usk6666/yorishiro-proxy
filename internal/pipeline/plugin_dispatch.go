// Plugin dispatch logic shared between PluginStepPre and PluginStepPost.
//
// The dispatcher derives the (plugin protocol, plugin event) tuple from an
// envelope, looks up matching hooks for the requested phase, runs each hook
// in registration order via Engine.Dispatch, applies per-hook mutations
// (Unchanged / RawOnly / MessageOnly / Both — RFC §9.3 D4), and short-
// circuits the chain on the first DROP / RESPOND.
//
// The plugin protocol vocabulary is intentionally distinct from
// envelope.Protocol (USK-665 surface.go). The dispatcher is the bridge: it
// type-switches on env.Message (the protocol-confined view per principle
// P4) for event derivation, and consults env.Protocol ONLY to choose
// between "grpc" and "grpc-web" — the one legitimate place where Protocol-
// string switching is needed because GRPCStart/Data/EndMessage types are
// intentionally shared across the two transports (RFC §3.2.3).

package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// pluginTarget is the (plugin protocol, plugin event) string pair the
// pluginv2 surface table is keyed by.
type pluginTarget struct {
	Protocol string
	Event    string
}

// dispatchTarget returns the plugin (protocol, event) for env, or
// (zero, false) if the envelope shape does not surface as a hook event
// (e.g. *GRPCEndMessage — observation-only, fires from Layer terminal
// events not from PluginStepPre/Post).
func dispatchTarget(env *envelope.Envelope) (pluginTarget, bool) {
	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		if isWebSocketUpgradeHTTP(msg) {
			return pluginTarget{Protocol: pluginv2.ProtoWS, Event: pluginv2.EventOnUpgrade}, true
		}
		if env.Direction == envelope.Send {
			return pluginTarget{Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest}, true
		}
		return pluginTarget{Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnResponse}, true
	case *envelope.WSMessage:
		return pluginTarget{Protocol: pluginv2.ProtoWS, Event: pluginv2.EventOnMessage}, true
	case *envelope.GRPCStartMessage:
		return pluginTarget{Protocol: grpcProtoFor(env.Protocol), Event: pluginv2.EventOnStart}, true
	case *envelope.GRPCDataMessage:
		return pluginTarget{Protocol: grpcProtoFor(env.Protocol), Event: pluginv2.EventOnData}, true
	case *envelope.SSEMessage:
		return pluginTarget{Protocol: pluginv2.ProtoSSE, Event: pluginv2.EventOnEvent}, true
	case *envelope.RawMessage:
		return pluginTarget{Protocol: pluginv2.ProtoRaw, Event: pluginv2.EventOnChunk}, true
	default:
		// Includes *GRPCEndMessage (lifecycle: fires from Layer, not
		// Pipeline) and any future Message type without a surface row.
		return pluginTarget{}, false
	}
}

// grpcProtoFor selects the plugin protocol vocabulary string for a gRPC
// Message. GRPCStart/Data/End types are shared between native gRPC and
// gRPC-Web; env.Protocol is the single authoritative discriminator.
func grpcProtoFor(p envelope.Protocol) string {
	if p == envelope.ProtocolGRPCWeb {
		return pluginv2.ProtoGRPCWeb
	}
	return pluginv2.ProtoGRPC
}

// isWebSocketUpgradeHTTP reports whether an HTTPMessage represents a
// WebSocket upgrade exchange. Both the upgrade request (Send) and the 101
// response (Receive) carry Upgrade: websocket — so this same predicate
// fires (ws, on_upgrade) for both directions, matching the surface table
// row that does not split request/response (only one event name).
//
// Header lookup is case-insensitive (RFC 7230 § 3.2: header names are
// case-insensitive on the wire). We intentionally do NOT consult env.Context
// or env.Protocol to make this decision: the wire shape is the ground truth
// per the no-normalization principle — if the headers say it's an upgrade,
// it's an upgrade.
func isWebSocketUpgradeHTTP(msg *envelope.HTTPMessage) bool {
	hasUpgradeConn := false
	hasWSUpgrade := false
	for _, kv := range msg.Headers {
		switch {
		case headerNameEq(kv.Name, "connection"):
			if headerValueContainsToken(kv.Value, "upgrade") {
				hasUpgradeConn = true
			}
		case headerNameEq(kv.Name, "upgrade"):
			if headerValueContainsToken(kv.Value, "websocket") {
				hasWSUpgrade = true
			}
		}
	}
	return hasUpgradeConn && hasWSUpgrade
}

// headerNameEq reports whether two ASCII header names are equal under
// case folding. Inlined ASCII fold avoids the unicode pass that
// strings.EqualFold does — header names are ASCII-only by spec.
func headerNameEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// headerValueContainsToken reports whether v contains the given token under
// comma-split, whitespace-trim, ASCII-fold equality. Used to detect e.g.
// `Connection: keep-alive, Upgrade` carrying "upgrade".
func headerValueContainsToken(v, token string) bool {
	start := 0
	for i := 0; i <= len(v); i++ {
		if i == len(v) || v[i] == ',' {
			s := start
			e := i
			for s < e && (v[s] == ' ' || v[s] == '\t') {
				s++
			}
			for e > s && (v[e-1] == ' ' || v[e-1] == '\t') {
				e--
			}
			if headerNameEq(v[s:e], token) {
				return true
			}
			start = i + 1
		}
	}
	return false
}

// pluginDispatcher is the shared engine + registry + logger triple held by
// both PluginStepPre and PluginStepPost. The Step types are thin wrappers
// that call dispatch() with their phase.
type pluginDispatcher struct {
	engine   *pluginv2.Engine
	encoders *WireEncoderRegistry
	logger   *slog.Logger
}

// dispatch runs every hook registered for the envelope's (protocol, event,
// phase) tuple in registration order. The first DROP/RESPOND short-circuits
// the chain. CONTINUE+mutate hooks pass their mutated envelope to the next
// hook in the chain.
//
// nil engine → pass-through (Result{}). No matching hooks → pass-through.
func (d *pluginDispatcher) dispatch(ctx context.Context, env *envelope.Envelope, phase pluginv2.Phase) Result {
	if d.engine == nil {
		return Result{}
	}
	target, ok := dispatchTarget(env)
	if !ok {
		return Result{}
	}
	hooks := d.engine.Registry().Lookup(target.Protocol, target.Event, phase)
	if len(hooks) == 0 {
		return Result{}
	}
	current := env
	for _, hook := range hooks {
		outcome, err := d.engine.Dispatch(ctx, hook, current)
		if err != nil {
			d.logger.WarnContext(ctx, "plugin: hook outcome rejected; treating as continue",
				slog.String("plugin", hook.PluginName),
				slog.String("hook", hook.Protocol+"."+hook.Event),
				slog.String("phase", string(phase)),
				slog.String("error", err.Error()),
			)
			continue
		}
		switch outcome.Action {
		case pluginv2.ActionDrop:
			return Result{Action: Drop}
		case pluginv2.ActionRespond:
			return Result{Action: Respond, Response: d.buildRespondEnvelope(current, outcome.Respond)}
		}
		// ActionContinue: apply mutation and pass the resulting envelope to
		// the next hook (and ultimately downstream Steps).
		current = d.applyMutation(ctx, current, outcome)
	}
	if current == env {
		return Result{}
	}
	return Result{Envelope: current}
}

// applyMutation produces the envelope to feed to the next hook (or
// downstream Steps) given a CONTINUE outcome.
//
// The wireEncodedState carried in ctx is updated to reflect the
// post-mutation relationship between Raw and Message:
//
//   - Unchanged: leave both flags as-is (the prior chain step's truth
//     still holds — Raw and Message are unchanged).
//   - RawOnly / Both: mark RawAuthoritative (RFC §9.3 D4: Raw is
//     user-verbatim; encoder must NOT overwrite it on the modified-variant
//     record path).
//   - MessageOnly: delegate to regenerateRaw, which sets Encoded on
//     success or clears both flags on fail-soft / partial / error.
func (d *pluginDispatcher) applyMutation(ctx context.Context, env *envelope.Envelope, outcome *pluginv2.HookOutcome) *envelope.Envelope {
	switch outcome.Mutation {
	case pluginv2.MutationUnchanged:
		return env
	case pluginv2.MutationRawOnly:
		// New raw bytes; original Message aliased. Raw wins per D4.
		markRawAuthoritative(ctx)
		next := *env
		next.Raw = outcome.NewRaw
		next.Message = outcome.NewMessage
		return &next
	case pluginv2.MutationMessageOnly:
		// New message; raw regenerated by encoder if available, else
		// preserved verbatim (Q-7 resolution: ship new Message + original
		// Raw, log Debug, variant snapshot still records the divergence).
		next := *env
		next.Message = outcome.NewMessage
		next.Raw = d.regenerateRaw(ctx, &next, env.Raw)
		return &next
	case pluginv2.MutationBoth:
		// "Raw wins" per RFC §9.3 D4: ship new Raw verbatim; new Message
		// is propagated for variant recording and downstream typed
		// inspection but does NOT drive wire bytes. RecordStep must skip
		// the encoder so the user's bytes survive into the modified-variant
		// record (USK-686).
		markRawAuthoritative(ctx)
		next := *env
		next.Raw = outcome.NewRaw
		next.Message = outcome.NewMessage
		return &next
	default:
		return env
	}
}

// regenerateRaw consults the registered WireEncoder for env.Protocol and
// returns the new Raw bytes when the encoder succeeds. Mirrors RecordStep's
// applyWireEncode policy (USK-666 fail-soft contract):
//
//   - encoder returns (non-nil, nil)                → use new bytes
//   - encoder returns (nil, nil)         (fail-soft) → keep originalRaw + Debug
//   - encoder returns (any, ErrPartialWireBytes)    → keep originalRaw + Warn
//     (UQ-C: wire-fidelity beats partial output for the live wire path)
//   - encoder returns (any, other error)            → keep originalRaw + Warn
//   - no encoder registered for env.Protocol        → keep originalRaw + Debug
func (d *pluginDispatcher) regenerateRaw(ctx context.Context, env *envelope.Envelope, originalRaw []byte) []byte {
	if d.encoders == nil {
		clearWireEncoded(ctx)
		d.logger.DebugContext(ctx, "plugin: no wire encoder registry; preserving original raw",
			slog.String("protocol", string(env.Protocol)),
		)
		return originalRaw
	}
	enc, ok := d.encoders.Lookup(env.Protocol)
	if !ok {
		clearWireEncoded(ctx)
		d.logger.DebugContext(ctx, "plugin: no wire encoder for protocol; preserving original raw",
			slog.String("protocol", string(env.Protocol)),
		)
		return originalRaw
	}
	bytesOut, err := enc(env)
	switch {
	case err == nil:
		if bytesOut != nil {
			// env.Raw is now the encoder's output for the current Message.
			// RecordStep can skip its own applyWireEncode call (USK-684).
			markWireEncoded(ctx)
			return bytesOut
		}
		clearWireEncoded(ctx)
		d.logger.DebugContext(ctx, "plugin: wire encoder returned nil bytes (fail-soft); preserving original raw",
			slog.String("protocol", string(env.Protocol)),
		)
		return originalRaw
	default:
		clearWireEncoded(ctx)
		d.logger.WarnContext(ctx, "plugin: wire encoder failed; preserving original raw",
			slog.String("protocol", string(env.Protocol)),
			slog.String("error", err.Error()),
		)
		return originalRaw
	}
}

// buildRespondEnvelope synthesizes the response envelope for a RESPOND
// outcome. The shape depends on the *RespondAction payload (HTTP vs gRPC)
// — both are honored regardless of the requesting envelope's Protocol so
// a plugin can RESPOND_GRPC from an HTTP envelope (e.g. on an HTTP/2
// request that should be rejected with a gRPC status). The orchestrator
// is responsible for ensuring the responding Layer can render the
// resulting Message.
func (d *pluginDispatcher) buildRespondEnvelope(env *envelope.Envelope, payload *pluginv2.RespondAction) *envelope.Envelope {
	resp := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence + 1,
		Direction: envelope.Receive,
		Protocol:  env.Protocol,
		Context:   env.Context,
	}
	switch {
	case payload == nil:
		return resp
	case payload.HTTPResponse != nil:
		resp.Protocol = envelope.ProtocolHTTP
		resp.Message = &envelope.HTTPMessage{
			Status:  payload.HTTPResponse.StatusCode,
			Headers: payload.HTTPResponse.Headers,
			Body:    payload.HTTPResponse.Body,
		}
	case payload.GRPCResponse != nil:
		// Preserve env.Protocol so a grpc-web request gets a grpc-web
		// shaped end frame (the Layer's encoder picks the wire form).
		resp.Message = &envelope.GRPCEndMessage{
			Status:   payload.GRPCResponse.Status,
			Message:  payload.GRPCResponse.Message,
			Trailers: payload.GRPCResponse.Trailers,
		}
	}
	// Best-effort Raw rendering. Layers that can't be encoded offline
	// (gRPC End is HPACK-owned; GRPCWeb End is LPM-trailer-owned) leave
	// Raw nil and the responding Layer's Send regenerates from Message.
	if d.encoders != nil {
		if enc, ok := d.encoders.Lookup(resp.Protocol); ok {
			if bytesOut, err := enc(resp); err == nil && bytesOut != nil {
				resp.Raw = bytesOut
			}
		}
	}
	return resp
}
