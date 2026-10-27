// Plugin dispatch logic shared between PluginStepPre and PluginStepPost.
//
// The dispatcher derives the (plugin protocol, plugin event) tuple from an
// envelope, looks up matching hooks for the requested phase, runs each hook
// in registration order via Engine.Dispatch, applies per-hook mutations
// (Unchanged / RawOnly / MessageOnly / Both — RFC §9.3 D4), and short-
// circuits the chain on the first DROP / RESPOND. A DROP / RESPOND Result
// carries the plugin identity tags and asks RunDetailed to record the
// stopped envelope and the plugin's response (Result.Record, USK-1393); a
// DROP is attributed blocked_by="plugin".
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
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"

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

	// rawRefusedWarned records the rawRefusedKey tuples whose refused
	// msg["raw"] write has already been logged at Warn, so a plugin that
	// writes raw on every h2 envelope warns once and then drops to Debug.
	// Bounded by the finite set of registered hooks.
	rawRefusedWarned sync.Map
}

// rawRefusedKey identifies one hook registration for the once-per-hook
// refusal Warn.
type rawRefusedKey struct {
	plugin, protocol, event string
	phase                   pluginv2.Phase
}

// dispatch runs every hook registered for the envelope's (protocol, event,
// phase) tuple in registration order. The first DROP/RESPOND short-circuits
// the chain. CONTINUE+mutate hooks pass their mutated envelope to the next
// hook in the chain.
//
// A RESPOND on a Receive-direction HTTP response is not a Respond Result:
// the plugin's response replaces the upstream response in place
// (receiveReplacement) and the Step returns it as a CONTINUE substitute, so
// later Steps (Intercept, Transform, PluginPost, Record) process the
// replacement. The remaining hooks of this phase are still skipped.
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
			// ErrChunkTooLarge is a CWE-400 cap-hit on the (raw, on_chunk)
			// path: the plugin returned bytes too large for the TCP relay
			// budget. Logged at the same Warn level as ErrDisallowedAction
			// because both are "plugin produced an output we refuse to
			// honour" — fail-soft: continue with the previous envelope so
			// the original chunk passes through to the wire untouched.
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
			return Result{
				Action:      Drop,
				BlockedBy:   BlockedByPlugin,
				Record:      true,
				Annotations: pluginOutcomeTags(hook, phase),
			}
		case pluginv2.ActionRespond:
			if replacement := d.receiveReplacement(ctx, current, outcome.Respond); replacement != nil {
				releaseDroppedBody(env, replacement)
				return Result{Envelope: replacement}
			}
			return Result{
				Action:      Respond,
				Response:    d.buildRespondEnvelope(current, outcome.Respond),
				Record:      true,
				Annotations: pluginOutcomeTags(hook, phase),
			}
		}
		// ActionContinue: apply mutation and pass the resulting envelope to
		// the next hook (and ultimately downstream Steps).
		current = d.applyMutation(ctx, current, outcome, hook, phase)
	}
	if current == env {
		return Result{}
	}
	releaseDroppedBody(env, current)
	return Result{Envelope: current}
}

// Stream tags naming the plugin hook that ended a Pipeline Run with DROP /
// RESPOND (USK-1393). The plugin name is a tag, not part of blocked_by:
// blocked_by stays a closed enum the query tool can filter on exactly.
const (
	tagPlugin      = "plugin"
	tagPluginHook  = "plugin_hook"
	tagPluginPhase = "plugin_phase"
)

// pluginOutcomeTags returns the Result.Annotations identifying the hook
// whose DROP / RESPOND ended the chain: its plugin name, its
// "<protocol>.<event>" (RFC-001 section 9.3 hook identity) and its phase.
func pluginOutcomeTags(hook pluginv2.Hook, phase pluginv2.Phase) map[string]string {
	return map[string]string{
		tagPlugin:      hook.PluginName,
		tagPluginHook:  hook.Protocol + "." + hook.Event,
		tagPluginPhase: string(phase),
	}
}

// releaseDroppedBody applies the session's substituted-envelope rule
// (session.runPipelineTracked, "Substituted envelopes") to the plugin
// chain's substitute. The substitute aliases the input and holds no
// references of its own: while it still points at the input's
// HTTPMessage.BodyBuffer, the session backstop releases the Layer
// reference. When a hook replaced the body (pluginv2 drops BodyBuffer from
// the new Message) nothing else would, so it is released here.
//
// Called once per dispatch, on the CONTINUE return only: a DROP / RESPOND
// keeps the input envelope, which still points at the buffer, and the
// backstop releases it as usual. The input's field is cleared so a later
// Step that ends the chain cannot hand the backstop a stale pointer. The
// Pipeline snapshot holds its own reference, so the original variant is
// still recorded from the spilled body.
//
// Only BodyBuffer is released: the backstop owns the input's RawBuffer
// reference regardless of the returned envelope.
func releaseDroppedBody(in, out *envelope.Envelope) {
	im, _ := in.Message.(*envelope.HTTPMessage)
	if im == nil || im.BodyBuffer == nil {
		return
	}
	if om, ok := out.Message.(*envelope.HTTPMessage); ok && om != nil && om.BodyBuffer == im.BodyBuffer {
		return
	}
	_ = im.BodyBuffer.Release()
	im.BodyBuffer = nil
}

// applyMutation produces the envelope to feed to the next hook (or
// downstream Steps) given a CONTINUE outcome.
//
// RFC §9.3 D4 "raw wins" is carried on the envelope itself
// (Envelope.RawAuthoritative) so the Layer that writes the wire sees it
// (USK-1079); the ctx-scoped wireEncodedState only tracks the USK-684
// Encoded dedup flag:
//
//   - Unchanged: leave env and the Encoded flag as-is (the prior chain
//     step's truth still holds — Raw and Message are unchanged).
//   - RawOnly / Both: mark the envelope RawAuthoritative and clear
//     Encoded (Raw is user-verbatim, not encoder output). RawBuffer is
//     dropped: the plugin's bytes are the complete wire message, and a
//     disk-spilled body must not be stitched after them by WireBytes. The
//     session refcount backstop tracks the input envelope's RawBuffer, so
//     dropping the reference here does not leak it.
//   - MessageOnly: the Message is now the last writer, so the raw-wins
//     marker of an earlier hook is cleared; regenerateRaw then sets
//     Encoded on success or clears it on fail-soft / partial / error.
//     On success Raw is the complete re-encoded message, so RawBuffer is
//     dropped (without release) for the same reason as RawOnly / Both.
//
// RawOnly / Both are first checked against the route's RawWinsPolicy
// (WireEncoderRegistry.RawWinsSupported). When the destination Layer
// cannot write the bytes verbatim — an h2 HTTPMessage, a gRPC Start/End,
// a gRPC-Web Start: all header blocks whose Raw is an unframed HPACK /
// header snapshot — the raw write is refused with a Warn so the recorded
// modified variant stays equal to the wire: RawOnly is treated as
// Unchanged, Both as MessageOnly.
func (d *pluginDispatcher) applyMutation(ctx context.Context, env *envelope.Envelope, outcome *pluginv2.HookOutcome, hook pluginv2.Hook, phase pluginv2.Phase) *envelope.Envelope {
	switch outcome.Mutation {
	case pluginv2.MutationUnchanged:
		return env
	case pluginv2.MutationRawOnly, pluginv2.MutationBoth:
		if !d.rawWinsSupported(env, outcome) {
			d.warnRawRefused(ctx, env, hook, phase)
			if outcome.Mutation == pluginv2.MutationRawOnly {
				return env
			}
			return d.applyMessageOnly(ctx, env, outcome.NewMessage)
		}
		// RawOnly: new raw bytes, original Message aliased. Both: the new
		// Message is propagated for variant recording and downstream typed
		// inspection but does NOT drive wire bytes. Either way Raw wins
		// per D4: the Layer writes it verbatim and RecordStep must not
		// run the encoder over it (USK-686).
		clearWireEncoded(ctx)
		next := *env
		next.Raw = outcome.NewRaw
		next.RawBuffer = nil
		next.RawAuthoritative = true
		next.Message = outcome.NewMessage
		return &next
	case pluginv2.MutationMessageOnly:
		return d.applyMessageOnly(ctx, env, outcome.NewMessage)
	default:
		return env
	}
}

// applyMessageOnly installs msg as the new Message: raw regenerated by
// encoder if available, else preserved verbatim (Q-7 resolution: ship new
// Message + original Raw, log Debug, variant snapshot still records the
// divergence).
func (d *pluginDispatcher) applyMessageOnly(ctx context.Context, env *envelope.Envelope, msg envelope.Message) *envelope.Envelope {
	next := *env
	next.Message = msg
	next.RawAuthoritative = false
	raw, encoded := d.regenerateRaw(ctx, &next, env.Raw)
	next.Raw = raw
	if encoded {
		// Raw is now the encoder's complete message, body included. A
		// disk-spilled RawBuffer holds the input's wire body and must not
		// be stitched after it by WireBytes, or the recorded modified
		// variant carries the old body after the new message. Not
		// released: the session backstop owns the input's RawBuffer
		// reference regardless of the returned envelope.
		next.RawBuffer = nil
	}
	return &next
}

// rawWinsSupported consults the route's RawWinsPolicy for the envelope a
// raw write would produce (the plugin's Message on Both, the incoming one
// on RawOnly — the Message type never changes across a hook).
func (d *pluginDispatcher) rawWinsSupported(env *envelope.Envelope, outcome *pluginv2.HookOutcome) bool {
	probe := *env
	if outcome.NewMessage != nil {
		probe.Message = outcome.NewMessage
	}
	probe.Raw = outcome.NewRaw
	return d.encoders.RawWinsSupported(&probe)
}

// warnRawRefused logs one refused msg["raw"] write. The first refusal per
// (plugin, protocol.event, phase) is a Warn per the plugin misbehaviour row
// of the log-level table: the proxy continues, but the plugin author's
// intent did not reach the wire. Repeats for the same hook drop to Debug
// so a plugin that always writes raw does not flood the operator log.
func (d *pluginDispatcher) warnRawRefused(ctx context.Context, env *envelope.Envelope, hook pluginv2.Hook, phase pluginv2.Phase) {
	level := slog.LevelWarn
	key := rawRefusedKey{plugin: hook.PluginName, protocol: hook.Protocol, event: hook.Event, phase: phase}
	if _, seen := d.rawRefusedWarned.LoadOrStore(key, struct{}{}); seen {
		level = slog.LevelDebug
	}
	d.logger.Log(ctx, level, "plugin: msg[\"raw\"] cannot be written verbatim on this envelope; raw write ignored (edit msg[\"headers\"] / msg[\"body\"] / msg[\"metadata\"] instead)",
		slog.String("plugin", hook.PluginName),
		slog.String("hook", hook.Protocol+"."+hook.Event),
		slog.String("phase", string(phase)),
		slog.String("message_type", fmt.Sprintf("%T", env.Message)),
		slog.String("stream_id", env.StreamID),
	)
}

// regenerateRaw consults the registered WireEncoder for env.Protocol and
// returns the new Raw bytes when the encoder succeeds; encoded reports
// whether raw is encoder output. Mirrors RecordStep's applyWireEncode
// policy (USK-666 fail-soft contract):
//
//   - encoder returns (non-nil, nil)                → use new bytes
//   - encoder returns (nil, nil)         (fail-soft) → keep originalRaw + Debug
//   - encoder returns (any, ErrPartialWireBytes)    → keep originalRaw + Warn
//     (UQ-C: wire-fidelity beats partial output for the live wire path)
//   - encoder returns (any, other error)            → keep originalRaw + Warn
//   - no encoder registered for env.Protocol        → keep originalRaw + Debug
func (d *pluginDispatcher) regenerateRaw(ctx context.Context, env *envelope.Envelope, originalRaw []byte) (raw []byte, encoded bool) {
	if d.encoders == nil {
		clearWireEncoded(ctx)
		d.logger.DebugContext(ctx, "plugin: no wire encoder registry; preserving original raw",
			slog.String("protocol", string(env.Protocol)),
		)
		return originalRaw, false
	}
	enc, ok := d.encoders.Lookup(env.Protocol)
	if !ok {
		clearWireEncoded(ctx)
		d.logger.DebugContext(ctx, "plugin: no wire encoder for protocol; preserving original raw",
			slog.String("protocol", string(env.Protocol)),
		)
		return originalRaw, false
	}
	bytesOut, err := enc(env)
	switch {
	case err == nil:
		if bytesOut != nil {
			// env.Raw is now the encoder's output for the current Message.
			// RecordStep can skip its own applyWireEncode call (USK-684).
			markWireEncoded(ctx)
			return bytesOut, true
		}
		clearWireEncoded(ctx)
		d.logger.DebugContext(ctx, "plugin: wire encoder returned nil bytes (fail-soft); preserving original raw",
			slog.String("protocol", string(env.Protocol)),
		)
		return originalRaw, false
	default:
		clearWireEncoded(ctx)
		d.logger.WarnContext(ctx, "plugin: wire encoder failed; preserving original raw",
			slog.String("protocol", string(env.Protocol)),
			slog.String("error", err.Error()),
		)
		return originalRaw, false
	}
}

// receiveReplacement realizes a RESPOND on a Receive-direction HTTP
// response (http.on_response, or ws.on_upgrade on the upstream's 101): the
// plugin's response supersedes the upstream response in place (RFC-001
// §9.3). It returns the substitute envelope, or nil when the RESPOND is not
// a response-side HTTP replacement (a Send-side RESPOND answers the client
// instead of forwarding; a gRPC RESPOND_GRPC ends the RPC in the session).
//
// The substitute keeps the upstream response's identity (StreamID, FlowID,
// Sequence, Direction, Protocol, Context) so the rest of the chain — later
// Steps and RecordStep's variant pair — treats it as a modification of that
// response: the upstream bytes stay the original variant, the plugin's
// response becomes the modified one. Opaque is cleared so the client Layer
// writes the substitute from its Message instead of patching the upstream
// head; Raw is the route encoder's rendering of the substitute (RawBuffer
// dropped without release, as in applyMessageOnly).
func (d *pluginDispatcher) receiveReplacement(ctx context.Context, current *envelope.Envelope, payload *pluginv2.RespondAction) *envelope.Envelope {
	if current.Direction != envelope.Receive || payload == nil || payload.HTTPResponse == nil {
		return nil
	}
	if _, ok := current.Message.(*envelope.HTTPMessage); !ok {
		return nil
	}
	next := *current
	next.Message = httpRespondMessage(payload.HTTPResponse)
	next.Opaque = nil
	next.RawAuthoritative = false
	next.RawBuffer = nil
	next.Raw, _ = d.regenerateRaw(ctx, &next, nil)
	return &next
}

// httpRespondMessage renders an action.RESPOND payload as an HTTPMessage.
func httpRespondMessage(p *pluginv2.HTTPRespondPayload) *envelope.HTTPMessage {
	return &envelope.HTTPMessage{
		Status:  p.StatusCode,
		Headers: p.Headers,
		Body:    p.Body,
	}
}

// buildRespondEnvelope synthesizes the response envelope for a RESPOND
// outcome. The shape follows the *RespondAction payload: an HTTP payload
// becomes an *HTTPMessage, a gRPC payload a *GRPCEndMessage. No conversion
// between the two happens here. pluginv2.Engine.Dispatch has already refused
// (as ErrDisallowedAction) any payload whose shape does not match the hook's
// protocol family, so the payload reaching this function is one the
// responding Layer can render: action.RESPOND_GRPC on grpc / grpc-web
// hooks, action.RESPOND on http / ws hooks.
//
// The response is a new message, not the request answered in place: it
// gets its own FlowID and Context.Synthetic=true, so RecordStep stores it
// as its own Receive row marked metadata synthetic="true" (USK-1393).
func (d *pluginDispatcher) buildRespondEnvelope(env *envelope.Envelope, payload *pluginv2.RespondAction) *envelope.Envelope {
	resp := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    uuid.NewString(),
		Sequence:  env.Sequence + 1,
		Direction: envelope.Receive,
		Protocol:  env.Protocol,
		Context:   env.Context,
	}
	resp.Context.Synthetic = true
	switch {
	case payload == nil:
		return resp
	case payload.HTTPResponse != nil:
		resp.Protocol = envelope.ProtocolHTTP
		resp.Message = httpRespondMessage(payload.HTTPResponse)
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
