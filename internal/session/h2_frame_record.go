// Package session — h2 DATA frame envelope recording for the WS-over-h2 /
// SSE-over-h2 detach paths (USK-889).
//
// The per-stream sub-stack overlay (RFC-001 §3.4.1) detaches an h2 stream's
// DATA byte stream to a ws.Layer / sse.Layer. Pre-USK-889 those DATA frames
// were lost to the recorder — only the post-overlay semantic envelopes
// (WSMessage / SSEMessage) reached the Pipeline. This file installs the
// recover path: a record-only Pipeline + a frame-record callback wired into
// http2.Layer.DetachStream via WithFrameRecordCallback.
//
// Design summary (per the USK-889 design review):
//
//   - Q2: the record-only Pipeline lives in the orchestrator, NOT in the
//     h2 Layer. The h2 Layer stays protocol-neutral; the orchestrator
//     composes p.Without(InterceptStep, TransformStep, PluginStepPre,
//     PluginStepPost, SafetyStep, BudgetStep) to drop every policy/
//     transform step while keeping the scope gates + RecordStep.
//   - Q3: the callback is synchronous on the runDetachDrain goroutine.
//     The contract is documented on WithFrameRecordCallback —
//     non-blocking is mandatory.
//   - Q18: callback fires BEFORE pipe.Write. CLAUDE.md MITM Principle 3.
//   - Q4 / Q5 / Q6 / Q7: the envelope arrives as-is from the h2 channel —
//     Protocol=ProtocolHTTP, Message=*H2DataEvent, Raw=DATA payload bytes
//     (no 9-byte frame header), EndStream preserved on the typed field.
//   - Q8 / Q9 / Q14: frame envelopes share the parent sessionStreamID but
//     stamp WireLevel=h2-frame and run a per-direction sequence counter
//     scoped to (sessionStreamID, h2-frame). The schemaV14 widened UNIQUE
//     constraint (stream_id, sequence, direction, variant, wire_level)
//     keeps frame and semantic rows from colliding on the sequence space.
//   - Q15: per-Stream cap (config.MaxHTTP2FrameRecordsPerStream) is
//     applied by RecordStep via WithHTTP2FrameMaxPerStream — wired
//     centrally through proxybuild.

package session

import (
	"context"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// h2FrameRecordCallback constructs the synchronous callback installed via
// http2.Layer.DetachStream(WithFrameRecordCallback(...)). Delegates to the
// generic wireLevelRecordCallback helper after binding the WireLevel
// discriminator to flow.WireLevelH2Frame. Retained as a thin wrapper for
// the call sites that already exist on the h2 detach paths.
func h2FrameRecordCallback(
	ctx context.Context,
	recPipeline *pipeline.Pipeline,
	sessionStreamID string,
	direction envelope.Direction,
	flowCtx envelope.EnvelopeContext,
) func(*envelope.Envelope) {
	return wireLevelRecordCallback(ctx, recPipeline, sessionStreamID, direction, flowCtx, flow.WireLevelH2Frame)
}

// wireLevelRecordCallback is the wire-level-agnostic record-callback
// helper shared by every non-semantic envelope producer (USK-889
// h2-frame, USK-895 h1-chunk). The returned function is bound to
// (recPipeline, sessionStreamID, direction, ctx, flowCtx, wireLevel) —
// the orchestrator must produce one callback per detach side since
// direction and the per-direction sequence counter differ.
//
// Sequence semantics: the counter is local to the closure so two callbacks
// installed on the same sessionStreamID (the WS-over-h2 symmetric case)
// run independent counters. Distinct (StreamID, Direction, WireLevel)
// tuples produce a unique sequence space — exactly what the schemaV14
// UNIQUE constraint requires.
//
// FlowID: a fresh UUID per envelope (per Q28). Frame / chunk envelopes do
// not participate in the variant pair so they need no stable FlowID
// across observations.
//
// Defensive copy of payload: the caller is responsible for arranging that
// env.Raw outlives the callback return. The h2 path relies on the
// H2DataEvent payload buffer ownership; the h1-chunk path constructs a
// fresh copy in the parser before invoking the callback.
//
// Termination: there is no separate termination signal. The caller's
// outer goroutine owns lifetime; when it exits the callback simply
// stops being invoked.
func wireLevelRecordCallback(
	ctx context.Context,
	recPipeline *pipeline.Pipeline,
	sessionStreamID string,
	direction envelope.Direction,
	flowCtx envelope.EnvelopeContext,
	wireLevel string,
) func(*envelope.Envelope) {
	if recPipeline == nil {
		// Defensive: nil Pipeline disables recording. This branch should
		// not be reached on the production path (proxybuild wires a
		// canonical Pipeline) but keeps unit tests that synthesize
		// detach calls without a Pipeline compiling.
		return nil
	}

	// flowCtx is intentionally not used to overwrite env.Context here
	// (USK-910): the inner envelope's Context arrives populated by the
	// producing Layer's WithEnvelopeContext template (ConnID, TLS,
	// ClientAddr, TargetHost) and clobbering it with a sparse builder-
	// derived template breaks the USK-908 first-write-wins createStream
	// guard — the streams row would be stamped with an empty conn_id when
	// the wire-level envelope races ahead of the semantic envelope. The
	// parameter is preserved for signature stability; only WireLevel is
	// stamped in-place on the inner envelope per MITM Principle #1 (do
	// not normalize what the wire did not normalize).
	_ = flowCtx

	var seq int64

	return func(env *envelope.Envelope) {
		if env == nil {
			return
		}
		// Rewrite the envelope identity to the post-swap session-scope
		// values. The detach producer emits the lower-layer view; we
		// project onto the analyst-facing post-swap stream identity so
		// frame / chunk envelopes share the same StreamID as the
		// semantic envelopes recorded by the main Pipeline.
		env.StreamID = sessionStreamID
		env.FlowID = uuid.NewString()
		env.Direction = direction
		// Sequence is per (sessionStreamID, direction, wire_level).
		// Atomic so a future change that fires the callback from
		// multiple goroutines does not corrupt the counter; today the
		// callback is single-goroutine (the producer's read goroutine)
		// and a plain int would suffice. The atomic cost is negligible
		// against the SQLite write.
		env.Sequence = int(atomic.AddInt64(&seq, 1) - 1)
		// Stamp WireLevel in place. The inner envelope's Context fields
		// (ConnID / TLS / ClientAddr / TargetHost) are populated by the
		// producing Layer's WithEnvelopeContext and must be preserved
		// verbatim per MITM Principle #1 (USK-910).
		env.Context.WireLevel = wireLevel

		// Run through the record-only Pipeline. The Pipeline.Run return
		// values are intentionally discarded — record-only means the
		// only side effect we care about is the SaveFlow performed by
		// RecordStep. Drop / Respond cannot fire here because
		// p.Without(...) stripped every Step that could produce them.
		_, _, _ = recPipeline.Run(ctx, env)
	}
}

// h2FrameFlowContext builds the EnvelopeContext stamped on every frame
// envelope produced by the detach callbacks. It primarily threads the
// connection-scope ConnID / TargetHost / TLS / ClientAddr from the
// pre-swap CONNECT request so the scope gates in the record-only
// Pipeline match those frame envelopes against the operator's
// capture-scope rules consistently with the WS / SSE semantic envelopes.
//
// upgradeReq is the wire-observed extended-CONNECT request envelope
// captured by UpgradeStep at observation time. When nil (test paths that
// drive the upgrade orchestrator without going through UpgradeStep), we
// fall back to the Channel's identity. The fallback may yield a sparse
// Context — frame envelopes still record but capture_scope filters that
// gate on ConnID may evaluate as "no match".
//
// WireLevel is set to flow.WireLevelH2Frame at callback assembly time
// (h2FrameRecordCallback) rather than here so this helper stays usable
// as a generic Context builder for future wire_level values.
func h2FrameFlowContext(upgradeReq *envelope.Envelope, fallback layer.Channel) envelope.EnvelopeContext {
	if upgradeReq != nil {
		// Shallow copy is sufficient — EnvelopeContext fields are either
		// scalars, pointers to immutable state (TLS snapshot), or
		// interfaces with no defensive-copy contract.
		ctx := upgradeReq.Context
		// Defensive clear: ensure the WireLevel discriminator starts at
		// the zero value so h2FrameRecordCallback's stamp is the source
		// of truth. The pre-swap envelope is a semantic envelope; if it
		// somehow already carries a WireLevel value, that is upstream
		// leakage we want to discard.
		ctx.WireLevel = ""
		return ctx
	}
	if fallback != nil {
		// Channel layer does not expose the full EnvelopeContext today —
		// the wsChannelConnIDSnapshot helper covers ConnID for the WS
		// path. We return an empty Context here and let the recorder's
		// scope filter default to "no scope match" (= record); analysts
		// that exercise the synthetic test paths know they may need to
		// thread a real Context in.
		_ = fallback
	}
	return envelope.EnvelopeContext{}
}

// h2FrameRecordPipeline returns the record-only Pipeline derived from the
// canonical p by stripping every policy / transform / plugin Step. The
// surviving Steps are HostScopeStep, HTTPScopeStep, BudgetStep, and
// RecordStep — Q14 of the USK-889 design review.
//
// We keep HostScope / HTTPScope so capture_scope filters apply to frame
// envelopes consistently with the semantic envelopes the analyst already
// sees in the same Stream. BudgetStep stays so over-budget streams do not
// secretly continue recording frames after the budget triggered the
// session's main Pipeline drop.
//
// We DROP SafetyStep, PluginStepPre, InterceptStep, TransformStep,
// PluginStepPost — those operate on the semantic envelope; running them
// on frame envelopes would be wrong (Q13) and is the whole point of the
// record-only Pipeline.
//
// UpgradeStep is not included by Pipeline.Without(...) — it is only
// appended to the live Pipeline by proxybuild and is not present in the
// vanilla canonical Pipeline this helper consumes. If the caller's
// Pipeline happens to include UpgradeStep, leaving it in is harmless on
// frame envelopes because UpgradeStep's type-switch on env.Message would
// not match *H2DataEvent.
func h2FrameRecordPipeline(p *pipeline.Pipeline) *pipeline.Pipeline {
	if p == nil {
		return nil
	}
	return p.Without(
		&pipeline.SafetyStep{},
		&pipeline.PluginStepPre{},
		&pipeline.InterceptStep{},
		&pipeline.TransformStep{},
		&pipeline.PluginStepPost{},
	)
}

// sseOverH2UpstreamFrameRecordCB constructs the frame-record callback
// for the SSE-over-h2 upstream-side detach (USK-889). SSE is half-duplex
// (RFC 8895 §6); only the upstream side carries inbound DATA frames the
// proxy can observe. Pulled out of runUpgradeSSEOverH2 to keep that
// function's cyclomatic complexity below the project lint threshold.
//
// firstResp may be nil for test paths that drive runUpgradeSSEOverH2
// directly without going through UpgradeStep; in that case we fall back
// to the upstream channel's StreamID for the post-swap StreamID stamp
// and synthesize an empty Context.
func sseOverH2UpstreamFrameRecordCB(
	ctx context.Context,
	p *pipeline.Pipeline,
	firstResp *envelope.Envelope,
	upstreamCh layer.Channel,
) func(*envelope.Envelope) {
	sessionStreamID := ""
	if upstreamCh != nil {
		sessionStreamID = upstreamCh.StreamID()
	}
	var flowCtx envelope.EnvelopeContext
	if firstResp != nil {
		sessionStreamID = firstResp.StreamID
		flowCtx = firstResp.Context
	}
	flowCtx.WireLevel = "" // h2FrameRecordCallback stamps the discriminator.
	recPipeline := h2FrameRecordPipeline(p)
	return h2FrameRecordCallback(ctx, recPipeline, sessionStreamID, envelope.Receive, flowCtx)
}

// sseDetachOptions returns the http2.DetachOption slice for an
// SSE-over-h2 detach call. Today the only option is
// WithFrameRecordCallback when frameCB != nil; the helper exists so the
// runUpgradeSSEOverH2 call site stays a one-line invocation under the
// project gocyclo lint threshold.
func sseDetachOptions(frameCB func(*envelope.Envelope)) []http2.DetachOption {
	if frameCB == nil {
		return nil
	}
	return []http2.DetachOption{http2.WithFrameRecordCallback(frameCB)}
}

// AggregatorH2FrameRecordOption assembles the
// httpaggregator.WithH2FrameRecordCallback Option the orchestrator layers
// onto every httpaggregator.Wrap call on the aggregator path (USK-897 v2
// wave #3). It mirrors GRPCLPMRecordOption's shape so the same orchestrator
// per-stream wiring pattern applies to both helpers:
//
//   - Build a record-only Pipeline by stripping every policy / transform /
//     plugin Step from p (via the wire-level-agnostic h2FrameRecordPipeline
//     helper shared with USK-889 / USK-895 / USK-896).
//   - Dispatch the H2DataEvent wire envelope through it with WireLevel =
//     flow.WireLevelH2Frame stamped on EnvelopeContext.
//   - Run independent per-direction sequence counters (Send vs Receive) so
//     bidi exchanges produce a unique (StreamID, Direction, sequence,
//     WireLevel) tuple per the schemaV14 UNIQUE constraint when the SAME
//     Option is installed on both client-side and upstream-side wraps.
//
// sessionStreamID is the per-stream session-scope identity (the
// client-side aggregator's StreamID for the live data path). When
// non-empty, the callback rewrites env.StreamID to this value before
// running the record-only Pipeline. This mirrors
// session.upstreamToClient's StreamID-unification so h2-frame rows from
// the upstream-side wrap land under the same Stream as h2-frame rows
// from the client-side wrap and the semantic envelopes recorded by the
// main Pipeline.
//
// flowCtx supplies the connection-scope ConnID / TargetHost / TLS /
// ClientAddr stamped onto every H2DataEvent wire envelope so the
// record-only Pipeline's HostScope / HTTPScope gates evaluate
// consistently with the semantic envelopes recorded on the main Pipeline.
// The caller may leave flowCtx.WireLevel at any value —
// AggregatorH2FrameRecordOption defensively clears it before stamping
// flow.WireLevelH2Frame.
//
// Returns a httpaggregator.WrapOption that installs a nil callback (no-op)
// when p is nil so callers can unconditionally splat the result into
// their wopts slice without branching on Pipeline availability.
//
// USK-899 refactor: the actual closure construction is shared with
// GRPCH2DataFrameRecordOption via buildH2FrameRecordClosure. Both Options
// produce wire_level=h2-frame envelopes; they differ only in the Layer
// Option they wrap (httpaggregator.WrapOption vs grpclayer.Option), so
// extracting the closure builder keeps the two helpers symmetric.
func AggregatorH2FrameRecordOption(ctx context.Context, p *pipeline.Pipeline, sessionStreamID string, flowCtx envelope.EnvelopeContext) httpaggregator.WrapOption {
	cb := buildH2FrameRecordClosure(ctx, p, sessionStreamID, flowCtx)
	return httpaggregator.WithH2FrameRecordCallback(cb)
}

// buildH2FrameRecordClosure constructs the wire_level=h2-frame record
// callback closure shared by AggregatorH2FrameRecordOption (USK-897) and
// GRPCH2DataFrameRecordOption (USK-899). The closure is producer-agnostic:
// both Layer Options call this builder and wrap the returned function in
// their own Option type.
//
// Returns nil when p is nil so callers can pass the result directly to
// httpaggregator.WithH2FrameRecordCallback / grpclayer.WithH2DataFrameRecordCallback
// without branching on Pipeline availability.
//
// Closure contract (matches the documented per-Option callback contracts):
//   - Stamps WireLevel = flow.WireLevelH2Frame on env.Context.
//   - Rewrites env.StreamID to sessionStreamID when sessionStreamID != "".
//   - Assigns a fresh uuid.NewString() to env.FlowID.
//   - Assigns env.Sequence from one of two per-direction atomic counters
//     so the schemaV14 UNIQUE constraint on
//     (stream_id, sequence, direction, variant, wire_level) holds when
//     the same closure is installed on both client-side and upstream-side
//     wraps of one stream.
//   - Drops envelopes with a zero / unknown direction defensively.
//   - Runs the envelope through a record-only Pipeline built by
//     h2FrameRecordPipeline (HostScope + HTTPScope + Budget + Record;
//     no policy / transform / plugin Steps).
func buildH2FrameRecordClosure(ctx context.Context, p *pipeline.Pipeline, sessionStreamID string, flowCtx envelope.EnvelopeContext) func(*envelope.Envelope) {
	recPipeline := h2FrameRecordPipeline(p)
	if recPipeline == nil {
		// No Pipeline → no-op closure. Callers wrap nil into their
		// Option type (httpaggregator.WithH2FrameRecordCallback(nil) /
		// grpclayer.WithH2DataFrameRecordCallback(nil)) which is the
		// documented disable-recording contract on both Options.
		return nil
	}
	// flowCtx is intentionally not used to overwrite env.Context here
	// (USK-910): the inner envelope's Context arrives populated by the
	// producing Layer (httpaggregator wire-envelope builders /
	// grpc.channel h2-frame wire builders propagate Context: env.Context)
	// and clobbering it with a sparse builder-derived template breaks the
	// USK-908 first-write-wins createStream guard — the streams row would
	// be stamped with an empty conn_id when the wire-level envelope
	// races ahead of the semantic envelope. The parameter is preserved
	// for signature stability; only WireLevel is stamped in-place on the
	// inner envelope per MITM Principle #1 (do not normalize what the
	// wire did not normalize).
	_ = flowCtx

	// Per-direction sequence counters. The same closure installed on
	// both client-side (Send) and upstream-side (Receive) Layer wraps
	// runs independent counters; the schemaV14 UNIQUE constraint on
	// (stream_id, sequence, direction, variant, wire_level) requires
	// per-direction independence.
	var sendSeq, recvSeq int64

	return func(env *envelope.Envelope) {
		if env == nil {
			return
		}
		// Stamp wire-record envelope identity.
		env.FlowID = uuid.NewString()
		// StreamID unification: rewrite to the session-scope identity
		// when supplied so client-side and upstream-side h2-frame
		// envelopes share the Stream row created by the main Pipeline's
		// first Send envelope.
		if sessionStreamID != "" {
			env.StreamID = sessionStreamID
		}
		switch env.Direction {
		case envelope.Send:
			env.Sequence = int(atomic.AddInt64(&sendSeq, 1) - 1)
		case envelope.Receive:
			env.Sequence = int(atomic.AddInt64(&recvSeq, 1) - 1)
		default:
			// Defensive: producers (aggregator + grpc layers) never
			// emit H2DataEvent envelopes with a zero / unknown
			// direction, but if they ever did we drop the envelope
			// rather than risk a sequence-space collision against the
			// per-direction counters.
			return
		}
		// Stamp WireLevel in place. The inner envelope's Context fields
		// (ConnID / TLS / ClientAddr / TargetHost) are populated by the
		// producing Layer's WithEnvelopeContext template and propagated
		// verbatim by the wire-envelope builders; preserving them keeps
		// the streams row consistent with the connections row and the
		// other wire_level rows on the same Stream (USK-910).
		env.Context.WireLevel = flow.WireLevelH2Frame

		// Run through the record-only Pipeline. Drop / Respond cannot
		// fire here because h2FrameRecordPipeline stripped every Step
		// that could produce them.
		_, _, _ = recPipeline.Run(ctx, env)
	}
}
