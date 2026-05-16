// Package session — gRPC-Web base64 wire-record envelope recording for the
// gRPC-Web text-variant data path (USK-898).
//
// gRPC-Web text variants (application/grpc-web-text[+proto]) carry the
// LPM-framed body base64-encoded over HTTP/1.x and HTTP/2. Pre-USK-898 the
// grpcweb Layer base64-decoded the body BEFORE producing envelopes, so the
// wire-observed base64 byte form was lost — violating CLAUDE.md MITM
// Principle 3 (raw bytes preservation). This file installs the recover
// path: a record-only Pipeline + a per-body record callback wired into
// grpcweb.Wrap via the new WithEncodedFormRecordCallback Option.
//
// Design summary (composes with USK-889 / USK-895 / USK-896 / USK-897 —
// fifth implementation of the same per-Layer record-callback pattern;
// common WireLevelTap interface refactor remains deferred):
//
//   - Naming: <protocol>-<unit> flat, value = "grpcweb-base64" (per-
//     protocol canonical: the base64 unit is gRPC-Web's text wire form,
//     distinct from binary which has no encoded form to record).
//   - API: per-Layer ad-hoc Option (grpcweb.WithEncodedFormRecordCallback)
//     mirroring USK-896's WithLPMFrameRecordCallback shape and USK-895's
//     WithChunkRecordCallback shape.
//   - Pipeline: record-only via h2FrameRecordPipeline (already wire-level
//     agnostic — strips Safety / PluginPre / Intercept / Transform /
//     PluginPost; leaves HostScope / HTTPScope / Budget / Record).
//   - Cap: RecordStep.WithGRPCWebBase64MaxPerStream (default 10000,
//     USK-802 LRU shared). proxybuild.Deps.RecordGRPCWebBase64MaxPerStream
//     wires it through.
//   - Bidi RPC: gRPC-Web has no client streaming on the wire (request is
//     a single HTTPMessage; response is a single HTTPMessage). The
//     orchestrator installs the SAME Option on both the client-side and
//     upstream-side grpcweb.Wrap; the client-side wrap fires the
//     callback for the Send-direction (request) text body, the upstream-
//     side wrap fires it for the Receive-direction (response) text body.
//     Per-direction sequence counters live inside the callback closure
//     so each direction's flow rows form a unique (StreamID, Direction,
//     sequence, WireLevel) tuple per the schemaV14 UNIQUE constraint.
//
// StreamID unification (mirrors session.upstreamToClient and the
// USK-896 / USK-897 helpers): the upstream-side grpcweb Layer emits
// envelopes carrying the upstream stream's StreamID, which differs from
// the client-side StreamID. To make the base64 wire envelopes shareable
// with the semantic envelopes recorded on the main Pipeline under the
// client StreamID, the orchestrator passes the client-side StreamID to
// GRPCWebBase64RecordOption at build time; the callback rewrites
// env.StreamID to that value before dispatching to the record-only
// Pipeline. The same closure is installed on both wraps, so all base64
// wire envelopes end up under one Stream row.
//
// Live? Defense-in-depth (per USK-898 Issue body). No live bug is
// currently triggering this gap; the goal is to make base64 padding
// anomalies, illegal-character smuggling, and encoding-side bombs
// observable when they arise.

package session

import (
	"context"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// GRPCWebBase64RecordOption assembles the
// grpcweb.WithEncodedFormRecordCallback Option that the orchestrator
// layers onto the grpcwebOpts chain passed into DispatchH2StreamFull /
// WrapH2UpstreamForDispatchFull (h2 path) and into the OnStack-built
// grpcweb wraps (h1 path). It builds a record-only Pipeline by stripping
// every policy / transform / plugin Step from p (via the existing
// h2FrameRecordPipeline helper, which is wire-level-agnostic) and
// dispatches the base64 wire envelope through it with WireLevel =
// flow.WireLevelGRPCWebBase64 stamped on EnvelopeContext.
//
// sessionStreamID is the per-stream session-scope identity (the
// client-side grpcweb stream's StreamID for the live data path). When
// non-empty, the callback rewrites env.StreamID to this value before
// running the record-only Pipeline. This mirrors
// session.upstreamToClient's StreamID-unification (env.StreamID =
// clientID) so base64 wire rows from the upstream-side wrap land under
// the same Stream as base64 wire rows from the client-side wrap and the
// semantic envelopes recorded by the main Pipeline. Pass "" when no
// unification is required (e.g., synthetic test paths that exercise only
// one wrap).
//
// flowCtx supplies the connection-scope ConnID / TargetHost / TLS /
// ClientAddr stamped onto every base64 wire envelope so the record-only
// Pipeline's HostScope / HTTPScope gates evaluate consistently with the
// semantic envelopes recorded on the main Pipeline. The caller may leave
// flowCtx.WireLevel at any value — GRPCWebBase64RecordOption defensively
// clears it before stamping flow.WireLevelGRPCWebBase64.
//
// Returns a grpcweb.Option that installs a nil callback (no-op) when p
// is nil so callers can unconditionally splat the result into their
// grpcwebOpts slice without branching on Pipeline availability.
func GRPCWebBase64RecordOption(ctx context.Context, p *pipeline.Pipeline, sessionStreamID string, flowCtx envelope.EnvelopeContext) grpcweb.Option {
	recPipeline := h2FrameRecordPipeline(p)
	if recPipeline == nil {
		// No Pipeline → no-op Option (matches the
		// WithEncodedFormRecordCallback contract: nil callback disables
		// wire-record).
		return grpcweb.WithEncodedFormRecordCallback(nil)
	}
	// flowCtx is intentionally not used to overwrite env.Context here
	// (USK-910): the inner envelope's Context arrives populated by the
	// producing grpcweb Layer's wire builders and clobbering it with a
	// sparse builder-derived template breaks the USK-908 first-write-wins
	// createStream guard — the streams row would be stamped with an empty
	// conn_id when the base64 wire envelope races ahead of the semantic
	// envelope. The parameter is preserved for signature stability; only
	// WireLevel is stamped in-place on the inner envelope per MITM
	// Principle #1 (do not normalize what the wire did not normalize).
	_ = flowCtx

	// Per-direction sequence counters. The same Option installed on both
	// client-side (Send) and upstream-side (Receive) grpcweb wraps runs
	// independent counters; the schemaV14 UNIQUE constraint on
	// (stream_id, sequence, direction, variant, wire_level) requires
	// per-direction independence.
	var sendSeq, recvSeq int64

	return grpcweb.WithEncodedFormRecordCallback(func(env *envelope.Envelope) {
		if env == nil {
			return
		}
		// Stamp wire-record envelope identity.
		env.FlowID = uuid.NewString()
		// StreamID unification: rewrite to the session-scope identity
		// when supplied so client-side and upstream-side base64 wire
		// envelopes share the Stream row created by the main Pipeline's
		// first Send envelope. The orchestrator passes the client-side
		// grpcweb stream StreamID here; for synthetic test paths that
		// pass "" we preserve the channel-emitted StreamID.
		if sessionStreamID != "" {
			env.StreamID = sessionStreamID
		}
		switch env.Direction {
		case envelope.Send:
			env.Sequence = int(atomic.AddInt64(&sendSeq, 1) - 1)
		case envelope.Receive:
			env.Sequence = int(atomic.AddInt64(&recvSeq, 1) - 1)
		default:
			// Defensive: the grpcweb channel never emits base64 wire
			// envelopes with a zero / unknown direction, but if it ever
			// did we drop the envelope rather than risk a sequence-space
			// collision against the per-direction counters.
			return
		}
		// Stamp WireLevel in place. The inner envelope's Context fields
		// (ConnID / TLS / ClientAddr / TargetHost) are populated by the
		// producing Layer's WithEnvelopeContext template and propagated
		// verbatim by the wire-envelope builders; preserving them keeps
		// the streams row consistent with the connections row (USK-910).
		env.Context.WireLevel = flow.WireLevelGRPCWebBase64

		// Run through the record-only Pipeline. The Pipeline.Run return
		// values are intentionally discarded — record-only means the
		// only side effect we care about is the SaveFlow performed by
		// RecordStep. Drop / Respond cannot fire here because
		// h2FrameRecordPipeline stripped every Step that could produce
		// them.
		_, _, _ = recPipeline.Run(ctx, env)
	})
}
