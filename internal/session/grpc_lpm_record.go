// Package session — gRPC LPM (Length-Prefixed Message) envelope recording
// for the gRPC data path (USK-896).
//
// gRPC over HTTP/2 carries application payloads as LPM frames:
//
//	[compressed_flag (1 byte)] [length (4 bytes BE)] [payload (length bytes)]
//
// Multiple LPMs can be packed into a single h2 DATA frame, and a single
// LPM can be split across multiple h2 DATA frames. Pre-USK-896 only the
// semantic GRPCDataMessage envelope (decompressed payload + parsed
// metadata) reached the recorder; the LPM wire bytes were lost. This
// hid two classes of bug from analysts:
//
//   - LPM length-prefix smuggling (length-prefix ≠ actual payload bytes)
//   - Compressed-flag anomalies (RFC values are 0 / 1; any other value
//     indicates a malicious or buggy peer)
//
// USK-896 closes the gap by stamping wire_level=grpc-lpm-frame on a
// per-LPM record envelope produced from grpc.Wrap's
// WithLPMFrameRecordCallback Option.
//
// Design summary (composes with USK-889 / USK-895 — third Rule-of-Three
// producer; common WireLevelTap interface deferred to a follow-up Issue):
//
//   - Naming: <protocol>-<unit> flat, value = "grpc-lpm-frame" (per-protocol
//     canonical: LPM framing is gRPC's own, distinct from h2 DATA which has
//     its own wire_level=h2-frame).
//   - API: per-Layer ad-hoc Option (grpc.WithLPMFrameRecordCallback)
//     mirroring USK-889's WithFrameRecordCallback shape and USK-895's
//     WithChunkRecordCallback shape.
//   - Pipeline: record-only via h2FrameRecordPipeline (already wire-level
//     agnostic — strips Safety / PluginPre / Intercept / Transform /
//     PluginPost; leaves HostScope / HTTPScope / Budget / Record).
//   - Cap: RecordStep.WithGRPCLPMFrameMaxPerStream (default 10000,
//     USK-802 LRU shared). proxybuild.Deps.RecordGRPCLPMFrameMaxPerStream
//     wires it through.
//   - Bidi RPC: LPMs flow in both directions on the same client-facing
//     stream. The orchestrator installs the SAME Option on both the
//     client-side and upstream-side grpc.Wrap; the client-side wrap
//     fires the callback for Send LPMs, the upstream-side wrap fires it
//     for Receive LPMs (each wrap only fires absorbData on the direction
//     of its Next() reads). Per-direction sequence counters live inside
//     the callback closure so each direction's flow rows form a unique
//     (StreamID, Direction, sequence, WireLevel) tuple per the schemaV14
//     UNIQUE constraint.
//
// StreamID unification (mirrors session.upstreamToClient): the upstream-
// side grpc Layer emits envelopes carrying the upstream stream's
// StreamID, which differs from the client-side StreamID. To make the
// LPM wire envelopes shareable with the semantic envelopes recorded on
// the main Pipeline under the client StreamID, the orchestrator passes
// the client-side StreamID to GRPCLPMRecordOption at build time; the
// callback rewrites env.StreamID to that value before dispatching to
// the record-only Pipeline. The same closure is installed on both
// wraps, so all LPMs end up under one Stream row.
//
// Live? Defense-in-depth (per USK-896 Issue body). No live bug is
// currently triggering this gap; the goal is to make smuggling /
// compressed-flag / multi-LPM-packing anomalies observable when they
// arise.

package session

import (
	"context"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// GRPCLPMRecordOption assembles the grpc.WithLPMFrameRecordCallback
// Option that the orchestrator layers onto the grpcOpts chain passed
// into connector.DispatchH2StreamWithOpts /
// WrapH2UpstreamForDispatch. It builds a record-only Pipeline by
// stripping every policy / transform / plugin Step from p (via the
// existing h2FrameRecordPipeline helper, which is wire-level-agnostic)
// and dispatches the LPM wire envelope through it with WireLevel =
// flow.WireLevelGRPCLPMFrame stamped on EnvelopeContext.
//
// sessionStreamID is the per-stream session-scope identity (the
// client-side gRPC stream's StreamID for the live data path). When
// non-empty, the callback rewrites env.StreamID to this value before
// running the record-only Pipeline. This mirrors
// session.upstreamToClient's StreamID-unification (env.StreamID =
// clientID) so LPM rows from the upstream-side wrap land under the
// same Stream as LPM rows from the client-side wrap and the semantic
// envelopes recorded by the main Pipeline. Pass "" when no unification
// is required (e.g., synthetic test paths that exercise only one
// wrap).
//
// flowCtx supplies the connection-scope ConnID / TargetHost / TLS /
// ClientAddr stamped onto every LPM wire envelope so the record-only
// Pipeline's HostScope / HTTPScope gates evaluate consistently with the
// semantic envelopes recorded on the main Pipeline. The caller may leave
// flowCtx.WireLevel at any value — GRPCLPMRecordOption defensively clears
// it before stamping flow.WireLevelGRPCLPMFrame.
//
// Returns a grpclayer.Option that installs a nil callback (no-op) when
// p is nil so callers can unconditionally splat the result into their
// grpcOpts slice without branching on Pipeline availability.
func GRPCLPMRecordOption(ctx context.Context, p *pipeline.Pipeline, sessionStreamID string, flowCtx envelope.EnvelopeContext) grpclayer.Option {
	recPipeline := h2FrameRecordPipeline(p)
	if recPipeline == nil {
		// No Pipeline → no-op Option (matches the
		// WithLPMFrameRecordCallback contract: nil callback disables
		// wire-record).
		return grpclayer.WithLPMFrameRecordCallback(nil)
	}
	// flowCtx is intentionally not used to overwrite env.Context here
	// (USK-910): the inner envelope's Context arrives populated by the
	// producing grpc Layer's wire builders (buildLPMWireEnvelopeLocked
	// propagates Context: env.Context) and clobbering it with a sparse
	// builder-derived template breaks the USK-908 first-write-wins
	// createStream guard — the streams row would be stamped with an empty
	// conn_id when the LPM wire envelope races ahead of the semantic
	// envelope. The parameter is preserved for signature stability; only
	// WireLevel is stamped in-place on the inner envelope per MITM
	// Principle #1 (do not normalize what the wire did not normalize).
	_ = flowCtx

	// Per-direction sequence counters. Bidi gRPC RPCs observe both
	// Send and Receive LPMs on the same Stream; the schemaV14 UNIQUE
	// constraint on (stream_id, sequence, direction, variant, wire_level)
	// means the two directions must run independent counters, which is
	// exactly what separate atomic ints give us.
	var sendSeq, recvSeq int64

	return grpclayer.WithLPMFrameRecordCallback(func(env *envelope.Envelope) {
		if env == nil {
			return
		}
		// Stamp wire-record envelope identity.
		env.FlowID = uuid.NewString()
		// StreamID unification: rewrite to the session-scope identity
		// when supplied so client-side and upstream-side LPMs share the
		// Stream row created by the main Pipeline's first Send envelope.
		// The orchestrator passes the client-side gRPC stream StreamID
		// here; for synthetic test paths that pass "" we preserve the
		// channel-emitted StreamID.
		if sessionStreamID != "" {
			env.StreamID = sessionStreamID
		}
		switch env.Direction {
		case envelope.Send:
			env.Sequence = int(atomic.AddInt64(&sendSeq, 1) - 1)
		case envelope.Receive:
			env.Sequence = int(atomic.AddInt64(&recvSeq, 1) - 1)
		default:
			// Defensive: the grpc channel never emits LPM envelopes
			// with a zero / unknown direction, but if it ever did we
			// drop the envelope rather than risk a sequence-space
			// collision against the per-direction counters.
			return
		}
		// Stamp WireLevel in place. The inner envelope's Context fields
		// (ConnID / TLS / ClientAddr / TargetHost) are populated by the
		// producing Layer's WithEnvelopeContext template and propagated
		// verbatim by the wire-envelope builders; preserving them keeps
		// the streams row consistent with the connections row (USK-910).
		env.Context.WireLevel = flow.WireLevelGRPCLPMFrame

		// Run through the record-only Pipeline. The Pipeline.Run return
		// values are intentionally discarded — record-only means the
		// only side effect we care about is the SaveFlow performed by
		// RecordStep. Drop / Respond cannot fire here because
		// h2FrameRecordPipeline stripped every Step that could produce
		// them.
		_, _, _ = recPipeline.Run(ctx, env)
	})
}
