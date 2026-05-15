// Package session — native-gRPC h2 DATA frame envelope recording (USK-899).
//
// Native gRPC over h2 is wrapped by grpc.Wrap directly and bypasses
// httpaggregator.Wrap, so USK-897's aggregator-path
// httpaggregator.WithH2FrameRecordCallback never fires on this path. This
// file installs the recover Option: a record-only Pipeline +
// grpc.WithH2DataFrameRecordCallback wired in proxybuild alongside the
// existing per-LPM Option (USK-896) and the aggregator's h2-frame Option
// (USK-897).
//
// Result: native-gRPC streams produce three wire_level rows per direction —
// semantic (GRPCStartMessage / GRPCDataMessage / GRPCEndMessage) +
// grpc-lpm-frame (USK-896) + h2-frame (this Option) — matching gRPC-Web-
// over-h2 and aggregator-path coverage.
//
// Diagnostic value (defense-in-depth, per USK-899 Issue body):
//   - Tiny-DATA-frame covert channels (one LPM split across many one-byte
//     H2 DATA frames) — newly observable as count(h2-frame) >> count(LPM).
//   - Zero-payload DATA frame side-channels between LPMs — newly
//     recordable (previously silently discarded by reassembler).
//   - SETTINGS_MAX_FRAME_SIZE boundary anomalies — newly observable at
//     DATA-frame granularity.
//
// Storage cap inheritance: pipeline.recordCapForEnvelope keys on
// env.Context.WireLevel == flow.WireLevelH2Frame, NOT on producer protocol,
// so RecordStep.WithHTTP2FrameMaxPerStream automatically applies to the
// envelopes produced here. No new cap / config / schema migration.
//
// Sequence-space collision: schemaV14 widened the UNIQUE constraint on the
// flows table to (stream_id, sequence, direction, variant, wire_level).
// Per stream only one of {grpc.Wrap, httpaggregator.Wrap} wraps the h2
// transport, so the two h2-frame producers are mutually exclusive per
// stream — no risk of duplicate-key collisions between USK-897 and
// USK-899 rows under the same StreamID.

package session

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// GRPCH2DataFrameRecordOption assembles the
// grpc.WithH2DataFrameRecordCallback Option the orchestrator layers onto
// the grpcOpts chain passed into connector.DispatchH2StreamWithOpts /
// connector.WrapH2UpstreamForDispatchFull (USK-899). It mirrors the shape
// of AggregatorH2FrameRecordOption (USK-897) — both Options dispatch
// wire_level=h2-frame envelopes through the same record-only Pipeline,
// differing only in which Layer's Option type they wrap.
//
// sessionStreamID is the per-stream session-scope identity (the
// client-side gRPC channel's StreamID for the live data path). When
// non-empty, the callback rewrites env.StreamID to this value before
// running the record-only Pipeline. This mirrors
// session.upstreamToClient's StreamID-unification so h2-frame rows from
// the upstream-side wrap land under the same Stream as h2-frame rows from
// the client-side wrap and the semantic envelopes recorded by the main
// Pipeline. Pass "" for synthetic test paths that exercise only one wrap.
//
// flowCtx supplies the connection-scope ConnID / TargetHost / TLS /
// ClientAddr stamped onto every H2DataEvent wire envelope so the
// record-only Pipeline's HostScope / HTTPScope gates evaluate consistently
// with the semantic envelopes recorded on the main Pipeline. The caller
// may leave flowCtx.WireLevel at any value — buildH2FrameRecordClosure
// defensively clears it before stamping flow.WireLevelH2Frame.
//
// Returns a grpclayer.Option that installs a nil callback (no-op) when p
// is nil so callers can unconditionally splat the result into their
// grpcOpts slice without branching on Pipeline availability.
//
// Implementation note: the closure construction is shared with
// AggregatorH2FrameRecordOption via buildH2FrameRecordClosure
// (h2_frame_record.go). The closure is producer-agnostic — both Options
// produce wire_level=h2-frame envelopes, and the only producer-specific
// behavior is the Layer Option type they wrap.
func GRPCH2DataFrameRecordOption(ctx context.Context, p *pipeline.Pipeline, sessionStreamID string, flowCtx envelope.EnvelopeContext) grpclayer.Option {
	cb := buildH2FrameRecordClosure(ctx, p, sessionStreamID, flowCtx)
	return grpclayer.WithH2DataFrameRecordCallback(cb)
}
