package pipeline

import (
	"bytes"
	"container/list"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// defaultRecordCacheCapacity bounds RecordStep's per-Stream
// recording-decision cache. The cache exists so that streams whose
// recording decision was made on first-Send (with full HTTP method/path
// context) carry that decision through to subsequent envelopes that lack
// HTTP-typed context (WS frames, gRPC data messages, SSE events). 10000
// matches the magnitude of RetentionMaxSessions and bounds memory under
// any realistic concurrent-stream load. See WithRecordScope.
const defaultRecordCacheCapacity = 10000

// defaultCountCacheCapacity bounds RecordStep's per-Stream record-count
// cache used for the gRPC / SSE per-stream record caps (USK-802). It mirrors
// defaultRecordCacheCapacity for symmetry — both caches are LRU-bounded to
// the same magnitude so memory is bounded under realistic concurrent-stream
// load. On eviction, a subsequent envelope on the evicted Stream restarts
// the count from zero (acknowledged trade-off; see countCache.put).
const defaultCountCacheCapacity = 10000

// recordsTruncatedReason is the canonical AppendTags value the RecordStep
// stamps on a Stream the first time its per-protocol record cap is reached.
// MCP query consumers (and the WebUI) read this tag to surface a "records
// truncated" badge on streams whose Flow row count is bounded by the cap
// rather than by the actual envelope count on the wire.
const recordsTruncatedReason = "per_stream_cap_reached"

// WireEncoder re-encodes an Envelope's post-mutation Message into wire-form
// bytes. It is used by RecordStep when recording the "modified" variant of
// an intercepted envelope: env.Raw captures the ingress wire bytes and must
// not be rewritten when a Pipeline Step mutates env.Message, so RecordStep
// calls a per-protocol WireEncoder to render the post-mutation wire bytes
// into flow.Flow.RawBytes of the modified variant only.
//
// Implementations must be pure: they must not mutate env or env.Message and
// must not perform network IO. Returning ErrPartialWireBytes together with a
// non-nil byte slice signals that re-encoding was only partially possible
// (for example, headers were re-serialized but a passthrough body could not
// be replayed). RecordStep tags the flow's Metadata["wire_bytes"] with
// "partial" in that case and still stores the returned header-only bytes.
//
// Returning any other non-nil error — or a nil byte slice — causes
// RecordStep to keep env.Raw as the modified variant's RawBytes and tag
// Metadata["wire_bytes"] = "unavailable".
type WireEncoder func(env *envelope.Envelope) ([]byte, error)

// ErrPartialWireBytes is an alias for envelope.ErrPartialWireBytes. It is
// re-exported here so tests and callers that live in the pipeline package
// can use errors.Is without importing envelope directly. See
// envelope.ErrPartialWireBytes for the contract.
var ErrPartialWireBytes = envelope.ErrPartialWireBytes

// RecordStep is an Envelope-only Pipeline Step that records Envelope data to
// the Flow Store. It runs last in the Pipeline (after all transformations)
// and never modifies the Envelope.
//
// On the first Send (Sequence==0): creates a Stream (state="active") and
// records a send Flow.
// On subsequent Sends (Sequence>0): records a send Flow only.
// On Receive: records a receive Flow only.
//
// RecordStep does NOT manage Stream state transitions (complete/error).
// That is Session's responsibility via OnComplete.
//
// If preceding Steps modified the Envelope (detected by comparing with the
// snapshot stored in context), both the original and modified variants are
// recorded. When a per-protocol WireEncoder is registered via
// WithWireEncoder, the modified variant's flow.Flow.RawBytes is overwritten
// with the encoder's output so the recorded bytes reflect what the proxy
// would emit on the wire after the mutation, rather than the ingress Raw.
type RecordStep struct {
	store    flow.Writer
	logger   *slog.Logger
	encoders *WireEncoderRegistry
	// maxBodySize caps flow.Flow.Body when materializing a BodyBuffer. A
	// larger materialized body is truncated and Flow.BodyTruncated is set
	// to true. Zero means use config.MaxBodySize.
	maxBodySize int64
	// protocolRetagged tracks streamIDs whose Stream.Protocol has already
	// been updated past the initial createStream value. Used by the
	// upgrade path retag (USK-781): when a non-HTTP envelope arrives on
	// a stream that was created from a pre-swap HTTPMessage (CONNECT
	// request), the first such envelope triggers a single
	// store.UpdateStream(Protocol=…) call and stamps the streamID here
	// so subsequent envelopes do not re-issue the same write.
	//
	// sync.Map suits the keys-set-once pattern (LoadOrStore is the
	// hot-path operation); the map is bounded by the number of streams
	// that survive an upgrade per process lifetime, which is the same
	// bound the rest of the recorder already accepts (no eviction).
	protocolRetagged sync.Map

	// scope filters which envelopes are recorded. nil = capture all
	// (current behaviour). When non-nil, ShouldRecord is consulted for
	// every envelope and the result is cached per StreamID in
	// decisionCache so non-HTTP frames inherit the decision made at the
	// stream's first Send (where method/path were observable).
	scope         *flow.RecordScope
	decisionCache *recordDecisionCache

	// origin stamps Stream.Origin on every Stream created by this Step
	// (USK-785). Defaults to OriginProxy for the live MITM data path; the
	// resend MCP tools opt into OriginResend via WithOrigin so resend-
	// originated Streams can be filtered out of "live capture" views.
	// OriginFuzz is reserved as an enum value but is not yet stamped from
	// any production code path.
	origin flow.Origin

	// USK-802 per-Stream record caps. grpcMaxPerStream gates
	// *envelope.GRPCDataMessage envelopes; sseMaxPerStream gates
	// *envelope.SSEMessage envelopes. Zero (the zero value of the field
	// when no Option is applied) means "unlimited" — RecordStep records
	// every envelope. The proxy_start MCP path resolves to the package
	// default (config.MaxGRPCMessagesPerStream / config.MaxSSEEventsPerStream)
	// before reaching this Step, so production traffic always observes a
	// positive cap; the zero meaning is reserved for synthetic test stacks
	// that explicitly opt out.
	grpcMaxPerStream int
	sseMaxPerStream  int
	// USK-889 per-Stream frame-level record cap. Gates envelopes whose
	// EnvelopeContext.WireLevel is flow.WireLevelH2Frame (frame envelopes
	// produced by the per-stream sub-stack overlay on the WS-over-h2 /
	// SSE-over-h2 detach paths). Zero means "unlimited" with the same
	// rationale as the USK-802 cap fields: the production wiring resolves
	// to config.MaxHTTP2FrameRecordsPerStream so the zero meaning is
	// reserved for synthetic test stacks.
	h2FrameMaxPerStream int
	// USK-895 per-Stream chunk-level record cap. Gates envelopes whose
	// EnvelopeContext.WireLevel is flow.WireLevelHTTP1Chunk (chunk-boundary
	// envelopes produced on the SSE-over-h1-chunked streaming detach path).
	// Zero means "unlimited" with the same rationale as the USK-802 and
	// USK-889 cap fields: the production wiring resolves to
	// config.MaxHTTP1ChunkRecordsPerStream so the zero meaning is reserved
	// for synthetic test stacks.
	h1ChunkMaxPerStream int
	// USK-896 per-Stream LPM-level record cap. Gates envelopes whose
	// EnvelopeContext.WireLevel is flow.WireLevelGRPCLPMFrame (gRPC
	// Length-Prefixed Message envelopes produced by the grpc Layer's
	// per-LPM record callback). Zero means "unlimited" with the same
	// rationale as the USK-802 / USK-889 / USK-895 cap fields: the
	// production wiring resolves to config.MaxGRPCLPMFrameRecordsPerStream
	// so the zero meaning is reserved for synthetic test stacks.
	grpcLPMFrameMaxPerStream int
	// USK-898 per-Stream base64-body record cap. Gates envelopes whose
	// EnvelopeContext.WireLevel is flow.WireLevelGRPCWebBase64 (gRPC-Web
	// text-variant body envelopes produced by the grpcweb Layer's
	// per-body record callback). Zero means "unlimited" with the same
	// rationale as the USK-802 / USK-889 / USK-895 / USK-896 cap fields:
	// the production wiring resolves to
	// config.MaxGRPCWebBase64RecordsPerStream so the zero meaning is
	// reserved for synthetic test stacks.
	grpcWebBase64MaxPerStream int
	// countCache is the per-StreamID record-count LRU. Allocated lazily on
	// first per-stream gating need (i.e. when any cap Option resolves to
	// a positive value). Concurrent access is bound by countCache.mu — see
	// recordCountCache for the contract.
	countCache *recordCountCache
}

// Option configures a RecordStep.
type Option func(*RecordStep)

// WithWireEncoder registers a per-protocol WireEncoder used when recording
// the "modified" variant of an intercepted envelope. The encoder is invoked
// only for envelopes whose Protocol matches proto. See WireEncoder for the
// contract on return values.
//
// Passing a nil fn removes any previously-registered encoder for proto.
//
// Internally registers into the RecordStep's WireEncoderRegistry, which is
// also accessible via WithWireEncoderRegistry for the case where the same
// registry is shared with PluginStepPost.
func WithWireEncoder(proto envelope.Protocol, fn WireEncoder) Option {
	return func(s *RecordStep) {
		if s.encoders == nil {
			s.encoders = NewWireEncoderRegistry()
		}
		s.encoders.Register(proto, fn)
	}
}

// WithWireEncoderRegistry attaches a pre-built WireEncoderRegistry to the
// RecordStep. Use this when the same registry is shared with PluginStepPost
// so both Steps see the same encoder map. If both this Option and
// WithWireEncoder are applied, the explicit registry wins (the per-protocol
// Options are no-ops because they would re-register into the wrong map).
func WithWireEncoderRegistry(reg *WireEncoderRegistry) Option {
	return func(s *RecordStep) {
		s.encoders = reg
	}
}

// WithRecordScope attaches a recording-only observability filter to the
// RecordStep (USK-776). When the scope is non-empty, RecordStep evaluates
// ShouldRecord against the first Send envelope of each stream, caches
// the decision keyed by StreamID, and applies it to every subsequent
// envelope on the same stream — including non-HTTP frames (WS / gRPC /
// SSE) whose Message types do not carry method/path context.
//
// A nil scope is permitted and means "capture all" (current default
// behaviour). The same pointer is shared between MCP tools (writers)
// and the live data-path RecordStep (reader); flow.RecordScope's
// internal RWMutex coordinates concurrent access.
//
// The decision cache is bounded at defaultRecordCacheCapacity (10000
// entries). On cache eviction a subsequent non-first-Send envelope on
// the evicted stream defaults to NOT-recorded, which prevents flow rows
// from being inserted without their parent Stream row (the foreign-key
// guard in internal/flow/schema.go). The bound is large enough that
// realistic concurrent-stream load never trips eviction; under a sustained
// burst above the bound, the proxy under-records rather than crashing.
func WithRecordScope(scope *flow.RecordScope) Option {
	return func(s *RecordStep) {
		s.scope = scope
		if scope != nil && s.decisionCache == nil {
			s.decisionCache = newRecordDecisionCache(defaultRecordCacheCapacity)
		}
	}
}

// WithMaxBodySize caps the number of bytes materialized into flow.Flow.Body
// when an HTTPMessage carries a BodyBuffer. If the materialized body exceeds
// n bytes it is truncated to n and flow.Flow.BodyTruncated is set to true.
// n <= 0 is ignored (falls back to config.MaxBodySize).
func WithMaxBodySize(n int64) Option {
	return func(s *RecordStep) {
		if n > 0 {
			s.maxBodySize = n
		}
	}
}

// WithOrigin sets the Stream.Origin value stamped onto every Stream the
// RecordStep creates (USK-785). The default (no option, or empty value)
// is flow.OriginProxy, which matches the live MITM data path. The resend
// MCP tools pass flow.OriginResend so resend-recorded streams can be
// filtered apart from live captures by the query tool.
//
// An empty Origin argument is treated as "use default" (OriginProxy) so
// callers can pass through a config-provided value without an explicit
// nil-check.
func WithOrigin(origin flow.Origin) Option {
	return func(s *RecordStep) {
		s.origin = origin
	}
}

// WithGRPCMaxMessagesPerStream caps the number of *envelope.GRPCDataMessage
// envelopes RecordStep persists per Stream (USK-802). Once the cap is
// reached, further GRPCDataMessage envelopes pass through the Pipeline
// untouched (the wire-forwarding path runs in
// session.dispatchClientAction → upstream.Send unaffected) but are not
// written to the flow store. GRPCStartMessage and GRPCEndMessage envelopes
// are bounded ≤2 per Stream and always recorded.
//
// On the first cap-hit per Stream, RecordStep stamps
// AppendTags["records_truncated"]=recordsTruncatedReason and emits a
// single slog.Debug ("flow record dropped: per-stream cap reached") so the
// truncation is operator-visible via the query MCP tool without flooding
// the log on every subsequent over-cap envelope.
//
// Zero (or negative) means "unlimited" — the cap gate is bypassed entirely
// for gRPC envelopes. This matches the zero-means-default convention used
// by other RecordStep Options (e.g. WithMaxBodySize). The production wiring
// in mcpserver/init.go always resolves to a positive default through
// config.ResolveGRPCMaxMessagesPerStream, so the zero meaning only applies
// to synthetic test constructions.
func WithGRPCMaxMessagesPerStream(n int) Option {
	return func(s *RecordStep) {
		if n > 0 {
			s.grpcMaxPerStream = n
		}
	}
}

// WithSSEMaxEventsPerStream caps the number of *envelope.SSEMessage
// envelopes RecordStep persists per Stream (USK-802). Same wire-passthrough
// contract as WithGRPCMaxMessagesPerStream — the SSE Channel TeeReader
// continues to relay every event byte to the client; only the persisted
// flow rows are bounded.
//
// The pre-event firstEnv (HTTP response shell, *envelope.HTTPMessage) does
// NOT count toward the cap; only per-event SSEMessage envelopes are gated.
// This keeps the operator's mental model "the cap counts events" intact.
//
// Zero (or negative) means "unlimited"; see WithGRPCMaxMessagesPerStream
// for the rationale.
func WithSSEMaxEventsPerStream(n int) Option {
	return func(s *RecordStep) {
		if n > 0 {
			s.sseMaxPerStream = n
		}
	}
}

// WithHTTP2FrameMaxPerStream caps the number of frame-level envelopes
// (EnvelopeContext.WireLevel = flow.WireLevelH2Frame) RecordStep persists
// per Stream (USK-889). Once the cap is reached, further frame envelopes
// pass through the record-only Pipeline untouched but are not written to
// the flow store.
//
// Wire forwarding is unaffected because the frame-record callback that
// the http2.Layer.DetachStream orchestrators install runs BEFORE
// pipe.Write inside runDetachDrain; this cap only suppresses the
// downstream RecordStep dispatch, never the io.Pipe relay carrying the
// payload to the WS / SSE Layer.
//
// The cap is keyed on the same per-Stream LRU as the USK-802 gRPC / SSE
// caps; the cache entry's count is bumped for every gated envelope so
// the invariant "len(SaveFlow calls for frame envelopes, stream S) ≤
// cap" holds even under parallel observation. On the first cap-hit per
// Stream RecordStep stamps AppendTags["records_truncated"] =
// recordsTruncatedReason exactly as it does for gRPC / SSE.
//
// Shared-counter caveat (SSE-over-h2 only): recordCountCache.bumpAndCheck
// keys on streamID alone, so semantic SSEMessage envelopes (gated by
// WithSSEMaxEventsPerStream) and h2-frame envelopes on the same Stream
// share one counter. A single SSE-over-h2 Stream that records N SSE
// events and M frames hits its first cap-hit when N+M crosses the
// smaller of the two caps, NOT when either kind individually exceeds
// its own cap. WS-over-h2 is unaffected (semantic WSMessage envelopes
// fall through recordCapForEnvelope with cap=0 and never bump the
// counter). With both production defaults at 10000 the practical
// threshold is N+M > 10000 per Stream, which only matters for very
// long-lived SSE-over-h2 streams; the operator-visible
// records_truncated tag surfaces the truncation either way. Splitting
// the counter axis (per-kind keying) is deferred to a follow-up Issue
// if production data shows premature truncation.
//
// Zero (or negative) means "unlimited"; see WithGRPCMaxMessagesPerStream
// for the rationale.
func WithHTTP2FrameMaxPerStream(n int) Option {
	return func(s *RecordStep) {
		if n > 0 {
			s.h2FrameMaxPerStream = n
		}
	}
}

// WithHTTP1ChunkMaxPerStream caps the number of chunk-boundary envelopes
// (EnvelopeContext.WireLevel = flow.WireLevelHTTP1Chunk) RecordStep
// persists per Stream (USK-895). Once the cap is reached, further chunk
// envelopes pass through the record-only Pipeline untouched but are not
// written to the flow store.
//
// Wire forwarding is unaffected because the chunk-record callback runs
// inside the parser's chunked-decode loop BEFORE the dechunked payload is
// forwarded to the consumer; this cap only suppresses the downstream
// RecordStep dispatch, never the streaming body relay carrying the
// payload to the SSE event-boundary reader.
//
// The cap is keyed on the same per-Stream LRU as the USK-802 gRPC / SSE
// and USK-889 h2-frame caps. The shared-counter caveat documented on
// WithHTTP2FrameMaxPerStream applies analogously to h1-chunk on
// SSE-over-h1-chunked: semantic SSEMessage envelopes and h1-chunk
// envelopes on the same Stream share one counter. With both production
// defaults at 10000 the practical threshold is N+M > 10000 per Stream;
// the operator-visible records_truncated tag surfaces the truncation
// either way. Splitting the counter axis (per-kind keying) is deferred to
// a follow-up Issue if production data shows premature truncation.
//
// Zero (or negative) means "unlimited"; see WithGRPCMaxMessagesPerStream
// for the rationale.
func WithHTTP1ChunkMaxPerStream(n int) Option {
	return func(s *RecordStep) {
		if n > 0 {
			s.h1ChunkMaxPerStream = n
		}
	}
}

// WithGRPCLPMFrameMaxPerStream caps the number of gRPC LPM (Length-Prefixed
// Message) wire envelopes (EnvelopeContext.WireLevel =
// flow.WireLevelGRPCLPMFrame) RecordStep persists per Stream (USK-896).
// Once the cap is reached, further LPM envelopes pass through the
// record-only Pipeline untouched but are not written to the flow store.
//
// Wire forwarding is unaffected because the per-LPM record callback runs
// inside grpcChannel.absorbData BEFORE the semantic GRPCDataMessage
// envelope is queued for emission to the Pipeline (and BEFORE the inner
// HTTP/2 channel's payload bytes are relayed further); this cap only
// suppresses the downstream RecordStep dispatch.
//
// The cap is keyed on the same per-Stream LRU as the USK-802 gRPC / SSE
// and USK-889 / USK-895 frame / chunk caps. The shared-counter caveat
// documented on WithHTTP2FrameMaxPerStream applies analogously: semantic
// GRPCDataMessage envelopes (gated by WithGRPCMaxMessagesPerStream) and
// grpc-lpm-frame envelopes on the same Stream share one counter. With
// both production defaults at 10000 the practical threshold is N+M >
// 10000 per Stream; the operator-visible records_truncated tag surfaces
// the truncation either way. Splitting the counter axis (per-kind keying)
// is deferred to a follow-up Issue if production data shows premature
// truncation.
//
// Zero (or negative) means "unlimited"; see WithGRPCMaxMessagesPerStream
// for the rationale.
func WithGRPCLPMFrameMaxPerStream(n int) Option {
	return func(s *RecordStep) {
		if n > 0 {
			s.grpcLPMFrameMaxPerStream = n
		}
	}
}

// WithGRPCWebBase64MaxPerStream caps the number of gRPC-Web text-variant
// body wire envelopes (EnvelopeContext.WireLevel =
// flow.WireLevelGRPCWebBase64) RecordStep persists per Stream (USK-898).
// Once the cap is reached, further base64 wire envelopes pass through the
// record-only Pipeline untouched but are not written to the flow store.
//
// Wire forwarding is unaffected because the per-body record callback
// runs inside grpcweb.channel.refillFromHTTPMessage BEFORE the in-place
// base64 decode + LPM parse — this cap only suppresses the downstream
// RecordStep dispatch, never the semantic envelope emission carrying
// the decoded LPM payload to consumers.
//
// The cap is keyed on the same per-Stream LRU as the USK-802 / USK-889 /
// USK-895 / USK-896 caps. The shared-counter caveat documented on
// WithHTTP2FrameMaxPerStream applies analogously: every wire_level and
// semantic envelope on the same Stream shares one counter. With every
// production default at 10000 the practical threshold is the aggregate
// envelope count > 10000 per Stream; the operator-visible
// records_truncated tag surfaces the truncation either way.
//
// Zero (or negative) means "unlimited"; see WithGRPCMaxMessagesPerStream
// for the rationale.
func WithGRPCWebBase64MaxPerStream(n int) Option {
	return func(s *RecordStep) {
		if n > 0 {
			s.grpcWebBase64MaxPerStream = n
		}
	}
}

// NewRecordStep creates a RecordStep with the given flow.Writer.
// If store is nil, Process returns immediately with no side effects.
//
// Additional configuration (per-protocol wire encoders, etc.) may be
// supplied via functional Options.
func NewRecordStep(store flow.Writer, logger *slog.Logger, opts ...Option) *RecordStep {
	if logger == nil {
		logger = slog.Default()
	}
	s := &RecordStep{store: store, logger: logger}
	for _, opt := range opts {
		opt(s)
	}
	if s.maxBodySize <= 0 {
		s.maxBodySize = config.MaxBodySize
	}
	// USK-785: live data path defaults to OriginProxy so callers do not
	// have to thread the value explicitly. Resend pipelines override via
	// WithOrigin(flow.OriginResend).
	if s.origin == "" {
		s.origin = flow.OriginProxy
	}
	// USK-802 / USK-889 / USK-895 / USK-896 / USK-898: lazily allocate the
	// per-Stream record-count LRU when at least one cap Option resolved to
	// a positive value. Synthetic test stacks that omit every Option skip
	// the allocation entirely.
	if (s.grpcMaxPerStream > 0 || s.sseMaxPerStream > 0 || s.h2FrameMaxPerStream > 0 || s.h1ChunkMaxPerStream > 0 || s.grpcLPMFrameMaxPerStream > 0 || s.grpcWebBase64MaxPerStream > 0) && s.countCache == nil {
		s.countCache = newRecordCountCache(defaultCountCacheCapacity)
	}
	return s
}

// Process records the Envelope to the Flow Store. It always returns a zero
// Result (Action=Continue, Envelope=nil) because RecordStep never modifies
// the Envelope or interrupts the Pipeline.
func (s *RecordStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if s.store == nil {
		return Result{}
	}

	// USK-841 milestone (f): every envelope as it enters RecordStep.Process.
	// Live SQLite ground truth on 2026-05-12 showed no post-101 ws Stream
	// in the user's flow.db while in-process trace shows wsChannel.Next
	// fires successfully — the gap is downstream of the WS Layer. This
	// trace reveals whether ws envelopes reach RecordStep at all (H6 vs
	// downstream of Process entry).
	rawLen := 0
	if env != nil {
		rawLen = len(env.Raw)
	}
	s.logger.DebugContext(ctx, "record: step entry",
		"phase", "recordstep-entry",
		"streamID", env.StreamID,
		"connID", env.Context.ConnID,
		"protocol", string(env.Protocol),
		"direction", env.Direction.String(),
		"sequence", env.Sequence,
		"bytes", rawLen,
	)

	// USK-776: capture-scope filter gate. When the scope filters out this
	// envelope (or its parent stream), skip both Stream creation and Flow
	// recording. Wire transmission is unaffected — the Pipeline returns
	// Continue/no-mutation as usual; only persistence is suppressed.
	if !s.shouldRecord(env) {
		s.logger.DebugContext(ctx, "record: out-of-scope; flow not captured",
			"stream_id", env.StreamID,
			"flow_id", env.FlowID,
			"direction", env.Direction.String(),
			"sequence", env.Sequence,
			"protocol", string(env.Protocol),
		)
		s.logger.DebugContext(ctx, "record: savestream skipped",
			"phase", "recordstep-savestream-skip",
			"streamID", env.StreamID,
			"connID", env.Context.ConnID,
			"protocol", string(env.Protocol),
			"reason", "out-of-scope",
		)
		return Result{}
	}

	// Create Stream on first Send (Sequence==0).
	if env.Direction == envelope.Send && env.Sequence == 0 {
		s.createStream(ctx, env)
	} else {
		// USK-841 milestone (g, skip path): SaveStream was not invoked
		// because the envelope is not a first-Send. Reveals whether the
		// post-swap ws Stream is missing because the first ws envelope
		// arrived with Sequence != 0 or Direction != Send (H7 / driver
		// artifact) versus because Process never observed it at all
		// (H6: chain broken).
		s.logger.DebugContext(ctx, "record: savestream skipped",
			"phase", "recordstep-savestream-skip",
			"streamID", env.StreamID,
			"connID", env.Context.ConnID,
			"protocol", string(env.Protocol),
			"direction", env.Direction.String(),
			"sequence", env.Sequence,
			"reason", "not-first-send",
		)
	}

	// USK-781: retag the Stream's Protocol when an envelope on a non-
	// HTTP protocol arrives on a Stream that was created from a pre-
	// swap HTTPMessage. This handles wss-over-h2 where the pre-swap
	// CONNECT request creates the Stream as Protocol="http"; the post-
	// swap WS frames carry Protocol="websocket" and the analyst
	// expects to see the upgraded protocol in the query("flows") view.
	// One UpdateStream per Stream — gated by the protocolRetagged
	// LoadOrStore so subsequent WS frames are write-free.
	s.maybeRetagProtocol(ctx, env)

	// On Receive, project upstream TLS snapshot (if present) onto
	// Stream.ConnInfo. The Send side carries the synthetic MITM cert we
	// presented to the client; Receive carries the real upstream TLS
	// reality that analysts actually need. UpdateStream is idempotent —
	// repeated Receive envelopes on the same stream rewrite the same
	// values.
	if env.Direction == envelope.Receive && env.Context.TLS != nil {
		s.updateStreamTLS(ctx, env)
	}

	// USK-802: per-Stream record cap gate for streaming protocols
	// (gRPC GRPCDataMessage / SSE SSEMessage). Wire forwarding has
	// already happened by the time this Step runs in the Pipeline; the
	// gate only suppresses the SaveFlow / variant-record persistence
	// path. Other protocols and bounded gRPC Start/End envelopes pass
	// through unchanged. Stream-level UpdateStream calls (TLS, retag)
	// above are intentionally outside the gate so the Stream metadata
	// stays consistent with the wire.
	if !s.allowFlowRecord(ctx, env) {
		return Result{}
	}

	// Record Flow for every Envelope (Send or Receive).
	snap := SnapshotFromContext(ctx)
	if snap != nil && envelopeModified(snap, env) {
		s.recordVariantFlows(ctx, snap, env)
	} else {
		s.recordFlow(ctx, env)
	}

	return Result{}
}

// allowFlowRecord reports whether env passes the per-Stream record cap
// gate (USK-802). It returns true for any envelope outside the gated
// protocols (gRPC data / SSE) and for envelopes whose StreamID is empty
// (synthetic test stacks). For gated envelopes it consults the
// per-StreamID record-count cache; the first envelope to push the count
// past the cap stamps the Stream's tags via AppendTags["records_truncated"]
// = recordsTruncatedReason and emits a single slog.Debug.
//
// Counting policy: the counter is incremented on every gated envelope
// observation including those that get dropped, so the cap is a
// "records persisted" budget — once N envelopes have been written, the
// (N+1)th drops. This produces the cleaner invariant
// "len(SaveFlow calls for protocol P, stream S) ≤ cap" than incrementing
// only on persist (where a parallel reader could observe a partial state
// where the count exceeds cap). The drop / latch decision derives from
// the post-increment count, not the pre-increment count.
func (s *RecordStep) allowFlowRecord(ctx context.Context, env *envelope.Envelope) bool {
	cap := s.recordCapForEnvelope(env)
	if cap <= 0 {
		return true
	}
	streamID := env.StreamID
	if streamID == "" {
		// No stable cache key. Synthetic test stacks omit StreamID; do not
		// gate (matches the shouldRecord fallback for the same case).
		return true
	}
	if s.countCache == nil {
		// Defensive: a positive cap implies countCache was allocated in
		// NewRecordStep, but if a caller assembled a RecordStep through
		// some other path we degrade to "do not gate" rather than crash.
		return true
	}
	count, firstHit := s.countCache.bumpAndCheck(streamID, cap)
	if count <= cap {
		return true
	}
	if firstHit {
		s.markStreamTruncated(ctx, env)
	}
	return false
}

// recordCapForEnvelope returns the active per-Stream record cap for env's
// protocol/message combination, or 0 (= "do not gate") for envelopes that
// fall outside the gated protocols. The decision is intentionally split on
// the Message type rather than the Protocol alone so gRPC Start/End
// envelopes (which are bounded ≤2 per Stream and always recorded) bypass
// the gate cleanly.
//
// USK-889 / USK-895 / USK-896 / USK-898: non-semantic wire_level envelopes
// are gated by a per-wire_level cap. The switch dispatches on
// env.Context.WireLevel BEFORE the Message-type switch so non-semantic
// envelopes are always treated as their wire_level rather than as the
// (unrelated) typed Message they happen to carry. Unknown non-semantic
// wire_level values fall through to cap=0 (do not gate) — the value-set
// is closed at compile time today (h2-frame / h1-chunk / grpc-lpm-frame
// / grpcweb-base64) and a future addition that should be gated must wire
// its own arm and Option.
func (s *RecordStep) recordCapForEnvelope(env *envelope.Envelope) int {
	if env == nil {
		return 0
	}
	switch env.Context.WireLevel {
	case "", flow.WireLevelSemantic:
		// Fall through to the per-Message-type switch below.
	case flow.WireLevelH2Frame:
		return s.h2FrameMaxPerStream
	case flow.WireLevelHTTP1Chunk:
		return s.h1ChunkMaxPerStream
	case flow.WireLevelGRPCLPMFrame:
		return s.grpcLPMFrameMaxPerStream
	case flow.WireLevelGRPCWebBase64:
		return s.grpcWebBase64MaxPerStream
	default:
		// Unknown non-semantic wire_level: do not gate (defensive — keeps
		// new wire_level values recording until they get their own gate
		// Option). Unit tests cover this branch so a regression that
		// accidentally folds an unknown value into one of the existing
		// caps surfaces immediately.
		return 0
	}
	if env.Message == nil {
		return 0
	}
	switch env.Message.(type) {
	case *envelope.GRPCDataMessage:
		return s.grpcMaxPerStream
	case *envelope.SSEMessage:
		return s.sseMaxPerStream
	default:
		return 0
	}
}

// markStreamTruncated stamps the Stream's tags with the truncation reason
// (operator visibility via the query MCP tool) and emits the one-shot
// debug log. Both side-effects are gated upstream by countCache.firstHit
// so a cap-saturated stream produces exactly one tag write and one log
// line per process lifetime regardless of how many over-cap envelopes
// arrive afterward.
func (s *RecordStep) markStreamTruncated(ctx context.Context, env *envelope.Envelope) {
	s.logger.DebugContext(ctx, "flow record dropped: per-stream cap reached",
		"stream_id", env.StreamID,
		"protocol", string(env.Protocol),
		"cap", s.recordCapForEnvelope(env),
	)
	if err := s.store.UpdateStream(ctx, env.StreamID, flow.StreamUpdate{
		AppendTags: map[string]string{"records_truncated": recordsTruncatedReason},
	}); err != nil {
		s.logger.Error("record step: truncated tag update failed",
			"stream_id", env.StreamID,
			"error", err,
		)
	}
}

// updateStreamTLS projects env.Context.TLS into Stream.ConnInfo via
// UpdateStream. Fires on every Receive envelope with a non-nil TLS
// snapshot.
//
// The per-Receive invocation is intentional: it keeps RecordStep
// protocol-agnostic (no per-stream sync.Map state) and idempotent on
// the same row — repeated Receive envelopes on the same stream rewrite
// the same values. For N6 HTTP/2 complete-message aggregation this is
// exactly one UpdateStream per Stream, so the cost is negligible.
//
// Future consideration (N7 streaming protocols — gRPC / WebSocket /
// SSE): this fires once per received envelope, which could produce N
// redundant UpdateStream calls per Stream where only the first is
// meaningful (TLS snapshot is set-once per connection). If that
// becomes a bottleneck, replace with a first-Receive gate then.
func (s *RecordStep) updateStreamTLS(ctx context.Context, env *envelope.Envelope) {
	tls := env.Context.TLS
	update := flow.StreamUpdate{
		TLSVersion:           tls.VersionName(),
		TLSCipher:            tls.CipherName(),
		TLSALPN:              tls.ALPN,
		TLSServerCertSubject: tls.PeerCertSubject(),
	}
	if update.TLSVersion == "" && update.TLSCipher == "" && update.TLSALPN == "" && update.TLSServerCertSubject == "" {
		// No data worth writing.
		return
	}
	if err := s.store.UpdateStream(ctx, env.StreamID, update); err != nil {
		s.logger.Error("record step: TLS snapshot update failed",
			"stream_id", env.StreamID,
			"error", err,
		)
	}
}

// maybeRetagProtocol updates the Stream's Protocol when env carries a
// non-HTTP Protocol but the Stream was already created (so we cannot
// rewrite Protocol via createStream). Fires at most once per StreamID
// per process lifetime — gated by the protocolRetagged sync.Map.
//
// Skipped on:
//   - Empty / unset Protocol (no information to retag with).
//   - HTTP-family envelopes (the createStream path already covers them
//     and a same-value rewrite is wasteful).
//   - Empty StreamID (defensive — the LoadOrStore key would alias).
func (s *RecordStep) maybeRetagProtocol(ctx context.Context, env *envelope.Envelope) {
	if env == nil || env.StreamID == "" {
		return
	}
	if env.Protocol == "" || env.Protocol == envelope.ProtocolHTTP {
		return
	}
	if _, loaded := s.protocolRetagged.LoadOrStore(env.StreamID, struct{}{}); loaded {
		return
	}
	if err := s.store.UpdateStream(ctx, env.StreamID, flow.StreamUpdate{Protocol: string(env.Protocol)}); err != nil {
		s.logger.Error("record step: protocol retag update failed",
			"stream_id", env.StreamID,
			"protocol", string(env.Protocol),
			"error", err,
		)
	}
}

// createStream creates a new Stream record from the Envelope.
func (s *RecordStep) createStream(ctx context.Context, env *envelope.Envelope) {
	st := &flow.Stream{
		ID:        env.StreamID,
		ConnID:    env.Context.ConnID,
		Protocol:  string(env.Protocol),
		State:     "active",
		Timestamp: time.Now(),
		Origin:    s.origin,
	}

	// Derive scheme from Message type when available.
	if msg, ok := env.Message.(*envelope.HTTPMessage); ok && msg.Scheme != "" {
		st.Scheme = msg.Scheme
	}

	// USK-841 milestone (g): SaveStream call decision. Reveals which Stream
	// fields are about to land in SQLite — particularly streamID + connID +
	// protocol — so a live trace with no ws-Stream row can be correlated to
	// either H7 (empty streamID) or H8 (empty connID from missing
	// WithEnvelopeContext) at the call site.
	s.logger.DebugContext(ctx, "record: savestream invoking",
		"phase", "recordstep-savestream",
		"streamID", st.ID,
		"connID", st.ConnID,
		"protocol", st.Protocol,
		"origin", string(st.Origin),
	)

	err := s.store.SaveStream(ctx, st)

	// USK-841 milestone (g, result): SaveStream return. Distinguishes "the
	// call fired and wrote (or silently no-oped on FK)" from "the call
	// returned an error the operator never sees because the original log
	// is Error-only on a path the user's debug-level capture may filter".
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	s.logger.DebugContext(ctx, "record: savestream returned",
		"phase", "recordstep-savestream-result",
		"streamID", st.ID,
		"err", errStr,
	)

	if err != nil {
		s.logger.Error("record step: stream save failed",
			"stream_id", env.StreamID,
			"error", err,
		)
	}
}

// recordFlow records a single Flow from the Envelope.
func (s *RecordStep) recordFlow(ctx context.Context, env *envelope.Envelope) {
	fl := s.envelopeToFlow(ctx, env)
	if err := s.store.SaveFlow(ctx, fl); err != nil {
		s.logger.Error("record step: flow save failed",
			"stream_id", env.StreamID,
			"flow_id", env.FlowID,
			"direction", env.Direction.String(),
			"error", err,
		)
	}
}

// recordVariantFlows records both the original (from snapshot) and the
// modified (current) Envelope as separate flows with variant metadata.
//
// The original variant's RawBytes reflect the ingress wire bytes (snap.Raw).
// The modified variant's RawBytes are replaced with the output of the
// protocol-specific WireEncoder (if any) so the recorded bytes reflect the
// post-mutation wire representation instead of the ingress bytes. When no
// encoder is registered or the encoder fails, the modified flow keeps
// current.Raw and Metadata["wire_bytes"] is tagged "unavailable"; on
// ErrPartialWireBytes the returned bytes are stored and the tag is
// "partial". env.Raw itself is never mutated.
func (s *RecordStep) recordVariantFlows(ctx context.Context, snap, current *envelope.Envelope) {
	// envelopeToFlow always initializes Metadata with {"protocol": ...}, so
	// no nil-check is needed before assigning the "variant" entry.
	origFlow := s.envelopeToFlow(ctx, snap)
	// origFlow.ID keeps the wire-observed FlowID (a UUID produced by the
	// Layer). The variant pair is disambiguated at the SQL layer by the
	// schemaV11 `variant` column (projected from Metadata["variant"]) and
	// at the MCP query layer by resolveVariantPair, neither of which
	// depend on the FlowID string shape.
	origFlow.Metadata["variant"] = "original"
	if err := s.store.SaveFlow(ctx, origFlow); err != nil {
		s.logger.Error("record step: original variant save failed",
			"stream_id", current.StreamID,
			"flow_id", origFlow.ID,
			"error", err,
		)
	}

	modFlow := s.envelopeToFlow(ctx, current)
	// USK-878: the modified-variant row needs an `id` distinct from the
	// original-variant row so the flows table's PRIMARY KEY accepts both.
	// We mint a fresh UUID rather than reusing the suffix scheme
	// ("<base-uuid>-modified") that was used pre-USK-878, because
	// `manage import_flows` strict-validates flow UUIDs and the suffix
	// caused the importer to reject the entire ExportRecord — silently
	// dropping every intercept-touched stream on round-trip. The variant
	// pair stays linkable via Metadata["base_flow_id"] (pointing back at
	// the snapshot's FlowID); SQL UNIQUE(stream_id, sequence, direction,
	// variant) already keeps the rows from colliding on identity.
	modFlow.ID = uuid.NewString()
	modFlow.Metadata["variant"] = "modified"
	modFlow.Metadata["base_flow_id"] = current.FlowID
	s.applyWireEncode(ctx, current, modFlow)
	if err := s.store.SaveFlow(ctx, modFlow); err != nil {
		s.logger.Error("record step: modified variant save failed",
			"stream_id", current.StreamID,
			"flow_id", modFlow.ID,
			"error", err,
		)
	}
}

// applyWireEncode consults the registered WireEncoder for current.Protocol
// and, if present, rewrites modFlow.RawBytes with the post-mutation wire
// representation. The Metadata["wire_bytes"] tag follows this decision table:
//
//   - No encoders registered at all, or no encoder registered for
//     current.Protocol: the call is skipped entirely. Metadata is untouched
//     (kept silent for protocols that have no wire-encoding notion, e.g. raw).
//   - Encoder succeeds and returns non-nil bytes: RawBytes is overwritten, tag
//     is not set.
//   - Encoder succeeds but returns nil bytes: RawBytes keeps env.Raw, tag is
//     set to "unavailable".
//   - Encoder returns ErrPartialWireBytes with non-nil bytes: partial bytes
//     are stored in RawBytes, tag is set to "partial".
//   - Encoder returns ErrPartialWireBytes with nil bytes: RawBytes keeps
//     env.Raw, tag is set to "unavailable" (the contract requires bytes
//     alongside the partial sentinel; a nil return is treated the same as an
//     encoder failure).
//   - Encoder returns any other non-nil error: RawBytes keeps env.Raw, tag
//     is set to "unavailable" and the error is logged.
func (s *RecordStep) applyWireEncode(ctx context.Context, current *envelope.Envelope, modFlow *flow.Flow) {
	if s.encoders == nil || s.encoders.Len() == 0 {
		return
	}
	// Skip the encoder when env.Raw already matches the desired record
	// bytes:
	//
	//   - USK-684 (Encoded): a preceding Step (PluginStepPost today) just
	//     rendered the post-mutation wire bytes via the same WireEncoder
	//     into current.Raw. envelopeToFlow has copied current.Raw into
	//     modFlow.RawBytes, so a second encoder call here would produce
	//     bit-identical bytes — pure waste on heavy encoders.
	//
	//   - USK-686 (RawAuthoritative): a preceding PluginStepPost
	//     MutationRawOnly / MutationBoth set current.Raw to user-verbatim
	//     bytes the plugin injected via msg["raw"] (RFC §9.3 D4 raw-wins).
	//     Calling the encoder would overwrite the user's smuggling-test
	//     bytes with a "cleaned-up" re-encoded form, destroying the
	//     diagnostic signal that motivated D4.
	//
	// shouldSkipEncoder ORs both flags. Fail-soft / partial / no-encoder
	// paths leave both flags clear, so they still fall through to the
	// call below and tag modFlow's Metadata["wire_bytes"] correctly.
	if shouldSkipEncoder(ctx) {
		return
	}
	enc, ok := s.encoders.Lookup(current.Protocol)
	if !ok {
		return
	}
	bytesOut, err := enc(current)
	switch {
	case err == nil:
		if bytesOut != nil {
			modFlow.RawBytes = bytesOut
		} else {
			modFlow.Metadata["wire_bytes"] = "unavailable"
		}
	case errors.Is(err, ErrPartialWireBytes):
		if bytesOut != nil {
			modFlow.RawBytes = bytesOut
			modFlow.Metadata["wire_bytes"] = "partial"
		} else {
			// Partial sentinel with no bytes violates the WireEncoder
			// contract; treat as unavailable rather than misrepresent the
			// stored ingress Raw as a partial re-encode.
			modFlow.Metadata["wire_bytes"] = "unavailable"
		}
	default:
		modFlow.Metadata["wire_bytes"] = "unavailable"
		s.logger.Warn("record step: wire encoder failed",
			"stream_id", current.StreamID,
			"flow_id", modFlow.ID,
			"protocol", string(current.Protocol),
			"error", err,
		)
	}
}

// envelopeToFlow converts an Envelope to a flow.Flow.
// Protocol-specific fields (Method, URL, StatusCode, Headers) are populated
// from the Message when it is an HTTPMessage. For RawMessage, Body is set
// to the raw bytes.
//
// When HTTPMessage.Body is nil but BodyBuffer is non-nil, the buffer is
// materialized via Bytes(ctx) into Flow.Body. If the materialized body
// exceeds s.maxBodySize it is truncated and Flow.BodyTruncated is set.
// Materialization errors are logged at Warn (operator-visible data loss)
// and Flow.Body is left nil.
//
// RecordStep never Releases the BodyBuffer — terminal release is owned by
// the Session OnComplete backstop (USK-634). Snapshot and current each hold
// independent Retain counts from CloneMessage().
//
// USK-772: when env.RawBuffer is non-nil (disk-spilled wire body), RawBytes
// is materialized via env.WireBytes(ctx) and capped at the BLOB-projection
// size. The cap intentionally differs from the network passthrough — the
// relayed wire bytes are always complete (the Channel send path streams
// from the buffer); only the BLOB-projected snapshot is truncated. A
// truncation here is logged but not surfaced as an Anomaly because the
// underlying wire fidelity is preserved on the wire.
func (s *RecordStep) envelopeToFlow(ctx context.Context, env *envelope.Envelope) *flow.Flow {
	fl := &flow.Flow{
		ID:        env.FlowID,
		StreamID:  env.StreamID,
		Sequence:  env.Sequence,
		Direction: env.Direction.String(),
		Timestamp: time.Now(),
		RawBytes:  s.projectRawBytes(ctx, env),
		Metadata:  map[string]string{"protocol": string(env.Protocol)},
		// USK-889: project EnvelopeContext.WireLevel onto the persisted
		// Flow so the schemaV14 wire_level column distinguishes the
		// frame-level overlay envelopes (h2-frame) from the canonical
		// semantic envelopes. An empty context value reads back as
		// WireLevelSemantic via SQLiteStore.saveFlowSync's empty-string
		// backstop, so existing semantic-only producers do not need to
		// thread the constant explicitly.
		WireLevel: env.Context.WireLevel,
	}

	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		fl.Method = m.Method
		fl.StatusCode = m.Status
		// USK-788: project the HTTPMessage's wire-version (set by the
		// producing Layer — http1.channel for HTTP/1.x, httpaggregator
		// for HTTP/2) onto the persisted Flow so MCP query consumers and
		// downstream filters (USK-792) can branch on the canonical value
		// without re-parsing raw bytes or guessing from ALPN.
		fl.HTTPVersion = m.HTTPVersion
		s.projectHTTPBody(ctx, env, m, fl)

		if m.Path != "" || m.Authority != "" {
			fl.URL = &url.URL{
				Scheme:   m.Scheme,
				Host:     m.Authority,
				Path:     m.Path,
				RawQuery: m.RawQuery,
			}
		}

		if hdrs := keyValuesToMap(m.Headers); hdrs != nil {
			fl.Headers = hdrs
		}
		if trlrs := keyValuesToMap(m.Trailers); trlrs != nil {
			fl.Trailers = trlrs
		}
		// USK-849: project HTTPMessage.Anomalies into per-type Metadata
		// keys so MCP `query flow` analysts can see typed protocol
		// anomalies (HTTP/1.x parser anomalies, HTTP/2 receive-side
		// non-conformance, HTTP/2 send-side strips from USK-840).
		// Mirrors the gRPC/SSE projection (USK-659 / USK-656). The
		// helper returns "" for an unknown AnomalyType so callers know
		// to fall back to a stable namespaced default — never silently
		// drop, since future producers must still be observable.
		for _, a := range m.Anomalies {
			key := httpAnomalyMetadataKey(a.Type)
			if key == "" {
				continue
			}
			fl.Metadata[key] = a.Detail
		}
	case *envelope.RawMessage:
		fl.Body = m.Bytes
	case *envelope.WSMessage:
		projectWSMessage(m, fl)
	case *envelope.GRPCStartMessage:
		projectGRPCStart(m, fl)
	case *envelope.GRPCDataMessage:
		projectGRPCData(m, fl)
	case *envelope.GRPCEndMessage:
		projectGRPCEnd(m, fl)
	case *envelope.SSEMessage:
		projectSSE(m, fl)
	case *envelope.TLSHandshakeMessage:
		projectTLSHandshake(m, fl)
	}

	return fl
}

// projectTLSHandshake projects a TLSHandshakeMessage (USK-790 passthrough
// audit-trail meta flow) into Flow.Metadata. Snake_case keys per the
// CLAUDE.md naming convention. Empty fields are intentionally omitted so
// MCP consumers can distinguish "the proxy did not observe this" (key
// absent) from "the proxy observed an empty value" — though for this
// message family every populated field carries non-empty data by
// construction.
func projectTLSHandshake(m *envelope.TLSHandshakeMessage, fl *flow.Flow) {
	if m.SNI != "" {
		fl.Metadata["sni"] = m.SNI
	}
	if m.LocalAddr != "" {
		fl.Metadata["local_addr"] = m.LocalAddr
	}
	if m.RemoteAddr != "" {
		fl.Metadata["remote_addr"] = m.RemoteAddr
	}
	if m.UpstreamAddr != "" {
		fl.Metadata["upstream_addr"] = m.UpstreamAddr
	}
	fl.Metadata["bytes_client_to_upstream"] = strconv.FormatInt(m.BytesClientToUpstream, 10)
	fl.Metadata["bytes_upstream_to_client"] = strconv.FormatInt(m.BytesUpstreamToClient, 10)
	if m.Outcome != "" {
		fl.Metadata["outcome"] = m.Outcome
	}
	if m.ErrorReason != "" {
		fl.Metadata["error"] = m.ErrorReason
	}
}

// projectRawBytes returns the wire bytes for the Flow.RawBytes BLOB
// projection. When env.RawBuffer is nil this is just env.Raw (zero-copy).
// When env.RawBuffer is non-nil (USK-772 disk-spill path) the helper calls
// env.WireBytes(ctx) which stitches header (Raw) + body (RawBuffer.Bytes).
// The materialized result is capped at the configured BLOB cap; truncation
// is logged at Warn so the operator can correlate a truncated BLOB with
// the captured-bytes count, but does NOT surface as a flow Anomaly because
// the wire passthrough was complete (the Channel write path streams from
// the same RawBuffer without applying this cap).
func (s *RecordStep) projectRawBytes(ctx context.Context, env *envelope.Envelope) []byte {
	if env == nil {
		return nil
	}
	if env.RawBuffer == nil {
		return env.Raw
	}
	wire, err := env.WireBytes(ctx)
	if err != nil {
		s.logger.Warn("record step: read wire bytes from RawBuffer failed",
			"stream_id", env.StreamID,
			"flow_id", env.FlowID,
			"protocol", string(env.Protocol),
			"error", err,
		)
		return nil
	}
	cap := s.maxBodySize
	if cap <= 0 {
		cap = config.MaxBodySize
	}
	if int64(len(wire)) > cap {
		s.logger.Warn("record step: wire bytes BLOB truncated for flow projection",
			"stream_id", env.StreamID,
			"flow_id", env.FlowID,
			"protocol", string(env.Protocol),
			"captured_bytes", len(wire),
			"cap", cap,
		)
		return wire[:cap]
	}
	return wire
}

// keyValuesToMap projects an ordered KeyValue slice into the flow.Flow
// multimap shape. Duplicate-name order is preserved via append; inter-name
// order lives in flow.Flow.RawBytes (map iteration is undefined). Returns
// nil for an empty input so callers can leave Flow.Headers/Trailers nil.
func keyValuesToMap(kvs []envelope.KeyValue) map[string][]string {
	if len(kvs) == 0 {
		return nil
	}
	out := make(map[string][]string, len(kvs))
	for _, kv := range kvs {
		out[kv.Name] = append(out[kv.Name], kv.Value)
	}
	return out
}

// projectWSMessage projects a WSMessage into fl.Body and fl.Metadata.
//
// Sentinel keys ws_opcode / ws_fin / ws_compressed are always present —
// they identify the WS frame event. ws_close_code and ws_close_reason
// are emitted only for Close frames; populating them on non-Close
// frames would fabricate fields the wire never sent (MITM wire
// fidelity). Mask and Masked are wire-level masking artifacts; they
// are not projected because the unmasked Payload is the analyst's view
// and Mask is regenerated on Send.
func projectWSMessage(m *envelope.WSMessage, fl *flow.Flow) {
	fl.Body = m.Payload
	fl.Metadata["ws_opcode"] = strconv.FormatUint(uint64(m.Opcode), 10)
	fl.Metadata["ws_fin"] = strconv.FormatBool(m.Fin)
	fl.Metadata["ws_compressed"] = strconv.FormatBool(m.Compressed)
	if m.Opcode == envelope.WSClose {
		fl.Metadata["ws_close_code"] = strconv.FormatUint(uint64(m.CloseCode), 10)
		fl.Metadata["ws_close_reason"] = m.CloseReason
	}
}

// projectGRPCStart projects a GRPCStartMessage. grpc_event / grpc_service /
// grpc_method are always present (RPC identity); content_type and encoding
// are conditional on non-empty values to avoid fabricating wire fields.
// Metadata KeyValues project to Flow.Headers via the same multimap shape
// as HTTPMessage. Parser-detected Anomalies project into stable per-type
// grpc_anomaly_* keys (USK-659); stream-terminating problems surface as
// *layer.StreamError elsewhere and never reach this slice.
func projectGRPCStart(m *envelope.GRPCStartMessage, fl *flow.Flow) {
	fl.Metadata["grpc_event"] = "start"
	fl.Metadata["grpc_service"] = m.Service
	fl.Metadata["grpc_method"] = m.Method
	if m.ContentType != "" {
		fl.Metadata["grpc_content_type"] = m.ContentType
	}
	if m.Encoding != "" {
		fl.Metadata["grpc_encoding"] = m.Encoding
	}
	if hdrs := keyValuesToMap(m.Metadata); hdrs != nil {
		fl.Headers = hdrs
	}
	for _, a := range m.Anomalies {
		key := grpcAnomalyMetadataKey(a.Type)
		if key == "" {
			continue
		}
		fl.Metadata[key] = a.Detail
	}
}

// grpcAnomalyMetadataKey returns the stable Metadata key under which a
// gRPC-Web anomaly's Detail is recorded. Returns empty for unknown / non-
// gRPC anomaly types so projection silently drops them.
func grpcAnomalyMetadataKey(t envelope.AnomalyType) string {
	switch t {
	case envelope.AnomalyMalformedGRPCWebBase64:
		return "grpc_anomaly_malformed_base64"
	case envelope.AnomalyMalformedGRPCWebLPM:
		return "grpc_anomaly_malformed_lpm"
	case envelope.AnomalyMalformedGRPCWebTrailer:
		return "grpc_anomaly_malformed_trailer"
	case envelope.AnomalyMissingGRPCWebTrailer:
		return "grpc_anomaly_missing_trailer"
	case envelope.AnomalyUnexpectedGRPCWebRequestTrailer:
		return "grpc_anomaly_unexpected_request_trailer"
	default:
		return ""
	}
}

// projectGRPCData projects a GRPCDataMessage. Body holds the decompressed
// payload; RawBytes (set by envelopeToFlow) holds the wire form (5-byte
// LPM prefix + compressed payload).
func projectGRPCData(m *envelope.GRPCDataMessage, fl *flow.Flow) {
	fl.Body = m.Payload
	fl.Metadata["grpc_event"] = "data"
	fl.Metadata["grpc_service"] = m.Service
	fl.Metadata["grpc_method"] = m.Method
	fl.Metadata["grpc_compressed"] = strconv.FormatBool(m.Compressed)
	fl.Metadata["grpc_wire_length"] = strconv.FormatUint(uint64(m.WireLength), 10)
	fl.Metadata["grpc_end_stream"] = strconv.FormatBool(m.EndStream)
}

// projectGRPCEnd projects a GRPCEndMessage. grpc_status is always present
// (RPC outcome identity); grpc_message and grpc_status_details_bin are
// conditional on non-empty values. Trailers project via the multimap shape.
// Parser-detected Anomalies project into stable per-type grpc_anomaly_* keys
// (USK-660 missing-trailer / unexpected-request-trailer); stream-terminating
// problems surface as *layer.StreamError elsewhere and never reach this slice.
func projectGRPCEnd(m *envelope.GRPCEndMessage, fl *flow.Flow) {
	fl.Metadata["grpc_event"] = "end"
	fl.Metadata["grpc_status"] = strconv.FormatUint(uint64(m.Status), 10)
	if m.Message != "" {
		fl.Metadata["grpc_message"] = m.Message
	}
	if len(m.StatusDetails) > 0 {
		fl.Metadata["grpc_status_details_bin"] = base64.StdEncoding.EncodeToString(m.StatusDetails)
	}
	if trlrs := keyValuesToMap(m.Trailers); trlrs != nil {
		fl.Trailers = trlrs
	}
	for _, a := range m.Anomalies {
		key := grpcAnomalyMetadataKey(a.Type)
		if key == "" {
			continue
		}
		fl.Metadata[key] = a.Detail
	}
}

// projectSSE projects an SSEMessage. SSE event fields are independently
// optional on the wire; emit only when non-empty / non-zero so analysts can
// distinguish "wire didn't send this field" from "field was empty". Parser-
// detected Anomalies project into stable per-type sse_anomaly_* keys (USK-656);
// stream-terminating problems surface as *layer.StreamError elsewhere and
// never reach this slice.
func projectSSE(m *envelope.SSEMessage, fl *flow.Flow) {
	fl.Body = []byte(m.Data)
	if m.Event != "" {
		fl.Metadata["sse_event"] = m.Event
	}
	if m.ID != "" {
		fl.Metadata["sse_id"] = m.ID
	}
	if m.Retry > 0 {
		fl.Metadata["sse_retry_ms"] = strconv.FormatInt(m.Retry.Milliseconds(), 10)
	}
	for _, a := range m.Anomalies {
		key := sseAnomalyMetadataKey(a.Type)
		if key == "" {
			continue
		}
		fl.Metadata[key] = a.Detail
	}
}

// sseAnomalyMetadataKey returns the stable Metadata key under which an SSE
// anomaly's Detail is recorded. Returns empty for unknown / non-SSE anomaly
// types so projection silently drops them.
func sseAnomalyMetadataKey(t envelope.AnomalyType) string {
	switch t {
	case envelope.AnomalySSEMissingData:
		return "sse_anomaly_missing_data"
	case envelope.AnomalySSETruncated:
		return "sse_anomaly_truncated"
	case envelope.AnomalySSEDuplicateID:
		return "sse_anomaly_duplicate_id"
	case envelope.AnomalySSEProxyEventTooLarge:
		return "sse_anomaly_proxy_event_too_large"
	default:
		return ""
	}
}

// httpAnomalyKeys is the closed AnomalyType → stable Metadata key map
// for HTTP/1.x and HTTP/2 anomalies (USK-849). Each entry yields a
// snake_case column name so reviewers can grep for a stable schema
// across SQLite rows. Mirrors the gRPC/SSE precedent (USK-659 /
// USK-656). A map (vs switch) keeps gocyclo under threshold while
// preserving a single-source-of-truth table — adding a new AnomalyType
// is a one-line append.
var httpAnomalyKeys = map[envelope.AnomalyType]string{
	// HTTP/1.x parser-detected anomalies (parser.Anomaly*).
	envelope.AnomalyCLTE:                  "http_anomaly_cl_te",
	envelope.AnomalyDuplicateCL:           "http_anomaly_duplicate_cl",
	envelope.AnomalyInvalidTE:             "http_anomaly_invalid_te",
	envelope.AnomalyHeaderInjection:       "http_anomaly_header_injection",
	envelope.AnomalyAmbiguousTE:           "http_anomaly_ambiguous_te",
	envelope.AnomalyObsFold:               "http_anomaly_obs_fold",
	envelope.AnomalyTrailerPseudoHeader:   "http_anomaly_trailer_pseudo_header",
	envelope.AnomalyTrailerForbidden:      "http_anomaly_trailer_forbidden",
	envelope.AnomalyTrailersInPassthrough: "http_anomaly_trailers_in_passthrough",
	envelope.AnomalyRawBodyTruncated:      "http_anomaly_raw_body_truncated",
	// HTTP/2 receive-side anomalies emitted by the aggregator on parse.
	envelope.H2DuplicatePseudoHeader:    "http_anomaly_h2_duplicate_pseudo_header",
	envelope.H2PseudoHeaderAfterRegular: "http_anomaly_h2_pseudo_header_after_regular",
	envelope.H2InvalidPseudoHeader:      "http_anomaly_h2_invalid_pseudo_header",
	envelope.H2UppercaseHeaderName:      "http_anomaly_h2_uppercase_header_name",
	envelope.H2ConnectionSpecificHeader: "http_anomaly_h2_connection_specific_header",
	// HTTP/2 send-side strip mirror (USK-840).
	envelope.H2ConnectionSpecificHeaderStrippedOnSend: "http_anomaly_h2_connection_specific_header_stripped_on_send",
	envelope.H2TrailersAfterPassthrough:               "http_anomaly_h2_trailers_after_passthrough",
	envelope.H2PushPromise:                            "http_anomaly_h2_push_promise",
	envelope.H2UnsupportedConnectProtocol:             "http_anomaly_h2_unsupported_connect_protocol",
}

// httpAnomalyMetadataKey returns the stable Metadata key under which an
// HTTP anomaly's Detail is recorded (USK-849). Unknown types are
// surfaced under a stable `http_anomaly_unknown_<lowercased-type>`
// prefix so future producers that add a new AnomalyType become visible
// without requiring a synchronous patch (Principle #5 — surface, don't
// drop). The per-protocol helper mirrors grpcAnomalyMetadataKey /
// sseAnomalyMetadataKey; CLAUDE.md DRY policy explicitly allows the
// duplication because each protocol owns its anomaly vocabulary
// (Principle #2 — do not unify across protocols).
func httpAnomalyMetadataKey(t envelope.AnomalyType) string {
	if k, ok := httpAnomalyKeys[t]; ok {
		return k
	}
	// Stable namespaced fallback. Lowercased for grep-friendliness; the
	// raw AnomalyType value (already snake-style for H2*) is appended
	// verbatim minus case-folding.
	return "http_anomaly_unknown_" + strings.ToLower(string(t))
}

// projectHTTPBody populates fl.Body (and BodyTruncated) from m.Body or
// m.BodyBuffer, applying the maxBodySize cap.
func (s *RecordStep) projectHTTPBody(ctx context.Context, env *envelope.Envelope, m *envelope.HTTPMessage, fl *flow.Flow) {
	if m.Body != nil {
		fl.Body = m.Body
		return
	}
	if m.BodyBuffer == nil {
		return
	}
	b, err := m.BodyBuffer.Bytes(ctx)
	if err != nil {
		// Flow body data loss — operator-visible event.
		s.logger.WarnContext(ctx, "record: materialize body failed",
			"stream_id", env.StreamID,
			"flow_id", env.FlowID,
			"err", err,
		)
		return
	}
	if s.maxBodySize > 0 && int64(len(b)) > s.maxBodySize {
		fl.Body = b[:s.maxBodySize]
		fl.BodyTruncated = true
		return
	}
	fl.Body = b
}

// envelopeModified reports whether the current Envelope differs from the
// snapshot in Raw bytes or Message content.
func envelopeModified(snap, current *envelope.Envelope) bool {
	if !bytes.Equal(snap.Raw, current.Raw) {
		return true
	}
	return messageModified(snap.Message, current.Message)
}

// messageModified reports whether two Messages differ in their protocol-
// specific content. This is a type-switch dispatch; each protocol checks
// its own fields.
func messageModified(a, b envelope.Message) bool {
	if a == nil && b == nil {
		return false
	}
	if a == nil || b == nil {
		return true
	}

	switch ma := a.(type) {
	case *envelope.RawMessage:
		mb, ok := b.(*envelope.RawMessage)
		if !ok {
			return true
		}
		return !bytes.Equal(ma.Bytes, mb.Bytes)
	case *envelope.HTTPMessage:
		mb, ok := b.(*envelope.HTTPMessage)
		if !ok {
			return true
		}
		return httpMessageModified(ma, mb)
	default:
		return appMessageModified(a, b)
	}
}

// appMessageModified is the application-layer dispatch for messageModified —
// it handles the N7 Message types (WS, gRPC Start/Data/End, SSE) so the
// outer messageModified stays under gocyclo's threshold. Returns false for
// any unrecognized type (unknown Message means "not modified" to avoid
// false-positive variant recordings).
func appMessageModified(a, b envelope.Message) bool {
	switch ma := a.(type) {
	case *envelope.WSMessage:
		mb, ok := b.(*envelope.WSMessage)
		if !ok {
			return true
		}
		return wsMessageModified(ma, mb)
	case *envelope.GRPCStartMessage:
		mb, ok := b.(*envelope.GRPCStartMessage)
		if !ok {
			return true
		}
		return grpcStartModified(ma, mb)
	case *envelope.GRPCDataMessage:
		mb, ok := b.(*envelope.GRPCDataMessage)
		if !ok {
			return true
		}
		return grpcDataModified(ma, mb)
	case *envelope.GRPCEndMessage:
		mb, ok := b.(*envelope.GRPCEndMessage)
		if !ok {
			return true
		}
		return grpcEndModified(ma, mb)
	case *envelope.SSEMessage:
		mb, ok := b.(*envelope.SSEMessage)
		if !ok {
			return true
		}
		return sseMessageModified(ma, mb)
	default:
		return false
	}
}

// httpMessageModified reports whether two HTTPMessages differ in their
// content fields (headers, trailers, body). No normalization is applied
// (MITM wire fidelity).
//
// Body detection prefers BodyBuffer pointer identity over byte compare:
//   - If a.BodyBuffer != b.BodyBuffer, the body changed. This catches the
//     common Transform commit path where BodyBuffer→Body materialization
//     sets the snapshot's BodyBuffer!=nil and the current's BodyBuffer==nil.
//   - If both BodyBuffer pointers match (including both nil), fall back to
//     bytes.Equal(a.Body, b.Body) for the memory-backed path.
//
// Follows the USK-631 `isBodyChanged` precedent in
// internal/layer/http1/channel.go.
func httpMessageModified(a, b *envelope.HTTPMessage) bool {
	if a.Method != b.Method || a.Status != b.Status {
		return true
	}
	if a.Path != b.Path || a.Authority != b.Authority || a.Scheme != b.Scheme {
		return true
	}
	if !keyValuesEqual(a.Headers, b.Headers) {
		return true
	}
	if !keyValuesEqual(a.Trailers, b.Trailers) {
		return true
	}
	// BodyBuffer pointer inequality = modified. Transform Releases+nils the
	// BodyBuffer on commit, so snapshot retains the original pointer and
	// current is nil — a cheap pointer compare catches this without
	// materializing either side.
	if a.BodyBuffer != b.BodyBuffer {
		return true
	}
	// BodyBuffer pointers equal (both nil or same pointer) — compare Body
	// bytes. In the same-pointer case Body is expected to be nil on both
	// sides; bytes.Equal(nil, nil) == true keeps that as "unchanged".
	if !bytes.Equal(a.Body, b.Body) {
		return true
	}
	return false
}

// keyValuesEqual reports whether two KeyValue slices are identical in order,
// name, and value. No normalization is applied (MITM wire fidelity).
func keyValuesEqual(a, b []envelope.KeyValue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

// stringSliceEqual reports whether two string slices are identical in length,
// order, and value.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// wsMessageModified reports whether two WSMessages differ in observable
// content. Mask and Masked are excluded — wire-level masking is regenerated
// on Send and treating it as observable would produce false-positive
// variants for every client→server frame after re-masking.
func wsMessageModified(a, b *envelope.WSMessage) bool {
	if a.Opcode != b.Opcode || a.Fin != b.Fin || a.Compressed != b.Compressed {
		return true
	}
	if a.CloseCode != b.CloseCode || a.CloseReason != b.CloseReason {
		return true
	}
	return !bytes.Equal(a.Payload, b.Payload)
}

// grpcStartModified reports whether two GRPCStartMessages differ. All mutable
// fields are compared; Metadata uses keyValuesEqual (order/case strict, no
// normalization).
func grpcStartModified(a, b *envelope.GRPCStartMessage) bool {
	if a.Service != b.Service || a.Method != b.Method {
		return true
	}
	if a.Timeout != b.Timeout || a.ContentType != b.ContentType || a.Encoding != b.Encoding {
		return true
	}
	if !stringSliceEqual(a.AcceptEncoding, b.AcceptEncoding) {
		return true
	}
	return !keyValuesEqual(a.Metadata, b.Metadata)
}

// grpcDataModified reports whether two GRPCDataMessages differ. Service and
// Method are denormalized read-only from the associated GRPCStartMessage,
// but defensively compared so an errant Step that mutates them produces a
// recorded variant.
func grpcDataModified(a, b *envelope.GRPCDataMessage) bool {
	if a.Service != b.Service || a.Method != b.Method {
		return true
	}
	if a.Compressed != b.Compressed || a.WireLength != b.WireLength {
		return true
	}
	if a.EndStream != b.EndStream {
		return true
	}
	return !bytes.Equal(a.Payload, b.Payload)
}

// grpcEndModified reports whether two GRPCEndMessages differ. Anomalies are
// intentionally excluded — they are parser-derived state observed on the
// wire, not user-mutable, so they must not produce variant rows.
func grpcEndModified(a, b *envelope.GRPCEndMessage) bool {
	if a.Status != b.Status || a.Message != b.Message {
		return true
	}
	if !bytes.Equal(a.StatusDetails, b.StatusDetails) {
		return true
	}
	return !keyValuesEqual(a.Trailers, b.Trailers)
}

// sseMessageModified reports whether two SSEMessages differ.
func sseMessageModified(a, b *envelope.SSEMessage) bool {
	return a.Event != b.Event || a.Data != b.Data || a.ID != b.ID || a.Retry != b.Retry
}

// shouldRecord reports whether env passes the capture-scope filter and
// must therefore be persisted.
//
// The decision is cached per StreamID so streams whose recording status
// was decided on first Send (where method/path are observable) carry
// that decision through every subsequent envelope — including non-HTTP
// frames whose Message types do not carry HTTP fields. This keeps the
// flows.stream_id foreign-key invariant intact: filtered streams never
// get a Stream row, so any Flow that survives the gate must arrive on a
// Stream that does exist.
//
// The fallback for cache misses on non-first-Send envelopes is
// "do not record". Under realistic load (concurrent stream count well
// below cache capacity) misses do not occur. Above capacity the proxy
// trades a small amount of under-recording for foreign-key safety.
func (s *RecordStep) shouldRecord(env *envelope.Envelope) bool {
	if s.scope == nil || s.scope.IsEmpty() {
		return true
	}
	streamID := env.StreamID
	if streamID == "" {
		// No stable cache key. Evaluate per envelope; this only fires
		// for synthetic test stacks that omit StreamID.
		return s.scope.ShouldRecord(env)
	}
	if s.decisionCache != nil {
		if decision, ok := s.decisionCache.get(streamID); ok {
			return decision
		}
	}
	if env.Direction == envelope.Send && env.Sequence == 0 {
		decision := s.scope.ShouldRecord(env)
		if s.decisionCache != nil {
			s.decisionCache.put(streamID, decision)
		}
		return decision
	}
	// Cache miss on a non-first-Send envelope. We cannot recover the
	// stream's recording status from the envelope alone (later WS / gRPC
	// frames carry no method or path), so fail closed to keep the FK
	// invariant on flows.stream_id intact. Document this in the
	// WithRecordScope option doc.
	return false
}

// recordDecisionCache is a small bounded LRU keyed by StreamID. It is
// safe for concurrent use; RecordStep.Process is invoked from many
// goroutines (one per active stream + per envelope direction).
type recordDecisionCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	lru      *list.List
}

// recordDecisionEntry is the value type stored in recordDecisionCache.
// It is referenced from both the lookup map and the LRU list.
type recordDecisionEntry struct {
	streamID string
	record   bool
}

// newRecordDecisionCache returns a cache with the given fixed capacity.
// A capacity of zero or negative degenerates to a no-op cache (every
// access misses); RecordStep guards capacity via the WithRecordScope
// option which always uses defaultRecordCacheCapacity.
func newRecordDecisionCache(capacity int) *recordDecisionCache {
	if capacity <= 0 {
		capacity = defaultRecordCacheCapacity
	}
	return &recordDecisionCache{
		capacity: capacity,
		items:    make(map[string]*list.Element, capacity),
		lru:      list.New(),
	}
}

// get returns the cached recording decision for streamID, or false +
// ok=false on miss. A hit refreshes the entry's LRU position.
func (c *recordDecisionCache) get(streamID string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[streamID]; ok {
		c.lru.MoveToFront(e)
		return e.Value.(*recordDecisionEntry).record, true
	}
	return false, false
}

// put inserts or updates the recording decision for streamID. If the
// cache is at capacity, the least-recently-used entry is evicted.
func (c *recordDecisionCache) put(streamID string, record bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[streamID]; ok {
		e.Value.(*recordDecisionEntry).record = record
		c.lru.MoveToFront(e)
		return
	}
	e := c.lru.PushFront(&recordDecisionEntry{streamID: streamID, record: record})
	c.items[streamID] = e
	if c.lru.Len() > c.capacity {
		oldest := c.lru.Back()
		if oldest != nil {
			c.lru.Remove(oldest)
			delete(c.items, oldest.Value.(*recordDecisionEntry).streamID)
		}
	}
}

// len reports the current number of cached entries. Test-only helper.
func (c *recordDecisionCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// recordCountCache is the per-StreamID record-count LRU used by RecordStep
// to enforce the gRPC / SSE per-stream record caps (USK-802). It mirrors
// recordDecisionCache's shape — bounded LRU keyed by StreamID, single mutex
// per cache — so the two caches share an internal-quality bar even though
// they store different value types.
//
// The "truncated" latch on each entry is a one-shot bool: the first
// over-cap observation flips it true and the caller knows to perform the
// AppendTags + slog.Debug side-effects exactly once per Stream. Subsequent
// over-cap observations on the same Stream see truncated=true and skip
// the side-effect path. Cache eviction resets the latch alongside the
// counter (both are part of the discarded entry); a Stream that gets
// re-discovered after eviction will re-stamp its tag, which is the
// acknowledged trade-off for bounding cache memory.
type recordCountCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	lru      *list.List
}

// recordCountEntry is the value type stored in recordCountCache. count
// tracks total observed gated envelopes for the Stream; truncated is the
// one-shot latch that flips on the first over-cap observation.
type recordCountEntry struct {
	streamID  string
	count     int
	truncated bool
}

// newRecordCountCache returns a cache with the given fixed capacity.
// Capacity zero or negative degenerates to defaultCountCacheCapacity so
// the cache always has a sensible bound — RecordStep never exposes the
// raw constructor.
func newRecordCountCache(capacity int) *recordCountCache {
	if capacity <= 0 {
		capacity = defaultCountCacheCapacity
	}
	return &recordCountCache{
		capacity: capacity,
		items:    make(map[string]*list.Element, capacity),
		lru:      list.New(),
	}
}

// bumpAndCheck records one observed envelope for streamID and returns the
// post-increment count plus a one-shot firstHit flag that is true exactly
// when this call is the first to push the count past cap.
//
// The cap argument is taken per-call rather than stored on the entry
// because the cache holds entries for both gRPC and SSE streams in the
// same map and the two protocols may carry different caps. Caller is
// responsible for routing the right cap.
//
// On first insertion at capacity the LRU evicts the least-recently-used
// entry, which discards both its counter and its truncated latch. A
// re-discovered Stream past eviction restarts at count=1; if it again
// exceeds the cap the firstHit flag fires again. This produces a
// duplicate AppendTags / slog.Debug pair under sustained churn above
// defaultCountCacheCapacity concurrent gated streams. The trade-off is
// preferred over an unbounded cache because the operator-observable
// surface (AppendTags = "per_stream_cap_reached") is idempotent — the
// second tag write rewrites the same value.
func (c *recordCountCache) bumpAndCheck(streamID string, cap int) (count int, firstHit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[streamID]; ok {
		entry := e.Value.(*recordCountEntry)
		entry.count++
		c.lru.MoveToFront(e)
		// firstHit fires only on the transition from "within cap" to
		// "over cap" — i.e. when count crosses cap+1 for the first time.
		// Subsequent over-cap envelopes set the truncated latch and
		// return firstHit=false so the caller's stamp/log fires once.
		if !entry.truncated && entry.count > cap {
			entry.truncated = true
			return entry.count, true
		}
		return entry.count, false
	}
	entry := &recordCountEntry{streamID: streamID, count: 1}
	if cap < 1 {
		// Defensive: a 0/negative cap should be filtered upstream by
		// recordCapForEnvelope, but if we somehow land here the entry
		// records the observation and triggers firstHit immediately so
		// the truncation tag still surfaces.
		entry.truncated = true
	}
	e := c.lru.PushFront(entry)
	c.items[streamID] = e
	if c.lru.Len() > c.capacity {
		oldest := c.lru.Back()
		if oldest != nil {
			c.lru.Remove(oldest)
			delete(c.items, oldest.Value.(*recordCountEntry).streamID)
		}
	}
	if entry.truncated {
		return entry.count, true
	}
	return entry.count, false
}

// len reports the current number of cached entries. Test-only helper.
func (c *recordCountCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
