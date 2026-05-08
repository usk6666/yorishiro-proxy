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
	"sync"
	"time"

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

	// scope filters which envelopes are recorded. nil = capture all
	// (current behaviour). When non-nil, ShouldRecord is consulted for
	// every envelope and the result is cached per StreamID in
	// decisionCache so non-HTTP frames inherit the decision made at the
	// stream's first Send (where method/path were observable).
	scope         *flow.RecordScope
	decisionCache *recordDecisionCache
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
	return s
}

// Process records the Envelope to the Flow Store. It always returns a zero
// Result (Action=Continue, Envelope=nil) because RecordStep never modifies
// the Envelope or interrupts the Pipeline.
func (s *RecordStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if s.store == nil {
		return Result{}
	}

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
		return Result{}
	}

	// Create Stream on first Send (Sequence==0).
	if env.Direction == envelope.Send && env.Sequence == 0 {
		s.createStream(ctx, env)
	}

	// On Receive, project upstream TLS snapshot (if present) onto
	// Stream.ConnInfo. The Send side carries the synthetic MITM cert we
	// presented to the client; Receive carries the real upstream TLS
	// reality that analysts actually need. UpdateStream is idempotent —
	// repeated Receive envelopes on the same stream rewrite the same
	// values.
	if env.Direction == envelope.Receive && env.Context.TLS != nil {
		s.updateStreamTLS(ctx, env)
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

// createStream creates a new Stream record from the Envelope.
func (s *RecordStep) createStream(ctx context.Context, env *envelope.Envelope) {
	st := &flow.Stream{
		ID:        env.StreamID,
		ConnID:    env.Context.ConnID,
		Protocol:  string(env.Protocol),
		State:     "active",
		Timestamp: time.Now(),
	}

	// Derive scheme from Message type when available.
	if msg, ok := env.Message.(*envelope.HTTPMessage); ok && msg.Scheme != "" {
		st.Scheme = msg.Scheme
	}

	if err := s.store.SaveStream(ctx, st); err != nil {
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
	origFlow.ID = current.FlowID + "-original"
	origFlow.Metadata["variant"] = "original"
	if err := s.store.SaveFlow(ctx, origFlow); err != nil {
		s.logger.Error("record step: original variant save failed",
			"stream_id", current.StreamID,
			"flow_id", origFlow.ID,
			"error", err,
		)
	}

	modFlow := s.envelopeToFlow(ctx, current)
	// Suffix the modified-variant FlowID symmetric to "-original" above so
	// the two records do not collide on the flow table's
	// UNIQUE(stream_id, sequence, direction) constraint. The base FlowID
	// alone matches the snapshot's identity, so without this suffix the
	// SaveFlow below would silently fail with "constraint failed" on every
	// intercept(modify_and_forward), losing the modified record entirely.
	modFlow.ID = current.FlowID + "-modified"
	modFlow.Metadata["variant"] = "modified"
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
func (s *RecordStep) envelopeToFlow(ctx context.Context, env *envelope.Envelope) *flow.Flow {
	fl := &flow.Flow{
		ID:        env.FlowID,
		StreamID:  env.StreamID,
		Sequence:  env.Sequence,
		Direction: env.Direction.String(),
		Timestamp: time.Now(),
		// TODO(USK-772): switch to env.WireBytes(ctx) once RawBuffer is
		// populated for disk-spilled bodies. While RawBuffer is always nil
		// (USK-773 memory-only path) env.Raw IS the full wire snapshot and
		// WireBytes would just be a more expensive read; once USK-772 lands
		// and Raw may be nil with RawBuffer non-nil, this projection will
		// silently drop wire bytes from Flow.RawBytes unless updated.
		RawBytes: env.Raw,
		Metadata: map[string]string{"protocol": string(env.Protocol)},
	}

	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		fl.Method = m.Method
		fl.StatusCode = m.Status
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
	}

	return fl
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
	default:
		return ""
	}
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
