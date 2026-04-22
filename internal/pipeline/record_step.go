package pipeline

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

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
	store        flow.Writer
	logger       *slog.Logger
	wireEncoders map[envelope.Protocol]WireEncoder
}

// Option configures a RecordStep.
type Option func(*RecordStep)

// WithWireEncoder registers a per-protocol WireEncoder used when recording
// the "modified" variant of an intercepted envelope. The encoder is invoked
// only for envelopes whose Protocol matches proto. See WireEncoder for the
// contract on return values.
//
// Passing a nil fn removes any previously-registered encoder for proto.
func WithWireEncoder(proto envelope.Protocol, fn WireEncoder) Option {
	return func(s *RecordStep) {
		if s.wireEncoders == nil {
			s.wireEncoders = make(map[envelope.Protocol]WireEncoder)
		}
		if fn == nil {
			delete(s.wireEncoders, proto)
			return
		}
		s.wireEncoders[proto] = fn
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
	return s
}

// Process records the Envelope to the Flow Store. It always returns a zero
// Result (Action=Continue, Envelope=nil) because RecordStep never modifies
// the Envelope or interrupts the Pipeline.
func (s *RecordStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if s.store == nil {
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
	fl := envelopeToFlow(env)
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
	origFlow := envelopeToFlow(snap)
	origFlow.ID = current.FlowID + "-original"
	origFlow.Metadata["variant"] = "original"
	if err := s.store.SaveFlow(ctx, origFlow); err != nil {
		s.logger.Error("record step: original variant save failed",
			"stream_id", current.StreamID,
			"flow_id", origFlow.ID,
			"error", err,
		)
	}

	modFlow := envelopeToFlow(current)
	modFlow.Metadata["variant"] = "modified"
	s.applyWireEncode(current, modFlow)
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
func (s *RecordStep) applyWireEncode(current *envelope.Envelope, modFlow *flow.Flow) {
	if len(s.wireEncoders) == 0 {
		return
	}
	enc, ok := s.wireEncoders[current.Protocol]
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
func envelopeToFlow(env *envelope.Envelope) *flow.Flow {
	fl := &flow.Flow{
		ID:        env.FlowID,
		StreamID:  env.StreamID,
		Sequence:  env.Sequence,
		Direction: env.Direction.String(),
		Timestamp: time.Now(),
		RawBytes:  env.Raw,
		Metadata:  map[string]string{"protocol": string(env.Protocol)},
	}

	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		fl.Method = m.Method
		fl.StatusCode = m.Status
		fl.Body = m.Body

		if m.Path != "" || m.Authority != "" {
			fl.URL = &url.URL{
				Scheme:   m.Scheme,
				Host:     m.Authority,
				Path:     m.Path,
				RawQuery: m.RawQuery,
			}
		}

		if len(m.Headers) > 0 {
			hdrs := make(map[string][]string, len(m.Headers))
			for _, kv := range m.Headers {
				hdrs[kv.Name] = append(hdrs[kv.Name], kv.Value)
			}
			fl.Headers = hdrs
		}

		if len(m.Trailers) > 0 {
			trlrs := make(map[string][]string, len(m.Trailers))
			for _, kv := range m.Trailers {
				trlrs[kv.Name] = append(trlrs[kv.Name], kv.Value)
			}
			fl.Trailers = trlrs
		}
	case *envelope.RawMessage:
		fl.Body = m.Bytes
	}

	return fl
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
		// Unknown Message type — assume not modified to avoid false positives.
		return false
	}
}

// httpMessageModified reports whether two HTTPMessages differ in their
// content fields (headers, trailers, body). No normalization is applied
// (MITM wire fidelity).
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
