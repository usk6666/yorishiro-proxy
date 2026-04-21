package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

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
// recorded.
type RecordStep struct {
	store  flow.Writer
	logger *slog.Logger
}

// NewRecordStep creates a RecordStep with the given flow.Writer.
// If store is nil, Process returns immediately with no side effects.
func NewRecordStep(store flow.Writer, logger *slog.Logger) *RecordStep {
	if logger == nil {
		logger = slog.Default()
	}
	return &RecordStep{store: store, logger: logger}
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
func (s *RecordStep) recordVariantFlows(ctx context.Context, snap, current *envelope.Envelope) {
	origFlow := envelopeToFlow(snap)
	origFlow.ID = current.FlowID + "-original"
	if origFlow.Metadata == nil {
		origFlow.Metadata = make(map[string]string, 1)
	}
	origFlow.Metadata["variant"] = "original"
	if err := s.store.SaveFlow(ctx, origFlow); err != nil {
		s.logger.Error("record step: original variant save failed",
			"stream_id", current.StreamID,
			"flow_id", origFlow.ID,
			"error", err,
		)
	}

	modFlow := envelopeToFlow(current)
	if modFlow.Metadata == nil {
		modFlow.Metadata = make(map[string]string, 1)
	}
	modFlow.Metadata["variant"] = "modified"
	if err := s.store.SaveFlow(ctx, modFlow); err != nil {
		s.logger.Error("record step: modified variant save failed",
			"stream_id", current.StreamID,
			"flow_id", modFlow.ID,
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
