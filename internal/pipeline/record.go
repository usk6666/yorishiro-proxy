package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// RecordWriter is the consumer-side alias for flow persistence.
// It reuses flow.Writer (StreamWriter + FlowWriter) to avoid maintaining
// a duplicate interface.
type RecordWriter = flow.Writer

// RecordStep records Exchange data to the Flow Store. It runs last in the
// Pipeline (after all transformations) and never modifies the Exchange.
//
// On Send: creates a Flow (state="active") and appends a send Message.
// On Receive: appends a receive Message and updates the Flow (state="complete").
//
// If preceding Steps modified the Exchange (detected by comparing with the
// snapshot stored in context), both the original and modified variants are
// recorded.
type RecordStep struct {
	store  RecordWriter
	logger *slog.Logger
}

// NewRecordStep creates a RecordStep with the given RecordWriter.
// If store is nil, Process returns immediately with no side effects.
func NewRecordStep(store RecordWriter, logger *slog.Logger) *RecordStep {
	if logger == nil {
		logger = slog.Default()
	}
	return &RecordStep{store: store, logger: logger}
}

// Process records the Exchange to the Flow Store. It always returns a zero
// Result (Action=Continue, Exchange=nil) because RecordStep never modifies
// the Exchange or interrupts the Pipeline.
func (s *RecordStep) Process(ctx context.Context, ex *exchange.Exchange) Result {
	if s.store == nil {
		return Result{}
	}

	switch ex.Direction {
	case exchange.Send:
		s.recordSend(ctx, ex)
	case exchange.Receive:
		s.recordReceive(ctx, ex)
	}
	return Result{}
}

// recordSend creates a Flow and appends the send Message. If a variant
// snapshot exists and differs from the current Exchange, both original and
// modified messages are recorded.
func (s *RecordStep) recordSend(ctx context.Context, ex *exchange.Exchange) {
	connID := proxy.ConnIDFromContext(ctx)

	st := &flow.Stream{
		ID:        ex.StreamID,
		ConnID:    connID,
		Protocol:  ex.Protocol.String(),
		State:     "active",
		Timestamp: time.Now(),
	}
	if ex.URL != nil {
		st.Scheme = ex.URL.Scheme
	}

	if err := s.store.SaveStream(ctx, st); err != nil {
		s.logger.Error("record step: stream save failed",
			"stream_id", ex.StreamID,
			"error", err,
		)
		return
	}

	snap := SnapshotFromContext(ctx)
	if snap != nil && exchangeModified(snap, ex) {
		s.recordVariantFlows(ctx, snap, ex, st.ID, "send")
		return
	}

	fl := exchangeToFlow(ex, st.ID, ex.Sequence, "send")
	if err := s.store.SaveFlow(ctx, fl); err != nil {
		s.logger.Error("record step: send flow save failed",
			"stream_id", st.ID,
			"error", err,
		)
	}
}

// recordReceive appends a receive flow and updates the Stream to "complete".
func (s *RecordStep) recordReceive(ctx context.Context, ex *exchange.Exchange) {
	snap := SnapshotFromContext(ctx)
	if snap != nil && exchangeModified(snap, ex) {
		s.recordVariantFlows(ctx, snap, ex, ex.StreamID, "receive")
	} else {
		fl := exchangeToFlow(ex, ex.StreamID, ex.Sequence, "receive")
		if err := s.store.SaveFlow(ctx, fl); err != nil {
			s.logger.Error("record step: receive flow save failed",
				"stream_id", ex.StreamID,
				"error", err,
			)
		}
	}

	update := flow.StreamUpdate{
		State:    "complete",
		Duration: 0, // placeholder; real duration comes from Session
	}
	if err := s.store.UpdateStream(ctx, ex.StreamID, update); err != nil {
		s.logger.Error("record step: stream update failed",
			"stream_id", ex.StreamID,
			"error", err,
		)
	}
}

// recordVariantFlows records both the original (from snapshot) and the
// modified (current) Exchange as separate flows with variant metadata.
func (s *RecordStep) recordVariantFlows(ctx context.Context, snap, current *exchange.Exchange, streamID, direction string) {
	origFlow := exchangeToFlow(snap, streamID, current.Sequence, direction)
	if origFlow.Metadata == nil {
		origFlow.Metadata = make(map[string]string, 1)
	}
	origFlow.Metadata["variant"] = "original"
	if err := s.store.SaveFlow(ctx, origFlow); err != nil {
		s.logger.Error("record step: original variant save failed",
			"stream_id", streamID,
			"error", err,
		)
	}

	modFlow := exchangeToFlow(current, streamID, current.Sequence+1, direction)
	if modFlow.Metadata == nil {
		modFlow.Metadata = make(map[string]string, 1)
	}
	modFlow.Metadata["variant"] = "modified"
	if err := s.store.SaveFlow(ctx, modFlow); err != nil {
		s.logger.Error("record step: modified variant save failed",
			"stream_id", streamID,
			"error", err,
		)
	}
}

// exchangeToFlow converts an Exchange to a flow.Flow.
func exchangeToFlow(ex *exchange.Exchange, streamID string, sequence int, direction string) *flow.Flow {
	fl := &flow.Flow{
		StreamID:  streamID,
		Sequence:  sequence,
		Direction: direction,
		Timestamp: time.Now(),
		Method:    ex.Method,
		URL:       ex.URL,
		Body:      ex.Body,
		RawBytes:  ex.RawBytes,
	}

	if ex.Status != 0 {
		fl.StatusCode = ex.Status
	}

	// Convert exchange.KeyValue headers to map[string][]string for flow.Flow.
	if len(ex.Headers) > 0 {
		hdrs := make(map[string][]string, len(ex.Headers))
		for _, kv := range ex.Headers {
			hdrs[kv.Name] = append(hdrs[kv.Name], kv.Value)
		}
		fl.Headers = hdrs
	}

	// Convert exchange.Metadata (map[string]any) to flow.Flow.Metadata (map[string]string).
	if len(ex.Metadata) > 0 {
		meta := make(map[string]string, len(ex.Metadata))
		for k, v := range ex.Metadata {
			if s, ok := v.(string); ok {
				meta[k] = s
			}
		}
		if len(meta) > 0 {
			fl.Metadata = meta
		}
	}

	return fl
}

// exchangeModified reports whether the current Exchange differs from the
// snapshot in Headers, Trailers, Body, or RawBytes.
func exchangeModified(snap, current *exchange.Exchange) bool {
	if !headersEqual(snap.Headers, current.Headers) {
		return true
	}
	if !headersEqual(snap.Trailers, current.Trailers) {
		return true
	}
	if !bytes.Equal(snap.Body, current.Body) {
		return true
	}
	if !bytes.Equal(snap.RawBytes, current.RawBytes) {
		return true
	}
	return false
}

// headersEqual reports whether two KeyValue slices are identical in order,
// name, and value. No normalization is applied (MITM wire fidelity).
func headersEqual(a, b []exchange.KeyValue) bool {
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
