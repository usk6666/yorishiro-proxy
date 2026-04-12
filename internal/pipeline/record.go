//go:build legacy

package pipeline

import (
	"bytes"
	"context"
	"fmt"
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
// On the first Send (Sequence==0): creates a Stream (state="active") and
// records a send Flow.
// On subsequent Sends (Sequence>0): records a send Flow only.
// On Receive: records a receive Flow only.
//
// RecordStep does NOT manage Stream state transitions (complete/error).
// That is Session's responsibility (USK-578).
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

	// Create Stream on first Send (Sequence==0).
	if ex.Direction == exchange.Send && ex.Sequence == 0 {
		s.createStream(ctx, ex)
	}

	// Record Flow for every Exchange (Send or Receive).
	snap := SnapshotFromContext(ctx)
	if snap != nil && exchangeModified(snap, ex) {
		s.recordVariantFlows(ctx, snap, ex)
	} else {
		s.recordFlow(ctx, ex)
	}

	return Result{}
}

// createStream creates a new Stream record from the Exchange.
func (s *RecordStep) createStream(ctx context.Context, ex *exchange.Exchange) {
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
	}
}

// recordFlow records a single Flow from the Exchange.
func (s *RecordStep) recordFlow(ctx context.Context, ex *exchange.Exchange) {
	fl := exchangeToFlow(ex)
	if err := s.store.SaveFlow(ctx, fl); err != nil {
		s.logger.Error("record step: flow save failed",
			"stream_id", ex.StreamID,
			"flow_id", ex.FlowID,
			"direction", directionString(ex.Direction),
			"error", err,
		)
	}
}

// recordVariantFlows records both the original (from snapshot) and the
// modified (current) Exchange as separate flows with variant metadata.
func (s *RecordStep) recordVariantFlows(ctx context.Context, snap, current *exchange.Exchange) {
	origFlow := exchangeToFlow(snap)
	// Use current's FlowID with "-original" suffix for the original variant.
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

	modFlow := exchangeToFlow(current)
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

// exchangeToFlow converts an Exchange to a flow.Flow.
func exchangeToFlow(ex *exchange.Exchange) *flow.Flow {
	fl := &flow.Flow{
		ID:        ex.FlowID,
		StreamID:  ex.StreamID,
		Sequence:  ex.Sequence,
		Direction: directionString(ex.Direction),
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
			meta[k] = fmt.Sprint(v)
		}
		if len(meta) > 0 {
			fl.Metadata = meta
		}
	}

	return fl
}

// directionString returns the string representation of a Direction
// suitable for flow.Flow.Direction ("send" or "receive").
func directionString(d exchange.Direction) string {
	switch d {
	case exchange.Send:
		return "send"
	case exchange.Receive:
		return "receive"
	default:
		return "unknown"
	}
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
