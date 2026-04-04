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

// FlowWriter is the consumer-side alias for flow persistence.
// It reuses flow.FlowWriter to avoid maintaining a duplicate interface.
type FlowWriter = flow.FlowWriter

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
	store  FlowWriter
	logger *slog.Logger
}

// NewRecordStep creates a RecordStep with the given FlowWriter.
// If store is nil, Process returns immediately with no side effects.
func NewRecordStep(store FlowWriter, logger *slog.Logger) *RecordStep {
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

	fl := &flow.Flow{
		ID:        ex.FlowID,
		ConnID:    connID,
		Protocol:  ex.Protocol.String(),
		FlowType:  "unary",
		State:     "active",
		Timestamp: time.Now(),
	}
	if ex.URL != nil {
		fl.Scheme = ex.URL.Scheme
	}

	if err := s.store.SaveFlow(ctx, fl); err != nil {
		s.logger.Error("record step: flow save failed",
			"flow_id", ex.FlowID,
			"error", err,
		)
		return
	}

	snap := SnapshotFromContext(ctx)
	if snap != nil && exchangeModified(snap, ex) {
		s.recordVariantMessages(ctx, snap, ex, fl.ID, "send")
		return
	}

	msg := exchangeToMessage(ex, fl.ID, ex.Sequence, "send")
	if err := s.store.AppendMessage(ctx, msg); err != nil {
		s.logger.Error("record step: send message save failed",
			"flow_id", fl.ID,
			"error", err,
		)
	}
}

// recordReceive appends a receive Message and updates the Flow to "complete".
func (s *RecordStep) recordReceive(ctx context.Context, ex *exchange.Exchange) {
	snap := SnapshotFromContext(ctx)
	if snap != nil && exchangeModified(snap, ex) {
		s.recordVariantMessages(ctx, snap, ex, ex.FlowID, "receive")
	} else {
		msg := exchangeToMessage(ex, ex.FlowID, ex.Sequence, "receive")
		if err := s.store.AppendMessage(ctx, msg); err != nil {
			s.logger.Error("record step: receive message save failed",
				"flow_id", ex.FlowID,
				"error", err,
			)
		}
	}

	update := flow.FlowUpdate{
		State:    "complete",
		Duration: 0, // placeholder; real duration comes from Session
	}
	if err := s.store.UpdateFlow(ctx, ex.FlowID, update); err != nil {
		s.logger.Error("record step: flow update failed",
			"flow_id", ex.FlowID,
			"error", err,
		)
	}
}

// recordVariantMessages records both the original (from snapshot) and the
// modified (current) Exchange as separate messages with variant metadata.
func (s *RecordStep) recordVariantMessages(ctx context.Context, snap, current *exchange.Exchange, flowID, direction string) {
	origMsg := exchangeToMessage(snap, flowID, current.Sequence, direction)
	if origMsg.Metadata == nil {
		origMsg.Metadata = make(map[string]string, 1)
	}
	origMsg.Metadata["variant"] = "original"
	if err := s.store.AppendMessage(ctx, origMsg); err != nil {
		s.logger.Error("record step: original variant save failed",
			"flow_id", flowID,
			"error", err,
		)
	}

	modMsg := exchangeToMessage(current, flowID, current.Sequence+1, direction)
	if modMsg.Metadata == nil {
		modMsg.Metadata = make(map[string]string, 1)
	}
	modMsg.Metadata["variant"] = "modified"
	if err := s.store.AppendMessage(ctx, modMsg); err != nil {
		s.logger.Error("record step: modified variant save failed",
			"flow_id", flowID,
			"error", err,
		)
	}
}

// exchangeToMessage converts an Exchange to a flow.Message.
func exchangeToMessage(ex *exchange.Exchange, flowID string, sequence int, direction string) *flow.Message {
	msg := &flow.Message{
		FlowID:    flowID,
		Sequence:  sequence,
		Direction: direction,
		Timestamp: time.Now(),
		Method:    ex.Method,
		URL:       ex.URL,
		Body:      ex.Body,
		RawBytes:  ex.RawBytes,
	}

	if ex.Status != 0 {
		msg.StatusCode = ex.Status
	}

	// Convert exchange.KeyValue headers to map[string][]string for flow.Message.
	if len(ex.Headers) > 0 {
		hdrs := make(map[string][]string, len(ex.Headers))
		for _, kv := range ex.Headers {
			hdrs[kv.Name] = append(hdrs[kv.Name], kv.Value)
		}
		msg.Headers = hdrs
	}

	// Convert exchange.Metadata (map[string]any) to flow.Message.Metadata (map[string]string).
	if len(ex.Metadata) > 0 {
		meta := make(map[string]string, len(ex.Metadata))
		for k, v := range ex.Metadata {
			if s, ok := v.(string); ok {
				meta[k] = s
			}
		}
		if len(meta) > 0 {
			msg.Metadata = meta
		}
	}

	return msg
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
