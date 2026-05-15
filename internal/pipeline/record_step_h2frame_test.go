package pipeline

import (
	"context"
	"strconv"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// h2FrameEnvelope is a minimal record-time fixture matching the shape
// produced by the orchestrator-owned frame-record callback that the
// session.runUpgrade* paths install via http2.Layer.DetachStream's
// WithFrameRecordCallback option. The Message is intentionally generic
// here (RawMessage) because the pipeline package cannot import http2 —
// the discriminator is the EnvelopeContext.WireLevel, not the Message
// type.
func h2FrameEnvelope(streamID string, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "frame-" + strconv.Itoa(seq),
		Direction: envelope.Receive,
		Sequence:  seq,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("payload-" + strconv.Itoa(seq)),
		Message:   &envelope.RawMessage{Bytes: []byte("payload-" + strconv.Itoa(seq))},
		Context:   envelope.EnvelopeContext{WireLevel: flow.WireLevelH2Frame},
	}
}

// TestRecordStep_H2FrameWireLevelProjected verifies that envelopes
// carrying EnvelopeContext.WireLevel = flow.WireLevelH2Frame project the
// value onto Flow.WireLevel so the schemaV14 column receives the
// discriminator without callers having to populate Flow.WireLevel
// directly.
func TestRecordStep_H2FrameWireLevelProjected(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()
	step.Process(ctx, h2FrameEnvelope("s1", 1))
	if len(w.flows) != 1 {
		t.Fatalf("flows recorded = %d, want 1", len(w.flows))
	}
	if got := w.flows[0].WireLevel; got != flow.WireLevelH2Frame {
		t.Errorf("Flow.WireLevel = %q, want %q", got, flow.WireLevelH2Frame)
	}
}

// TestRecordStep_H2FramePerStreamCap verifies the USK-889 cap: when
// WithHTTP2FrameMaxPerStream(n) is supplied, frame envelopes past the
// nth on a single (stream_id) tuple are dropped, the first over-cap
// envelope stamps AppendTags["records_truncated"], and subsequent
// over-cap envelopes drop silently without further UpdateStream calls.
func TestRecordStep_H2FramePerStreamCap(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithHTTP2FrameMaxPerStream(3))
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		step.Process(ctx, h2FrameEnvelope("s1", i))
	}
	if len(w.flows) != 3 {
		t.Errorf("flows recorded = %d, want 3 (cap)", len(w.flows))
	}
	tagUpdates := 0
	for _, u := range w.updates {
		if u.streamID == "s1" && u.update.AppendTags["records_truncated"] == "per_stream_cap_reached" {
			tagUpdates++
		}
	}
	if tagUpdates != 1 {
		t.Errorf("AppendTags[records_truncated] updates = %d, want 1", tagUpdates)
	}
}

// TestRecordStep_H2FrameCapDoesNotAffectSemantic verifies independence:
// the frame cap gates only WireLevelH2Frame envelopes. Semantic
// envelopes on the same Stream pass through unconditionally even after
// the frame cap fires.
func TestRecordStep_H2FrameCapDoesNotAffectSemantic(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithHTTP2FrameMaxPerStream(1))
	ctx := context.Background()
	// 3 frame envelopes; only the first survives the cap.
	for i := 0; i < 3; i++ {
		step.Process(ctx, h2FrameEnvelope("s1", i))
	}
	// 2 semantic envelopes (WS message-shaped — anything not flagged).
	for i := 0; i < 2; i++ {
		env := &envelope.Envelope{
			StreamID:  "s1",
			FlowID:    "ws-" + strconv.Itoa(i),
			Direction: envelope.Receive,
			Sequence:  i + 10,
			Protocol:  envelope.ProtocolWebSocket,
			Message:   &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hi")},
		}
		step.Process(ctx, env)
	}
	if len(w.flows) != 3 {
		t.Errorf("flows recorded = %d, want 3 (1 frame + 2 semantic)", len(w.flows))
	}
	frameCount, semanticCount := 0, 0
	for _, fl := range w.flows {
		switch fl.WireLevel {
		case flow.WireLevelH2Frame:
			frameCount++
		default:
			semanticCount++
		}
	}
	if frameCount != 1 {
		t.Errorf("frame flows = %d, want 1", frameCount)
	}
	if semanticCount != 2 {
		t.Errorf("semantic flows = %d, want 2", semanticCount)
	}
}

// TestRecordStep_H2FrameCapLazyCache verifies the lazy-allocation
// contract: WithHTTP2FrameMaxPerStream(n>0) allocates the countCache
// (sharing it with the USK-802 gRPC / SSE caps) and a zero-value Option
// keeps it nil.
func TestRecordStep_H2FrameCapLazyCache(t *testing.T) {
	t.Run("no_option_no_cache", func(t *testing.T) {
		s := NewRecordStep(&mockWriter{}, nil)
		if s.countCache != nil {
			t.Error("countCache allocated without any cap Option")
		}
	})
	t.Run("frame_option_allocates_cache", func(t *testing.T) {
		s := NewRecordStep(&mockWriter{}, nil, WithHTTP2FrameMaxPerStream(10))
		if s.countCache == nil {
			t.Error("countCache nil after WithHTTP2FrameMaxPerStream(>0)")
		}
	})
	t.Run("zero_value_skips_allocation", func(t *testing.T) {
		s := NewRecordStep(&mockWriter{}, nil, WithHTTP2FrameMaxPerStream(0))
		if s.countCache != nil {
			t.Error("countCache allocated when WithHTTP2FrameMaxPerStream(0)")
		}
	})
}
