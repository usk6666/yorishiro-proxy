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

// USK-895 unit tests for the h1-chunk wire_level and the switch-on-
// WireLevel refactor of recordCapForEnvelope.

// h1ChunkEnvelope builds a minimal h1-chunk envelope shaped like the
// envelopes produced by session.h1ChunkRecordCallback on the
// SSE-over-h1-chunked detach path. Message is intentionally nil — chunk
// envelopes have no L7 structured view by design.
func h1ChunkEnvelope(streamID string, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "chunk-" + strconv.Itoa(seq),
		Direction: envelope.Receive,
		Sequence:  seq,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("5\r\nhello\r\n"),
		Context:   envelope.EnvelopeContext{WireLevel: flow.WireLevelHTTP1Chunk},
	}
}

// TestRecordStep_H1ChunkWireLevelProjected mirrors the USK-889 H2 frame
// projection test for USK-895: h1-chunk envelopes must surface their
// WireLevel onto Flow.WireLevel so the schemaV14 column distinguishes
// them from semantic and h2-frame rows.
func TestRecordStep_H1ChunkWireLevelProjected(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()
	step.Process(ctx, h1ChunkEnvelope("s1", 1))
	if len(w.flows) != 1 {
		t.Fatalf("flows recorded = %d, want 1", len(w.flows))
	}
	if got := w.flows[0].WireLevel; got != flow.WireLevelHTTP1Chunk {
		t.Errorf("Flow.WireLevel = %q, want %q", got, flow.WireLevelHTTP1Chunk)
	}
}

// TestRecordStep_H1ChunkPerStreamCap verifies the USK-895 cap: when
// WithHTTP1ChunkMaxPerStream(n) is supplied, chunk envelopes past the
// nth on a single (stream_id) tuple are dropped and AppendTags
// ["records_truncated"] is stamped exactly once.
func TestRecordStep_H1ChunkPerStreamCap(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithHTTP1ChunkMaxPerStream(2))
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		step.Process(ctx, h1ChunkEnvelope("s1", i))
	}
	if len(w.flows) != 2 {
		t.Errorf("flows recorded = %d, want 2 (cap)", len(w.flows))
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

// TestRecordStep_H1ChunkCapIsolation verifies the per-WireLevel cap
// separation: WithHTTP1ChunkMaxPerStream gates only h1-chunk envelopes,
// not h2-frame or semantic. Cross-pollution would silently break either
// the SSE-over-h1-chunked path (under-recording) or the SSE-over-h2
// path (over-recording).
func TestRecordStep_H1ChunkCapIsolation(t *testing.T) {
	w := &mockWriter{}
	// h1-chunk capped at 1; h2-frame uncapped (zero → unlimited);
	// semantic uncapped (no SSE/gRPC envelopes in this test).
	step := NewRecordStep(w, nil,
		WithHTTP1ChunkMaxPerStream(1),
	)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		step.Process(ctx, h1ChunkEnvelope("s1", i))
	}
	for i := 10; i < 13; i++ {
		step.Process(ctx, h2FrameEnvelope("s1", i))
	}
	chunkCount, frameCount := 0, 0
	for _, fl := range w.flows {
		switch fl.WireLevel {
		case flow.WireLevelHTTP1Chunk:
			chunkCount++
		case flow.WireLevelH2Frame:
			frameCount++
		}
	}
	if chunkCount != 1 {
		t.Errorf("h1-chunk flows = %d, want 1 (cap)", chunkCount)
	}
	// h2-frame is uncapped here (its cap field is zero), so all 3 pass through.
	if frameCount != 3 {
		t.Errorf("h2-frame flows = %d, want 3 (uncapped)", frameCount)
	}
}

// TestRecordStep_UnknownWireLevelNotGated verifies the switch refactor's
// default arm: an unknown / future non-semantic wire_level value falls
// through to cap=0 (do not gate). This protects against a future
// addition silently inheriting one of the existing caps when it should
// not.
func TestRecordStep_UnknownWireLevelNotGated(t *testing.T) {
	w := &mockWriter{}
	// Caps set on h2-frame and h1-chunk; an envelope with a different
	// non-semantic WireLevel must NOT inherit either cap.
	step := NewRecordStep(w, nil,
		WithHTTP2FrameMaxPerStream(1),
		WithHTTP1ChunkMaxPerStream(1),
	)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		step.Process(ctx, &envelope.Envelope{
			StreamID:  "s1",
			FlowID:    "future-" + strconv.Itoa(i),
			Direction: envelope.Receive,
			Sequence:  i,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("future"),
			Context:   envelope.EnvelopeContext{WireLevel: "future-unknown-discriminator"},
		})
	}
	// All 5 must survive — the unknown WireLevel is not gated.
	count := 0
	for _, fl := range w.flows {
		if fl.WireLevel == "future-unknown-discriminator" {
			count++
		}
	}
	if count != 5 {
		t.Errorf("future-unknown-discriminator flows = %d, want 5 (not gated)", count)
	}
}

// TestRecordStep_H1ChunkCapLazyCache verifies the lazy-allocation
// contract analogous to the USK-889 frame test: a positive
// WithHTTP1ChunkMaxPerStream allocates countCache.
func TestRecordStep_H1ChunkCapLazyCache(t *testing.T) {
	t.Run("h1_chunk_option_allocates_cache", func(t *testing.T) {
		s := NewRecordStep(&mockWriter{}, nil, WithHTTP1ChunkMaxPerStream(10))
		if s.countCache == nil {
			t.Error("countCache nil after WithHTTP1ChunkMaxPerStream(>0)")
		}
	})
	t.Run("zero_value_skips_allocation", func(t *testing.T) {
		s := NewRecordStep(&mockWriter{}, nil, WithHTTP1ChunkMaxPerStream(0))
		if s.countCache != nil {
			t.Error("countCache allocated when WithHTTP1ChunkMaxPerStream(0)")
		}
	})
}
