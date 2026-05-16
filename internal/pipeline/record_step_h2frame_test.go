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

// USK-896 unit tests for the grpc-lpm-frame wire_level. Mirrors the
// USK-889 h2-frame / USK-895 h1-chunk patterns.

// grpcLPMFrameEnvelope builds a minimal grpc-lpm-frame envelope shaped
// like the envelopes produced by GRPCLPMRecordOption's callback on the
// gRPC data path. Message is intentionally nil — LPM wire envelopes
// have no L7 structured view by design (the GRPCDataMessage envelope
// queued immediately after the LPM-record callback provides the
// decompressed view).
func grpcLPMFrameEnvelope(streamID string, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "lpm-" + strconv.Itoa(seq),
		Direction: envelope.Receive,
		Sequence:  seq,
		Protocol:  envelope.ProtocolGRPC,
		// 5-byte LPM prefix (compressed=0, length=4) + 4-byte payload.
		Raw:     []byte{0x00, 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef},
		Context: envelope.EnvelopeContext{WireLevel: flow.WireLevelGRPCLPMFrame},
	}
}

// TestRecordStep_GRPCLPMFrameWireLevelProjected verifies that envelopes
// carrying EnvelopeContext.WireLevel = flow.WireLevelGRPCLPMFrame
// project the value onto Flow.WireLevel so the schemaV14 column
// distinguishes LPM wire rows from semantic GRPCDataMessage rows.
func TestRecordStep_GRPCLPMFrameWireLevelProjected(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()
	step.Process(ctx, grpcLPMFrameEnvelope("s1", 1))
	if len(w.flows) != 1 {
		t.Fatalf("flows recorded = %d, want 1", len(w.flows))
	}
	if got := w.flows[0].WireLevel; got != flow.WireLevelGRPCLPMFrame {
		t.Errorf("Flow.WireLevel = %q, want %q", got, flow.WireLevelGRPCLPMFrame)
	}
}

// TestRecordStep_GRPCLPMFramePerStreamCap verifies the USK-896 cap:
// when WithGRPCLPMFrameMaxPerStream(n) is supplied, LPM wire envelopes
// past the nth on a single (stream_id) tuple are dropped, the first
// over-cap envelope stamps AppendTags["records_truncated"], and
// subsequent over-cap envelopes drop silently.
func TestRecordStep_GRPCLPMFramePerStreamCap(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithGRPCLPMFrameMaxPerStream(3))
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		step.Process(ctx, grpcLPMFrameEnvelope("s1", i))
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

// TestRecordStep_GRPCLPMFrameCapIsolation verifies the per-WireLevel cap
// separation: WithGRPCLPMFrameMaxPerStream gates only grpc-lpm-frame
// envelopes, not h2-frame, h1-chunk, or semantic. Cross-pollution would
// silently break either the gRPC LPM recording path (under-recording)
// or one of the other paths (over-recording).
func TestRecordStep_GRPCLPMFrameCapIsolation(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithGRPCLPMFrameMaxPerStream(1),
	)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		step.Process(ctx, grpcLPMFrameEnvelope("s1", i))
	}
	for i := 10; i < 13; i++ {
		step.Process(ctx, h2FrameEnvelope("s1", i))
	}
	for i := 20; i < 23; i++ {
		step.Process(ctx, h1ChunkEnvelope("s1", i))
	}
	lpmCount, frameCount, chunkCount := 0, 0, 0
	for _, fl := range w.flows {
		switch fl.WireLevel {
		case flow.WireLevelGRPCLPMFrame:
			lpmCount++
		case flow.WireLevelH2Frame:
			frameCount++
		case flow.WireLevelHTTP1Chunk:
			chunkCount++
		}
	}
	if lpmCount != 1 {
		t.Errorf("grpc-lpm-frame flows = %d, want 1 (cap)", lpmCount)
	}
	// h2-frame and h1-chunk are uncapped here; all 3 each pass through.
	if frameCount != 3 {
		t.Errorf("h2-frame flows = %d, want 3 (uncapped)", frameCount)
	}
	if chunkCount != 3 {
		t.Errorf("h1-chunk flows = %d, want 3 (uncapped)", chunkCount)
	}
}

// TestRecordStep_GRPCLPMFrameCapLazyCache verifies the lazy-allocation
// contract analogous to the USK-889 / USK-895 frame/chunk tests: a
// positive WithGRPCLPMFrameMaxPerStream allocates countCache.
func TestRecordStep_GRPCLPMFrameCapLazyCache(t *testing.T) {
	t.Run("grpc_lpm_option_allocates_cache", func(t *testing.T) {
		s := NewRecordStep(&mockWriter{}, nil, WithGRPCLPMFrameMaxPerStream(10))
		if s.countCache == nil {
			t.Error("countCache nil after WithGRPCLPMFrameMaxPerStream(>0)")
		}
	})
	t.Run("zero_value_skips_allocation", func(t *testing.T) {
		s := NewRecordStep(&mockWriter{}, nil, WithGRPCLPMFrameMaxPerStream(0))
		if s.countCache != nil {
			t.Error("countCache allocated when WithGRPCLPMFrameMaxPerStream(0)")
		}
	})
}

// USK-908 unit tests for the streamCreated one-shot guard.
//
// Native gRPC streams emit three wire_level envelopes per direction
// (semantic + grpc-lpm-frame + h2-frame, USK-899) sharing the same
// StreamID; aggregator-path h2 streams emit two (h2-frame + semantic
// HTTPMessage, USK-897). All such envelopes arrive at RecordStep with
// Direction=Send, Sequence=0 and previously each triggered SaveStream,
// producing UNIQUE constraint failures on streams.id. The guard
// short-circuits the duplicate createStream calls; SaveFlow continues
// to fire for every wire_level envelope.

// semanticGRPCStartSendEnvelope builds a Direction=Send Sequence=0
// envelope shaped like the semantic GRPCStartMessage envelope native
// gRPC channels queue first (internal/layer/grpc/channel.go:450).
// Context.WireLevel is intentionally empty — semantic envelopes leave
// it unset and sqlite projects empty→"semantic" only at persist time.
func semanticGRPCStartSendEnvelope(streamID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "semantic-" + streamID,
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       []byte("HEADERS"),
		Message: &envelope.GRPCStartMessage{
			Service: "svc",
			Method:  "Method",
		},
		Context: envelope.EnvelopeContext{ConnID: "c1"},
	}
}

// h2FrameSendEnvelope builds a Direction=Send Sequence=0 wire-level
// envelope. The existing h2FrameEnvelope helper only covers Receive;
// USK-908 reproduces the duplicate-SaveStream race specifically on the
// Send/Seq=0 first-frame.
func h2FrameSendEnvelope(streamID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "h2frame-send-" + streamID,
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("h2-frame-payload"),
		Message:   &envelope.RawMessage{Bytes: []byte("h2-frame-payload")},
		Context:   envelope.EnvelopeContext{ConnID: "c1", WireLevel: flow.WireLevelH2Frame},
	}
}

// grpcLPMFrameSendEnvelope builds a Direction=Send Sequence=0
// wire-level envelope. Matches the shape produced by
// internal/layer/grpc/channel.go:638-640 (per-LPM record callback).
func grpcLPMFrameSendEnvelope(streamID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "lpm-send-" + streamID,
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       []byte{0x00, 0x00, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef},
		Context:   envelope.EnvelopeContext{ConnID: "c1", WireLevel: flow.WireLevelGRPCLPMFrame},
	}
}

// TestRecordStep_CreateStream_FiresOnceAcrossWireLevels_NativeGRPCOrder
// reproduces the native gRPC arrival ordering: semantic GRPCStartMessage
// first (queued before LPM dispatch in absorbHeaders), then the
// h2-frame and grpc-lpm-frame wire-record callbacks fire during
// absorbData on the first DATA. All three arrive at RecordStep with
// Direction=Send, Sequence=0 and the same StreamID. Without the
// streamCreated guard, SaveStream fires three times — two UNIQUE
// constraint failures.
func TestRecordStep_CreateStream_FiresOnceAcrossWireLevels_NativeGRPCOrder(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()

	step.Process(ctx, semanticGRPCStartSendEnvelope("s1"))
	step.Process(ctx, h2FrameSendEnvelope("s1"))
	step.Process(ctx, grpcLPMFrameSendEnvelope("s1"))

	if len(w.streams) != 1 {
		t.Errorf("SaveStream calls = %d, want 1 (one-shot guard)", len(w.streams))
	}
	if len(w.flows) != 3 {
		t.Errorf("SaveFlow calls = %d, want 3 (every wire_level recorded)", len(w.flows))
	}
	// First-write wins: the semantic envelope arrived first, so the
	// Stream row carries Protocol=grpc derived from semanticGRPCStart-
	// SendEnvelope's Protocol.
	if got := w.streams[0].Protocol; got != "grpc" {
		t.Errorf("Stream.Protocol = %q, want %q (first-write wins)", got, "grpc")
	}
}

// TestRecordStep_CreateStream_FiresOnceAcrossWireLevels_AggregatorOrder
// reproduces the aggregator-path arrival ordering: wire-level h2-frame
// first (fired in httpaggregator.absorbData BEFORE the body-buffer
// mutation), then the semantic HTTPMessage envelope on END_STREAM.
// Both arrive at RecordStep with Direction=Send, Sequence=0 and the
// same StreamID. The wire-level envelope wins createStream; the
// semantic envelope is short-circuited. SaveFlow fires twice — once
// per wire_level envelope so wire-record persistence is preserved.
//
// Note: in production the aggregator-path Stream row would carry
// Protocol=http on the wire-level envelope (the wire bytes are an h2
// DATA frame, not a gRPC LPM); the subsequent semantic envelope's
// HTTPMessage carries Protocol=http too, so maybeRetagProtocol is a
// no-op and Stream.Protocol stays "http". This test exercises the
// same path with Protocol=http on both envelopes to match production.
func TestRecordStep_CreateStream_FiresOnceAcrossWireLevels_AggregatorOrder(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()

	step.Process(ctx, h2FrameSendEnvelope("s1"))
	step.Process(ctx, &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "semantic-s1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/2"),
		Message: &envelope.HTTPMessage{
			Method:    "POST",
			Scheme:    "https",
			Authority: "example.test",
			Path:      "/",
			Headers:   []envelope.KeyValue{{Name: ":method", Value: "POST"}},
		},
		Context: envelope.EnvelopeContext{ConnID: "c1"},
	})

	if len(w.streams) != 1 {
		t.Errorf("SaveStream calls = %d, want 1 (one-shot guard)", len(w.streams))
	}
	if len(w.flows) != 2 {
		t.Errorf("SaveFlow calls = %d, want 2 (every wire_level recorded)", len(w.flows))
	}
	// First-write wins: the h2-frame envelope arrived first, so the
	// Stream row carries Protocol=http (h2-frame's Protocol).
	if got := w.streams[0].Protocol; got != "http" {
		t.Errorf("Stream.Protocol = %q, want %q (first-write wins)", got, "http")
	}
}

// TestRecordStep_CreateStream_StreamCreatedDoesNotShortCircuitProtocolRetag
// guards the streamCreated/protocolRetagged decoupling. The retag path
// is independent: when a non-HTTP envelope arrives on a stream that was
// created by a wire-level envelope (Protocol=http on the aggregator
// path), the retag path must still fire on the first non-HTTP envelope.
//
// Scenario: wire-level h2-frame with Protocol=http arrives first and
// creates the Stream. The subsequent semantic envelope with
// Protocol=grpc on the same StreamID must trigger
// UpdateStream(Protocol=grpc) via maybeRetagProtocol.
func TestRecordStep_CreateStream_StreamCreatedDoesNotShortCircuitProtocolRetag(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()

	// First: wire-level h2-frame with Protocol=http creates the Stream.
	step.Process(ctx, h2FrameSendEnvelope("s1"))
	// Second: semantic envelope with Protocol=grpc must trigger retag.
	step.Process(ctx, semanticGRPCStartSendEnvelope("s1"))

	if len(w.streams) != 1 {
		t.Fatalf("SaveStream calls = %d, want 1 (one-shot guard)", len(w.streams))
	}
	if w.streams[0].Protocol != "http" {
		t.Errorf("Stream.Protocol on createStream = %q, want %q (h2-frame first)", w.streams[0].Protocol, "http")
	}

	// Find the protocol-retag UpdateStream call.
	retagCount := 0
	for _, u := range w.updates {
		if u.streamID == "s1" && u.update.Protocol == "grpc" {
			retagCount++
		}
	}
	if retagCount != 1 {
		t.Errorf("UpdateStream(Protocol=grpc) calls = %d, want 1 (retag must fire)", retagCount)
	}
}

// TestRecordStep_CreateStream_UnknownWireLevelStillCreatesStream is the
// permissive-default counterpart to TestRecordStep_UnknownWireLevelNotGated:
// an envelope with an unknown WireLevel value must still trip
// createStream on the first Send/Seq=0. The streamCreated guard does
// NOT discriminate on WireLevel — whichever envelope arrives first
// wins, regardless of value. This matches the cap-path precedent: the
// gate is permissive for unknown wire_levels.
func TestRecordStep_CreateStream_UnknownWireLevelStillCreatesStream(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()

	step.Process(ctx, &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "future-1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("future"),
		Message:   &envelope.RawMessage{Bytes: []byte("future")},
		Context:   envelope.EnvelopeContext{WireLevel: "future-unknown-discriminator"},
	})

	if len(w.streams) != 1 {
		t.Errorf("SaveStream calls = %d, want 1 (permissive: unknown WireLevel still creates stream)", len(w.streams))
	}
	if len(w.flows) != 1 {
		t.Errorf("SaveFlow calls = %d, want 1", len(w.flows))
	}
}
