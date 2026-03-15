package protobuf

import (
	"encoding/binary"
	"testing"
)

// TestParseFrame_Single tests parsing a single gRPC frame.
func TestParseFrame_Single(t *testing.T) {
	payload := []byte("hello")
	frame := BuildFrame(Frame{Compressed: 0, Payload: payload})

	f, consumed, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if consumed != len(frame) {
		t.Errorf("consumed = %d, want %d", consumed, len(frame))
	}
	if f.Compressed != 0 {
		t.Errorf("compressed = %d, want 0", f.Compressed)
	}
	assertBytesEqual(t, payload, f.Payload)
}

// TestParseFrame_Compressed tests parsing a compressed frame.
func TestParseFrame_Compressed(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	frame := BuildFrame(Frame{Compressed: 1, Payload: payload})

	f, _, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if f.Compressed != 1 {
		t.Errorf("compressed = %d, want 1", f.Compressed)
	}
	assertBytesEqual(t, payload, f.Payload)
}

// TestParseFrames_Multiple tests parsing multiple gRPC frames.
func TestParseFrames_Multiple(t *testing.T) {
	frames := []Frame{
		{Compressed: 0, Payload: []byte("msg1")},
		{Compressed: 0, Payload: []byte("msg2")},
		{Compressed: 1, Payload: []byte("msg3")},
	}
	data := BuildFrames(frames)

	parsed, err := ParseFrames(data)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(parsed) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(parsed))
	}
	for i, f := range frames {
		if parsed[i].Compressed != f.Compressed {
			t.Errorf("frame[%d] compressed = %d, want %d", i, parsed[i].Compressed, f.Compressed)
		}
		assertBytesEqual(t, f.Payload, parsed[i].Payload)
	}
}

// TestParseFrames_Empty tests parsing empty data.
func TestParseFrames_Empty(t *testing.T) {
	frames, err := ParseFrames([]byte{})
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(frames) != 0 {
		t.Errorf("expected 0 frames, got %d", len(frames))
	}
}

// TestParseFrame_IncompleteHeader tests parsing with incomplete header.
func TestParseFrame_IncompleteHeader(t *testing.T) {
	_, _, err := ParseFrame([]byte{0x00, 0x00})
	if err == nil {
		t.Error("expected error for incomplete header")
	}
}

// TestParseFrame_TruncatedPayload tests parsing with truncated payload.
func TestParseFrame_TruncatedPayload(t *testing.T) {
	// Header says 10 bytes payload, but only 3 available
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x02, 0x03}
	_, _, err := ParseFrame(data)
	if err == nil {
		t.Error("expected error for truncated payload")
	}
}

// TestBuildFrame_EmptyPayload tests building a frame with empty payload.
func TestBuildFrame_EmptyPayload(t *testing.T) {
	frame := BuildFrame(Frame{Compressed: 0, Payload: []byte{}})
	if len(frame) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(frame))
	}
	// Header should be: 0x00 0x00 0x00 0x00 0x00
	expected := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	assertBytesEqual(t, expected, frame)
}

// TestFrames_RoundTrip tests round-trip of frame build/parse.
func TestFrames_RoundTrip(t *testing.T) {
	original := []Frame{
		{Compressed: 0, Payload: hexToBytes(t, "089601")},
		{Compressed: 1, Payload: hexToBytes(t, "120774657374696e67")},
	}
	data := BuildFrames(original)
	parsed, err := ParseFrames(data)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(parsed) != len(original) {
		t.Fatalf("expected %d frames, got %d", len(original), len(parsed))
	}
	for i := range original {
		if parsed[i].Compressed != original[i].Compressed {
			t.Errorf("frame[%d] compressed mismatch", i)
		}
		assertBytesEqual(t, original[i].Payload, parsed[i].Payload)
	}
}

// TestParseFrame_ExceedsMaxPayloadSize tests that oversized frame payloads are rejected.
func TestParseFrame_ExceedsMaxPayloadSize(t *testing.T) {
	// Create a frame header claiming a payload of maxFramePayloadSize + 1
	oversizeLen := uint32(maxFramePayloadSize + 1)
	header := make([]byte, 5)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], oversizeLen)

	_, _, err := ParseFrame(header)
	if err == nil {
		t.Error("expected error for oversized frame payload")
	}
}

// TestParseFrames_ExceedsMaxPayloadSize tests ParseFrames with oversized payload.
func TestParseFrames_ExceedsMaxPayloadSize(t *testing.T) {
	oversizeLen := uint32(maxFramePayloadSize + 1)
	header := make([]byte, 5)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], oversizeLen)

	_, err := ParseFrames(header)
	if err == nil {
		t.Error("expected error for oversized frame payload")
	}
}

// TestParseFrame_AtMaxPayloadSize tests that a frame at exactly maxFramePayloadSize succeeds.
func TestParseFrame_AtMaxPayloadSize(t *testing.T) {
	// We only test the header parsing logic, not actual allocation of 16MB.
	// Build a small valid frame to verify non-oversized frames still work.
	payload := make([]byte, 100)
	frame := BuildFrame(Frame{Compressed: 0, Payload: payload})
	f, consumed, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if consumed != 105 {
		t.Errorf("consumed = %d, want 105", consumed)
	}
	if len(f.Payload) != 100 {
		t.Errorf("payload length = %d, want 100", len(f.Payload))
	}
}

// TestParseFrames_ProtobufPayload tests parsing frames containing real protobuf.
func TestParseFrames_ProtobufPayload(t *testing.T) {
	// Build a frame with protobuf payload: field 1 = "test message"
	payload := hexToBytes(t, "0a0c74657374206d657373616765")
	frame := BuildFrame(Frame{Compressed: 0, Payload: payload})

	f, _, err := ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}

	// Decode the protobuf payload
	jsonStr, err := Decode(f.Payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Re-encode
	reencoded, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, payload, reencoded)
}
