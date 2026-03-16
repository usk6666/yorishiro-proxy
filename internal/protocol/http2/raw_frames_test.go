package http2

import (
	"bytes"
	"context"
	"testing"
)

func TestJoinRawFrames_NilInput(t *testing.T) {
	result := joinRawFrames(nil)
	if result != nil {
		t.Errorf("joinRawFrames(nil) = %v, want nil", result)
	}
}

func TestJoinRawFrames_EmptySlice(t *testing.T) {
	result := joinRawFrames([][]byte{})
	if result != nil {
		t.Errorf("joinRawFrames([]) = %v, want nil", result)
	}
}

func TestJoinRawFrames_EmptyFrames(t *testing.T) {
	result := joinRawFrames([][]byte{{}, {}})
	if result != nil {
		t.Errorf("joinRawFrames([[], []]) = %v, want nil", result)
	}
}

func TestJoinRawFrames_SingleFrame(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x05, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	result := joinRawFrames([][]byte{frame})
	if !bytes.Equal(result, frame) {
		t.Errorf("joinRawFrames single frame mismatch: got %v, want %v", result, frame)
	}
}

func TestJoinRawFrames_MultipleFrames(t *testing.T) {
	frame1 := []byte{0x01, 0x02, 0x03}
	frame2 := []byte{0x04, 0x05}
	frame3 := []byte{0x06}
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	result := joinRawFrames([][]byte{frame1, frame2, frame3})
	if !bytes.Equal(result, expected) {
		t.Errorf("joinRawFrames multiple frames: got %v, want %v", result, expected)
	}
}

func TestBuildFrameMetadata_NilInput(t *testing.T) {
	result := buildFrameMetadata(nil, nil)
	if result != nil {
		t.Errorf("buildFrameMetadata(nil, nil) = %v, want nil", result)
	}
}

func TestBuildFrameMetadata_EmptyFrames(t *testing.T) {
	result := buildFrameMetadata([][]byte{}, nil)
	if result != nil {
		t.Errorf("buildFrameMetadata([], nil) = %v, want nil", result)
	}
}

func TestBuildFrameMetadata_SingleFrame(t *testing.T) {
	frames := [][]byte{make([]byte, 15)} // 15 bytes
	result := buildFrameMetadata(frames, nil)

	if result == nil {
		t.Fatal("expected non-nil metadata")
	}
	if result["h2_frame_count"] != "1" {
		t.Errorf("h2_frame_count = %q, want %q", result["h2_frame_count"], "1")
	}
	if result["h2_total_wire_bytes"] != "15" {
		t.Errorf("h2_total_wire_bytes = %q, want %q", result["h2_total_wire_bytes"], "15")
	}
}

func TestBuildFrameMetadata_MultipleFrames(t *testing.T) {
	frames := [][]byte{
		make([]byte, 10),
		make([]byte, 20),
		make([]byte, 5),
	}
	result := buildFrameMetadata(frames, nil)

	if result == nil {
		t.Fatal("expected non-nil metadata")
	}
	if result["h2_frame_count"] != "3" {
		t.Errorf("h2_frame_count = %q, want %q", result["h2_frame_count"], "3")
	}
	if result["h2_total_wire_bytes"] != "35" {
		t.Errorf("h2_total_wire_bytes = %q, want %q", result["h2_total_wire_bytes"], "35")
	}
}

func TestBuildFrameMetadata_PreservesExistingKeys(t *testing.T) {
	frames := [][]byte{make([]byte, 9)}
	existing := map[string]string{
		"variant":             "original",
		"h2_frame_count":      "override-me-not",
		"h2_total_wire_bytes": "override-me-not",
	}
	result := buildFrameMetadata(frames, existing)

	// Existing keys should take precedence.
	if result["h2_frame_count"] != "override-me-not" {
		t.Errorf("h2_frame_count = %q, want existing value", result["h2_frame_count"])
	}
	if result["h2_total_wire_bytes"] != "override-me-not" {
		t.Errorf("h2_total_wire_bytes = %q, want existing value", result["h2_total_wire_bytes"])
	}
	// Non-conflicting keys should be preserved.
	if result["variant"] != "original" {
		t.Errorf("variant = %q, want %q", result["variant"], "original")
	}
}

func TestBuildFrameMetadata_MergesIntoExisting(t *testing.T) {
	frames := [][]byte{make([]byte, 9)}
	existing := map[string]string{"variant": "original"}
	result := buildFrameMetadata(frames, existing)

	if result["variant"] != "original" {
		t.Errorf("variant = %q, want %q", result["variant"], "original")
	}
	if result["h2_frame_count"] != "1" {
		t.Errorf("h2_frame_count = %q, want %q", result["h2_frame_count"], "1")
	}
	if result["h2_total_wire_bytes"] != "9" {
		t.Errorf("h2_total_wire_bytes = %q, want %q", result["h2_total_wire_bytes"], "9")
	}
}

func TestBuildFrameMetadata_NilFramesReturnsExisting(t *testing.T) {
	existing := map[string]string{"key": "value"}
	result := buildFrameMetadata(nil, existing)
	if result == nil || result["key"] != "value" {
		t.Error("expected original existing map returned for nil frames")
	}
}

func TestContextWithRawFrames_RoundTrip(t *testing.T) {
	frames := [][]byte{{0x01, 0x02}, {0x03, 0x04}}
	ctx := contextWithRawFrames(context.Background(), frames)

	got := rawFramesFromContext(ctx)
	if len(got) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(got))
	}
	if !bytes.Equal(got[0], frames[0]) || !bytes.Equal(got[1], frames[1]) {
		t.Error("raw frames round-trip mismatch")
	}
}

func TestRawFramesFromContext_NoValue(t *testing.T) {
	got := rawFramesFromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}
