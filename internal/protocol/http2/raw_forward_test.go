package http2

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
)

func TestRewriteRawFrameStreamIDs(t *testing.T) {
	tests := []struct {
		name          string
		rawBytes      []byte
		newStreamID   uint32
		wantEndStream bool
		wantErr       bool
		checkResult   func(t *testing.T, result []byte)
	}{
		{
			name:     "empty input",
			rawBytes: nil,
			wantErr:  false,
		},
		{
			name:          "single HEADERS frame without END_STREAM",
			rawBytes:      buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders, 1, []byte("header-data")),
			newStreamID:   3,
			wantEndStream: false,
			wantErr:       false,
			checkResult: func(t *testing.T, result []byte) {
				hdr, err := frame.ParseHeader(result)
				if err != nil {
					t.Fatalf("parse header: %v", err)
				}
				if hdr.StreamID != 3 {
					t.Errorf("stream ID = %d, want 3", hdr.StreamID)
				}
				if hdr.Type != frame.TypeHeaders {
					t.Errorf("type = %s, want HEADERS", hdr.Type)
				}
			},
		},
		{
			name:          "HEADERS frame with END_STREAM",
			rawBytes:      buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders|frame.FlagEndStream, 1, []byte("header-data")),
			newStreamID:   5,
			wantEndStream: true,
			wantErr:       false,
			checkResult: func(t *testing.T, result []byte) {
				hdr, err := frame.ParseHeader(result)
				if err != nil {
					t.Fatalf("parse header: %v", err)
				}
				if hdr.StreamID != 5 {
					t.Errorf("stream ID = %d, want 5", hdr.StreamID)
				}
			},
		},
		{
			name:          "DATA frame with END_STREAM",
			rawBytes:      buildTestFrame(frame.TypeData, frame.FlagEndStream, 1, []byte("body-data")),
			newStreamID:   7,
			wantEndStream: true,
			wantErr:       false,
		},
		{
			name: "multiple frames: HEADERS + DATA with END_STREAM",
			rawBytes: append(
				buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders, 1, []byte("headers")),
				buildTestFrame(frame.TypeData, frame.FlagEndStream, 1, []byte("body"))...,
			),
			newStreamID:   9,
			wantEndStream: true,
			wantErr:       false,
			checkResult: func(t *testing.T, result []byte) {
				// First frame: HEADERS
				hdr1, err := frame.ParseHeader(result[:frame.HeaderSize])
				if err != nil {
					t.Fatalf("parse first header: %v", err)
				}
				if hdr1.StreamID != 9 {
					t.Errorf("first frame stream ID = %d, want 9", hdr1.StreamID)
				}
				if hdr1.Type != frame.TypeHeaders {
					t.Errorf("first frame type = %s, want HEADERS", hdr1.Type)
				}

				// Second frame: DATA
				offset := frame.HeaderSize + int(hdr1.Length)
				hdr2, err := frame.ParseHeader(result[offset : offset+frame.HeaderSize])
				if err != nil {
					t.Fatalf("parse second header: %v", err)
				}
				if hdr2.StreamID != 9 {
					t.Errorf("second frame stream ID = %d, want 9", hdr2.StreamID)
				}
				if hdr2.Type != frame.TypeData {
					t.Errorf("second frame type = %s, want DATA", hdr2.Type)
				}
			},
		},
		{
			name:        "connection-level frame (stream ID 0) not rewritten",
			rawBytes:    buildTestFrame(frame.TypeSettings, 0, 0, nil),
			newStreamID: 3,
			wantErr:     false,
			checkResult: func(t *testing.T, result []byte) {
				hdr, err := frame.ParseHeader(result)
				if err != nil {
					t.Fatalf("parse header: %v", err)
				}
				if hdr.StreamID != 0 {
					t.Errorf("connection frame stream ID = %d, want 0", hdr.StreamID)
				}
			},
		},
		{
			name:     "truncated header",
			rawBytes: []byte{0, 0, 5, 0, 0, 0, 0, 0}, // only 8 bytes, need 9
			wantErr:  true,
		},
		{
			name:     "truncated payload",
			rawBytes: buildTestFrame(frame.TypeData, 0, 1, []byte("data"))[:frame.HeaderSize+2], // payload shorter than declared
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, hasEndStream, err := rewriteRawFrameStreamIDs(tt.rawBytes, tt.newStreamID)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if hasEndStream != tt.wantEndStream {
				t.Errorf("hasEndStream = %v, want %v", hasEndStream, tt.wantEndStream)
			}

			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

func TestRewriteRawFrameStreamIDs_PreservesPayload(t *testing.T) {
	payload := []byte("hello-world-body")
	raw := buildTestFrame(frame.TypeData, frame.FlagEndStream, 1, payload)

	result, _, err := rewriteRawFrameStreamIDs(raw, 5)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	// Extract payload from result.
	resultPayload := result[frame.HeaderSize:]
	if string(resultPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", resultPayload, payload)
	}
}

func TestRewriteRawFrameStreamIDs_DoesNotMutateInput(t *testing.T) {
	raw := buildTestFrame(frame.TypeHeaders, frame.FlagEndHeaders, 1, []byte("data"))
	original := make([]byte, len(raw))
	copy(original, raw)

	_, _, err := rewriteRawFrameStreamIDs(raw, 99)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	for i := range raw {
		if raw[i] != original[i] {
			t.Errorf("input modified at byte %d: got 0x%02x, want 0x%02x", i, raw[i], original[i])
		}
	}
}

// buildTestFrame creates a raw HTTP/2 frame for testing.
func buildTestFrame(typ frame.Type, flags frame.Flags, streamID uint32, payload []byte) []byte {
	hdr := frame.Header{
		Length:   uint32(len(payload)),
		Type:     typ,
		Flags:    flags,
		StreamID: streamID,
	}
	buf := hdr.AppendTo(make([]byte, 0, frame.HeaderSize+len(payload)))
	buf = append(buf, payload...)
	return buf
}
