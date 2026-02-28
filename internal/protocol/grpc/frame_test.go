package grpc

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestReadFrame_ValidUncompressed(t *testing.T) {
	payload := []byte{0x0A, 0x05, 'h', 'e', 'l', 'l', 'o'} // Example protobuf data
	data := EncodeFrame(false, payload)

	frame, err := ReadFrame(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if frame.Compressed {
		t.Error("Compressed = true, want false")
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload = %x, want %x", frame.Payload, payload)
	}
}

func TestReadFrame_ValidCompressed(t *testing.T) {
	payload := []byte{0x1F, 0x8B, 0x08} // Fake gzip header bytes
	data := EncodeFrame(true, payload)

	frame, err := ReadFrame(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if !frame.Compressed {
		t.Error("Compressed = false, want true")
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload = %x, want %x", frame.Payload, payload)
	}
}

func TestReadFrame_EmptyPayload(t *testing.T) {
	data := EncodeFrame(false, nil)

	frame, err := ReadFrame(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if frame.Compressed {
		t.Error("Compressed = true, want false")
	}
	if len(frame.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(frame.Payload))
	}
}

func TestReadFrame_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty reader returns EOF",
			data:    nil,
			wantErr: "read grpc frame header",
		},
		{
			name:    "truncated header (3 bytes)",
			data:    []byte{0x00, 0x00, 0x00},
			wantErr: "read grpc frame header",
		},
		{
			name:    "invalid compressed flag",
			data:    []byte{0x02, 0x00, 0x00, 0x00, 0x00},
			wantErr: "invalid grpc compressed flag: 2",
		},
		{
			name: "message too large",
			data: func() []byte {
				b := make([]byte, 5)
				b[0] = 0x00
				binary.BigEndian.PutUint32(b[1:5], maxMessageSize+1)
				return b
			}(),
			wantErr: "grpc message too large",
		},
		{
			name: "truncated payload",
			data: func() []byte {
				b := make([]byte, 5)
				b[0] = 0x00
				binary.BigEndian.PutUint32(b[1:5], 100)
				// Only append 50 bytes of payload instead of 100
				b = append(b, make([]byte, 50)...)
				return b
			}(),
			wantErr: "read grpc payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tt.data))
			if err == nil {
				t.Fatal("ReadFrame() error = nil, want error")
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tt.wantErr)) {
				t.Errorf("ReadFrame() error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadFrame_EOF(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader(nil))
	if err == nil {
		t.Fatal("ReadFrame() error = nil, want error")
	}
	// Should wrap io.EOF or io.ErrUnexpectedEOF
	if !bytes.Contains([]byte(err.Error()), []byte("EOF")) {
		t.Errorf("ReadFrame() error = %q, want EOF-related error", err)
	}
}

func TestReadAllFrames_MultipleFrames(t *testing.T) {
	payload1 := []byte("message-one")
	payload2 := []byte("message-two")
	payload3 := []byte("message-three")

	var data []byte
	data = append(data, EncodeFrame(false, payload1)...)
	data = append(data, EncodeFrame(true, payload2)...)
	data = append(data, EncodeFrame(false, payload3)...)

	frames, err := ReadAllFrames(data)
	if err != nil {
		t.Fatalf("ReadAllFrames() error = %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("ReadAllFrames() returned %d frames, want 3", len(frames))
	}

	if !bytes.Equal(frames[0].Payload, payload1) || frames[0].Compressed {
		t.Errorf("frame[0]: Payload = %q, Compressed = %v", frames[0].Payload, frames[0].Compressed)
	}
	if !bytes.Equal(frames[1].Payload, payload2) || !frames[1].Compressed {
		t.Errorf("frame[1]: Payload = %q, Compressed = %v", frames[1].Payload, frames[1].Compressed)
	}
	if !bytes.Equal(frames[2].Payload, payload3) || frames[2].Compressed {
		t.Errorf("frame[2]: Payload = %q, Compressed = %v", frames[2].Payload, frames[2].Compressed)
	}
}

func TestReadAllFrames_Empty(t *testing.T) {
	frames, err := ReadAllFrames(nil)
	if err != nil {
		t.Fatalf("ReadAllFrames(nil) error = %v", err)
	}
	if frames != nil {
		t.Errorf("ReadAllFrames(nil) = %v, want nil", frames)
	}

	frames, err = ReadAllFrames([]byte{})
	if err != nil {
		t.Fatalf("ReadAllFrames([]) error = %v", err)
	}
	if frames != nil {
		t.Errorf("ReadAllFrames([]) = %v, want nil", frames)
	}
}

func TestReadAllFrames_IncompleteHeader(t *testing.T) {
	// Start with a valid frame, then an incomplete header.
	data := EncodeFrame(false, []byte("valid"))
	data = append(data, 0x00, 0x00) // 2 bytes, not enough for header

	frames, err := ReadAllFrames(data)
	if err == nil {
		t.Fatal("ReadAllFrames() error = nil, want error")
	}
	if len(frames) != 1 {
		t.Errorf("ReadAllFrames() returned %d frames before error, want 1", len(frames))
	}
}

func TestReadAllFrames_IncompletePayload(t *testing.T) {
	var data []byte
	data = append(data, EncodeFrame(false, []byte("ok"))...)
	// Add header claiming 100 bytes but only provide 10
	header := make([]byte, 5)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], 100)
	data = append(data, header...)
	data = append(data, make([]byte, 10)...)

	frames, err := ReadAllFrames(data)
	if err == nil {
		t.Fatal("ReadAllFrames() error = nil, want error")
	}
	if len(frames) != 1 {
		t.Errorf("ReadAllFrames() returned %d valid frames, want 1", len(frames))
	}
}

func TestReadAllFrames_InvalidCompressedFlag(t *testing.T) {
	data := []byte{0x05, 0x00, 0x00, 0x00, 0x01, 0x00} // compressed flag = 5
	frames, err := ReadAllFrames(data)
	if err == nil {
		t.Fatal("ReadAllFrames() error = nil, want error")
	}
	if len(frames) != 0 {
		t.Errorf("ReadAllFrames() returned %d frames, want 0", len(frames))
	}
}

func TestEncodeFrame_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		compressed bool
		payload    []byte
	}{
		{
			name:       "uncompressed with data",
			compressed: false,
			payload:    []byte("test-payload-data"),
		},
		{
			name:       "compressed with data",
			compressed: true,
			payload:    []byte{0x1f, 0x8b, 0x08, 0x00},
		},
		{
			name:       "empty payload",
			compressed: false,
			payload:    []byte{},
		},
		{
			name:       "nil payload",
			compressed: false,
			payload:    nil,
		},
		{
			name:       "large payload",
			compressed: false,
			payload:    bytes.Repeat([]byte("x"), 65536),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeFrame(tt.compressed, tt.payload)

			frame, err := ReadFrame(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("ReadFrame() error = %v", err)
			}

			if frame.Compressed != tt.compressed {
				t.Errorf("Compressed = %v, want %v", frame.Compressed, tt.compressed)
			}

			expectedLen := len(tt.payload)
			if tt.payload == nil {
				expectedLen = 0
			}
			if len(frame.Payload) != expectedLen {
				t.Errorf("Payload length = %d, want %d", len(frame.Payload), expectedLen)
			}
			if expectedLen > 0 && !bytes.Equal(frame.Payload, tt.payload) {
				t.Errorf("Payload mismatch")
			}
		})
	}
}

func TestEncodeFrame_HeaderFormat(t *testing.T) {
	payload := []byte("hello")
	encoded := EncodeFrame(false, payload)

	if len(encoded) != frameHeaderSize+len(payload) {
		t.Fatalf("encoded length = %d, want %d", len(encoded), frameHeaderSize+len(payload))
	}

	// Check compressed flag.
	if encoded[0] != 0x00 {
		t.Errorf("compressed flag = 0x%02x, want 0x00", encoded[0])
	}

	// Check length field.
	length := binary.BigEndian.Uint32(encoded[1:5])
	if length != uint32(len(payload)) {
		t.Errorf("length = %d, want %d", length, len(payload))
	}

	// Check payload.
	if !bytes.Equal(encoded[5:], payload) {
		t.Errorf("payload = %x, want %x", encoded[5:], payload)
	}

	// Test compressed flag.
	encodedCompressed := EncodeFrame(true, payload)
	if encodedCompressed[0] != 0x01 {
		t.Errorf("compressed flag = 0x%02x, want 0x01", encodedCompressed[0])
	}
}

func TestReadFrame_StreamMultiple(t *testing.T) {
	// Write multiple frames to a single reader and read them sequentially.
	payloads := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	}

	var buf bytes.Buffer
	for _, p := range payloads {
		buf.Write(EncodeFrame(false, p))
	}

	reader := bytes.NewReader(buf.Bytes())
	for i, wantPayload := range payloads {
		frame, err := ReadFrame(reader)
		if err != nil {
			t.Fatalf("ReadFrame[%d]() error = %v", i, err)
		}
		if !bytes.Equal(frame.Payload, wantPayload) {
			t.Errorf("frame[%d] Payload = %q, want %q", i, frame.Payload, wantPayload)
		}
	}

	// Next read should return EOF.
	_, err := ReadFrame(reader)
	if err == nil {
		t.Error("expected EOF after all frames consumed")
	}
	if !bytes.Contains([]byte(err.Error()), []byte(io.EOF.Error())) {
		t.Errorf("expected EOF-related error, got: %v", err)
	}
}
