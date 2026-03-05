package ws

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestReadFrame_UnmaskedTextFrame(t *testing.T) {
	// A single unmasked text frame with "Hello".
	// FIN=1, Opcode=1, MASK=0, Payload len=5
	payload := []byte("Hello")
	buf := buildFrame(t, true, OpcodeText, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if !frame.Fin {
		t.Error("Fin = false, want true")
	}
	if frame.Opcode != OpcodeText {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, OpcodeText)
	}
	if frame.Masked {
		t.Error("Masked = true, want false")
	}
	if string(frame.Payload) != "Hello" {
		t.Errorf("Payload = %q, want %q", frame.Payload, "Hello")
	}
}

func TestReadFrame_MaskedTextFrame(t *testing.T) {
	// A masked text frame with "Hello".
	payload := []byte("Hello")
	maskKey := [4]byte{0x37, 0xFA, 0x21, 0x3D}
	masked := make([]byte, len(payload))
	copy(masked, payload)
	maskPayload(maskKey, masked)

	buf := buildFrame(t, true, OpcodeText, true, maskKey, masked)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if !frame.Masked {
		t.Error("Masked = false, want true")
	}
	if frame.MaskKey != maskKey {
		t.Errorf("MaskKey = %v, want %v", frame.MaskKey, maskKey)
	}
	// Payload should be unmasked after reading.
	if string(frame.Payload) != "Hello" {
		t.Errorf("Payload = %q, want %q (unmasked)", frame.Payload, "Hello")
	}
}

func TestReadFrame_BinaryFrame(t *testing.T) {
	payload := []byte{0x00, 0x01, 0x02, 0xFF}
	buf := buildFrame(t, true, OpcodeBinary, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if frame.Opcode != OpcodeBinary {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, OpcodeBinary)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Errorf("Payload = %v, want %v", frame.Payload, payload)
	}
}

func TestReadFrame_EmptyPayload(t *testing.T) {
	buf := buildFrame(t, true, OpcodeText, false, [4]byte{}, nil)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if len(frame.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(frame.Payload))
	}
}

func TestReadFrame_CloseFrame(t *testing.T) {
	// Close frame with status code 1000 (Normal Closure).
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, 1000)
	buf := buildFrame(t, true, OpcodeClose, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if frame.Opcode != OpcodeClose {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, OpcodeClose)
	}
	if !frame.IsControl() {
		t.Error("IsControl() = false, want true")
	}
	if len(frame.Payload) != 2 {
		t.Fatalf("Payload length = %d, want 2", len(frame.Payload))
	}
	statusCode := binary.BigEndian.Uint16(frame.Payload)
	if statusCode != 1000 {
		t.Errorf("Close status = %d, want 1000", statusCode)
	}
}

func TestReadFrame_PingFrame(t *testing.T) {
	payload := []byte("ping-data")
	buf := buildFrame(t, true, OpcodePing, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if frame.Opcode != OpcodePing {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, OpcodePing)
	}
	if !frame.IsControl() {
		t.Error("IsControl() = false, want true")
	}
	if string(frame.Payload) != "ping-data" {
		t.Errorf("Payload = %q, want %q", frame.Payload, "ping-data")
	}
}

func TestReadFrame_PongFrame(t *testing.T) {
	payload := []byte("pong-data")
	buf := buildFrame(t, true, OpcodePong, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if frame.Opcode != OpcodePong {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, OpcodePong)
	}
	if !frame.IsControl() {
		t.Error("IsControl() = false, want true")
	}
}

func TestReadFrame_ExtendedPayloadLength16(t *testing.T) {
	// Payload of 200 bytes (requires 16-bit extended length).
	payload := bytes.Repeat([]byte("A"), 200)
	buf := buildFrame(t, true, OpcodeText, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if len(frame.Payload) != 200 {
		t.Errorf("Payload length = %d, want 200", len(frame.Payload))
	}
}

func TestReadFrame_ExtendedPayloadLength64(t *testing.T) {
	// Payload of 70000 bytes (requires 64-bit extended length).
	payload := bytes.Repeat([]byte("B"), 70000)
	buf := buildFrame(t, true, OpcodeBinary, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if len(frame.Payload) != 70000 {
		t.Errorf("Payload length = %d, want 70000", len(frame.Payload))
	}
}

func TestReadFrame_ContinuationFrame(t *testing.T) {
	// Continuation frame (FIN=0, Opcode=0).
	payload := []byte("continued")
	buf := buildFrame(t, false, OpcodeContinuation, false, [4]byte{}, payload)

	frame, err := ReadFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if frame.Fin {
		t.Error("Fin = true, want false")
	}
	if frame.Opcode != OpcodeContinuation {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, OpcodeContinuation)
	}
	if !frame.IsControl() {
		// Continuation frame is NOT a control frame.
	}
}

func TestReadFrame_FragmentedMessage(t *testing.T) {
	// First fragment: FIN=0, Opcode=Text, payload="Hel"
	frag1 := buildFrame(t, false, OpcodeText, false, [4]byte{}, []byte("Hel"))
	// Continuation: FIN=0, Opcode=Continuation, payload="lo"
	frag2 := buildFrame(t, false, OpcodeContinuation, false, [4]byte{}, []byte("lo"))
	// Final: FIN=1, Opcode=Continuation, payload=" World"
	frag3 := buildFrame(t, true, OpcodeContinuation, false, [4]byte{}, []byte(" World"))

	data := append(frag1, frag2...)
	data = append(data, frag3...)
	reader := bytes.NewReader(data)

	// Read first fragment.
	frame1, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	if frame1.Fin || frame1.Opcode != OpcodeText {
		t.Errorf("Frame 1: Fin=%v Opcode=%d, want Fin=false Opcode=%d", frame1.Fin, frame1.Opcode, OpcodeText)
	}
	if string(frame1.Payload) != "Hel" {
		t.Errorf("Frame 1 Payload = %q, want %q", frame1.Payload, "Hel")
	}

	// Read continuation.
	frame2, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	if frame2.Fin || frame2.Opcode != OpcodeContinuation {
		t.Errorf("Frame 2: Fin=%v Opcode=%d, want Fin=false Opcode=%d", frame2.Fin, frame2.Opcode, OpcodeContinuation)
	}

	// Read final fragment.
	frame3, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame 3: %v", err)
	}
	if !frame3.Fin || frame3.Opcode != OpcodeContinuation {
		t.Errorf("Frame 3: Fin=%v Opcode=%d, want Fin=true Opcode=%d", frame3.Fin, frame3.Opcode, OpcodeContinuation)
	}

	// Assemble the full message.
	assembled := string(frame1.Payload) + string(frame2.Payload) + string(frame3.Payload)
	if assembled != "Hello World" {
		t.Errorf("Assembled message = %q, want %q", assembled, "Hello World")
	}
}

func TestReadFrame_RSVBits(t *testing.T) {
	var buf bytes.Buffer
	// FIN=1, RSV1=1, RSV2=0, RSV3=1, Opcode=Text (0x1)
	// b0 = 1_1_0_1_0001 = 0xD1
	buf.WriteByte(0xD1)
	// MASK=0, Payload len=3
	buf.WriteByte(0x03)
	buf.Write([]byte("abc"))

	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if !frame.RSV1 {
		t.Error("RSV1 = false, want true")
	}
	if frame.RSV2 {
		t.Error("RSV2 = true, want false")
	}
	if !frame.RSV3 {
		t.Error("RSV3 = false, want true")
	}
}

func TestReadFrame_ErrorCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty input",
			data: nil,
		},
		{
			name: "only one byte",
			data: []byte{0x81},
		},
		{
			name: "16-bit length truncated",
			data: []byte{0x81, 126, 0x00}, // missing second byte of 16-bit length
		},
		{
			name: "64-bit length truncated",
			data: []byte{0x81, 127, 0x00, 0x00}, // missing rest of 64-bit length
		},
		{
			name: "payload truncated",
			data: []byte{0x81, 0x05, 'H', 'e'}, // says 5 bytes, only has 2
		},
		{
			name: "mask key truncated",
			data: []byte{0x81, 0x85, 0x37, 0xFA}, // masked, but only 2 of 4 mask key bytes
		},
		{
			name: "control frame too large",
			data: func() []byte {
				// Close frame with 126 bytes (exceeds 125 limit).
				var b bytes.Buffer
				b.WriteByte(0x88) // FIN=1, Opcode=Close
				b.WriteByte(126)  // 16-bit extended length
				binary.Write(&b, binary.BigEndian, uint16(126))
				b.Write(bytes.Repeat([]byte{0x00}, 126))
				return b.Bytes()
			}(),
		},
		{
			name: "control frame fragmented",
			data: []byte{0x09, 0x04, 'p', 'i', 'n', 'g'}, // FIN=0 (0x09 without 0x80), Opcode=Ping, but FIN=0 is invalid for control
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tt.data))
			if err == nil {
				t.Error("ReadFrame should have returned an error")
			}
		})
	}
}

func TestReadFrame_PayloadTooLarge(t *testing.T) {
	// Craft a frame header that claims a payload larger than maxFramePayloadSize.
	var buf bytes.Buffer
	buf.WriteByte(0x82) // FIN=1, Opcode=Binary
	buf.WriteByte(127)  // 64-bit extended length
	tooLarge := uint64(maxFramePayloadSize + 1)
	binary.Write(&buf, binary.BigEndian, tooLarge)

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Error("ReadFrame should have returned an error for oversized payload")
	}
}

func TestReadFrame_MSBSetInLength(t *testing.T) {
	// 64-bit length with MSB set (invalid per RFC 6455).
	var buf bytes.Buffer
	buf.WriteByte(0x82) // FIN=1, Opcode=Binary
	buf.WriteByte(127)  // 64-bit extended length
	// Set MSB: 0x80_00_00_00_00_00_00_00
	binary.Write(&buf, binary.BigEndian, uint64(1<<63))

	_, err := ReadFrame(&buf)
	if err == nil {
		t.Error("ReadFrame should have returned an error for length with MSB set")
	}
}

func TestWriteFrame_UnmaskedTextFrame(t *testing.T) {
	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: []byte("Hello"),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Read it back.
	readBack, err := ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if readBack.Opcode != OpcodeText {
		t.Errorf("Opcode = %d, want %d", readBack.Opcode, OpcodeText)
	}
	if string(readBack.Payload) != "Hello" {
		t.Errorf("Payload = %q, want %q", readBack.Payload, "Hello")
	}
}

func TestWriteFrame_MaskedTextFrame(t *testing.T) {
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78}
	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: maskKey,
		Payload: []byte("Hello"),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Verify the original payload was not modified.
	if string(frame.Payload) != "Hello" {
		t.Errorf("Original payload was modified: %q", frame.Payload)
	}

	// Read it back (ReadFrame will unmask).
	readBack, err := ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if string(readBack.Payload) != "Hello" {
		t.Errorf("Payload = %q, want %q", readBack.Payload, "Hello")
	}
	if readBack.MaskKey != maskKey {
		t.Errorf("MaskKey = %v, want %v", readBack.MaskKey, maskKey)
	}
}

func TestWriteFrame_CloseFrame(t *testing.T) {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, 1000)
	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	readBack, err := ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if readBack.Opcode != OpcodeClose {
		t.Errorf("Opcode = %d, want %d", readBack.Opcode, OpcodeClose)
	}
	if len(readBack.Payload) != 2 {
		t.Fatalf("Payload length = %d, want 2", len(readBack.Payload))
	}
	statusCode := binary.BigEndian.Uint16(readBack.Payload)
	if statusCode != 1000 {
		t.Errorf("Close status = %d, want 1000", statusCode)
	}
}

func TestWriteFrame_EmptyPayload(t *testing.T) {
	frame := &Frame{
		Fin:    true,
		Opcode: OpcodeText,
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	if buf.Len() != 2 {
		t.Errorf("Frame size = %d bytes, want 2", buf.Len())
	}

	readBack, err := ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if len(readBack.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(readBack.Payload))
	}
}

func TestWriteFrame_PayloadLengthEncoding(t *testing.T) {
	tests := []struct {
		name         string
		payloadSize  int
		expectedSize int // total frame size (header + payload)
	}{
		{"small (5 bytes)", 5, 2 + 5},           // 2-byte header
		{"exactly 125", 125, 2 + 125},            // 2-byte header
		{"126 bytes", 126, 4 + 126},              // 4-byte header (16-bit ext)
		{"medium (1000 bytes)", 1000, 4 + 1000},   // 4-byte header (16-bit ext)
		{"exactly 65535", 65535, 4 + 65535},        // 4-byte header (16-bit ext)
		{"65536 bytes", 65536, 10 + 65536},        // 10-byte header (64-bit ext)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, tt.payloadSize)
			for i := range payload {
				payload[i] = byte(i % 256)
			}

			frame := &Frame{
				Fin:     true,
				Opcode:  OpcodeBinary,
				Payload: payload,
			}

			var buf bytes.Buffer
			if err := WriteFrame(&buf, frame); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}

			if buf.Len() != tt.expectedSize {
				t.Errorf("Frame size = %d, want %d", buf.Len(), tt.expectedSize)
			}

			// Verify round-trip.
			readBack, err := ReadFrame(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}

			if len(readBack.Payload) != tt.payloadSize {
				t.Errorf("Payload length = %d, want %d", len(readBack.Payload), tt.payloadSize)
			}
			if !bytes.Equal(readBack.Payload, payload) {
				t.Error("Payload data mismatch after round-trip")
			}
		})
	}
}

func TestWriteFrame_RSVBits(t *testing.T) {
	frame := &Frame{
		Fin:     true,
		RSV1:    true,
		RSV2:    false,
		RSV3:    true,
		Opcode:  OpcodeText,
		Payload: []byte("test"),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	readBack, err := ReadFrame(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if !readBack.RSV1 {
		t.Error("RSV1 = false, want true")
	}
	if readBack.RSV2 {
		t.Error("RSV2 = true, want false")
	}
	if !readBack.RSV3 {
		t.Error("RSV3 = false, want true")
	}
}

func TestWriteFrame_WriteError(t *testing.T) {
	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: []byte("Hello"),
	}

	// Use a writer that always returns an error.
	w := &errorWriter{err: io.ErrClosedPipe}
	err := WriteFrame(w, frame)
	if err == nil {
		t.Error("WriteFrame should have returned an error")
	}
}

func TestMaskPayload(t *testing.T) {
	tests := []struct {
		name    string
		key     [4]byte
		data    []byte
		want    []byte
	}{
		{
			name: "simple",
			key:  [4]byte{0xFF, 0x00, 0xFF, 0x00},
			data: []byte{0x48, 0x65, 0x6C, 0x6C},
			want: []byte{0x48 ^ 0xFF, 0x65, 0x6C ^ 0xFF, 0x6C},
		},
		{
			name: "empty",
			key:  [4]byte{0x01, 0x02, 0x03, 0x04},
			data: []byte{},
			want: []byte{},
		},
		{
			name: "single byte",
			key:  [4]byte{0xAB, 0x00, 0x00, 0x00},
			data: []byte{0x48},
			want: []byte{0x48 ^ 0xAB},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, len(tt.data))
			copy(data, tt.data)
			maskPayload(tt.key, data)
			if !bytes.Equal(data, tt.want) {
				t.Errorf("maskPayload = %v, want %v", data, tt.want)
			}

			// Apply again to verify it's its own inverse.
			maskPayload(tt.key, data)
			if !bytes.Equal(data, tt.data) {
				t.Errorf("double mask = %v, want %v (original)", data, tt.data)
			}
		})
	}
}

func TestIsControl(t *testing.T) {
	tests := []struct {
		opcode byte
		want   bool
	}{
		{OpcodeContinuation, false},
		{OpcodeText, false},
		{OpcodeBinary, false},
		{OpcodeClose, true},
		{OpcodePing, true},
		{OpcodePong, true},
		{0x3, false}, // reserved data frame
		{0xB, true},  // reserved control frame
	}

	for _, tt := range tests {
		f := &Frame{Opcode: tt.opcode}
		if got := f.IsControl(); got != tt.want {
			t.Errorf("IsControl(opcode=0x%x) = %v, want %v", tt.opcode, got, tt.want)
		}
	}
}

func TestOpcodeString(t *testing.T) {
	tests := []struct {
		opcode byte
		want   string
	}{
		{OpcodeContinuation, "continuation"},
		{OpcodeText, "text"},
		{OpcodeBinary, "binary"},
		{OpcodeClose, "close"},
		{OpcodePing, "ping"},
		{OpcodePong, "pong"},
		{0x3, "unknown(0x3)"},
		{0xF, "unknown(0xf)"},
	}

	for _, tt := range tests {
		got := OpcodeString(tt.opcode)
		if got != tt.want {
			t.Errorf("OpcodeString(0x%x) = %q, want %q", tt.opcode, got, tt.want)
		}
	}
}

func TestReadWriteFrame_RoundTrip(t *testing.T) {
	frames := []*Frame{
		{Fin: true, Opcode: OpcodeText, Payload: []byte("hello")},
		{Fin: true, Opcode: OpcodeBinary, Payload: []byte{0x00, 0x01, 0xFF}},
		{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03, 0xE8}}, // status 1000
		{Fin: true, Opcode: OpcodePing, Payload: []byte("ping")},
		{Fin: true, Opcode: OpcodePong, Payload: []byte("pong")},
		{Fin: false, Opcode: OpcodeText, Payload: []byte("frag1")},
		{Fin: true, Opcode: OpcodeContinuation, Payload: []byte("frag2")},
		{Fin: true, Opcode: OpcodeText, Masked: true, MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78}, Payload: []byte("masked")},
	}

	for i, orig := range frames {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, orig); err != nil {
			t.Fatalf("Frame %d WriteFrame: %v", i, err)
		}

		readBack, err := ReadFrame(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("Frame %d ReadFrame: %v", i, err)
		}

		if readBack.Fin != orig.Fin {
			t.Errorf("Frame %d: Fin = %v, want %v", i, readBack.Fin, orig.Fin)
		}
		if readBack.Opcode != orig.Opcode {
			t.Errorf("Frame %d: Opcode = %d, want %d", i, readBack.Opcode, orig.Opcode)
		}
		if !bytes.Equal(readBack.Payload, orig.Payload) {
			t.Errorf("Frame %d: Payload mismatch", i)
		}
	}
}

// buildFrame constructs raw WebSocket frame bytes for testing.
func buildFrame(t *testing.T, fin bool, opcode byte, masked bool, maskKey [4]byte, payload []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	// First byte: FIN + Opcode.
	var b0 byte
	if fin {
		b0 |= 0x80
	}
	b0 |= opcode & 0x0F
	buf.WriteByte(b0)

	// Second byte: MASK + Payload length.
	payloadLen := len(payload)
	var b1 byte
	if masked {
		b1 |= 0x80
	}

	switch {
	case payloadLen <= 125:
		b1 |= byte(payloadLen)
		buf.WriteByte(b1)
	case payloadLen <= 65535:
		b1 |= 126
		buf.WriteByte(b1)
		binary.Write(&buf, binary.BigEndian, uint16(payloadLen))
	default:
		b1 |= 127
		buf.WriteByte(b1)
		binary.Write(&buf, binary.BigEndian, uint64(payloadLen))
	}

	if masked {
		buf.Write(maskKey[:])
	}

	buf.Write(payload)

	return buf.Bytes()
}

// errorWriter is a writer that always returns an error.
type errorWriter struct {
	err error
}

func (w *errorWriter) Write(p []byte) (int, error) {
	return 0, w.err
}
