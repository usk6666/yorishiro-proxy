package ws_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

func TestEncodeWireBytes_NilEnvelope(t *testing.T) {
	t.Parallel()
	out, err := ws.EncodeWireBytes(nil)
	if err == nil {
		t.Fatalf("expected error for nil envelope, got nil (out=%v)", out)
	}
	if !strings.Contains(err.Error(), "nil envelope") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeWireBytes_NilMessage(t *testing.T) {
	t.Parallel()
	out, err := ws.EncodeWireBytes(&envelope.Envelope{})
	if err == nil {
		t.Fatalf("expected error for nil Message, got nil (out=%v)", out)
	}
	if !strings.Contains(err.Error(), "nil Message") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeWireBytes_WrongMessageType(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.RawMessage{Bytes: []byte("hi")}}
	out, err := ws.EncodeWireBytes(env)
	if err == nil {
		t.Fatalf("expected error for wrong Message type, got nil (out=%v)", out)
	}
	if !strings.Contains(err.Error(), "requires *WSMessage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeWireBytes_TextFrameRoundTrip(t *testing.T) {
	t.Parallel()
	payload := []byte("hello, world")
	env := &envelope.Envelope{Message: &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Fin:     true,
		Payload: payload,
	}}
	out, err := ws.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := ws.ReadFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("ReadFrame round-trip failed: %v", err)
	}
	if got.Opcode != ws.OpcodeText {
		t.Fatalf("opcode mismatch: got %d, want %d", got.Opcode, ws.OpcodeText)
	}
	if !got.Fin {
		t.Fatalf("expected FIN=true")
	}
	if got.Masked {
		t.Fatalf("expected unmasked")
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload mismatch:\n got %q\nwant %q", got.Payload, payload)
	}
}

func TestEncodeWireBytes_BinaryFrameRoundTrip(t *testing.T) {
	t.Parallel()
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}
	env := &envelope.Envelope{Message: &envelope.WSMessage{
		Opcode:  envelope.WSBinary,
		Fin:     true,
		Payload: payload,
	}}
	out, err := ws.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := ws.ReadFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("ReadFrame round-trip failed: %v", err)
	}
	if got.Opcode != ws.OpcodeBinary {
		t.Fatalf("opcode mismatch: got %d, want %d", got.Opcode, ws.OpcodeBinary)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload mismatch:\n got %x\nwant %x", got.Payload, payload)
	}
}

func TestEncodeWireBytes_MaskedClientFrameRoundTrip(t *testing.T) {
	t.Parallel()
	payload := []byte("client→server frame")
	mask := [4]byte{0x01, 0x02, 0x03, 0x04}
	env := &envelope.Envelope{Message: &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Fin:     true,
		Masked:  true,
		Mask:    mask,
		Payload: payload,
	}}
	out, err := ws.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := ws.ReadFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("ReadFrame round-trip failed: %v", err)
	}
	if !got.Masked {
		t.Fatalf("expected Masked=true after round-trip")
	}
	if got.MaskKey != mask {
		t.Fatalf("mask key mismatch: got %x, want %x", got.MaskKey, mask)
	}
	// ReadFrame auto-unmasks; the recovered payload must match the original.
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("payload mismatch after unmask:\n got %q\nwant %q", got.Payload, payload)
	}
}

func TestEncodeWireBytes_CloseFrameWithStructuredFields(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.WSMessage{
		Opcode:      envelope.WSClose,
		Fin:         true,
		CloseCode:   1000,
		CloseReason: "normal closure",
	}}
	out, err := ws.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := ws.ReadFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("ReadFrame round-trip failed: %v", err)
	}
	if got.Opcode != ws.OpcodeClose {
		t.Fatalf("opcode mismatch: got %d, want %d", got.Opcode, ws.OpcodeClose)
	}
	if len(got.Payload) < 2 {
		t.Fatalf("expected at least 2-byte close payload, got %d", len(got.Payload))
	}
	gotCode := uint16(got.Payload[0])<<8 | uint16(got.Payload[1])
	if gotCode != 1000 {
		t.Fatalf("close code mismatch: got %d, want 1000", gotCode)
	}
	gotReason := string(got.Payload[2:])
	if gotReason != "normal closure" {
		t.Fatalf("close reason mismatch: got %q, want %q", gotReason, "normal closure")
	}
}

func TestEncodeWireBytes_CloseFrameWithVerbatimPayload(t *testing.T) {
	t.Parallel()
	// CloseCode=0 + CloseReason="" → fall back to Payload verbatim.
	verbatim := []byte{0x03, 0xE9, 'b', 'y', 'e'} // 1001 + "bye"
	env := &envelope.Envelope{Message: &envelope.WSMessage{
		Opcode:  envelope.WSClose,
		Fin:     true,
		Payload: verbatim,
	}}
	out, err := ws.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := ws.ReadFrame(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("ReadFrame round-trip failed: %v", err)
	}
	if !bytes.Equal(got.Payload, verbatim) {
		t.Fatalf("payload mismatch: got %x, want %x", got.Payload, verbatim)
	}
}

func TestEncodeWireBytes_CompressedFailsSoft(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.WSMessage{
		Opcode:     envelope.WSText,
		Fin:        true,
		Compressed: true,
		Payload:    []byte("would-be-compressed"),
	}}
	out, err := ws.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil for Compressed=true fail-soft, got %d bytes", len(out))
	}
}

func TestEncodeWireBytes_PingPongRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		opcode envelope.WSOpcode
		want   byte
	}{
		{"ping", envelope.WSPing, ws.OpcodePing},
		{"pong", envelope.WSPong, ws.OpcodePong},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := &envelope.Envelope{Message: &envelope.WSMessage{
				Opcode:  tc.opcode,
				Fin:     true,
				Payload: []byte("ping data"),
			}}
			out, err := ws.EncodeWireBytes(env)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, err := ws.ReadFrame(bytes.NewReader(out))
			if err != nil {
				t.Fatalf("ReadFrame round-trip failed: %v", err)
			}
			if got.Opcode != tc.want {
				t.Fatalf("opcode mismatch: got %d, want %d", got.Opcode, tc.want)
			}
		})
	}
}
