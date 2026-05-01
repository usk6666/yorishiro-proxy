package ws

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestNewResendWireEncoder_NonCompressed_DelegatesToEncodeWireBytes
// asserts that a non-compressed envelope produces the same bytes the
// standard EncodeWireBytes would produce — the resend encoder must be a
// transparent superset for the common case.
func TestNewResendWireEncoder_NonCompressed_DelegatesToEncodeWireBytes(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Fin:     true,
			Payload: []byte("hello"),
		},
	}
	enc := NewResendWireEncoder("")

	got, err := enc(env)
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}
	want, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("non-compressed bytes differ from EncodeWireBytes\n got=%x\nwant=%x", got, want)
	}
}

// TestNewResendWireEncoder_Compressed_RoundTripsThroughFlate verifies
// that a compressed envelope produces a frame whose RSV1=1 and whose
// payload, when prepended with the RFC 7692 trailer, decompresses back
// to the original payload bytes.
func TestNewResendWireEncoder_Compressed_RoundTripsThroughFlate(t *testing.T) {
	t.Parallel()
	original := []byte("hello hello hello hello hello hello") // repetitive → compressible
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:     envelope.WSText,
			Fin:        true,
			Payload:    original,
			Compressed: true,
		},
	}
	enc := NewResendWireEncoder("permessage-deflate")
	wire, err := enc(env)
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	// Parse the produced wire bytes: the first byte must have FIN=1 and
	// RSV1=1.
	if len(wire) < 2 {
		t.Fatalf("wire too short: %x", wire)
	}
	if wire[0]&0x80 == 0 {
		t.Errorf("FIN bit not set: byte0=0x%02x", wire[0])
	}
	if wire[0]&0x40 == 0 {
		t.Errorf("RSV1 bit not set: byte0=0x%02x", wire[0])
	}

	// Round-trip through flate to confirm the payload is real
	// permessage-deflate output.
	frame, err := ReadFrame(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	withTrailer := append(append([]byte{}, frame.Payload...), 0x00, 0x00, 0xff, 0xff)
	r := flate.NewReader(bytes.NewReader(withTrailer))
	defer r.Close()
	decoded, err := io.ReadAll(r)
	if err != nil && err != io.ErrUnexpectedEOF {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("round-trip mismatch\n got=%q\nwant=%q", decoded, original)
	}
}

// TestNewResendWireEncoder_CompressedWithoutNegotiation_Errors confirms
// the encoder fails fast when Compressed=true but the supplied
// extension header didn't enable client deflate.
func TestNewResendWireEncoder_CompressedWithoutNegotiation_Errors(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:     envelope.WSText,
			Fin:        true,
			Payload:    []byte("x"),
			Compressed: true,
		},
	}
	enc := NewResendWireEncoder("")
	if _, err := enc(env); err == nil {
		t.Fatal("expected error for compressed without negotiation, got nil")
	}
}
