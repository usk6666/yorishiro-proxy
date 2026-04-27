package grpcweb

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestEncodeWireBytes_NilEnvelope: nil envelope is a programmer error.
func TestEncodeWireBytes_NilEnvelope(t *testing.T) {
	if _, err := EncodeWireBytes(nil); err == nil {
		t.Error("expected error for nil envelope")
	}
}

// TestEncodeWireBytes_NilMessage: nil Message is a programmer error.
func TestEncodeWireBytes_NilMessage(t *testing.T) {
	env := &envelope.Envelope{Protocol: envelope.ProtocolGRPCWeb}
	if _, err := EncodeWireBytes(env); err == nil {
		t.Error("expected error for nil Message")
	}
}

// TestEncodeWireBytes_WrongMessageType: HTTP / Raw / WS messages are not
// gRPC-Web payloads.
func TestEncodeWireBytes_WrongMessageType(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message:  &envelope.RawMessage{Bytes: []byte("nope")},
	}
	if _, err := EncodeWireBytes(env); err == nil {
		t.Error("expected error for non-gRPC Message type")
	}
}

// TestEncodeWireBytes_GRPCStart_ReturnsNil: HTTP headers are owned by the
// inner Layer; the grpc-web encoder cannot re-render Start in isolation.
func TestEncodeWireBytes_GRPCStart_ReturnsNil(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCStartMessage{
			Service:     "pkg.Echo",
			Method:      "Say",
			ContentType: "application/grpc-web+proto",
		},
		Opaque: &opaqueGRPCWeb{wireBase64: false, encoding: ""},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if out != nil {
		t.Errorf("got %d bytes, want nil (Start cannot be re-rendered)", len(out))
	}
}

// TestEncodeWireBytes_GRPCData_BinaryRoundTrip: a binary-wire data frame
// re-encodes to a single 5-byte-prefixed LPM with the message payload.
func TestEncodeWireBytes_GRPCData_BinaryRoundTrip(t *testing.T) {
	payload := []byte("hello-binary")
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCDataMessage{
			Compressed: false,
			WireLength: uint32(len(payload)),
			Payload:    payload,
		},
		Opaque: &opaqueGRPCWeb{wireBase64: false, encoding: ""},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	want := EncodeFrame(false, false, payload)
	if !bytes.Equal(out, want) {
		t.Errorf("binary frame mismatch:\n got %x\nwant %x", out, want)
	}
}

// TestEncodeWireBytes_GRPCData_Base64RoundTrip: a base64-wire data frame
// re-encodes to a single base64-wrapped LPM frame. Base64-decoding once
// must yield a valid binary LPM (not a doubly-encoded payload).
func TestEncodeWireBytes_GRPCData_Base64RoundTrip(t *testing.T) {
	payload := []byte("hello-base64")
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCDataMessage{
			Compressed: false,
			WireLength: uint32(len(payload)),
			Payload:    payload,
		},
		Opaque: &opaqueGRPCWeb{wireBase64: true, encoding: ""},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	decoded, err := decodeBase64(out)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	want := EncodeFrame(false, false, payload)
	if !bytes.Equal(decoded, want) {
		t.Errorf("base64-decoded frame mismatch:\n got %x\nwant %x", decoded, want)
	}
}

// TestEncodeWireBytes_GRPCData_GzipCompressed: when the modified message
// is marked Compressed, EncodeWireBytes re-compresses the payload using
// the negotiated grpc-encoding before LPM-framing.
func TestEncodeWireBytes_GRPCData_GzipCompressed(t *testing.T) {
	payload := []byte(strings.Repeat("compress-me-", 64))
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCDataMessage{
			Compressed: true,
			WireLength: uint32(len(payload)),
			Payload:    payload,
		},
		Opaque: &opaqueGRPCWeb{wireBase64: false, encoding: "gzip"},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if len(out) < frameHeaderSize {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	flags := out[0]
	if flags&compressedFlagBit == 0 {
		t.Errorf("compressed flag bit not set on frame; flags=0x%02x", flags)
	}
	zr, err := gzip.NewReader(bytes.NewReader(out[frameHeaderSize:]))
	if err != nil {
		t.Fatalf("gzip new reader: %v", err)
	}
	defer zr.Close()
	decompressed, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Errorf("decompressed payload mismatch:\n got %q\nwant %q", decompressed, payload)
	}
}

// TestEncodeWireBytes_GRPCEnd_BinaryTrailers: an End message with
// status/message/trailers re-encodes to a trailer LPM frame (flags MSB).
func TestEncodeWireBytes_GRPCEnd_BinaryTrailers(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCEndMessage{
			Status:  0,
			Message: "OK",
			Trailers: []envelope.KeyValue{
				{Name: "x-custom", Value: "v1"},
			},
		},
		Opaque: &opaqueGRPCWeb{wireBase64: false, encoding: ""},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if len(out) < frameHeaderSize {
		t.Fatalf("output too short: %d bytes", len(out))
	}
	if out[0]&trailerFlagBit == 0 {
		t.Errorf("trailer flag bit not set; flags=0x%02x", out[0])
	}
	if !bytes.Contains(out[frameHeaderSize:], []byte("grpc-status: 0")) {
		t.Errorf("trailer payload missing grpc-status: %q", out[frameHeaderSize:])
	}
	if !bytes.Contains(out[frameHeaderSize:], []byte("x-custom: v1")) {
		t.Errorf("trailer payload missing x-custom: %q", out[frameHeaderSize:])
	}
}

// TestEncodeWireBytes_GRPCEnd_Base64Trailers: base64 wire wraps the entire
// trailer LPM frame once.
func TestEncodeWireBytes_GRPCEnd_Base64Trailers(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCEndMessage{
			Status: 0,
		},
		Opaque: &opaqueGRPCWeb{wireBase64: true, encoding: ""},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	decoded, err := decodeBase64(out)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if len(decoded) < frameHeaderSize {
		t.Fatalf("decoded too short: %d bytes", len(decoded))
	}
	if decoded[0]&trailerFlagBit == 0 {
		t.Errorf("trailer flag bit not set after decode; flags=0x%02x", decoded[0])
	}
}

// TestEncodeWireBytes_OpaqueMissing_GRPCDataFailSoft: when Opaque is nil
// (Resend path) on a GRPCDataMessage, the encoder returns (nil, nil) so
// RecordStep tags wire_bytes="unavailable" rather than crashing.
func TestEncodeWireBytes_OpaqueMissing_GRPCDataFailSoft(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCDataMessage{
			Payload: []byte("orphan"),
		},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if out != nil {
		t.Errorf("got %d bytes, want nil for fail-soft path", len(out))
	}
}

// TestEncodeWireBytes_OpaqueMissing_GRPCEndFailSoft: same fail-soft for End.
func TestEncodeWireBytes_OpaqueMissing_GRPCEndFailSoft(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message:  &envelope.GRPCEndMessage{Status: 0},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if out != nil {
		t.Errorf("got %d bytes, want nil for fail-soft path", len(out))
	}
}
