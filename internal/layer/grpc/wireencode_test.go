package grpc_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
)

func TestEncodeWireBytes_NilEnvelope(t *testing.T) {
	t.Parallel()
	out, err := grpc.EncodeWireBytes(nil)
	if err == nil {
		t.Fatalf("expected error for nil envelope, got nil (out=%v)", out)
	}
	if !strings.Contains(err.Error(), "nil envelope") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeWireBytes_NilMessage(t *testing.T) {
	t.Parallel()
	out, err := grpc.EncodeWireBytes(&envelope.Envelope{})
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
	out, err := grpc.EncodeWireBytes(env)
	if err == nil {
		t.Fatalf("expected error for wrong Message type, got nil (out=%v)", out)
	}
	if !strings.Contains(err.Error(), "requires *GRPC{Start,Data,End}Message") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeWireBytes_StartReturnsNil(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.GRPCStartMessage{
		Service: "echo.Echo", Method: "Unary",
	}}
	out, err := grpc.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil bytes for Start (HEADERS owned by HTTP/2 layer), got %d bytes", len(out))
	}
}

func TestEncodeWireBytes_EndReturnsNil(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.GRPCEndMessage{Status: 0}}
	out, err := grpc.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil bytes for End (trailer-HEADERS owned by HTTP/2 layer), got %d bytes", len(out))
	}
}

func TestEncodeWireBytes_UncompressedDataRoundTrip(t *testing.T) {
	t.Parallel()
	payload := []byte("hello, gRPC")
	env := &envelope.Envelope{Message: &envelope.GRPCDataMessage{
		Compressed: false,
		WireLength: uint32(len(payload)),
		Payload:    payload,
	}}
	out, err := grpc.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := make([]byte, 5+len(payload))
	// expected[0] = 0 (compressed-flag) — already zero
	binary.BigEndian.PutUint32(expected[1:5], uint32(len(payload)))
	copy(expected[5:], payload)
	if !bytes.Equal(out, expected) {
		t.Fatalf("LPM bytes mismatch:\n got %x\nwant %x", out, expected)
	}
}

func TestEncodeWireBytes_CompressedFailsSoft(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.GRPCDataMessage{
		Compressed: true,
		WireLength: 5,
		Payload:    []byte("hello"),
	}}
	out, err := grpc.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil for Compressed=true fail-soft, got %d bytes", len(out))
	}
}

func TestEncodeWireBytes_PureEndMarker(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.GRPCDataMessage{
		Compressed: false,
		WireLength: 0,
		Payload:    nil,
		EndStream:  true,
	}}
	out, err := grpc.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == nil {
		t.Fatalf("expected non-nil empty slice for pure end-marker, got nil")
	}
	if len(out) != 0 {
		t.Fatalf("expected zero-length bytes for pure end-marker, got %d bytes (%x)", len(out), out)
	}
}

func TestEncodeWireBytes_EndStreamOnNonEmptyPayload(t *testing.T) {
	t.Parallel()
	// EndStream=true on a real LPM: must still emit the LPM bytes (END_STREAM
	// lives in the H2 frame header, not in the LPM). The encoder should not
	// confuse this with the pure end-marker shape.
	payload := []byte("last")
	env := &envelope.Envelope{Message: &envelope.GRPCDataMessage{
		Compressed: false,
		WireLength: uint32(len(payload)),
		Payload:    payload,
		EndStream:  true,
	}}
	out, err := grpc.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(expected[1:5], uint32(len(payload)))
	copy(expected[5:], payload)
	if !bytes.Equal(out, expected) {
		t.Fatalf("LPM bytes mismatch:\n got %x\nwant %x", out, expected)
	}
}

func TestEncodeWireBytes_EmptyPayloadNonEnd(t *testing.T) {
	t.Parallel()
	// 0-byte payload with EndStream=false: emit a 5-byte LPM prefix only.
	env := &envelope.Envelope{Message: &envelope.GRPCDataMessage{
		Compressed: false,
		WireLength: 0,
		Payload:    []byte{},
		EndStream:  false,
	}}
	out, err := grpc.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0, 0, 0, 0, 0}
	if !bytes.Equal(out, expected) {
		t.Fatalf("expected 5-byte zero LPM prefix, got %x", out)
	}
}
