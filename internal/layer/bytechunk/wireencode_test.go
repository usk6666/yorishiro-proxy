package bytechunk

import (
	"bytes"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestEncodeWireBytes_RawMessage(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolRaw,
		Raw:      []byte("ingress"),
		Message:  &envelope.RawMessage{Bytes: []byte("mutated")},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.Equal(out, []byte("mutated")) {
		t.Errorf("got %q, want mutated (must use Message.Bytes not env.Raw)", out)
	}
}

func TestEncodeWireBytes_NilMessageFallsBackToRaw(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolRaw,
		Raw:      []byte("raw-fallback"),
		Message:  nil,
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if !bytes.Equal(out, []byte("raw-fallback")) {
		t.Errorf("got %q, want raw-fallback", out)
	}
}

func TestEncodeWireBytes_NilEnvelope(t *testing.T) {
	if _, err := EncodeWireBytes(nil); err == nil {
		t.Error("expected error for nil envelope")
	}
}

func TestEncodeWireBytes_WrongMessageType(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolRaw,
		Message:  &envelope.HTTPMessage{Method: "GET"},
	}
	if _, err := EncodeWireBytes(env); err == nil {
		t.Error("expected error for non-RawMessage")
	}
}
