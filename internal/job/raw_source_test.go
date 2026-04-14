package job

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- Test helpers ---

func makeRawSendFlow(rawBytes, body []byte) *flow.Flow {
	return &flow.Flow{
		ID:        "flow-1",
		StreamID:  "stream-1",
		Direction: "send",
		RawBytes:  rawBytes,
		Body:      body,
	}
}

// --- RawResendSource tests ---

func TestRawResendSource_BasicResend(t *testing.T) {
	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	sendFlow := makeRawSendFlow(rawBytes, nil)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if env.Direction != envelope.Send {
		t.Errorf("Direction: got %v, want Send", env.Direction)
	}
	if env.Protocol != envelope.ProtocolRaw {
		t.Errorf("Protocol: got %v, want %v", env.Protocol, envelope.ProtocolRaw)
	}
	if env.FlowID == "" {
		t.Error("FlowID should be generated")
	}

	msg, ok := env.Message.(*envelope.RawMessage)
	if !ok {
		t.Fatalf("Message type: got %T, want *RawMessage", env.Message)
	}
	if !bytes.Equal(msg.Bytes, rawBytes) {
		t.Errorf("Bytes: got %q, want %q", msg.Bytes, rawBytes)
	}
	if !bytes.Equal(env.Raw, rawBytes) {
		t.Errorf("Raw: got %q, want %q", env.Raw, rawBytes)
	}
}

func TestRawResendSource_FallbackToBody(t *testing.T) {
	body := []byte("body content")
	sendFlow := makeRawSendFlow(nil, body)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	if !bytes.Equal(msg.Bytes, body) {
		t.Errorf("Bytes: got %q, want %q (fallback to Body)", msg.Bytes, body)
	}
}

func TestRawResendSource_FullOverride(t *testing.T) {
	rawBytes := []byte("original data")
	override := []byte("completely new payload")
	sendFlow := makeRawSendFlow(rawBytes, nil)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{
		OverrideBytes: override,
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	if !bytes.Equal(msg.Bytes, override) {
		t.Errorf("Bytes: got %q, want %q", msg.Bytes, override)
	}
}

func TestRawResendSource_BytePatches(t *testing.T) {
	// Original: "GET / HTTP/1.1\r\n" — patch the method to "POST"
	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	sendFlow := makeRawSendFlow(rawBytes, nil)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{
		Patches: []BytePatch{
			// "GET " (4 bytes at offset 0) → "POST" (4 bytes): overwrites "GET " with "POST"
			{Offset: 0, Data: []byte("POST")},
		},
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	// "GET / HTTP/1.1..." → "POST/ HTTP/1.1..." (offset 0, 4 bytes replaced)
	expected := []byte("POST/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if !bytes.Equal(msg.Bytes, expected) {
		t.Errorf("Bytes: got %q, want %q", msg.Bytes, expected)
	}
}

func TestRawResendSource_SmugglingPayload(t *testing.T) {
	// Dual Content-Length — must be preserved byte-for-byte.
	payload := []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nContent-Length: 11\r\n\r\ntest")
	sendFlow := makeRawSendFlow(payload, nil)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	if !bytes.Equal(msg.Bytes, payload) {
		t.Errorf("smuggling payload not preserved: got %q, want %q", msg.Bytes, payload)
	}
}

func TestRawResendSource_OverrideTakesPrecedenceOverPatches(t *testing.T) {
	rawBytes := []byte("original")
	sendFlow := makeRawSendFlow(rawBytes, nil)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	override := []byte("override wins")
	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{
		OverrideBytes: override,
		Patches:       []BytePatch{{Offset: 0, Data: []byte("patch")}},
	})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	if !bytes.Equal(msg.Bytes, override) {
		t.Errorf("OverrideBytes should take precedence: got %q, want %q", msg.Bytes, override)
	}
}

func TestRawResendSource_SecondCallReturnsEOF(t *testing.T) {
	sendFlow := makeRawSendFlow([]byte("data"), nil)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{})

	_, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}

	_, err = src.Next(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Errorf("second call: got %v, want io.EOF", err)
	}
}

func TestRawResendSource_NoSendFlow(t *testing.T) {
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {
				{ID: "f1", StreamID: "stream-1", Direction: "receive"},
			},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{})
	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("expected error for missing send flow")
	}
}

func TestRawResendSource_ReaderError(t *testing.T) {
	reader := &mockFlowReader{
		err: errors.New("db error"),
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{})
	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("expected error from reader")
	}
}

func TestRawResendSource_DoesNotMutateFlowData(t *testing.T) {
	rawBytes := []byte("ABCDEF")
	original := make([]byte, len(rawBytes))
	copy(original, rawBytes)

	sendFlow := makeRawSendFlow(rawBytes, nil)
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {sendFlow},
		},
	}

	src := NewRawResendSource(reader, "stream-1", RawResendOverrides{})
	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the returned envelope's bytes — should not affect flow data.
	msg := env.Message.(*envelope.RawMessage)
	msg.Bytes[0] = 'X'

	if !bytes.Equal(rawBytes, original) {
		t.Errorf("flow data was mutated: got %q, want %q", rawBytes, original)
	}
}
