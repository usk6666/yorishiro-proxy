package job

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestWSResendSource_NextYieldsThenEOF(t *testing.T) {
	t.Parallel()

	src := NewWSResendSource("stream-1", "conn-1", "/chat", "v=2", WSResendOverrides{
		Opcode:  envelope.WSText,
		Fin:     true,
		Payload: []byte("hello"),
	})

	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if env == nil {
		t.Fatal("first Next: nil envelope")
	}
	if env.StreamID != "stream-1" {
		t.Errorf("StreamID = %q, want stream-1", env.StreamID)
	}
	if env.FlowID == "" {
		t.Error("FlowID empty (expected uuid)")
	}
	if env.Direction != envelope.Send {
		t.Errorf("Direction = %v, want Send", env.Direction)
	}
	if env.Protocol != envelope.ProtocolWebSocket {
		t.Errorf("Protocol = %v, want ProtocolWebSocket", env.Protocol)
	}
	if env.Context.ConnID != "conn-1" {
		t.Errorf("ConnID = %q, want conn-1", env.Context.ConnID)
	}
	if env.Context.UpgradePath != "/chat" {
		t.Errorf("UpgradePath = %q, want /chat", env.Context.UpgradePath)
	}
	if env.Context.UpgradeQuery != "v=2" {
		t.Errorf("UpgradeQuery = %q, want v=2", env.Context.UpgradeQuery)
	}
	msg, ok := env.Message.(*envelope.WSMessage)
	if !ok {
		t.Fatalf("Message = %T, want *WSMessage", env.Message)
	}
	if msg.Opcode != envelope.WSText {
		t.Errorf("Opcode = %v, want WSText", msg.Opcode)
	}
	if string(msg.Payload) != "hello" {
		t.Errorf("Payload = %q, want hello", msg.Payload)
	}

	if _, err := src.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("second Next: err = %v, want io.EOF", err)
	}
}

func TestWSResendSource_RawBytesSeedsEnvelopeRaw(t *testing.T) {
	t.Parallel()

	rawBytes := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	src := NewWSResendSource("s-2", "c-2", "", "", WSResendOverrides{
		Opcode:   envelope.WSText,
		Fin:      true,
		Payload:  []byte("hello"),
		RawBytes: rawBytes,
	})

	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(env.Raw) != string(rawBytes) {
		t.Errorf("Raw = %x, want %x", env.Raw, rawBytes)
	}
}
