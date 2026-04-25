package envelope

import "testing"

func TestWSMessage_Protocol(t *testing.T) {
	m := &WSMessage{}
	if got := m.Protocol(); got != ProtocolWebSocket {
		t.Errorf("WSMessage.Protocol() = %q, want %q", got, ProtocolWebSocket)
	}
}

func TestWSMessage_CloneMessage_DeepCopy(t *testing.T) {
	orig := &WSMessage{
		Opcode:      WSBinary,
		Fin:         true,
		Masked:      true,
		Mask:        [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
		Payload:     []byte{0x01, 0x02, 0x03, 0x04},
		CloseCode:   1000,
		CloseReason: "normal",
		Compressed:  true,
	}

	cloned := orig.CloneMessage().(*WSMessage)

	if cloned.Opcode != orig.Opcode {
		t.Errorf("Opcode: got %d, want %d", cloned.Opcode, orig.Opcode)
	}
	if cloned.Fin != orig.Fin {
		t.Errorf("Fin: got %v, want %v", cloned.Fin, orig.Fin)
	}
	if cloned.Masked != orig.Masked {
		t.Errorf("Masked: got %v, want %v", cloned.Masked, orig.Masked)
	}
	if cloned.Mask != orig.Mask {
		t.Errorf("Mask: got %v, want %v", cloned.Mask, orig.Mask)
	}
	if string(cloned.Payload) != string(orig.Payload) {
		t.Errorf("Payload: got %v, want %v", cloned.Payload, orig.Payload)
	}
	if cloned.CloseCode != orig.CloseCode {
		t.Errorf("CloseCode: got %d, want %d", cloned.CloseCode, orig.CloseCode)
	}
	if cloned.CloseReason != orig.CloseReason {
		t.Errorf("CloseReason: got %q, want %q", cloned.CloseReason, orig.CloseReason)
	}
	if cloned.Compressed != orig.Compressed {
		t.Errorf("Compressed: got %v, want %v", cloned.Compressed, orig.Compressed)
	}

	// Payload independence
	cloned.Payload[0] = 0xFF
	if orig.Payload[0] == 0xFF {
		t.Error("Payload is not independent: mutating clone affected original")
	}

	// Mask is a value type; mutating the clone's Mask must not affect orig.
	cloned.Mask[0] = 0x00
	if orig.Mask[0] == 0x00 {
		t.Error("Mask is not independent: mutating clone affected original")
	}
}

func TestWSMessage_CloneMessage_NilPayload(t *testing.T) {
	orig := &WSMessage{Opcode: WSPing}
	cloned := orig.CloneMessage().(*WSMessage)
	if cloned.Payload != nil {
		t.Error("CloneMessage of nil Payload should produce nil, not empty slice")
	}
}

func TestWSMessage_CloneMessage_ZeroValue(t *testing.T) {
	orig := &WSMessage{}
	cloned := orig.CloneMessage().(*WSMessage)
	if cloned.Opcode != WSContinuation {
		t.Errorf("zero Opcode should equal WSContinuation (0x0), got %d", cloned.Opcode)
	}
	if cloned.Fin || cloned.Masked || cloned.Compressed {
		t.Error("zero-value bool fields should be false")
	}
	if cloned.Mask != ([4]byte{}) {
		t.Errorf("zero-value Mask should be [4]byte{}, got %v", cloned.Mask)
	}
	if cloned.Payload != nil || cloned.CloseCode != 0 || cloned.CloseReason != "" {
		t.Error("zero-value scalar fields should stay zero")
	}
}

func TestWSOpcode_Constants(t *testing.T) {
	// RFC 6455 §11.8 opcode registry anchor points.
	tests := []struct {
		opcode WSOpcode
		want   uint8
	}{
		{WSContinuation, 0x0},
		{WSText, 0x1},
		{WSBinary, 0x2},
		{WSClose, 0x8},
		{WSPing, 0x9},
		{WSPong, 0xA},
	}
	for _, tt := range tests {
		if uint8(tt.opcode) != tt.want {
			t.Errorf("WSOpcode constant %v = 0x%X, want 0x%X",
				tt.opcode, uint8(tt.opcode), tt.want)
		}
	}
}
