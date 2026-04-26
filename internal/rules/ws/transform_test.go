package ws

import (
	"bytes"
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestTransformEngine_ReplacePayload_Regex(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformReplacePayload, `secret\d+`, "[REDACTED]",
		0, false, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte(`{"k":"secret123"}`)}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)

	if !e.Transform(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if string(msg.Payload) != `{"k":"[REDACTED]"}` {
		t.Errorf("Payload = %q", string(msg.Payload))
	}
}

func TestTransformEngine_ReplacePayload_NoChange_ReturnsFalse(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformReplacePayload, `nothing-here`, "X",
		0, false, 0, "")
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte(`hello`)}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if e.Transform(context.Background(), env, msg) {
		t.Error("expected no modification when regex does not match")
	}
	if string(msg.Payload) != "hello" {
		t.Errorf("Payload mutated despite no match: %q", string(msg.Payload))
	}
}

// TestTransformEngine_ReplacePayload_OnCloseFrame_StompsCloseCode verifies
// the documented raw-edit semantic: ReplacePayload on a Close frame
// mutates the Payload bytes verbatim (which include the encoded close
// code) without touching the structured CloseCode/CloseReason fields.
func TestTransformEngine_ReplacePayload_OnCloseFrame_StompsCloseCode(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformReplacePayload, `bye`, "hi!",
		0, false, 0, "")
	e.SetRules([]TransformRule{*rule})

	// Synthetic Close frame: Payload bytes include the encoded close code
	// + reason "bye". The structured fields are also populated for
	// realism — the test asserts that ReplacePayload only touches Payload.
	msg := &envelope.WSMessage{
		Opcode:      envelope.WSClose,
		Fin:         true,
		Payload:     []byte{0x03, 0xE8, 'b', 'y', 'e'}, // 1000 + "bye"
		CloseCode:   1000,
		CloseReason: "bye",
	}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if !e.Transform(context.Background(), env, msg) {
		t.Fatal("expected ReplacePayload to mutate")
	}
	if !bytes.Equal(msg.Payload, []byte{0x03, 0xE8, 'h', 'i', '!'}) {
		t.Errorf("Payload = %v, want raw replacement", msg.Payload)
	}
	if msg.CloseCode != 1000 || msg.CloseReason != "bye" {
		t.Errorf("ReplacePayload should not touch structured fields; got CloseCode=%d Reason=%q",
			msg.CloseCode, msg.CloseReason)
	}
}

// TestTransformEngine_ReplacePayload_PreservesCompressedFlag verifies the
// engine never flips the Compressed RSV1 bit. WSLayer.Send re-compresses
// when Compressed is true.
func TestTransformEngine_ReplacePayload_PreservesCompressedFlag(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformReplacePayload, `foo`, "bar",
		0, false, 0, "")
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("foo"), Compressed: true}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	e.Transform(context.Background(), env, msg)
	if !msg.Compressed {
		t.Error("Compressed flag was flipped by ReplacePayload")
	}
}

func TestTransformEngine_SetOpcode_Arbitrary(t *testing.T) {
	e := NewTransformEngine()
	// SetOpcode performs NO semantic validation — arbitrary bytes allowed.
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformSetOpcode, "", "",
		envelope.WSOpcode(0xF), false, 0, "") // reserved opcode
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("x")}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if !e.Transform(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if msg.Opcode != envelope.WSOpcode(0xF) {
		t.Errorf("Opcode = 0x%X, want 0xF", uint8(msg.Opcode))
	}
}

func TestTransformEngine_SetFin_Arbitrary(t *testing.T) {
	e := NewTransformEngine()
	// Fin=true on a frame originally Fin=false (no validation, attacker knob).
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformSetFin, "", "",
		0, true, 0, "")
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSContinuation, Fin: false, Payload: []byte("x")}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if !e.Transform(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if !msg.Fin {
		t.Error("Fin not set to true")
	}
}

// TestTransformEngine_SetClose_FlipsOpcode verifies that SetClose forces
// Opcode=WSClose when applied to a non-Close frame.
func TestTransformEngine_SetClose_FlipsOpcode(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformSetClose, "", "",
		0, false, 1011, "internal error")
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hi")}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if !e.Transform(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if msg.Opcode != envelope.WSClose {
		t.Errorf("Opcode = 0x%X, want WSClose", uint8(msg.Opcode))
	}
	if msg.CloseCode != 1011 {
		t.Errorf("CloseCode = %d, want 1011", msg.CloseCode)
	}
	if msg.CloseReason != "internal error" {
		t.Errorf("CloseReason = %q", msg.CloseReason)
	}
}

// TestTransformEngine_SetClose_OnCloseFrame_PreservesOpcode verifies
// SetClose on an already-Close frame does not double-flip the opcode and
// only updates CloseCode/CloseReason.
func TestTransformEngine_SetClose_OnCloseFrame_PreservesOpcode(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformSetClose, "", "",
		0, false, 1001, "going away")
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSClose, CloseCode: 1000, CloseReason: "normal"}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if !e.Transform(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if msg.Opcode != envelope.WSClose {
		t.Error("Opcode was changed unexpectedly")
	}
	if msg.CloseCode != 1001 || msg.CloseReason != "going away" {
		t.Errorf("CloseCode/Reason not updated: %d/%q", msg.CloseCode, msg.CloseReason)
	}
}

func TestTransformEngine_PriorityOrder(t *testing.T) {
	e := NewTransformEngine()
	r1, _ := CompileTransformRule("r1", 10, DirectionBoth, "", "", nil,
		TransformReplacePayload, `^.*$`, "second",
		0, false, 0, "")
	r2, _ := CompileTransformRule("r2", 1, DirectionBoth, "", "", nil,
		TransformReplacePayload, `^.*$`, "first",
		0, false, 0, "")
	e.SetRules([]TransformRule{*r1, *r2})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("orig")}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	e.Transform(context.Background(), env, msg)
	// r2 (priority 1) runs first → "first"; r1 (priority 10) runs second
	// over "first" and replaces it with "second".
	if string(msg.Payload) != "second" {
		t.Errorf("Payload = %q, want second (last priority wins)", string(msg.Payload))
	}
}

func TestTransformEngine_DirectionFilter(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionReceive, "", "", nil,
		TransformReplacePayload, `.+`, "X",
		0, false, 0, "")
	e.SetRules([]TransformRule{*rule})

	// Send frame: receive-only rule must not apply.
	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hello")}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if e.Transform(context.Background(), env, msg) {
		t.Error("Receive rule should not apply to Send frame")
	}
	if string(msg.Payload) != "hello" {
		t.Errorf("Payload mutated: %q", msg.Payload)
	}
}

func TestTransformEngine_OpcodeFilter(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "",
		[]envelope.WSOpcode{envelope.WSText},
		TransformReplacePayload, `.+`, "X",
		0, false, 0, "")
	e.SetRules([]TransformRule{*rule})

	// Binary frame should not be touched.
	bin := &envelope.WSMessage{Opcode: envelope.WSBinary, Payload: []byte("abcd")}
	env := testWSEnv(envelope.Send, "example.com", "/ws", bin)
	if e.Transform(context.Background(), env, bin) {
		t.Error("Text-only rule applied to Binary frame")
	}
	if string(bin.Payload) != "abcd" {
		t.Errorf("Binary payload mutated: %q", bin.Payload)
	}

	// Text frame should be transformed.
	tf := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("abcd")}
	env2 := testWSEnv(envelope.Send, "example.com", "/ws", tf)
	if !e.Transform(context.Background(), env2, tf) {
		t.Error("Text frame should have been transformed")
	}
}

func TestTransformEngine_HostCondition(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, `^target\.com$`, "", nil,
		TransformReplacePayload, `.+`, "X",
		0, false, 0, "")
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hi")}
	env := testWSEnv(envelope.Send, "other.com", "/ws", msg)
	if e.Transform(context.Background(), env, msg) {
		t.Error("should not match different host")
	}
	env2 := testWSEnv(envelope.Send, "target.com", "/ws", msg)
	if !e.Transform(context.Background(), env2, msg) {
		t.Error("should match target host")
	}
}

func TestTransformEngine_DisabledRule(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "", nil,
		TransformReplacePayload, `.+`, "X",
		0, false, 0, "")
	rule.Enabled = false
	e.SetRules([]TransformRule{*rule})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hi")}
	env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
	if e.Transform(context.Background(), env, msg) {
		t.Error("disabled rule applied")
	}
}
