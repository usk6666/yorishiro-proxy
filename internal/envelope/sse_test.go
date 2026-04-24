package envelope

import (
	"testing"
	"time"
)

func TestSSEMessage_Protocol(t *testing.T) {
	m := &SSEMessage{}
	if got := m.Protocol(); got != ProtocolSSE {
		t.Errorf("SSEMessage.Protocol() = %q, want %q", got, ProtocolSSE)
	}
}

func TestSSEMessage_CloneMessage_DeepCopy(t *testing.T) {
	orig := &SSEMessage{
		Event: "update",
		Data:  "line1\nline2",
		ID:    "42",
		Retry: 3 * time.Second,
	}

	cloned := orig.CloneMessage().(*SSEMessage)

	if cloned.Event != orig.Event {
		t.Errorf("Event: got %q, want %q", cloned.Event, orig.Event)
	}
	if cloned.Data != orig.Data {
		t.Errorf("Data: got %q, want %q", cloned.Data, orig.Data)
	}
	if cloned.ID != orig.ID {
		t.Errorf("ID: got %q, want %q", cloned.ID, orig.ID)
	}
	if cloned.Retry != orig.Retry {
		t.Errorf("Retry: got %v, want %v", cloned.Retry, orig.Retry)
	}

	// Mutating the clone's string fields must not affect the original
	// (strings are immutable in Go, so this is structurally guaranteed —
	// assert via equality after a clone-side reassignment).
	cloned.Event = "MUTATED"
	if orig.Event == "MUTATED" {
		t.Error("Event is not independent: clone reassignment affected original")
	}
}

func TestSSEMessage_CloneMessage_ZeroValue(t *testing.T) {
	orig := &SSEMessage{}
	cloned := orig.CloneMessage().(*SSEMessage)
	if cloned.Event != "" || cloned.Data != "" || cloned.ID != "" || cloned.Retry != 0 {
		t.Errorf("zero-value SSEMessage clone should be zero, got %#v", cloned)
	}
}
