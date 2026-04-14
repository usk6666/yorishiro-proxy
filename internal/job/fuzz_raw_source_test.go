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

func makeRawFuzzFlow() *flow.Flow {
	return &flow.Flow{
		ID:        "flow-1",
		StreamID:  "stream-1",
		Direction: "send",
		RawBytes:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}
}

func TestFuzzRawSource_Sequential(t *testing.T) {
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {makeRawFuzzFlow()},
		},
	}

	positions := []RawFuzzPosition{
		{ID: "pos-0", Offset: 0, Length: 3, PayloadSet: "methods"},
	}
	resolved := map[string][]string{
		"methods": {"POST", "PUT", "DELETE"},
	}

	src, err := NewFuzzRawSource(FuzzRawConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		Positions:        positions,
		ResolvedPayloads: resolved,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if src.Total() != 3 {
		t.Errorf("Total: got %d, want 3", src.Total())
	}

	// First: replace "GET" with "POST"
	env1, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next 1: %v", err)
	}
	msg1 := env1.Message.(*envelope.RawMessage)
	if !bytes.HasPrefix(msg1.Bytes, []byte("POST")) {
		t.Errorf("first iteration should start with POST: got %q", string(msg1.Bytes[:10]))
	}

	// Second: replace "GET" with "PUT"
	env2, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next 2: %v", err)
	}
	msg2 := env2.Message.(*envelope.RawMessage)
	if !bytes.HasPrefix(msg2.Bytes, []byte("PUT")) {
		t.Errorf("second iteration should start with PUT: got %q", string(msg2.Bytes[:10]))
	}

	// Third: replace "GET" with "DELETE"
	env3, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next 3: %v", err)
	}
	msg3 := env3.Message.(*envelope.RawMessage)
	if !bytes.HasPrefix(msg3.Bytes, []byte("DELETE")) {
		t.Errorf("third iteration should start with DELETE: got %q", string(msg3.Bytes[:10]))
	}

	// EOF
	_, err = src.Next(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got: %v", err)
	}
}

func TestFuzzRawSource_MultiplePositions(t *testing.T) {
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {makeRawFuzzFlow()},
		},
	}

	positions := []RawFuzzPosition{
		{ID: "pos-0", Offset: 0, Length: 3, PayloadSet: "methods"},
		{ID: "pos-1", Offset: 4, Length: 1, PayloadSet: "paths"},
	}
	resolved := map[string][]string{
		"methods": {"POST"},
		"paths":   {"/admin", "/login"},
	}

	src, err := NewFuzzRawSource(FuzzRawConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		Positions:        positions,
		ResolvedPayloads: resolved,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Total: 1 (methods) + 2 (paths) = 3 (sequential)
	if src.Total() != 3 {
		t.Errorf("Total: got %d, want 3", src.Total())
	}

	count := 0
	for {
		_, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		count++
	}
	if count != 3 {
		t.Errorf("count: got %d, want 3", count)
	}
}

func TestFuzzRawSource_InsertMode(t *testing.T) {
	// Length=0 means insert (not replace).
	rawBytes := []byte("ABCDEF")
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {{
				ID: "f1", StreamID: "stream-1", Direction: "send",
				RawBytes: rawBytes,
			}},
		},
	}

	positions := []RawFuzzPosition{
		{ID: "pos-0", Offset: 3, Length: 0, PayloadSet: "inserts"},
	}
	resolved := map[string][]string{
		"inserts": {"XY"},
	}

	src, err := NewFuzzRawSource(FuzzRawConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		Positions:        positions,
		ResolvedPayloads: resolved,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	if !bytes.Equal(msg.Bytes, []byte("ABCXYDEF")) {
		t.Errorf("insert: got %q, want %q", msg.Bytes, "ABCXYDEF")
	}
}

func TestFuzzRawSource_WithTemplateExpansion(t *testing.T) {
	rawBytes := []byte("GET /§path§ HTTP/1.1\r\n\r\n")
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {{
				ID: "f1", StreamID: "stream-1", Direction: "send",
				RawBytes: rawBytes,
			}},
		},
	}

	// Position replaces at a different spot; template expansion is separate.
	positions := []RawFuzzPosition{
		{ID: "pos-0", Offset: 0, Length: 3, PayloadSet: "methods"},
	}
	resolved := map[string][]string{
		"methods": {"POST"},
	}

	src, err := NewFuzzRawSource(FuzzRawConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		Positions:        positions,
		ResolvedPayloads: resolved,
		KVStore:          map[string]string{"path": "admin"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	msg := env.Message.(*envelope.RawMessage)
	expected := "POST /admin HTTP/1.1\r\n\r\n"
	if string(msg.Bytes) != expected {
		t.Errorf("template + fuzz: got %q, want %q", msg.Bytes, expected)
	}
}

func TestFuzzRawSource_ReaderError(t *testing.T) {
	reader := &mockFlowReader{err: errors.New("db error")}

	src, err := NewFuzzRawSource(FuzzRawConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		Positions:        []RawFuzzPosition{{ID: "p0", Offset: 0, Length: 1, PayloadSet: "s"}},
		ResolvedPayloads: map[string][]string{"s": {"v"}},
	})
	if err != nil {
		t.Fatalf("constructor should succeed: %v", err)
	}

	_, err = src.Next(context.Background())
	if err == nil {
		t.Fatal("expected reader error")
	}
}

func TestFuzzRawSource_MissingPayloadSet(t *testing.T) {
	_, err := NewFuzzRawSource(FuzzRawConfig{
		Reader:           &mockFlowReader{},
		StreamID:         "stream-1",
		Positions:        []RawFuzzPosition{{ID: "p0", Offset: 0, Length: 1, PayloadSet: "missing"}},
		ResolvedPayloads: map[string][]string{},
	})
	if err == nil {
		t.Fatal("expected error for missing payload set")
	}
}

func TestFuzzRawSource_DoesNotMutateBase(t *testing.T) {
	rawBytes := []byte("ABCDEF")
	original := make([]byte, len(rawBytes))
	copy(original, rawBytes)

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {{
				ID: "f1", StreamID: "stream-1", Direction: "send",
				RawBytes: rawBytes,
			}},
		},
	}

	positions := []RawFuzzPosition{
		{ID: "pos-0", Offset: 0, Length: 3, PayloadSet: "s"},
	}
	resolved := map[string][]string{"s": {"XYZ"}}

	src, _ := NewFuzzRawSource(FuzzRawConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		Positions:        positions,
		ResolvedPayloads: resolved,
	})

	_, _ = src.Next(context.Background())

	if !bytes.Equal(rawBytes, original) {
		t.Errorf("base bytes mutated: got %q, want %q", rawBytes, original)
	}
}
