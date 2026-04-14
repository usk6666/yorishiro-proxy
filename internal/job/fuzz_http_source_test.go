package job

import (
	"context"
	"errors"
	"io"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
)

func makeHTTPFuzzFlow() *flow.Flow {
	return &flow.Flow{
		ID:        "flow-1",
		StreamID:  "stream-1",
		Direction: "send",
		Method:    "GET",
		URL: &url.URL{
			Scheme:   "https",
			Host:     "example.com",
			Path:     "/api",
			RawQuery: "q=test",
		},
		Headers: map[string][]string{
			"Host":         {"example.com"},
			"Content-Type": {"text/plain"},
		},
		Body: []byte("original body"),
	}
}

func TestFuzzHTTPSource_Sequential(t *testing.T) {
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {makeHTTPFuzzFlow()},
		},
	}

	positions := []fuzzer.Position{
		{ID: "pos-0", Location: "header", Name: "Content-Type", PayloadSet: "types"},
	}
	resolved := map[string][]string{
		"types": {"application/json", "application/xml"},
	}

	src, err := NewFuzzHTTPSource(FuzzHTTPConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		AttackType:       "sequential",
		Positions:        positions,
		ResolvedPayloads: resolved,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if src.Total() != 2 {
		t.Errorf("Total: got %d, want 2", src.Total())
	}

	// First iteration: Content-Type = application/json
	env1, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next 1: %v", err)
	}
	msg1 := env1.Message.(*envelope.HTTPMessage)
	if msg1.Method != "GET" {
		t.Errorf("Method: got %q", msg1.Method)
	}
	// Check that Content-Type was changed.
	found := false
	for _, kv := range msg1.Headers {
		if kv.Name == "Content-Type" && kv.Value == "application/json" {
			found = true
		}
	}
	if !found {
		t.Error("Content-Type should be application/json in first iteration")
	}

	// Second iteration: Content-Type = application/xml
	env2, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next 2: %v", err)
	}
	msg2 := env2.Message.(*envelope.HTTPMessage)
	found = false
	for _, kv := range msg2.Headers {
		if kv.Name == "Content-Type" && kv.Value == "application/xml" {
			found = true
		}
	}
	if !found {
		t.Error("Content-Type should be application/xml in second iteration")
	}

	// Third call should return EOF.
	_, err = src.Next(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got: %v", err)
	}
}

func TestFuzzHTTPSource_Parallel(t *testing.T) {
	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {makeHTTPFuzzFlow()},
		},
	}

	positions := []fuzzer.Position{
		{ID: "pos-0", Location: "header", Name: "Content-Type", PayloadSet: "types"},
		{ID: "pos-1", Location: "query", Name: "q", PayloadSet: "queries"},
	}
	resolved := map[string][]string{
		"types":   {"application/json", "text/html"},
		"queries": {"fuzz1", "fuzz2"},
	}

	src, err := NewFuzzHTTPSource(FuzzHTTPConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		AttackType:       "parallel",
		Positions:        positions,
		ResolvedPayloads: resolved,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if src.Total() != 2 {
		t.Errorf("Total: got %d, want 2 (zip of equal-length sets)", src.Total())
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
	if count != 2 {
		t.Errorf("iteration count: got %d, want 2", count)
	}
}

func TestFuzzHTTPSource_WithTemplateExpansion(t *testing.T) {
	f := makeHTTPFuzzFlow()
	f.Body = []byte("token=§auth§")

	reader := &mockFlowReader{
		flows: map[string][]*flow.Flow{
			"stream-1": {f},
		},
	}

	positions := []fuzzer.Position{
		{ID: "pos-0", Location: "header", Name: "Content-Type", PayloadSet: "types"},
	}
	resolved := map[string][]string{
		"types": {"application/json"},
	}

	src, err := NewFuzzHTTPSource(FuzzHTTPConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		AttackType:       "sequential",
		Positions:        positions,
		ResolvedPayloads: resolved,
		KVStore:          map[string]string{"auth": "secret123"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	msg := env.Message.(*envelope.HTTPMessage)
	if string(msg.Body) != "token=secret123" {
		t.Errorf("Body template expansion: got %q, want %q", msg.Body, "token=secret123")
	}
}

func TestFuzzHTTPSource_ReaderError(t *testing.T) {
	reader := &mockFlowReader{err: errors.New("db error")}

	src, err := NewFuzzHTTPSource(FuzzHTTPConfig{
		Reader:           reader,
		StreamID:         "stream-1",
		AttackType:       "sequential",
		Positions:        []fuzzer.Position{{ID: "p0", Location: "header", Name: "X", PayloadSet: "s"}},
		ResolvedPayloads: map[string][]string{"s": {"v"}},
	})
	if err != nil {
		t.Fatalf("constructor should succeed: %v", err)
	}

	_, err = src.Next(context.Background())
	if err == nil {
		t.Fatal("expected reader error on first Next")
	}
}

func TestFuzzHTTPSource_InvalidAttackType(t *testing.T) {
	_, err := NewFuzzHTTPSource(FuzzHTTPConfig{
		Reader:           &mockFlowReader{},
		StreamID:         "stream-1",
		AttackType:       "invalid",
		Positions:        []fuzzer.Position{{ID: "p0", Location: "header", Name: "X", PayloadSet: "s"}},
		ResolvedPayloads: map[string][]string{"s": {"v"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid attack type")
	}
}
