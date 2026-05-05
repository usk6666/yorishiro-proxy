package sse_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
)

func TestEncodeWireBytes_NilEnvelope(t *testing.T) {
	t.Parallel()
	out, err := sse.EncodeWireBytes(nil)
	if err == nil {
		t.Fatalf("expected error for nil envelope, got nil (out=%v)", out)
	}
	if !strings.Contains(err.Error(), "nil envelope") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeWireBytes_NilMessage(t *testing.T) {
	t.Parallel()
	out, err := sse.EncodeWireBytes(&envelope.Envelope{})
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
	out, err := sse.EncodeWireBytes(env)
	if err == nil {
		t.Fatalf("expected error for wrong Message type, got nil (out=%v)", out)
	}
	if !strings.Contains(err.Error(), "requires *SSEMessage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncodeWireBytes_FullEventRoundTrip(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.SSEMessage{
		Event: "update",
		Data:  "hello",
		ID:    "42",
		Retry: 3 * time.Second,
	}}
	out, err := sse.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parser := sse.NewSSEParser(bytes.NewReader(out), 0)
	got, err := parser.Next()
	if err != nil {
		t.Fatalf("parse round-trip failed: %v", err)
	}
	if got.EventType != "update" {
		t.Fatalf("event type mismatch: got %q, want %q", got.EventType, "update")
	}
	if got.Data != "hello" {
		t.Fatalf("data mismatch: got %q, want %q", got.Data, "hello")
	}
	if got.ID != "42" {
		t.Fatalf("id mismatch: got %q, want %q", got.ID, "42")
	}
	if got.Retry != "3000" {
		t.Fatalf("retry mismatch: got %q, want %q", got.Retry, "3000")
	}
	if len(got.Anomalies) != 0 {
		t.Fatalf("expected no anomalies, got %v", got.Anomalies)
	}
}

func TestEncodeWireBytes_DataOnlyRoundTrip(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.SSEMessage{Data: "one line"}}
	out, err := sse.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "data: one line\n\n" {
		t.Fatalf("wire bytes mismatch: got %q, want %q", string(out), "data: one line\n\n")
	}

	parser := sse.NewSSEParser(bytes.NewReader(out), 0)
	got, err := parser.Next()
	if err != nil {
		t.Fatalf("parse round-trip failed: %v", err)
	}
	if got.Data != "one line" {
		t.Fatalf("data mismatch: got %q, want %q", got.Data, "one line")
	}
}

func TestEncodeWireBytes_MultiLineData(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.SSEMessage{Data: "a\nb\nc"}}
	out, err := sse.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "data: a\ndata: b\ndata: c\n\n"
	if string(out) != want {
		t.Fatalf("wire bytes mismatch:\n got %q\nwant %q", string(out), want)
	}

	parser := sse.NewSSEParser(bytes.NewReader(out), 0)
	got, err := parser.Next()
	if err != nil {
		t.Fatalf("parse round-trip failed: %v", err)
	}
	if got.Data != "a\nb\nc" {
		t.Fatalf("multi-line data round-trip mismatch: got %q, want %q", got.Data, "a\nb\nc")
	}
}

func TestEncodeWireBytes_EmptyDataWithFields(t *testing.T) {
	t.Parallel()
	// Event/ID set, no Data: encoder must NOT emit a bogus `data:` line.
	env := &envelope.Envelope{Message: &envelope.SSEMessage{Event: "ping", ID: "x"}}
	out, err := sse.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "data:") {
		t.Fatalf("encoder emitted bogus data: line for empty Data: %q", string(out))
	}
	want := "event: ping\nid: x\n\n"
	if string(out) != want {
		t.Fatalf("wire bytes mismatch:\n got %q\nwant %q", string(out), want)
	}
}

func TestEncodeWireBytes_AllEmptyEmitsBlankLine(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.SSEMessage{}}
	out, err := sse.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "\n" {
		t.Fatalf("expected single LF for empty event, got %q", string(out))
	}
	// Parser should consume the blank line and report EOF (no fields → not
	// an event).
	parser := sse.NewSSEParser(bytes.NewReader(out), 0)
	if _, err := parser.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF for blank-line-only input, got %v", err)
	}
}

func TestEncodeWireBytes_RetrySerialization(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		retry time.Duration
		want  string
	}{
		{"500ms", 500 * time.Millisecond, "500"},
		{"1s", time.Second, "1000"},
		{"sub-millisecond rounds down", 1500 * time.Microsecond, "1"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := &envelope.Envelope{Message: &envelope.SSEMessage{
				Data:  "x",
				Retry: tc.retry,
			}}
			out, err := sse.EncodeWireBytes(env)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(string(out), "retry: "+tc.want+"\n") {
				t.Fatalf("expected retry line %q in output, got %q", "retry: "+tc.want, string(out))
			}
		})
	}
}

func TestEncodeWireBytes_RetryZeroOmitted(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.SSEMessage{
		Data:  "x",
		Retry: 0,
	}}
	out, err := sse.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "retry:") {
		t.Fatalf("expected no retry line when Retry=0, got %q", string(out))
	}
}

func TestEncodeWireBytes_AnomaliesIgnored(t *testing.T) {
	t.Parallel()
	env := &envelope.Envelope{Message: &envelope.SSEMessage{
		Data: "x",
		Anomalies: []envelope.Anomaly{{
			Type:   envelope.AnomalySSEMissingData,
			Detail: "test",
		}},
	}}
	out, err := sse.EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Anomalies are record-only metadata; never appear on the wire.
	if strings.Contains(string(out), "Anomaly") || strings.Contains(string(out), "test") {
		t.Fatalf("anomaly leaked into wire bytes: %q", string(out))
	}
}
