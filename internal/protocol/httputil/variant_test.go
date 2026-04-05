package httputil

import (
	"context"
	"fmt"
	"log/slog"
	gohttp "net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// h2r is a test helper that converts gohttp.Header to parser.RawHeaders.
func h2r(h gohttp.Header) parser.RawHeaders {
	if h == nil {
		return nil
	}
	var rh parser.RawHeaders
	for name, vals := range h {
		for _, v := range vals {
			rh = append(rh, parser.RawHeader{Name: name, Value: v})
		}
	}
	return rh
}

// mockWriter is a minimal VariantRecordWriter for testing.
type mockWriter struct {
	messages  []*flow.Flow
	updates   []mockUpdate
	appendErr error
	updateErr error
}

type mockUpdate struct {
	id     string
	update flow.StreamUpdate
}

func (m *mockWriter) SaveFlow(_ context.Context, msg *flow.Flow) error {
	if m.appendErr != nil {
		return m.appendErr
	}
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockWriter) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updates = append(m.updates, mockUpdate{id: id, update: update})
	return nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

func TestRecordReceiveVariant_NoModification(t *testing.T) {
	w := &mockWriter{}
	headers := h2r(gohttp.Header{"Content-Type": {"text/plain"}})
	body := []byte("hello")
	snap := SnapshotResponse(200, headers, body)

	RecordReceiveVariant(context.Background(), w, ReceiveVariantParams{
		StreamID:       "f1",
		RecvSequence:   1,
		Start:          time.Now(),
		Duration:       50 * time.Millisecond,
		ServerAddr:     "10.0.0.1:80",
		RespStatusCode: 200,
		RespHeaders:    headers,
		RespBody:       body,
	}, &snap, discardLogger())

	if len(w.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(w.messages))
	}
	msg := w.messages[0]
	if msg.Sequence != 1 {
		t.Errorf("sequence = %d, want 1", msg.Sequence)
	}
	if msg.Metadata != nil {
		t.Errorf("metadata should be nil, got %v", msg.Metadata)
	}
	if msg.StatusCode != 200 {
		t.Errorf("status = %d, want 200", msg.StatusCode)
	}
	if len(w.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(w.updates))
	}
	if w.updates[0].update.State != "complete" {
		t.Errorf("state = %q, want %q", w.updates[0].update.State, "complete")
	}
}

func TestRecordReceiveVariant_NilSnap(t *testing.T) {
	w := &mockWriter{}

	RecordReceiveVariant(context.Background(), w, ReceiveVariantParams{
		StreamID:       "f2",
		RecvSequence:   1,
		Start:          time.Now(),
		Duration:       50 * time.Millisecond,
		ServerAddr:     "10.0.0.1:80",
		RespStatusCode: 200,
		RespHeaders:    parser.RawHeaders{},
		RespBody:       []byte("ok"),
	}, nil, discardLogger())

	if len(w.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(w.messages))
	}
	if w.messages[0].Metadata != nil {
		t.Errorf("metadata should be nil, got %v", w.messages[0].Metadata)
	}
}

func TestRecordReceiveVariant_StatusModified(t *testing.T) {
	w := &mockWriter{}
	headers := h2r(gohttp.Header{"Content-Type": {"text/plain"}})
	body := []byte("body")
	snap := SnapshotResponse(200, headers, body)

	RecordReceiveVariant(context.Background(), w, ReceiveVariantParams{
		StreamID:       "f3",
		RecvSequence:   2,
		Start:          time.Now(),
		Duration:       100 * time.Millisecond,
		ServerAddr:     "10.0.0.1:443",
		RespStatusCode: 403,
		RespHeaders:    headers.Clone(),
		RespBody:       body,
	}, &snap, discardLogger())

	if len(w.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(w.messages))
	}

	orig := w.messages[0]
	if orig.StatusCode != 200 {
		t.Errorf("original status = %d, want 200", orig.StatusCode)
	}
	if orig.Sequence != 2 {
		t.Errorf("original sequence = %d, want 2", orig.Sequence)
	}
	if orig.Metadata == nil || orig.Metadata["variant"] != "original" {
		t.Errorf("original variant = %v, want original", orig.Metadata)
	}

	mod := w.messages[1]
	if mod.StatusCode != 403 {
		t.Errorf("modified status = %d, want 403", mod.StatusCode)
	}
	if mod.Sequence != 3 {
		t.Errorf("modified sequence = %d, want 3", mod.Sequence)
	}
	if mod.Metadata == nil || mod.Metadata["variant"] != "modified" {
		t.Errorf("modified variant = %v, want modified", mod.Metadata)
	}

	if len(w.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(w.updates))
	}
	if w.updates[0].update.State != "complete" {
		t.Errorf("state = %q, want %q", w.updates[0].update.State, "complete")
	}
}

func TestRecordReceiveVariant_BodyModified(t *testing.T) {
	w := &mockWriter{}
	headers := h2r(gohttp.Header{"Content-Type": {"application/json"}})
	origBody := []byte(`{"v":"original"}`)
	modBody := []byte(`{"v":"modified"}`)

	snap := SnapshotResponse(200, headers, origBody)

	RecordReceiveVariant(context.Background(), w, ReceiveVariantParams{
		StreamID:       "f4",
		RecvSequence:   1,
		Start:          time.Now(),
		Duration:       50 * time.Millisecond,
		ServerAddr:     "10.0.0.1:80",
		RespStatusCode: 200,
		RespHeaders:    headers.Clone(),
		RespBody:       modBody,
	}, &snap, discardLogger())

	if len(w.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(w.messages))
	}
	if string(w.messages[0].Body) != `{"v":"original"}` {
		t.Errorf("original body = %q", w.messages[0].Body)
	}
	if string(w.messages[1].Body) != `{"v":"modified"}` {
		t.Errorf("modified body = %q", w.messages[1].Body)
	}
}

func TestRecordReceiveVariant_RawResponseOnOriginalOnly(t *testing.T) {
	w := &mockWriter{}
	headers := parser.RawHeaders{}
	origBody := []byte("original")
	modBody := []byte("modified")
	rawResp := []byte("HTTP/1.1 200 OK\r\n\r\noriginal")

	snap := SnapshotResponse(200, headers, origBody)

	RecordReceiveVariant(context.Background(), w, ReceiveVariantParams{
		StreamID:       "f5",
		RecvSequence:   1,
		Start:          time.Now(),
		Duration:       50 * time.Millisecond,
		ServerAddr:     "10.0.0.1:80",
		RespStatusCode: 200,
		RespHeaders:    headers,
		RespBody:       modBody,
		RawResponse:    rawResp,
	}, &snap, discardLogger())

	if len(w.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(w.messages))
	}
	if w.messages[0].RawBytes == nil {
		t.Error("original RawBytes should not be nil")
	}
	if w.messages[1].RawBytes != nil {
		t.Error("modified RawBytes should be nil")
	}
}

func TestRecordReceiveVariant_TLSCertSubject(t *testing.T) {
	w := &mockWriter{}

	RecordReceiveVariant(context.Background(), w, ReceiveVariantParams{
		StreamID:             "f6",
		RecvSequence:         1,
		Start:                time.Now(),
		Duration:             50 * time.Millisecond,
		ServerAddr:           "10.0.0.1:443",
		TLSServerCertSubject: "CN=example.com",
		RespStatusCode:       200,
		RespHeaders:          parser.RawHeaders{},
		RespBody:             []byte("ok"),
	}, nil, discardLogger())

	if len(w.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(w.updates))
	}
	if w.updates[0].update.TLSServerCertSubject != "CN=example.com" {
		t.Errorf("TLSServerCertSubject = %q, want %q",
			w.updates[0].update.TLSServerCertSubject, "CN=example.com")
	}
}

func TestRecordReceiveVariant_AppendError(t *testing.T) {
	w := &mockWriter{appendErr: fmt.Errorf("db write error")}

	// Should not panic on append error.
	RecordReceiveVariant(context.Background(), w, ReceiveVariantParams{
		StreamID:       "f7",
		RecvSequence:   1,
		Start:          time.Now(),
		Duration:       50 * time.Millisecond,
		ServerAddr:     "10.0.0.1:80",
		RespStatusCode: 200,
		RespHeaders:    parser.RawHeaders{},
		RespBody:       []byte("ok"),
	}, nil, discardLogger())

	// Flow update should still be attempted.
	if len(w.updates) != 1 {
		t.Errorf("expected 1 update attempt, got %d", len(w.updates))
	}
}

func TestResponseModified_Cases(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"text/plain"}}
	body := []byte("hello")
	snap := SnapshotResponse(200, h2r(headers), body)

	tests := []struct {
		name       string
		statusCode int
		headers    parser.RawHeaders
		body       []byte
		want       bool
	}{
		{"no change", 200, h2r(headers), body, false},
		{"status changed", 404, h2r(headers), body, true},
		{"body changed", 200, h2r(headers), []byte("world"), true},
		{"header added", 200, h2r(gohttp.Header{"Content-Type": {"text/plain"}, "X-New": {"v"}}), body, true},
		{"header removed", 200, h2r(gohttp.Header{}), body, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResponseModified(snap, tt.statusCode, tt.headers, tt.body)
			if got != tt.want {
				t.Errorf("ResponseModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSnapshotResponse_DeepCopy(t *testing.T) {
	headers := gohttp.Header{"Content-Type": {"application/json"}}
	body := []byte(`{"key":"value"}`)

	snap := SnapshotResponse(200, h2r(headers), body)

	// Mutate originals.
	headers.Set("Content-Type", "text/plain")
	body[0] = 'X'

	if snap.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", snap.StatusCode)
	}
	if snap.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("Headers mutated: %q", snap.Headers.Get("Content-Type"))
	}
	if snap.Body[0] != '{' {
		t.Errorf("Body mutated: %q", snap.Body)
	}
}

func TestSnapshotResponse_NilInputs(t *testing.T) {
	snap := SnapshotResponse(0, nil, nil)
	if snap.Headers != nil {
		t.Errorf("expected nil headers, got %v", snap.Headers)
	}
	if snap.Body != nil {
		t.Errorf("expected nil body, got %v", snap.Body)
	}
}

func TestHeadersModified_Cases(t *testing.T) {
	tests := []struct {
		name string
		a, b parser.RawHeaders
		want bool
	}{
		{"identical", h2r(gohttp.Header{"K": {"v"}}), h2r(gohttp.Header{"K": {"v"}}), false},
		{"both nil", nil, nil, false},
		{"both empty", parser.RawHeaders{}, parser.RawHeaders{}, false},
		{"a extra key", parser.RawHeaders{{Name: "K", Value: "v"}, {Name: "E", Value: "v"}}, parser.RawHeaders{{Name: "K", Value: "v"}}, true},
		{"b extra key", parser.RawHeaders{{Name: "K", Value: "v"}}, parser.RawHeaders{{Name: "K", Value: "v"}, {Name: "E", Value: "v"}}, true},
		{"different value", parser.RawHeaders{{Name: "K", Value: "old"}}, parser.RawHeaders{{Name: "K", Value: "new"}}, true},
		{"different count", parser.RawHeaders{{Name: "K", Value: "a"}, {Name: "K", Value: "b"}}, parser.RawHeaders{{Name: "K", Value: "a"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HeadersModified(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("HeadersModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecompressAndTruncate_Identity(t *testing.T) {
	body := []byte("hello world")
	result, decompressed, truncated := decompressAndTruncate(body, "", discardLogger())
	if decompressed {
		t.Error("expected no decompression for empty encoding")
	}
	if truncated {
		t.Error("expected no truncation")
	}
	if string(result) != "hello world" {
		t.Errorf("body = %q, want %q", result, "hello world")
	}
}

func TestDecompressAndTruncate_UnsupportedEncoding(t *testing.T) {
	body := []byte("hello world")
	result, decompressed, truncated := decompressAndTruncate(body, "br", discardLogger())
	if decompressed {
		t.Error("expected no decompression for unsupported encoding")
	}
	if truncated {
		t.Error("expected no truncation")
	}
	if string(result) != "hello world" {
		t.Errorf("body = %q, want %q", result, "hello world")
	}
}
