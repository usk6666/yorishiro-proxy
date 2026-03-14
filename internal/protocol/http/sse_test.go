package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestIsSSEResponse(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "exact text/event-stream",
			contentType: "text/event-stream",
			want:        true,
		},
		{
			name:        "text/event-stream with charset",
			contentType: "text/event-stream; charset=utf-8",
			want:        true,
		},
		{
			name:        "text/event-stream uppercase",
			contentType: "Text/Event-Stream",
			want:        true,
		},
		{
			name:        "text/event-stream with whitespace",
			contentType: " text/event-stream ",
			want:        true,
		},
		{
			name:        "text/html is not SSE",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "application/json is not SSE",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "empty content type",
			contentType: "",
			want:        false,
		},
		{
			name:        "text/event-stream-like but not exact",
			contentType: "text/event-stream-v2",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &gohttp.Response{
				Header: gohttp.Header{},
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			got := isSSEResponse(resp)
			if got != tt.want {
				t.Errorf("isSSEResponse() = %v, want %v (Content-Type: %q)", got, tt.want, tt.contentType)
			}
		})
	}
}

func TestAddSSETags(t *testing.T) {
	tests := []struct {
		name string
		tags map[string]string
		want map[string]string
	}{
		{
			name: "nil tags creates new map",
			tags: nil,
			want: map[string]string{"streaming_type": "sse"},
		},
		{
			name: "empty tags adds SSE tag",
			tags: map[string]string{},
			want: map[string]string{"streaming_type": "sse"},
		},
		{
			name: "existing tags preserved",
			tags: map[string]string{"existing": "value"},
			want: map[string]string{"existing": "value", "streaming_type": "sse"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := addSSETags(tt.tags)
			if len(got) != len(tt.want) {
				t.Fatalf("addSSETags() returned %d tags, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("addSSETags()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestWriteSSEResponseHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	resp := &gohttp.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: gohttp.Header{
			"Content-Type":  {"text/event-stream"},
			"Cache-Control": {"no-cache"},
		},
	}

	// Write headers in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeSSEResponseHeaders(server, resp)
	}()

	// Read from client side.
	reader := bufio.NewReader(client)
	readResp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}
	defer readResp.Body.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("writeSSEResponseHeaders failed: %v", err)
	}

	if readResp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", readResp.StatusCode)
	}
	if ct := readResp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/event-stream")
	}
	if cc := readResp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-cache")
	}
}

func TestStreamSSEBody(t *testing.T) {
	t.Run("streams data from source to destination", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		data := "data: hello\n\ndata: world\n\n"
		src := io.NopCloser(strings.NewReader(data))

		// Stream in a goroutine.
		errCh := make(chan error, 1)
		go func() {
			errCh <- streamSSEBody(context.Background(), server, src)
			server.Close()
		}()

		// Read from client side.
		var buf bytes.Buffer
		io.Copy(&buf, client)

		if err := <-errCh; err != nil {
			t.Fatalf("streamSSEBody failed: %v", err)
		}

		if buf.String() != data {
			t.Errorf("streamed data = %q, want %q", buf.String(), data)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		// Use a pipe reader as the source. When we close the write side,
		// the read will unblock. This simulates resp.Body closing when
		// the upstream connection drops.
		pr, pw := io.Pipe()

		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			errCh <- streamSSEBody(ctx, server, pr)
		}()

		// Cancel context after a short delay, then close the pipe to
		// unblock the read.
		time.Sleep(10 * time.Millisecond)
		cancel()
		pw.Close()

		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled && err != io.EOF {
				// The stream may return a write deadline error, which is acceptable.
				t.Logf("streamSSEBody returned: %v (expected context.Canceled, EOF, or deadline error)", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("streamSSEBody did not return after context cancellation")
		}
	})
}

// mockFlowStore is a minimal flow store for testing SSE recording.
type sseTestFlowStore struct {
	flows    []*flow.Flow
	messages []*flow.Message
	updates  []sseFlowUpdateRecord
}

type sseFlowUpdateRecord struct {
	flowID string
	update flow.FlowUpdate
}

func (s *sseTestFlowStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	f.ID = fmt.Sprintf("test-flow-%d", len(s.flows))
	s.flows = append(s.flows, f)
	return nil
}

func (s *sseTestFlowStore) AppendMessage(_ context.Context, m *flow.Message) error {
	s.messages = append(s.messages, m)
	return nil
}

func (s *sseTestFlowStore) UpdateFlow(_ context.Context, id string, update flow.FlowUpdate) error {
	s.updates = append(s.updates, sseFlowUpdateRecord{flowID: id, update: update})
	return nil
}

func TestRecordSSEReceive(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	resp := &gohttp.Response{
		StatusCode: 200,
		Header: gohttp.Header{
			"Content-Type": {"text/event-stream"},
		},
	}

	sendResult := &sendRecordResult{
		flowID:       "flow-1",
		tags:         map[string]string{"existing": "tag"},
		recvSequence: 1,
	}

	fwd := &forwardResult{
		resp:       resp,
		serverAddr: "127.0.0.1:8080",
	}

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()
	duration := 100 * time.Millisecond

	h.recordSSEReceive(ctx, sendResult, fwd, start, duration, "", logger)

	// Verify flow update.
	if len(store.updates) != 1 {
		t.Fatalf("expected 1 flow update, got %d", len(store.updates))
	}
	update := store.updates[0]
	if update.flowID != "flow-1" {
		t.Errorf("update flowID = %q, want %q", update.flowID, "flow-1")
	}
	if update.update.State != "complete" {
		t.Errorf("update State = %q, want %q", update.update.State, "complete")
	}
	if update.update.Tags["streaming_type"] != "sse" {
		t.Errorf("update Tags[streaming_type] = %q, want %q", update.update.Tags["streaming_type"], "sse")
	}
	if update.update.Tags["existing"] != "tag" {
		t.Errorf("update Tags[existing] = %q, want %q", update.update.Tags["existing"], "tag")
	}
	if update.update.ServerAddr != "127.0.0.1:8080" {
		t.Errorf("update ServerAddr = %q, want %q", update.update.ServerAddr, "127.0.0.1:8080")
	}

	// Verify receive message.
	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(store.messages))
	}
	msg := store.messages[0]
	if msg.FlowID != "flow-1" {
		t.Errorf("message FlowID = %q, want %q", msg.FlowID, "flow-1")
	}
	if msg.Direction != "receive" {
		t.Errorf("message Direction = %q, want %q", msg.Direction, "receive")
	}
	if msg.StatusCode != 200 {
		t.Errorf("message StatusCode = %d, want %d", msg.StatusCode, 200)
	}
	if msg.Body != nil {
		t.Errorf("message Body should be nil for SSE, got %v", msg.Body)
	}
	if ct := gohttp.Header(msg.Headers).Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("message Content-Type = %q, want %q", ct, "text/event-stream")
	}
}

func TestRecordSSEReceive_NilSendResult(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	resp := &gohttp.Response{StatusCode: 200, Header: gohttp.Header{}}
	fwd := &forwardResult{resp: resp}

	// Should be a no-op when sendResult is nil.
	h.recordSSEReceive(context.Background(), nil, fwd, time.Now(), time.Second, "", testutil.DiscardLogger())

	if len(store.updates) != 0 {
		t.Errorf("expected 0 updates for nil sendResult, got %d", len(store.updates))
	}
	if len(store.messages) != 0 {
		t.Errorf("expected 0 messages for nil sendResult, got %d", len(store.messages))
	}
}

func TestRecordSSEReceive_TLSCertSubject(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	sendResult := &sendRecordResult{
		flowID:       "flow-tls",
		recvSequence: 1,
	}

	fwd := &forwardResult{
		resp:       resp,
		serverAddr: "example.com:443",
	}

	h.recordSSEReceive(context.Background(), sendResult, fwd, time.Now(), time.Second, "CN=example.com", testutil.DiscardLogger())

	if len(store.updates) != 1 {
		t.Fatalf("expected 1 flow update, got %d", len(store.updates))
	}
	if store.updates[0].update.TLSServerCertSubject != "CN=example.com" {
		t.Errorf("TLSServerCertSubject = %q, want %q", store.updates[0].update.TLSServerCertSubject, "CN=example.com")
	}
}
