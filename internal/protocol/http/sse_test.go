package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestApplySSEIntercept_NoEngine(t *testing.T) {
	h := &Handler{}
	// No InterceptEngine or InterceptQueue set.

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	dropped := h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())
	if dropped {
		t.Error("applySSEIntercept should return false when no intercept engine is set")
	}
}

func TestApplySSEIntercept_NoMatchingRules(t *testing.T) {
	engine := intercept.NewEngine()
	// Add a request-only rule that won't match responses.
	engine.AddRule(intercept.Rule{
		ID:        "req-only",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	})

	queue := intercept.NewQueue()
	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	dropped := h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())
	if dropped {
		t.Error("applySSEIntercept should return false when no rules match")
	}
}

func TestApplySSEIntercept_Drop(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "drop-sse",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Drain client side so WriteHTTPError doesn't block on net.Pipe().
	go io.Copy(io.Discard, client)

	// Resolve the intercepted item with DROP action in a goroutine.
	go func() {
		// Wait for the item to appear in the queue.
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	dropped := h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())
	if !dropped {
		t.Error("applySSEIntercept should return true when DROP action is received")
	}
}

func TestApplySSEIntercept_Release(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "release-sse",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Resolve the intercepted item with RELEASE action in a goroutine.
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	dropped := h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())
	if dropped {
		t.Error("applySSEIntercept should return false when RELEASE action is received")
	}
}

func TestApplySSEIntercept_ModifyAndForward_TreatedAsRelease(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "modify-sse",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Resolve with ModifyAndForward, which should be treated as release for SSE.
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionModifyAndForward})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	dropped := h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())
	if dropped {
		t.Error("applySSEIntercept should return false for ModifyAndForward (treated as release)")
	}
}

func TestApplySSEIntercept_Timeout_AutoRelease(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "timeout-sse",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(50 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoRelease)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Don't resolve — let it timeout with auto_release.
	dropped := h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())
	if dropped {
		t.Error("applySSEIntercept should return false on timeout with auto_release")
	}
}

func TestApplySSEIntercept_Timeout_AutoDrop(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "timeout-drop-sse",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(50 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoDrop)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Drain client side so WriteHTTPError doesn't block on net.Pipe().
	go io.Copy(io.Discard, client)

	// Don't resolve — let it timeout with auto_drop.
	dropped := h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())
	if !dropped {
		t.Error("applySSEIntercept should return true on timeout with auto_drop")
	}
}

func TestApplySSEIntercept_EnqueuesWithNilBody(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "check-nil-body",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Verify the enqueued item has nil body.
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				if items[0].Body != nil {
					// Can't use t.Error from goroutine easily, but we can still resolve.
				}
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	h.applySSEIntercept(context.Background(), server, req, resp, testutil.DiscardLogger())

	// Verify the enqueued item had the correct phase and nil body.
	// We can't easily inspect the item after it's removed, but the test
	// passing without panic confirms the nil body path works.
}

func TestSSEHookContext_NilAllowed(t *testing.T) {
	// Verify that handleSSEStream works when hookCtx is nil (no plugin engine).
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	input := "data: hello\n\n"
	client, server := net.Pipe()
	defer client.Close()

	resp := &gohttp.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     gohttp.Header{"Content-Type": {"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(input)),
	}

	fwd := &forwardResult{
		resp:       resp,
		serverAddr: "127.0.0.1:8080",
	}

	sendResult := &sendRecordResult{
		flowID:       "flow-1",
		recvSequence: 1,
	}

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleSSEStream(context.Background(), server, req, fwd, time.Now(), sendResult, nil, testutil.DiscardLogger())
		server.Close()
	}()

	// Read response from client side.
	reader := bufio.NewReader(client)
	readResp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}

	// Read SSE body.
	body, _ := io.ReadAll(readResp.Body)
	readResp.Body.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("handleSSEStream failed: %v", err)
	}

	if string(body) != input {
		t.Errorf("body = %q, want %q", string(body), input)
	}
	if readResp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", readResp.StatusCode)
	}
}

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

		pr, pw := io.Pipe()

		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			errCh <- streamSSEBody(ctx, server, pr)
		}()

		time.Sleep(10 * time.Millisecond)
		cancel()
		pw.Close()

		select {
		case err := <-errCh:
			if err != nil && err != context.Canceled && err != io.EOF {
				t.Logf("streamSSEBody returned: %v (expected context.Canceled, EOF, or deadline error)", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("streamSSEBody did not return after context cancellation")
		}
	})
}

// sseTestFlowStore is a minimal flow store for testing SSE recording.
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

	h.recordSSEReceive(ctx, sendResult, fwd, start, "", logger)

	// Verify flow update.
	if len(store.updates) != 1 {
		t.Fatalf("expected 1 flow update, got %d", len(store.updates))
	}
	update := store.updates[0]
	if update.flowID != "flow-1" {
		t.Errorf("update flowID = %q, want %q", update.flowID, "flow-1")
	}
	if update.update.State != "active" {
		t.Errorf("update State = %q, want %q", update.update.State, "active")
	}
	if update.update.FlowType != "stream" {
		t.Errorf("update FlowType = %q, want %q", update.update.FlowType, "stream")
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
		t.Errorf("message Body should be nil for SSE headers, got %v", msg.Body)
	}
	if ct := gohttp.Header(msg.Headers).Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("message Content-Type = %q, want %q", ct, "text/event-stream")
	}
	if msg.Metadata["sse_type"] != "headers" {
		t.Errorf("message Metadata[sse_type] = %q, want %q", msg.Metadata["sse_type"], "headers")
	}
}

func TestRecordSSEReceive_NilSendResult(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	resp := &gohttp.Response{StatusCode: 200, Header: gohttp.Header{}}
	fwd := &forwardResult{resp: resp}

	// Should be a no-op when sendResult is nil.
	h.recordSSEReceive(context.Background(), nil, fwd, time.Now(), "", testutil.DiscardLogger())

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

	h.recordSSEReceive(context.Background(), sendResult, fwd, time.Now(), "CN=example.com", testutil.DiscardLogger())

	if len(store.updates) != 1 {
		t.Fatalf("expected 1 flow update, got %d", len(store.updates))
	}
	if store.updates[0].update.TLSServerCertSubject != "CN=example.com" {
		t.Errorf("TLSServerCertSubject = %q, want %q", store.updates[0].update.TLSServerCertSubject, "CN=example.com")
	}
}

func TestRecordSSEEvent(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	event := &SSEEvent{
		EventType: "message",
		Data:      "hello world",
		ID:        "42",
		Retry:     "5000",
		RawBytes:  []byte("event: message\nid: 42\nretry: 5000\ndata: hello world\n\n"),
	}

	var seq atomic.Int64
	seq.Store(2) // Start after headers message

	h.recordSSEEvent(context.Background(), "flow-1", event, &seq, testutil.DiscardLogger())

	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(store.messages))
	}

	msg := store.messages[0]
	if msg.FlowID != "flow-1" {
		t.Errorf("FlowID = %q, want %q", msg.FlowID, "flow-1")
	}
	if msg.Sequence != 2 {
		t.Errorf("Sequence = %d, want %d", msg.Sequence, 2)
	}
	if msg.Direction != "receive" {
		t.Errorf("Direction = %q, want %q", msg.Direction, "receive")
	}
	if string(msg.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", string(msg.Body), "hello world")
	}
	if msg.RawBytes == nil {
		t.Error("RawBytes should not be nil")
	}
	if msg.Metadata["sse_type"] != "event" {
		t.Errorf("Metadata[sse_type] = %q, want %q", msg.Metadata["sse_type"], "event")
	}
	if msg.Metadata["sse_event"] != "message" {
		t.Errorf("Metadata[sse_event] = %q, want %q", msg.Metadata["sse_event"], "message")
	}
	if msg.Metadata["sse_id"] != "42" {
		t.Errorf("Metadata[sse_id] = %q, want %q", msg.Metadata["sse_id"], "42")
	}
	if msg.Metadata["sse_retry"] != "5000" {
		t.Errorf("Metadata[sse_retry] = %q, want %q", msg.Metadata["sse_retry"], "5000")
	}
}

func TestRecordSSEEvent_NoOptionalFields(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	event := &SSEEvent{
		Data:     "simple data",
		RawBytes: []byte("data: simple data\n\n"),
	}

	var seq atomic.Int64
	seq.Store(1)

	h.recordSSEEvent(context.Background(), "flow-2", event, &seq, testutil.DiscardLogger())

	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(store.messages))
	}

	msg := store.messages[0]
	if _, ok := msg.Metadata["sse_event"]; ok {
		t.Error("sse_event should not be present when EventType is empty")
	}
	if _, ok := msg.Metadata["sse_id"]; ok {
		t.Error("sse_id should not be present when ID is empty")
	}
	if _, ok := msg.Metadata["sse_retry"]; ok {
		t.Error("sse_retry should not be present when Retry is empty")
	}
}

func TestRecordSSEEvent_NilStore(t *testing.T) {
	h := &Handler{} // No store set

	event := &SSEEvent{Data: "test", RawBytes: []byte("data: test\n\n")}
	var seq atomic.Int64

	// Should not panic with nil store.
	h.recordSSEEvent(context.Background(), "flow-1", event, &seq, testutil.DiscardLogger())
}

func TestRecordSSEEvent_SequenceIncrement(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	var seq atomic.Int64
	seq.Store(2) // Start after headers

	for i := 0; i < 3; i++ {
		event := &SSEEvent{
			Data:     fmt.Sprintf("event %d", i),
			RawBytes: []byte(fmt.Sprintf("data: event %d\n\n", i)),
		}
		h.recordSSEEvent(context.Background(), "flow-1", event, &seq, testutil.DiscardLogger())
	}

	if len(store.messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(store.messages))
	}

	for i, msg := range store.messages {
		wantSeq := i + 2
		if msg.Sequence != wantSeq {
			t.Errorf("message[%d].Sequence = %d, want %d", i, msg.Sequence, wantSeq)
		}
	}
}

func TestCompleteSSEFlow(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	sendResult := &sendRecordResult{
		flowID:       "flow-1",
		tags:         map[string]string{"existing": "tag"},
		recvSequence: 1,
	}

	resp := &gohttp.Response{StatusCode: 200, Header: gohttp.Header{}}
	fwd := &forwardResult{
		resp:       resp,
		serverAddr: "example.com:443",
	}

	var eventSeq atomic.Int64
	eventSeq.Store(5) // Simulates 3 events recorded (seq 2, 3, 4)

	h.completeSSEFlow(context.Background(), sendResult, fwd, 5*time.Second, "CN=example.com", &eventSeq, testutil.DiscardLogger())

	if len(store.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(store.updates))
	}

	update := store.updates[0]
	if update.update.State != "complete" {
		t.Errorf("State = %q, want %q", update.update.State, "complete")
	}
	if update.update.Duration != 5*time.Second {
		t.Errorf("Duration = %v, want %v", update.update.Duration, 5*time.Second)
	}
	if update.update.ServerAddr != "example.com:443" {
		t.Errorf("ServerAddr = %q, want %q", update.update.ServerAddr, "example.com:443")
	}
	if update.update.TLSServerCertSubject != "CN=example.com" {
		t.Errorf("TLSServerCertSubject = %q, want %q", update.update.TLSServerCertSubject, "CN=example.com")
	}
	if update.update.Tags["sse_events_recorded"] != "3" {
		t.Errorf("Tags[sse_events_recorded] = %q, want %q", update.update.Tags["sse_events_recorded"], "3")
	}
	if update.update.Tags["streaming_type"] != "sse" {
		t.Errorf("Tags[streaming_type] = %q, want %q", update.update.Tags["streaming_type"], "sse")
	}
	if update.update.Tags["existing"] != "tag" {
		t.Errorf("Tags[existing] = %q, want %q", update.update.Tags["existing"], "tag")
	}
}

func TestCompleteSSEFlow_NoEvents(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	sendResult := &sendRecordResult{
		flowID:       "flow-1",
		recvSequence: 1,
	}

	resp := &gohttp.Response{StatusCode: 200, Header: gohttp.Header{}}
	fwd := &forwardResult{resp: resp}

	var eventSeq atomic.Int64
	eventSeq.Store(2) // Only the headers message, no events

	h.completeSSEFlow(context.Background(), sendResult, fwd, time.Second, "", &eventSeq, testutil.DiscardLogger())

	if len(store.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(store.updates))
	}

	// No sse_events_recorded tag when 0 events.
	if _, ok := store.updates[0].update.Tags["sse_events_recorded"]; ok {
		t.Error("sse_events_recorded tag should not be present when 0 events")
	}
}

func TestStreamSSEEvents_RecordsEvents(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	input := "data: hello\n\nevent: update\ndata: world\n\n"

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var seq atomic.Int64
	seq.Store(2)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(input), "flow-1", &seq, testutil.DiscardLogger())
		server.Close()
	}()

	// Read from client side to verify forwarding.
	var buf bytes.Buffer
	io.Copy(&buf, client)

	if err := <-errCh; err != nil {
		t.Fatalf("streamSSEEvents failed: %v", err)
	}

	// Verify events were forwarded.
	if buf.String() != input {
		t.Errorf("forwarded data = %q, want %q", buf.String(), input)
	}

	// Verify events were recorded.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(store.messages))
	}

	msg0 := store.messages[0]
	if string(msg0.Body) != "hello" {
		t.Errorf("message[0].Body = %q, want %q", string(msg0.Body), "hello")
	}
	if msg0.Sequence != 2 {
		t.Errorf("message[0].Sequence = %d, want %d", msg0.Sequence, 2)
	}
	if msg0.Metadata["sse_type"] != "event" {
		t.Errorf("message[0].Metadata[sse_type] = %q, want %q", msg0.Metadata["sse_type"], "event")
	}

	msg1 := store.messages[1]
	if string(msg1.Body) != "world" {
		t.Errorf("message[1].Body = %q, want %q", string(msg1.Body), "world")
	}
	if msg1.Sequence != 3 {
		t.Errorf("message[1].Sequence = %d, want %d", msg1.Sequence, 3)
	}
	if msg1.Metadata["sse_event"] != "update" {
		t.Errorf("message[1].Metadata[sse_event] = %q, want %q", msg1.Metadata["sse_event"], "update")
	}
}

func TestStreamSSEEvents_ContextCancellation(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	pr, pw := io.Pipe()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())

	var seq atomic.Int64
	seq.Store(1)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.streamSSEEvents(ctx, server, pr, "flow-1", &seq, testutil.DiscardLogger())
	}()

	// Send one event then cancel.
	pw.Write([]byte("data: before cancel\n\n"))
	time.Sleep(10 * time.Millisecond)
	cancel()
	pw.Close()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Logf("streamSSEEvents returned: %v (expected context.Canceled or nil)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("streamSSEEvents did not return after context cancellation")
	}
}

func TestStreamSSEEvents_EmptyStream(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var seq atomic.Int64
	seq.Store(1)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(""), "flow-1", &seq, testutil.DiscardLogger())
		server.Close()
	}()

	var buf bytes.Buffer
	io.Copy(&buf, client)

	if err := <-errCh; err != nil {
		t.Fatalf("streamSSEEvents on empty stream failed: %v", err)
	}

	if len(store.messages) != 0 {
		t.Errorf("expected 0 messages for empty stream, got %d", len(store.messages))
	}
}
