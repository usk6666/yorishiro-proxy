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
	"github.com/usk6666/yorishiro-proxy/internal/safety"
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

	dropped := h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())
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

	dropped := h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())
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
	// Capture the enqueued item's body to verify it is nil.
	type itemInfo struct {
		body []byte
	}
	itemCh := make(chan itemInfo, 1)
	go func() {
		// Wait for the item to appear in the queue.
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				itemCh <- itemInfo{body: items[0].Body}
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	dropped := h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())
	if !dropped {
		t.Error("applySSEIntercept should return true when DROP action is received")
	}

	// Verify the enqueued item had nil body (SSE streams cannot buffer the body).
	select {
	case info := <-itemCh:
		if info.body != nil {
			t.Errorf("enqueued item body should be nil for SSE intercept, got %v", info.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for intercept queue item")
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
	// Capture the enqueued item's body to verify it is nil.
	type itemInfo struct {
		body []byte
	}
	itemCh := make(chan itemInfo, 1)
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				itemCh <- itemInfo{body: items[0].Body}
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	dropped := h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())
	if dropped {
		t.Error("applySSEIntercept should return false when RELEASE action is received")
	}

	// Verify the enqueued item had nil body (SSE streams cannot buffer the body).
	select {
	case info := <-itemCh:
		if info.body != nil {
			t.Errorf("enqueued item body should be nil for SSE intercept, got %v", info.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for intercept queue item")
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
	// Capture the enqueued item's body to verify it is nil.
	type itemInfo struct {
		body []byte
	}
	itemCh := make(chan itemInfo, 1)
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				itemCh <- itemInfo{body: items[0].Body}
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionModifyAndForward})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	dropped := h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())
	if dropped {
		t.Error("applySSEIntercept should return false for ModifyAndForward (treated as release)")
	}

	// Verify the enqueued item had nil body (SSE streams cannot buffer the body).
	select {
	case info := <-itemCh:
		if info.body != nil {
			t.Errorf("enqueued item body should be nil for SSE intercept, got %v", info.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for intercept queue item")
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
	dropped := h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())
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
	dropped := h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())
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
	type itemInfo struct {
		body []byte
	}
	itemCh := make(chan itemInfo, 1)
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				itemCh <- itemInfo{body: items[0].Body}
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	h.applySSEIntercept(context.Background(), server, goRequestToRaw(req), req.URL, goResponseToRaw(resp, nil), testutil.DiscardLogger())

	// Verify the enqueued item had nil body (SSE streams cannot buffer the body).
	select {
	case info := <-itemCh:
		if info.body != nil {
			t.Errorf("enqueued item body should be nil for SSE intercept, got %v", info.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for intercept queue item")
	}
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

	rawResp := goResponseToRaw(resp, nil)
	rawResp.Body = io.NopCloser(strings.NewReader(input))

	fwd := &forwardResult{
		resp:       rawResp,
		serverAddr: "127.0.0.1:8080",
	}

	sendResult := &sendRecordResult{
		flowID:       "flow-1",
		recvSequence: 1,
	}

	goReqSSE := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleSSEStream(context.Background(), server, goRequestToRaw(goReqSSE), goReqSSE.URL, fwd, time.Now(), sendResult, nil, testutil.DiscardLogger())
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
		resp:       goResponseToRaw(resp, nil),
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
	fwd := &forwardResult{resp: goResponseToRaw(resp, nil)}

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
		resp:       goResponseToRaw(resp, nil),
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
		resp:       goResponseToRaw(resp, nil),
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
	fwd := &forwardResult{resp: goResponseToRaw(resp, nil)}

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
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(input), "flow-1", &seq, nil, testutil.DiscardLogger())
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
		errCh <- h.streamSSEEvents(ctx, server, pr, "flow-1", &seq, nil, testutil.DiscardLogger())
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
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(""), "flow-1", &seq, nil, testutil.DiscardLogger())
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

// newTestSafetyEngine creates a safety engine with the given output rules
// for testing. It panics on error since test setup failures should abort.
func newTestSafetyEngine(t *testing.T, outputRules []safety.RuleConfig) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: outputRules,
	})
	if err != nil {
		t.Fatalf("failed to create safety engine: %v", err)
	}
	return engine
}

func TestApplySSEOutputFilter_NilEngine(t *testing.T) {
	h := &Handler{}
	event := &SSEEvent{
		Data:     "hello world",
		RawBytes: []byte("data: hello world\n\n"),
	}

	sendBytes, blocked := h.applySSEOutputFilter(event, testutil.DiscardLogger())
	if blocked {
		t.Error("expected blocked=false with nil engine")
	}
	if string(sendBytes) != string(event.RawBytes) {
		t.Errorf("sendBytes = %q, want %q", string(sendBytes), string(event.RawBytes))
	}
}

func TestApplySSEOutputFilter_NoRules(t *testing.T) {
	engine := newTestSafetyEngine(t, nil)
	h := &Handler{}
	h.SafetyEngine = engine

	event := &SSEEvent{
		Data:     "hello world",
		RawBytes: []byte("data: hello world\n\n"),
	}

	sendBytes, blocked := h.applySSEOutputFilter(event, testutil.DiscardLogger())
	if blocked {
		t.Error("expected blocked=false with no rules")
	}
	if string(sendBytes) != string(event.RawBytes) {
		t.Errorf("sendBytes = %q, want %q", string(sendBytes), string(event.RawBytes))
	}
}

func TestApplySSEOutputFilter_MaskAction(t *testing.T) {
	engine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:          "mask-secret",
			Name:        "Mask Secret",
			Pattern:     `SECRET-\d+`,
			Targets:     []string{"body"},
			Action:      "mask",
			Replacement: "[MASKED]",
		},
	})

	h := &Handler{}
	h.SafetyEngine = engine

	event := &SSEEvent{
		EventType: "message",
		Data:      "token is SECRET-12345",
		ID:        "1",
		RawBytes:  []byte("event: message\nid: 1\ndata: token is SECRET-12345\n\n"),
	}

	sendBytes, blocked := h.applySSEOutputFilter(event, testutil.DiscardLogger())
	if blocked {
		t.Error("expected blocked=false for mask action")
	}

	// Verify the sent bytes contain masked data.
	sent := string(sendBytes)
	if strings.Contains(sent, "SECRET-12345") {
		t.Error("sendBytes should not contain unmasked secret")
	}
	if !strings.Contains(sent, "[MASKED]") {
		t.Errorf("sendBytes should contain [MASKED], got %q", sent)
	}
	// Verify the event structure is preserved (event type, id).
	if !strings.Contains(sent, "event: message") {
		t.Errorf("sendBytes should preserve event type, got %q", sent)
	}
	if !strings.Contains(sent, "id: 1") {
		t.Errorf("sendBytes should preserve event id, got %q", sent)
	}
}

func TestApplySSEOutputFilter_BlockAction(t *testing.T) {
	engine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:      "block-dangerous",
			Name:    "Block Dangerous",
			Pattern: `DANGEROUS`,
			Targets: []string{"body"},
			Action:  "block",
		},
	})

	h := &Handler{}
	h.SafetyEngine = engine

	event := &SSEEvent{
		Data:     "payload contains DANGEROUS content",
		RawBytes: []byte("data: payload contains DANGEROUS content\n\n"),
	}

	sendBytes, blocked := h.applySSEOutputFilter(event, testutil.DiscardLogger())
	if !blocked {
		t.Error("expected blocked=true for block action")
	}
	if sendBytes != nil {
		t.Errorf("sendBytes should be nil when blocked, got %q", string(sendBytes))
	}
}

func TestApplySSEOutputFilter_LogOnlyAction(t *testing.T) {
	engine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:      "log-pii",
			Name:    "Log PII",
			Pattern: `user@example\.com`,
			Targets: []string{"body"},
			Action:  "log_only",
		},
	})

	h := &Handler{}
	h.SafetyEngine = engine

	event := &SSEEvent{
		Data:     "contact user@example.com",
		RawBytes: []byte("data: contact user@example.com\n\n"),
	}

	sendBytes, blocked := h.applySSEOutputFilter(event, testutil.DiscardLogger())
	if blocked {
		t.Error("expected blocked=false for log_only action")
	}
	// log_only should forward original bytes unchanged.
	if string(sendBytes) != string(event.RawBytes) {
		t.Errorf("sendBytes = %q, want %q", string(sendBytes), string(event.RawBytes))
	}
}

func TestApplySSEOutputFilter_NoMatch(t *testing.T) {
	engine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:          "mask-ssn",
			Name:        "Mask SSN",
			Pattern:     `\d{3}-\d{2}-\d{4}`,
			Targets:     []string{"body"},
			Action:      "mask",
			Replacement: "[SSN]",
		},
	})

	h := &Handler{}
	h.SafetyEngine = engine

	event := &SSEEvent{
		Data:     "no sensitive data here",
		RawBytes: []byte("data: no sensitive data here\n\n"),
	}

	sendBytes, blocked := h.applySSEOutputFilter(event, testutil.DiscardLogger())
	if blocked {
		t.Error("expected blocked=false when no match")
	}
	if string(sendBytes) != string(event.RawBytes) {
		t.Errorf("sendBytes = %q, want %q (should be unchanged)", string(sendBytes), string(event.RawBytes))
	}
}

func TestApplySSEOutputFilter_MultilineData(t *testing.T) {
	engine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:          "mask-token",
			Name:        "Mask Token",
			Pattern:     `tok_[a-zA-Z0-9]+`,
			Targets:     []string{"body"},
			Action:      "mask",
			Replacement: "[TOKEN]",
		},
	})

	h := &Handler{}
	h.SafetyEngine = engine

	event := &SSEEvent{
		Data:     "line1 tok_abc123\nline2 tok_def456",
		RawBytes: []byte("data: line1 tok_abc123\ndata: line2 tok_def456\n\n"),
	}

	sendBytes, blocked := h.applySSEOutputFilter(event, testutil.DiscardLogger())
	if blocked {
		t.Error("expected blocked=false")
	}

	sent := string(sendBytes)
	if strings.Contains(sent, "tok_abc123") || strings.Contains(sent, "tok_def456") {
		t.Errorf("sendBytes should not contain unmasked tokens, got %q", sent)
	}
	if !strings.Contains(sent, "[TOKEN]") {
		t.Errorf("sendBytes should contain [TOKEN], got %q", sent)
	}
}

func TestStreamSSEEvents_WithOutputFilter_Mask(t *testing.T) {
	store := &sseTestFlowStore{}
	engine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:          "mask-secret",
			Name:        "Mask Secret",
			Pattern:     `SECRET-\d+`,
			Targets:     []string{"body"},
			Action:      "mask",
			Replacement: "[MASKED]",
		},
	})

	h := &Handler{}
	h.Store = store
	h.SafetyEngine = engine

	input := "data: has SECRET-999\n\ndata: clean data\n\n"

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var seq atomic.Int64
	seq.Store(2)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(input), "flow-1", &seq, nil, testutil.DiscardLogger())
		server.Close()
	}()

	var buf bytes.Buffer
	io.Copy(&buf, client)

	if err := <-errCh; err != nil {
		t.Fatalf("streamSSEEvents failed: %v", err)
	}

	// Verify the client received masked data.
	output := buf.String()
	if strings.Contains(output, "SECRET-999") {
		t.Error("client received unmasked secret data")
	}
	if !strings.Contains(output, "[MASKED]") {
		t.Errorf("client should receive masked data, got %q", output)
	}
	// Second event should pass through unchanged.
	if !strings.Contains(output, "clean data") {
		t.Errorf("client should receive clean data, got %q", output)
	}

	// Verify flow recording stores original (unfiltered) data.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(store.messages))
	}
	if string(store.messages[0].Body) != "has SECRET-999" {
		t.Errorf("recorded body should be original data, got %q", string(store.messages[0].Body))
	}
}

func TestStreamSSEEvents_WithOutputFilter_Block(t *testing.T) {
	store := &sseTestFlowStore{}
	engine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:      "block-dangerous",
			Name:    "Block Dangerous",
			Pattern: `BLOCKED_PAYLOAD`,
			Targets: []string{"body"},
			Action:  "block",
		},
	})

	h := &Handler{}
	h.Store = store
	h.SafetyEngine = engine

	// First event is clean, second triggers block.
	input := "data: safe data\n\ndata: BLOCKED_PAYLOAD here\n\ndata: after block\n\n"

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var seq atomic.Int64
	seq.Store(2)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(input), "flow-1", &seq, nil, testutil.DiscardLogger())
		server.Close()
	}()

	var buf bytes.Buffer
	io.Copy(&buf, client)

	err := <-errCh
	if err != errSSEOutputFilterBlocked {
		t.Fatalf("expected errSSEOutputFilterBlocked, got %v", err)
	}

	// Only the first (safe) event should have been forwarded.
	output := buf.String()
	if !strings.Contains(output, "safe data") {
		t.Errorf("client should have received safe event, got %q", output)
	}
	if strings.Contains(output, "BLOCKED_PAYLOAD") {
		t.Error("client should not have received blocked event")
	}
	if strings.Contains(output, "after block") {
		t.Error("client should not have received events after block")
	}

	// Both the safe event and the blocked event should be recorded. Recording
	// happens before the output filter (raw data is preserved for forensics),
	// so the blocked event is recorded before the stream is terminated.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 recorded messages (including blocked event), got %d", len(store.messages))
	}
	if string(store.messages[0].Body) != "safe data" {
		t.Errorf("message[0].Body = %q, want %q", string(store.messages[0].Body), "safe data")
	}
	if string(store.messages[1].Body) != "BLOCKED_PAYLOAD here" {
		t.Errorf("message[1].Body = %q, want %q", string(store.messages[1].Body), "BLOCKED_PAYLOAD here")
	}
}

// --- SSE Event-Level Intercept Tests ---

func TestApplySSEEventIntercept_NoEngine(t *testing.T) {
	h := &Handler{}
	event := &SSEEvent{Data: "hello", RawBytes: []byte("data: hello\n\n")}

	got, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", nil, testutil.DiscardLogger())
	if dropped {
		t.Error("expected dropped=false with no engine")
	}
	if got.Data != event.Data {
		t.Errorf("event data = %q, want %q", got.Data, event.Data)
	}
}

func TestApplySSEEventIntercept_NilContext(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	event := &SSEEvent{Data: "hello", RawBytes: []byte("data: hello\n\n")}

	// nil sseCtx should skip intercept.
	got, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", nil, testutil.DiscardLogger())
	if dropped {
		t.Error("expected dropped=false with nil sseCtx")
	}
	if got.Data != event.Data {
		t.Errorf("event data = %q, want %q", got.Data, event.Data)
	}
}

func TestApplySSEEventIntercept_NoMatchingRules(t *testing.T) {
	engine := intercept.NewEngine()
	// Add request-only rule that won't match responses.
	engine.AddRule(intercept.Rule{
		ID:        "req-only",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	})

	queue := intercept.NewQueue()
	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	event := &SSEEvent{Data: "hello", RawBytes: []byte("data: hello\n\n")}
	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	got, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", sseCtx, testutil.DiscardLogger())
	if dropped {
		t.Error("expected dropped=false when no rules match")
	}
	if got.Data != event.Data {
		t.Errorf("event data = %q, want %q", got.Data, event.Data)
	}
}

func TestApplySSEEventIntercept_Drop(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "drop-event",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	event := &SSEEvent{Data: "drop me", RawBytes: []byte("data: drop me\n\n")}
	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	// Resolve with DROP action in a goroutine.
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	_, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", sseCtx, testutil.DiscardLogger())
	if !dropped {
		t.Error("expected dropped=true when DROP action is received")
	}
}

func TestApplySSEEventIntercept_Release(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "release-event",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	event := &SSEEvent{Data: "keep me", RawBytes: []byte("data: keep me\n\n")}
	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

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

	got, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", sseCtx, testutil.DiscardLogger())
	if dropped {
		t.Error("expected dropped=false when RELEASE action is received")
	}
	if got.Data != event.Data {
		t.Errorf("event data = %q, want %q", got.Data, event.Data)
	}
}

func TestApplySSEEventIntercept_ModifyAndForward(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "modify-event",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	event := &SSEEvent{
		EventType: "original-type",
		Data:      "original data",
		ID:        "1",
		RawBytes:  []byte("event: original-type\nid: 1\ndata: original data\n\n"),
	}
	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	newBody := "modified data"
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{
					Type:                    intercept.ActionModifyAndForward,
					OverrideResponseBody:    &newBody,
					OverrideResponseHeaders: map[string]string{"X-SSE-Event": "modified-type"},
				})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	got, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", sseCtx, testutil.DiscardLogger())
	if dropped {
		t.Error("expected dropped=false for ModifyAndForward")
	}
	if got.Data != "modified data" {
		t.Errorf("event Data = %q, want %q", got.Data, "modified data")
	}
	if got.EventType != "modified-type" {
		t.Errorf("event EventType = %q, want %q", got.EventType, "modified-type")
	}
	// ID should be unchanged since we didn't override it.
	if got.ID != "1" {
		t.Errorf("event ID = %q, want %q", got.ID, "1")
	}
}

func TestApplySSEEventIntercept_Timeout_AutoRelease(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "timeout-event",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(50 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoRelease)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	event := &SSEEvent{Data: "timeout me", RawBytes: []byte("data: timeout me\n\n")}
	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	// Don't resolve — let it timeout with auto_release.
	_, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", sseCtx, testutil.DiscardLogger())
	if dropped {
		t.Error("expected dropped=false on timeout with auto_release")
	}
}

func TestApplySSEEventIntercept_Timeout_AutoDrop(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "timeout-drop-event",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(50 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoDrop)

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	event := &SSEEvent{Data: "timeout drop", RawBytes: []byte("data: timeout drop\n\n")}
	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	// Don't resolve — let it timeout with auto_drop.
	_, dropped := h.applySSEEventIntercept(context.Background(), event, "flow-1", sseCtx, testutil.DiscardLogger())
	if !dropped {
		t.Error("expected dropped=true on timeout with auto_drop")
	}
}

func TestApplySSEEventIntercept_OutputFilterAppliedToEnqueuedBody(t *testing.T) {
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "filter-check",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	safetyEngine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:          "mask-secret",
			Name:        "Mask Secret",
			Pattern:     `SECRET-\d+`,
			Targets:     []string{"body"},
			Action:      "mask",
			Replacement: "[MASKED]",
		},
	})

	h := &Handler{}
	h.InterceptEngine = engine
	h.InterceptQueue = queue
	h.SafetyEngine = safetyEngine

	event := &SSEEvent{Data: "token SECRET-123", RawBytes: []byte("data: token SECRET-123\n\n")}
	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	// Capture the enqueued item's body.
	bodyCh := make(chan []byte, 1)
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				bodyCh <- items[0].Body
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	h.applySSEEventIntercept(context.Background(), event, "flow-1", sseCtx, testutil.DiscardLogger())

	select {
	case body := <-bodyCh:
		bodyStr := string(body)
		if strings.Contains(bodyStr, "SECRET-123") {
			t.Error("enqueued body should have SECRET masked")
		}
		if !strings.Contains(bodyStr, "[MASKED]") {
			t.Errorf("enqueued body should contain [MASKED], got %q", bodyStr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for intercept queue item")
	}
}

// --- SSE Event Modifications Tests ---

func TestApplySSEEventModifications(t *testing.T) {
	tests := []struct {
		name      string
		event     *SSEEvent
		action    intercept.InterceptAction
		wantData  string
		wantType  string
		wantID    string
		wantRetry string
	}{
		{
			name:  "override body only",
			event: &SSEEvent{EventType: "msg", Data: "original", ID: "1"},
			action: intercept.InterceptAction{
				Type:                 intercept.ActionModifyAndForward,
				OverrideResponseBody: strPtr("new data"),
			},
			wantData: "new data",
			wantType: "msg",
			wantID:   "1",
		},
		{
			name:  "override event type via headers",
			event: &SSEEvent{EventType: "old", Data: "data"},
			action: intercept.InterceptAction{
				Type:                    intercept.ActionModifyAndForward,
				OverrideResponseHeaders: map[string]string{"X-SSE-Event": "new-type"},
			},
			wantData: "data",
			wantType: "new-type",
		},
		{
			name:  "override ID and retry via add headers",
			event: &SSEEvent{Data: "data", ID: "old-id"},
			action: intercept.InterceptAction{
				Type:               intercept.ActionModifyAndForward,
				AddResponseHeaders: map[string]string{"X-SSE-Id": "new-id", "X-SSE-Retry": "3000"},
			},
			wantData:  "data",
			wantID:    "new-id",
			wantRetry: "3000",
		},
		{
			name:  "override everything",
			event: &SSEEvent{EventType: "a", Data: "b", ID: "c", Retry: "1000"},
			action: intercept.InterceptAction{
				Type:                    intercept.ActionModifyAndForward,
				OverrideResponseBody:    strPtr("new-body"),
				OverrideResponseHeaders: map[string]string{"X-SSE-Event": "x", "X-SSE-Id": "y", "X-SSE-Retry": "2000"},
			},
			wantData:  "new-body",
			wantType:  "x",
			wantID:    "y",
			wantRetry: "2000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applySSEEventModifications(tt.event, tt.action)
			if got.Data != tt.wantData {
				t.Errorf("Data = %q, want %q", got.Data, tt.wantData)
			}
			if got.EventType != tt.wantType {
				t.Errorf("EventType = %q, want %q", got.EventType, tt.wantType)
			}
			if got.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", got.ID, tt.wantID)
			}
			if got.Retry != tt.wantRetry {
				t.Errorf("Retry = %q, want %q", got.Retry, tt.wantRetry)
			}
			// RawBytes should be regenerated.
			if got.RawBytes == nil {
				t.Error("RawBytes should not be nil")
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// --- SSE Event Snapshot / Variant Tests ---

func TestSnapshotSSEEvent(t *testing.T) {
	event := &SSEEvent{
		EventType: "msg",
		Data:      "hello",
		ID:        "42",
		Retry:     "5000",
	}

	snap := snapshotSSEEvent(event)
	if snap.eventType != "msg" || snap.data != "hello" || snap.id != "42" || snap.retry != "5000" {
		t.Errorf("snapshot does not match event: %+v", snap)
	}
}

func TestSSEEventModified(t *testing.T) {
	tests := []struct {
		name  string
		snap  sseEventSnapshot
		event *SSEEvent
		want  bool
	}{
		{
			name:  "identical",
			snap:  sseEventSnapshot{eventType: "msg", data: "hello", id: "1"},
			event: &SSEEvent{EventType: "msg", Data: "hello", ID: "1"},
			want:  false,
		},
		{
			name:  "data changed",
			snap:  sseEventSnapshot{data: "original"},
			event: &SSEEvent{Data: "modified"},
			want:  true,
		},
		{
			name:  "event type changed",
			snap:  sseEventSnapshot{eventType: "old"},
			event: &SSEEvent{EventType: "new"},
			want:  true,
		},
		{
			name:  "id changed",
			snap:  sseEventSnapshot{id: "1"},
			event: &SSEEvent{ID: "2"},
			want:  true,
		},
		{
			name:  "retry changed",
			snap:  sseEventSnapshot{retry: "1000"},
			event: &SSEEvent{Retry: "2000"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sseEventModified(tt.snap, tt.event)
			if got != tt.want {
				t.Errorf("sseEventModified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordSSEEventWithVariant_NoModification(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	event := &SSEEvent{
		EventType: "msg",
		Data:      "hello",
		ID:        "1",
		RawBytes:  []byte("event: msg\nid: 1\ndata: hello\n\n"),
	}
	snap := snapshotSSEEvent(event)

	var seq atomic.Int64
	seq.Store(2)

	h.recordSSEEventWithVariant(context.Background(), "flow-1", event, &snap, &seq, testutil.DiscardLogger())

	// No modification: single message without variant metadata.
	if len(store.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(store.messages))
	}
	msg := store.messages[0]
	if _, ok := msg.Metadata["variant"]; ok {
		t.Error("variant metadata should not be set for unmodified event")
	}
	if msg.Sequence != 2 {
		t.Errorf("Sequence = %d, want 2", msg.Sequence)
	}
}

func TestRecordSSEEventWithVariant_Modified(t *testing.T) {
	store := &sseTestFlowStore{}
	h := &Handler{}
	h.Store = store

	snap := sseEventSnapshot{
		eventType: "original-type",
		data:      "original data",
		id:        "1",
	}

	modifiedEvent := &SSEEvent{
		EventType: "modified-type",
		Data:      "modified data",
		ID:        "1",
		RawBytes:  []byte("event: modified-type\nid: 1\ndata: modified data\n\n"),
	}

	var seq atomic.Int64
	seq.Store(2)

	h.recordSSEEventWithVariant(context.Background(), "flow-1", modifiedEvent, &snap, &seq, testutil.DiscardLogger())

	// Modified: two messages with variant metadata.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(store.messages))
	}

	// First message: original variant.
	orig := store.messages[0]
	if orig.Metadata["variant"] != "original" {
		t.Errorf("message[0] variant = %q, want %q", orig.Metadata["variant"], "original")
	}
	if string(orig.Body) != "original data" {
		t.Errorf("message[0] Body = %q, want %q", string(orig.Body), "original data")
	}
	if orig.Metadata["sse_event"] != "original-type" {
		t.Errorf("message[0] sse_event = %q, want %q", orig.Metadata["sse_event"], "original-type")
	}
	if orig.Sequence != 2 {
		t.Errorf("message[0] Sequence = %d, want 2", orig.Sequence)
	}

	// Second message: modified variant.
	mod := store.messages[1]
	if mod.Metadata["variant"] != "modified" {
		t.Errorf("message[1] variant = %q, want %q", mod.Metadata["variant"], "modified")
	}
	if string(mod.Body) != "modified data" {
		t.Errorf("message[1] Body = %q, want %q", string(mod.Body), "modified data")
	}
	if mod.Metadata["sse_event"] != "modified-type" {
		t.Errorf("message[1] sse_event = %q, want %q", mod.Metadata["sse_event"], "modified-type")
	}
	if mod.Sequence != 3 {
		t.Errorf("message[1] Sequence = %d, want 3", mod.Sequence)
	}
}

func TestRecordSSEEventWithVariant_NilStore(t *testing.T) {
	h := &Handler{} // No store

	event := &SSEEvent{Data: "test", RawBytes: []byte("data: test\n\n")}
	snap := snapshotSSEEvent(event)

	var seq atomic.Int64

	// Should not panic.
	h.recordSSEEventWithVariant(context.Background(), "flow-1", event, &snap, &seq, testutil.DiscardLogger())
}

// --- SSE Event-Level Plugin Hook Tests ---

func TestSSEEventToHTTPResponse(t *testing.T) {
	event := &SSEEvent{
		EventType: "notification",
		Data:      "hello world",
		ID:        "42",
		Retry:     "5000",
	}

	resp, body := sseEventToHTTPResponse(event)

	if string(body) != "hello world" {
		t.Errorf("body = %q, want %q", string(body), "hello world")
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", resp.Header.Get("Content-Type"), "text/event-stream")
	}
	if resp.Header.Get("X-SSE-Event") != "notification" {
		t.Errorf("X-SSE-Event = %q, want %q", resp.Header.Get("X-SSE-Event"), "notification")
	}
	if resp.Header.Get("X-SSE-Id") != "42" {
		t.Errorf("X-SSE-Id = %q, want %q", resp.Header.Get("X-SSE-Id"), "42")
	}
	if resp.Header.Get("X-SSE-Retry") != "5000" {
		t.Errorf("X-SSE-Retry = %q, want %q", resp.Header.Get("X-SSE-Retry"), "5000")
	}
}

func TestApplyHTTPResponseToSSEEvent_NoChange(t *testing.T) {
	original := &SSEEvent{
		EventType: "msg",
		Data:      "hello",
		ID:        "1",
		RawBytes:  []byte("event: msg\nid: 1\ndata: hello\n\n"),
	}

	resp, body := sseEventToHTTPResponse(original)
	got := applyHTTPResponseToSSEEvent(original, resp, body)

	// No change: RawBytes should be the original.
	if string(got.RawBytes) != string(original.RawBytes) {
		t.Errorf("RawBytes should be unchanged, got %q", string(got.RawBytes))
	}
}

func TestApplyHTTPResponseToSSEEvent_Changed(t *testing.T) {
	original := &SSEEvent{
		EventType: "msg",
		Data:      "hello",
		ID:        "1",
		RawBytes:  []byte("event: msg\nid: 1\ndata: hello\n\n"),
	}

	respHeaders := gohttp.Header{}
	respHeaders.Set("X-SSE-Event", "new-type")
	respHeaders.Set("X-SSE-Id", "1")
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     respHeaders,
	}
	body := []byte("new data")

	got := applyHTTPResponseToSSEEvent(original, resp, body)

	if got.EventType != "new-type" {
		t.Errorf("EventType = %q, want %q", got.EventType, "new-type")
	}
	if got.Data != "new data" {
		t.Errorf("Data = %q, want %q", got.Data, "new data")
	}
	// RawBytes should be regenerated since content changed.
	if strings.Contains(string(got.RawBytes), "hello") {
		t.Error("RawBytes should be regenerated for modified event")
	}
}

func TestApplyHTTPResponseToSSEEvent_NilResponse(t *testing.T) {
	original := &SSEEvent{Data: "hello", RawBytes: []byte("data: hello\n\n")}

	got := applyHTTPResponseToSSEEvent(original, nil, nil)
	if got != original {
		t.Error("nil response should return original event")
	}
}

func TestDispatchSSEOnReceiveFromServer_NilPlugin(t *testing.T) {
	h := &Handler{} // No plugin engine

	event := &SSEEvent{Data: "hello", RawBytes: []byte("data: hello\n\n")}
	got := h.dispatchSSEOnReceiveFromServer(context.Background(), event, nil, testutil.DiscardLogger())

	if got.Data != event.Data {
		t.Errorf("event should be unchanged, got %q", got.Data)
	}
}

func TestDispatchSSEOnBeforeSendToClient_NilPlugin(t *testing.T) {
	h := &Handler{} // No plugin engine

	event := &SSEEvent{Data: "hello", RawBytes: []byte("data: hello\n\n")}
	got := h.dispatchSSEOnBeforeSendToClient(context.Background(), event, nil, testutil.DiscardLogger())

	if got.Data != event.Data {
		t.Errorf("event should be unchanged, got %q", got.Data)
	}
}

// --- Integration: streamSSEEvents with intercept ---

func TestStreamSSEEvents_WithIntercept_Drop(t *testing.T) {
	store := &sseTestFlowStore{}
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "drop-events",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.Store = store
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	input := "data: event1\n\ndata: event2\n\ndata: event3\n\n"

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var seq atomic.Int64
	seq.Store(2)

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	// Drop the second event, release the first and third.
	var eventNum atomic.Int32
	go func() {
		for {
			items := queue.List()
			if len(items) > 0 {
				n := eventNum.Add(1)
				if n == 2 {
					queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				} else {
					queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				}
				// Wait briefly for the item to be removed.
				time.Sleep(5 * time.Millisecond)
			} else {
				time.Sleep(2 * time.Millisecond)
			}
			if eventNum.Load() >= 3 {
				return
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(input), "flow-1", &seq, sseCtx, testutil.DiscardLogger())
		server.Close()
	}()

	var buf bytes.Buffer
	io.Copy(&buf, client)

	if err := <-errCh; err != nil {
		t.Fatalf("streamSSEEvents failed: %v", err)
	}

	output := buf.String()
	// event1 and event3 should be forwarded, event2 should be dropped.
	if !strings.Contains(output, "event1") {
		t.Errorf("output should contain event1, got %q", output)
	}
	if strings.Contains(output, "event2") {
		t.Errorf("output should not contain event2 (dropped), got %q", output)
	}
	if !strings.Contains(output, "event3") {
		t.Errorf("output should contain event3, got %q", output)
	}
}

func TestStreamSSEEvents_WithIntercept_ModifyAndForward(t *testing.T) {
	store := &sseTestFlowStore{}
	engine := intercept.NewEngine()
	engine.AddRule(intercept.Rule{
		ID:        "modify-events",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)

	h := &Handler{}
	h.Store = store
	h.InterceptEngine = engine
	h.InterceptQueue = queue

	input := "data: original\n\n"

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var seq atomic.Int64
	seq.Store(2)

	req := &gohttp.Request{Method: "GET", URL: &url.URL{Path: "/events"}}
	sseCtx := &sseStreamContext{req: goRequestToRaw(req), reqURL: req.URL}

	newBody := "modified"
	go func() {
		for i := 0; i < 50; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{
					Type:                 intercept.ActionModifyAndForward,
					OverrideResponseBody: &newBody,
				})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.streamSSEEvents(context.Background(), server, strings.NewReader(input), "flow-1", &seq, sseCtx, testutil.DiscardLogger())
		server.Close()
	}()

	var buf bytes.Buffer
	io.Copy(&buf, client)

	if err := <-errCh; err != nil {
		t.Fatalf("streamSSEEvents failed: %v", err)
	}

	output := buf.String()
	// Client should receive modified data.
	if strings.Contains(output, "original") {
		t.Errorf("output should not contain original data, got %q", output)
	}
	if !strings.Contains(output, "modified") {
		t.Errorf("output should contain modified data, got %q", output)
	}

	// Recording should have both original and modified variants.
	if len(store.messages) != 2 {
		t.Fatalf("expected 2 messages (variant pair), got %d", len(store.messages))
	}
	if store.messages[0].Metadata["variant"] != "original" {
		t.Errorf("message[0] variant = %q, want %q", store.messages[0].Metadata["variant"], "original")
	}
	if string(store.messages[0].Body) != "original" {
		t.Errorf("message[0] Body = %q, want %q", string(store.messages[0].Body), "original")
	}
	if store.messages[1].Metadata["variant"] != "modified" {
		t.Errorf("message[1] variant = %q, want %q", store.messages[1].Metadata["variant"], "modified")
	}
	if string(store.messages[1].Body) != "modified" {
		t.Errorf("message[1] Body = %q, want %q", string(store.messages[1].Body), "modified")
	}
}

func TestFilterSSEEventBodyForIntercept_NoEngine(t *testing.T) {
	h := &Handler{}
	body := []byte("SECRET-123")
	got := h.filterSSEEventBodyForIntercept(body, testutil.DiscardLogger())
	if string(got) != string(body) {
		t.Errorf("got %q, want %q", string(got), string(body))
	}
}

func TestFilterSSEEventBodyForIntercept_WithMask(t *testing.T) {
	safetyEngine := newTestSafetyEngine(t, []safety.RuleConfig{
		{
			ID:          "mask-secret",
			Name:        "Mask Secret",
			Pattern:     `SECRET-\d+`,
			Targets:     []string{"body"},
			Action:      "mask",
			Replacement: "[MASKED]",
		},
	})

	h := &Handler{}
	h.SafetyEngine = safetyEngine

	body := []byte("token SECRET-123")
	got := h.filterSSEEventBodyForIntercept(body, testutil.DiscardLogger())
	if strings.Contains(string(got), "SECRET-123") {
		t.Error("expected SECRET to be masked")
	}
	if !strings.Contains(string(got), "[MASKED]") {
		t.Errorf("expected [MASKED] in output, got %q", string(got))
	}
}

func TestBuildSSEEventMessage(t *testing.T) {
	event := &SSEEvent{
		EventType: "msg",
		Data:      "hello",
		ID:        "1",
		Retry:     "5000",
		RawBytes:  []byte("event: msg\nid: 1\nretry: 5000\ndata: hello\n\n"),
	}

	msg := buildSSEEventMessage("flow-1", 3, event)

	if msg.FlowID != "flow-1" {
		t.Errorf("FlowID = %q, want %q", msg.FlowID, "flow-1")
	}
	if msg.Sequence != 3 {
		t.Errorf("Sequence = %d, want 3", msg.Sequence)
	}
	if msg.Direction != "receive" {
		t.Errorf("Direction = %q, want %q", msg.Direction, "receive")
	}
	if string(msg.Body) != "hello" {
		t.Errorf("Body = %q, want %q", string(msg.Body), "hello")
	}
	if msg.Metadata["sse_type"] != "event" {
		t.Errorf("Metadata[sse_type] = %q, want %q", msg.Metadata["sse_type"], "event")
	}
	if msg.Metadata["sse_event"] != "msg" {
		t.Errorf("Metadata[sse_event] = %q, want %q", msg.Metadata["sse_event"], "msg")
	}
	if msg.Metadata["sse_id"] != "1" {
		t.Errorf("Metadata[sse_id] = %q, want %q", msg.Metadata["sse_id"], "1")
	}
	if msg.Metadata["sse_retry"] != "5000" {
		t.Errorf("Metadata[sse_retry] = %q, want %q", msg.Metadata["sse_retry"], "5000")
	}
}
