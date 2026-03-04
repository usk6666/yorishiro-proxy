package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestRecordSend_Basic(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)

	result := handler.recordSend(ctx, sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        req,
		reqBody:    []byte("request body"),
	}, logger)

	if result == nil {
		t.Fatal("recordSend returned nil, expected non-nil result")
	}
	if result.flowID == "" {
		t.Fatal("flowID is empty")
	}

	// Verify flow was created with State="active".
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "active" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "active")
	}
	if entry.Session.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/1.x")
	}
	if entry.Session.ConnID != "conn-1" {
		t.Errorf("connID = %q, want %q", entry.Session.ConnID, "conn-1")
	}
	if entry.Session.Duration != 0 {
		t.Errorf("duration = %v, want 0 (not yet complete)", entry.Session.Duration)
	}

	// Verify send message was created.
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("method = %q, want %q", entry.Send.Method, "GET")
	}
	if string(entry.Send.Body) != "request body" {
		t.Errorf("request body = %q, want %q", entry.Send.Body, "request body")
	}

	// Verify no receive message yet.
	if entry.Receive != nil {
		t.Error("receive message should be nil after recordSend")
	}
}

func TestRecordSend_NilStore(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)

	result := handler.recordSend(ctx, sendRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		req:      req,
	}, logger)

	if result != nil {
		t.Errorf("recordSend with nil store should return nil, got %v", result)
	}
}

func TestRecordSend_WithReqURL(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req, _ := gohttp.NewRequest("POST", "https://example.com/api", nil)
	reqURL := &url.URL{
		Scheme:   "https",
		Host:     "example.com",
		Path:     "/api",
		RawQuery: "key=value",
	}

	result := handler.recordSend(ctx, sendRecordParams{
		protocol: "HTTPS",
		start:    time.Now(),
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqURL:   reqURL,
		reqBody:  []byte("body"),
	}, logger)

	if result == nil {
		t.Fatal("recordSend returned nil")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Send.URL.RawQuery != "key=value" {
		t.Errorf("URL query = %q, want %q", entries[0].Send.URL.RawQuery, "key=value")
	}
}

func TestRecordReceive_Basic(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	// First record send.
	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	sendResult := handler.recordSend(ctx, sendRecordParams{
		connID:   "conn-1",
		protocol: "HTTP/1.x",
		start:    start,
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqBody:  []byte("req"),
	}, logger)

	if sendResult == nil {
		t.Fatal("recordSend returned nil")
	}

	// Then record receive.
	resp := &gohttp.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     gohttp.Header{"Content-Type": {"text/plain"}},
	}
	duration := 50 * time.Millisecond

	handler.recordReceive(ctx, sendResult, receiveRecordParams{
		start:      start,
		duration:   duration,
		serverAddr: "93.184.216.34:80",
		resp:       resp,
		respBody:   []byte("response body"),
	}, logger)

	// Verify session is now complete.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.Duration != duration {
		t.Errorf("flow duration = %v, want %v", entry.Session.Duration, duration)
	}

	// Verify receive message.
	if entry.Receive == nil {
		t.Fatal("receive message is nil")
	}
	if entry.Receive.StatusCode != 200 {
		t.Errorf("status = %d, want %d", entry.Receive.StatusCode, 200)
	}
	if string(entry.Receive.Body) != "response body" {
		t.Errorf("response body = %q, want %q", entry.Receive.Body, "response body")
	}
}

func TestRecordReceive_NilSendResult(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	resp := &gohttp.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     gohttp.Header{},
	}

	// Should be a no-op when sendResult is nil.
	handler.recordReceive(ctx, nil, receiveRecordParams{
		start:    time.Now(),
		duration: time.Millisecond,
		resp:     resp,
		respBody: []byte("ok"),
	}, logger)

	entries := store.Entries()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries with nil sendResult, got %d", len(entries))
	}
}

func TestRecordReceive_NilResponse(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)
	sendResult := handler.recordSend(ctx, sendRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
	}, logger)

	// recordReceive with nil response should be a no-op (no receive message added).
	handler.recordReceive(ctx, sendResult, receiveRecordParams{
		start:    time.Now(),
		duration: time.Millisecond,
		resp:     nil,
	}, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Flow should still be "active" since recordReceive didn't execute.
	if entries[0].Session.State != "active" {
		t.Errorf("flow state = %q, want %q", entries[0].Session.State, "active")
	}
	if entries[0].Receive != nil {
		t.Error("receive message should be nil when resp is nil")
	}
}

func TestRecordSendError_Basic(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	// First record send.
	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	sendResult := handler.recordSend(ctx, sendRecordParams{
		connID:   "conn-1",
		protocol: "HTTP/1.x",
		start:    start,
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqBody:  []byte("req"),
	}, logger)

	if sendResult == nil {
		t.Fatal("recordSend returned nil")
	}

	// Then record error.
	upstreamErr := fmt.Errorf("upstream request: dial tcp 93.184.216.34:80: connection refused")
	handler.recordSendError(ctx, sendResult, start, upstreamErr, logger)

	// Verify session is in error state.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("flow duration = %v, want positive", entry.Session.Duration)
	}
	if entry.Session.Tags == nil {
		t.Fatal("flow tags is nil")
	}
	if _, ok := entry.Session.Tags["error"]; !ok {
		t.Error("flow tags should contain 'error' key")
	}

	// Verify send message is present but no receive.
	if entry.Send == nil {
		t.Fatal("send message should be present")
	}
	if entry.Receive != nil {
		t.Error("receive message should be nil for error session")
	}
}

func TestRecordSendError_NilSendResult(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	// Should be a no-op.
	handler.recordSendError(ctx, nil, time.Now(), fmt.Errorf("error"), logger)

	entries := store.Entries()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries with nil sendResult, got %d", len(entries))
	}
}

func TestRecordInterceptDrop_Basic(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("POST", "http://example.com/api", nil)

	handler.recordInterceptDrop(ctx, sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        req,
		reqBody:    []byte("intercepted body"),
	}, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.BlockedBy != "intercept_drop" {
		t.Errorf("flow BlockedBy = %q, want %q", entry.Session.BlockedBy, "intercept_drop")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("flow duration = %v, want positive", entry.Session.Duration)
	}

	// Verify send message is present but no receive.
	if entry.Send == nil {
		t.Fatal("send message should be present")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("method = %q, want %q", entry.Send.Method, "POST")
	}
	if string(entry.Send.Body) != "intercepted body" {
		t.Errorf("request body = %q, want %q", entry.Send.Body, "intercepted body")
	}
	if entry.Receive != nil {
		t.Error("receive message should be nil for intercept drop")
	}
}

func TestRecordInterceptDrop_NilStore(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)

	// Should not panic.
	handler.recordInterceptDrop(ctx, sendRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		req:      req,
	}, logger)
}

func TestRecordInterceptDrop_HTTPS(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "https://example.com/path", nil)
	reqURL := &url.URL{
		Scheme: "https",
		Host:   "example.com",
		Path:   "/path",
	}

	handler.recordInterceptDrop(ctx, sendRecordParams{
		connID:   "conn-1",
		protocol: "HTTPS",
		start:    start,
		connInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:1234",
			TLSVersion: "TLS 1.3",
			TLSCipher:  "TLS_AES_128_GCM_SHA256",
		},
		req:    req,
		reqURL: reqURL,
	}, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTPS")
	}
	if entry.Session.BlockedBy != "intercept_drop" {
		t.Errorf("BlockedBy = %q, want %q", entry.Session.BlockedBy, "intercept_drop")
	}
	if entry.Send.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", entry.Send.URL.Scheme, "https")
	}
}

func TestProgressiveRecording_FullLifecycle(t *testing.T) {
	// Test the full lifecycle: recordSend -> recordReceive
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("POST", "http://example.com/api", nil)
	req.Header.Set("Content-Type", "application/json")

	// Phase 1: Record send.
	sendResult := handler.recordSend(ctx, sendRecordParams{
		connID:     "conn-lifecycle",
		clientAddr: "10.0.0.1:5000",
		protocol:   "HTTP/1.x",
		start:      start,
		tags:       map[string]string{"test": "lifecycle"},
		connInfo:   &flow.ConnectionInfo{ClientAddr: "10.0.0.1:5000"},
		req:        req,
		reqBody:    []byte(`{"key":"value"}`),
		rawRequest: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}, logger)

	if sendResult == nil {
		t.Fatal("recordSend returned nil")
	}

	// Verify intermediate state: session is active, only send message exists.
	fl, err := store.GetFlow(ctx, sendResult.flowID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if fl.State != "active" {
		t.Errorf("after send: state = %q, want %q", fl.State, "active")
	}

	msgs, _ := store.GetMessages(ctx, sendResult.flowID, flow.MessageListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("after send: expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Direction != "send" {
		t.Errorf("after send: message direction = %q, want %q", msgs[0].Direction, "send")
	}

	// Phase 2: Record receive.
	duration := 100 * time.Millisecond
	resp := &gohttp.Response{
		StatusCode: 201,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     gohttp.Header{"Content-Type": {"application/json"}},
	}

	handler.recordReceive(ctx, sendResult, receiveRecordParams{
		start:      start,
		duration:   duration,
		serverAddr: "93.184.216.34:80",
		resp:       resp,
		respBody:   []byte(`{"status":"created"}`),
		rawResponse: []byte("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n"),
	}, logger)

	// Verify final state: session is complete, both messages exist.
	fl, err = store.GetFlow(ctx, sendResult.flowID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if fl.State != "complete" {
		t.Errorf("after receive: state = %q, want %q", fl.State, "complete")
	}
	if fl.Duration != duration {
		t.Errorf("after receive: duration = %v, want %v", fl.Duration, duration)
	}

	msgs, _ = store.GetMessages(ctx, sendResult.flowID, flow.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("after receive: expected 2 messages, got %d", len(msgs))
	}

	// Verify message ordering.
	var sendMsg, recvMsg *flow.Message
	for _, m := range msgs {
		if m.Direction == "send" {
			sendMsg = m
		} else if m.Direction == "receive" {
			recvMsg = m
		}
	}
	if sendMsg == nil {
		t.Fatal("send message not found")
	}
	if recvMsg == nil {
		t.Fatal("receive message not found")
	}
	if recvMsg.StatusCode != 201 {
		t.Errorf("receive status = %d, want %d", recvMsg.StatusCode, 201)
	}
}

func TestProgressiveRecording_ErrorLifecycle(t *testing.T) {
	// Test the error lifecycle: recordSend -> recordSendError (502 path)
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://unreachable.example.com/test", nil)

	// Phase 1: Record send.
	sendResult := handler.recordSend(ctx, sendRecordParams{
		connID:     "conn-error",
		clientAddr: "10.0.0.1:5000",
		protocol:   "HTTP/1.x",
		start:      start,
		connInfo:   &flow.ConnectionInfo{ClientAddr: "10.0.0.1:5000"},
		req:        req,
		reqBody:    nil,
	}, logger)

	if sendResult == nil {
		t.Fatal("recordSend returned nil")
	}

	// Phase 2: Record error (simulating upstream failure).
	upstreamErr := fmt.Errorf("upstream request: dial tcp: lookup unreachable.example.com: no such host")
	handler.recordSendError(ctx, sendResult, start, upstreamErr, logger)

	// Verify: session is in error state with error tag.
	fl, err := store.GetFlow(ctx, sendResult.flowID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if fl.State != "error" {
		t.Errorf("state = %q, want %q", fl.State, "error")
	}
	if fl.Tags == nil || fl.Tags["error"] == "" {
		t.Error("flow should have 'error' tag")
	}
	if fl.Duration <= 0 {
		t.Errorf("duration = %v, want positive", fl.Duration)
	}

	// Verify: only send message, no receive.
	msgs, _ := store.GetMessages(ctx, sendResult.flowID, flow.MessageListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (send only), got %d", len(msgs))
	}
	if msgs[0].Direction != "send" {
		t.Errorf("message direction = %q, want %q", msgs[0].Direction, "send")
	}
}

func TestProgressiveRecording_Tags(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)
	tags := map[string]string{"smuggling:cl_te_conflict": "true"}

	sendResult := handler.recordSend(ctx, sendRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		tags:     tags,
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
	}, logger)

	if sendResult == nil {
		t.Fatal("recordSend returned nil")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Session.Tags["smuggling:cl_te_conflict"] != "true" {
		t.Errorf("tags = %v, want smuggling:cl_te_conflict=true", entries[0].Session.Tags)
	}
}

func TestProgressiveRecording_TLSConnInfo(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	req, _ := gohttp.NewRequest("GET", "https://example.com", nil)

	sendResult := handler.recordSend(ctx, sendRecordParams{
		protocol: "HTTPS",
		start:    time.Now(),
		connInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:1234",
			ServerAddr: "93.184.216.34:443",
			TLSVersion: "TLS 1.3",
			TLSCipher:  "TLS_AES_128_GCM_SHA256",
			TLSALPN:    "h2",
		},
		req: req,
	}, logger)

	if sendResult == nil {
		t.Fatal("recordSend returned nil")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	ci := entries[0].Session.ConnInfo
	if ci == nil {
		t.Fatal("ConnInfo is nil")
	}
	if ci.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want %q", ci.TLSVersion, "TLS 1.3")
	}
	if ci.TLSCipher != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("TLSCipher = %q, want %q", ci.TLSCipher, "TLS_AES_128_GCM_SHA256")
	}
}

// TestHTTP_UpstreamFailure_RecordsSession verifies that when an upstream server
// is unreachable, the proxy records the flow with State="error" and the send
// message, rather than silently discarding it. This is the key behavior change
// introduced by progressive recording.
func TestHTTP_UpstreamFailure_RecordsSession(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Connect to the proxy and send a request to a non-existent upstream.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Use a URL that will fail to connect upstream (invalid port on localhost).
	httpReq := "GET http://127.0.0.1:1/fail HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(httpReq))

	// Read the 502 response.
	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}

	// Wait for async recording to complete.
	time.Sleep(200 * time.Millisecond)

	// Verify flow was recorded with error state.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry (error), got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Tags == nil || entry.Session.Tags["error"] == "" {
		t.Error("flow should have 'error' tag with error message")
	}

	// Verify send message is present.
	if entry.Send == nil {
		t.Fatal("send message should be present for error sessions")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "GET")
	}

	// Verify no receive message.
	if entry.Receive != nil {
		t.Error("receive message should be nil for error sessions")
	}
}

// TestHTTPS_UpstreamFailure_RecordsSession verifies the same behavior for HTTPS
// requests through a CONNECT tunnel.
func TestHTTPS_UpstreamFailure_RecordsSession(t *testing.T) {
	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	// Use a transport that will always fail to connect upstream.
	handler.Transport = &gohttp.Transport{
		// Force dial failure by using an invalid dialer.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("simulated connection refused")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, "localhost:443", rootCAs)
	defer tlsConn.Close()

	// Send a request that will fail upstream.
	httpReq := "GET /test-fail HTTP/1.1\r\nHost: localhost:443\r\nConnection: close\r\n\r\n"
	tlsConn.Write([]byte(httpReq))

	// Read the 502 response.
	httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	if httpsResp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", httpsResp.StatusCode, gohttp.StatusBadGateway)
	}

	// Wait for recording.
	time.Sleep(200 * time.Millisecond)

	// Verify error flow was recorded.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry (error), got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTPS")
	}
	if entry.Send == nil {
		t.Fatal("send message should be present for HTTPS error sessions")
	}
	if entry.Receive != nil {
		t.Error("receive message should be nil for error sessions")
	}
}

// TestHTTP_NormalRequest_ProgressiveRecording verifies that normal HTTP requests
// still produce the same result (State="complete", send + receive messages).
func TestHTTP_NormalRequest_ProgressiveRecording(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "progressive")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "progressive-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "progressive-ok" {
		t.Errorf("body = %q, want %q", body, "progressive-ok")
	}

	// Wait for recording.
	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/1.x")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Receive == nil {
		t.Fatal("receive message is nil")
	}
	if entry.Receive.StatusCode != 200 {
		t.Errorf("receive status = %d, want %d", entry.Receive.StatusCode, 200)
	}
}
