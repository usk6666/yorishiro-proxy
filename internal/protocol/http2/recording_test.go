package http2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- Progressive recording tests ---

func TestHandleStream_ProgressiveRecording_NormalFlow(t *testing.T) {
	// Verify that the normal flow creates a session with State="active" first,
	// then updates it to State="complete" with Send + Receive messages.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Resp", "ok")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "progressive-response")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-progressive", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqBody := "progressive-body"
	reqURL := fmt.Sprintf("%s/api/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "progressive-response" {
		t.Errorf("body = %q, want %q", body, "progressive-response")
	}

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}

	entry := entries[0]
	// Session should be complete after the full flow.
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
	}
	if entry.Session.ConnInfo == nil {
		t.Fatal("conn_info is nil")
	}
	if entry.Session.ConnInfo.ClientAddr != "127.0.0.1:12345" {
		t.Errorf("client_addr = %q, want %q", entry.Session.ConnInfo.ClientAddr, "127.0.0.1:12345")
	}
	// ServerAddr should be set via UpdateSession.
	if entry.Session.ConnInfo.ServerAddr == "" {
		t.Error("server_addr should be set after successful upstream request")
	}

	// Send message.
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "POST")
	}
	if entry.Send.URL == nil || entry.Send.URL.Path != "/api/test" {
		t.Errorf("send URL path = %v, want /api/test", entry.Send.URL)
	}
	if string(entry.Send.Body) != reqBody {
		t.Errorf("send body = %q, want %q", entry.Send.Body, reqBody)
	}
	if entry.Send.Sequence != 0 {
		t.Errorf("send sequence = %d, want 0", entry.Send.Sequence)
	}

	// Receive message.
	if entry.Receive == nil {
		t.Fatal("receive message is nil")
	}
	if entry.Receive.StatusCode != gohttp.StatusOK {
		t.Errorf("receive status = %d, want %d", entry.Receive.StatusCode, gohttp.StatusOK)
	}
	if string(entry.Receive.Body) != "progressive-response" {
		t.Errorf("receive body = %q, want %q", entry.Receive.Body, "progressive-response")
	}
	if entry.Receive.Sequence != 1 {
		t.Errorf("receive sequence = %d, want 1", entry.Receive.Sequence)
	}
}

func TestHandleStream_ProgressiveRecording_UpstreamError(t *testing.T) {
	// When the upstream request fails (e.g., connection refused),
	// the session should be recorded with State="error" and a send message,
	// but no receive message.
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-upstream-err", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Request to a non-existent upstream (port 1 is typically unreachable).
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:1/unreachable", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry for upstream error, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Session.Tags == nil || entry.Session.Tags["error"] == "" {
		t.Errorf("expected error tag to be set, got tags = %v", entry.Session.Tags)
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
	}

	// Send message should be present.
	if entry.Send == nil {
		t.Fatal("send message is nil for upstream error")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "GET")
	}

	// Receive message should NOT be present.
	if entry.Receive != nil {
		t.Error("receive message should be nil for upstream error")
	}
}

func TestHandleStream_ProgressiveRecording_InterceptDrop(t *testing.T) {
	// When the request is dropped by intercept, the session should be recorded
	// with State="complete", BlockedBy="intercept_drop", and only a send message.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		t.Error("upstream should not be reached when request is dropped")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	upstreamURL, _ := url.Parse(upstream.URL)

	err := engine.AddRule(intercept.Rule{
		ID:        "drop-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: upstreamURL.Hostname(),
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	addr, cancel := startH2CProxyListener(t, handler, "test-drop-prog", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Drop the intercepted request in a goroutine.
	go func() {
		for i := 0; i < 200; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	reqURL := fmt.Sprintf("%s/dropped", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader([]byte("drop-me")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry for intercept drop, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.BlockedBy != "intercept_drop" {
		t.Errorf("blocked_by = %q, want %q", entry.Session.BlockedBy, "intercept_drop")
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}

	// Send message should be present.
	if entry.Send == nil {
		t.Fatal("send message is nil for intercept drop")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "POST")
	}
	if string(entry.Send.Body) != "drop-me" {
		t.Errorf("send body = %q, want %q", entry.Send.Body, "drop-me")
	}

	// Receive message should NOT be present.
	if entry.Receive != nil {
		t.Error("receive message should be nil for intercept drop")
	}
}

func TestHandleStream_ProgressiveRecording_NilStore(t *testing.T) {
	// When Store is nil, no recording should happen and no panics.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok-nil-store")
	}))
	defer upstream.Close()

	handler := NewHandler(nil, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-nil-store", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "ok-nil-store" {
		t.Errorf("body = %q, want %q", body, "ok-nil-store")
	}
	// No panic means success for nil store.
}

// --- Unit tests for recording helper functions ---

func TestRecordSend_NilStore(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	result := handler.recordSend(context.Background(), sendRecordParams{
		req:    &gohttp.Request{Method: "GET"},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
	}, testutil.DiscardLogger())
	if result != nil {
		t.Error("expected nil result when Store is nil")
	}
}

func TestRecordSend_CreatesActiveSession(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	p := sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
		reqBody:    []byte("request-body"),
	}

	result := handler.recordSend(context.Background(), p, testutil.DiscardLogger())
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.sessionID == "" {
		t.Error("session ID should not be empty")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Session should be in "active" state before recordReceive is called.
	if entries[0].Session.State != "active" {
		t.Errorf("state = %q, want %q", entries[0].Session.State, "active")
	}
	if entries[0].Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entries[0].Session.Protocol, "HTTP/2")
	}
	if entries[0].Send == nil {
		t.Fatal("send message should be recorded")
	}
	if entries[0].Send.Method != "GET" {
		t.Errorf("send method = %q, want %q", entries[0].Send.Method, "GET")
	}
}

func TestRecordReceive_NilSendResult(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// Should be a no-op when sendResult is nil.
	handler.recordReceive(context.Background(), nil, receiveRecordParams{
		resp: &gohttp.Response{StatusCode: 200, Header: gohttp.Header{}},
	}, testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestRecordReceive_CompletesSession(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// First create a send record.
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	sendResult := handler.recordSend(context.Background(), sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
	}, testutil.DiscardLogger())

	// Now record the receive.
	start := time.Now()
	handler.recordReceive(context.Background(), sendResult, receiveRecordParams{
		start:      start,
		duration:   100 * time.Millisecond,
		serverAddr: "93.184.216.34:80",
		resp: &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{"Content-Type": {"text/plain"}},
		},
		respBody: []byte("response-body"),
	}, testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.Duration != 100*time.Millisecond {
		t.Errorf("duration = %v, want %v", entry.Session.Duration, 100*time.Millisecond)
	}
	if entry.Session.ConnInfo.ServerAddr != "93.184.216.34:80" {
		t.Errorf("server_addr = %q, want %q", entry.Session.ConnInfo.ServerAddr, "93.184.216.34:80")
	}
	if entry.Receive == nil {
		t.Fatal("receive message should be recorded")
	}
	if entry.Receive.StatusCode != 200 {
		t.Errorf("receive status = %d, want 200", entry.Receive.StatusCode)
	}
	if string(entry.Receive.Body) != "response-body" {
		t.Errorf("receive body = %q, want %q", entry.Receive.Body, "response-body")
	}
}

func TestRecordSendError_NilSendResult(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// Should be a no-op when sendResult is nil.
	handler.recordSendError(context.Background(), nil, time.Now(), errors.New("fail"), testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestRecordSendError_SetsErrorState(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// First create a send record.
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	sendResult := handler.recordSend(context.Background(), sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
	}, testutil.DiscardLogger())

	// Record the error.
	handler.recordSendError(context.Background(), sendResult, time.Now(), errors.New("connection refused"), testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Tags == nil || entry.Session.Tags["error"] != "connection refused" {
		t.Errorf("error tag = %v, want 'connection refused'", entry.Session.Tags)
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
	}
	// Send should exist but receive should not.
	if entry.Send == nil {
		t.Error("send message should be present")
	}
	if entry.Receive != nil {
		t.Error("receive message should be nil for error")
	}
}

func TestRecordInterceptDrop_RecordsSession(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/dropped"}
	p := sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "POST", Header: gohttp.Header{}},
		reqURL:     reqURL,
		reqBody:    []byte("drop-body"),
	}

	handler.recordInterceptDrop(context.Background(), p, testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.BlockedBy != "intercept_drop" {
		t.Errorf("blocked_by = %q, want %q", entry.Session.BlockedBy, "intercept_drop")
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Send == nil {
		t.Fatal("send message should be recorded")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "POST")
	}
	if string(entry.Send.Body) != "drop-body" {
		t.Errorf("send body = %q, want %q", entry.Send.Body, "drop-body")
	}
	if entry.Receive != nil {
		t.Error("receive message should be nil for intercept drop")
	}
}

func TestRecordOutReqError_RecordsSession(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/bad-req"}
	p := sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
	}

	handler.recordOutReqError(context.Background(), p, errors.New("invalid URL"), testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Tags == nil || entry.Session.Tags["error"] != "invalid URL" {
		t.Errorf("error tag = %v, want 'invalid URL'", entry.Session.Tags)
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Send == nil {
		t.Fatal("send message should be recorded")
	}
	if entry.Receive != nil {
		t.Error("receive message should be nil for outReq error")
	}
}

func TestRecordOutReqError_NilStore(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	p := sendRecordParams{
		req:    &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL: reqURL,
	}

	// Should not panic.
	handler.recordOutReqError(context.Background(), p, errors.New("fail"), testutil.DiscardLogger())
}

func TestRecordInterceptDrop_NilStore(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	p := sendRecordParams{
		req:    &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL: reqURL,
	}

	// Should not panic.
	handler.recordInterceptDrop(context.Background(), p, testutil.DiscardLogger())
}

func TestRecordReceive_WithTLSCertSubject(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	reqURL := &url.URL{Scheme: "https", Host: "secure.example.com", Path: "/test"}
	sendResult := handler.recordSend(context.Background(), sendRecordParams{
		connID:     "conn-tls",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &session.ConnectionInfo{ClientAddr: "127.0.0.1:1234", TLSVersion: "TLS 1.3"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
	}, testutil.DiscardLogger())

	handler.recordReceive(context.Background(), sendResult, receiveRecordParams{
		start:                time.Now(),
		duration:             50 * time.Millisecond,
		serverAddr:           "93.184.216.34:443",
		tlsServerCertSubject: "CN=secure.example.com",
		resp: &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{},
		},
		respBody: []byte("secure-response"),
	}, testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.ConnInfo.TLSServerCertSubject != "CN=secure.example.com" {
		t.Errorf("tls_server_cert_subject = %q, want %q",
			entry.Session.ConnInfo.TLSServerCertSubject, "CN=secure.example.com")
	}
	if entry.Session.ConnInfo.ServerAddr != "93.184.216.34:443" {
		t.Errorf("server_addr = %q, want %q",
			entry.Session.ConnInfo.ServerAddr, "93.184.216.34:443")
	}
}
