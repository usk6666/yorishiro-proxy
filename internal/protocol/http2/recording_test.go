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

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- Progressive recording tests ---

func TestHandleStream_ProgressiveRecording_NormalFlow(t *testing.T) {
	// Verify that the normal flow creates a flow with State="active" first,
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
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	// Flow should be complete after the full flow.
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
	// ServerAddr should be set via UpdateFlow.
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
	// the flow should be recorded with State="error" and a send message,
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
		t.Fatalf("expected 1 flow entry for upstream error, got %d", len(entries))
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
	// When the request is dropped by intercept, the flow should be recorded
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
		t.Fatalf("expected 1 flow entry for intercept drop, got %d", len(entries))
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
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
		reqBody:    []byte("request-body"),
	}

	result := handler.recordSend(context.Background(), p, testutil.DiscardLogger())
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.flowID == "" {
		t.Error("flow ID should not be empty")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Flow should be in "active" state before recordReceive is called.
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
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
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
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
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
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
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
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
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
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234", TLSVersion: "TLS 1.3"},
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

func TestRequestHeaders_InjectsHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		wantHost string
	}{
		{
			name:     "host from req.Host",
			host:     "example.com",
			wantHost: "example.com",
		},
		{
			name:     "empty host is not injected",
			host:     "",
			wantHost: "",
		},
		{
			name:     "host with port",
			host:     "example.com:8080",
			wantHost: "example.com:8080",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &gohttp.Request{
				Method: "GET",
				Host:   tt.host,
				Header: gohttp.Header{"X-Custom": {"value"}},
			}

			headers := requestHeaders(req)

			if headers.Get("X-Custom") != "value" {
				t.Errorf("X-Custom = %q, want %q", headers.Get("X-Custom"), "value")
			}

			if tt.wantHost == "" {
				if _, ok := headers["Host"]; ok {
					t.Errorf("Host header should not be present for empty host")
				}
			} else {
				if headers.Get("Host") != tt.wantHost {
					t.Errorf("Host = %q, want %q", headers.Get("Host"), tt.wantHost)
				}
			}

			// Verify it does not mutate the original req.Header.
			if _, ok := req.Header["Host"]; ok {
				t.Error("requestHeaders should not mutate req.Header")
			}
		})
	}
}

func TestRecordSend_HostHeader(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	req := &gohttp.Request{
		Method: "GET",
		Host:   "example.com",
		Header: gohttp.Header{"Content-Type": {"application/json"}},
	}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}

	result := handler.recordSend(context.Background(), sendRecordParams{
		connID:     "conn-host",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        req,
		reqURL:     reqURL,
	}, testutil.DiscardLogger())

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	hostVals := entries[0].Send.Headers["Host"]
	if len(hostVals) != 1 || hostVals[0] != "example.com" {
		t.Errorf("Host header = %v, want [example.com]", hostVals)
	}
}

// --- Raw bytes recording tests ---

func TestRecordSend_WithRawFrames(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	frame1 := []byte{0x00, 0x00, 0x05, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01}
	frame2 := []byte{0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	p := sendRecordParams{
		connID:     "conn-raw",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "POST", Header: gohttp.Header{}},
		reqURL:     reqURL,
		reqBody:    []byte("body"),
		rawFrames:  [][]byte{frame1, frame2},
	}

	result := handler.recordSend(context.Background(), p, testutil.DiscardLogger())
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	send := entries[0].Send
	if send == nil {
		t.Fatal("send message is nil")
	}

	// RawBytes should be the concatenation of frame1 + frame2.
	expectedRaw := append([]byte{}, frame1...)
	expectedRaw = append(expectedRaw, frame2...)
	if !bytes.Equal(send.RawBytes, expectedRaw) {
		t.Errorf("RawBytes = %v, want %v", send.RawBytes, expectedRaw)
	}

	// Metadata should contain frame info.
	if send.Metadata == nil {
		t.Fatal("Metadata is nil")
	}
	if send.Metadata["h2_frame_count"] != "2" {
		t.Errorf("h2_frame_count = %q, want %q", send.Metadata["h2_frame_count"], "2")
	}
	if send.Metadata["h2_total_wire_bytes"] != "18" {
		t.Errorf("h2_total_wire_bytes = %q, want %q", send.Metadata["h2_total_wire_bytes"], "18")
	}
}

func TestRecordSend_NoRawFrames(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	p := sendRecordParams{
		connID:     "conn-no-raw",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
	}

	result := handler.recordSend(context.Background(), p, testutil.DiscardLogger())
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	entries := store.Entries()
	send := entries[0].Send
	if send.RawBytes != nil {
		t.Errorf("RawBytes should be nil without raw frames, got %v", send.RawBytes)
	}
	if send.Metadata != nil {
		t.Errorf("Metadata should be nil without raw frames, got %v", send.Metadata)
	}
}

func TestRecordSendWithVariant_RawBytesOnOriginalOnly(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	frame1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

	req := &gohttp.Request{
		Method: "POST",
		Header: gohttp.Header{"Content-Type": {"application/json"}},
	}
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/api"}

	originalBody := []byte(`{"key":"original"}`)
	modifiedBody := []byte(`{"key":"modified"}`)

	snap := snapshotRequest(req.Header, originalBody)

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID:    "conn-variant-raw",
		start:     time.Now(),
		connInfo:  &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:       req,
		reqURL:    reqURL,
		reqBody:   modifiedBody,
		rawFrames: [][]byte{frame1},
	}, &snap, logger)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	msgs, _ := store.GetMessages(ctx, result.flowID, flow.MessageListOptions{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}

	// Original message (sequence 0) should have RawBytes.
	original := msgs[0]
	if original.RawBytes == nil {
		t.Error("original RawBytes should not be nil")
	}
	if !bytes.Equal(original.RawBytes, frame1) {
		t.Errorf("original RawBytes = %v, want %v", original.RawBytes, frame1)
	}
	if original.Metadata == nil || original.Metadata["variant"] != "original" {
		t.Error("original should have variant=original metadata")
	}
	if original.Metadata["h2_frame_count"] != "1" {
		t.Errorf("original h2_frame_count = %q, want %q", original.Metadata["h2_frame_count"], "1")
	}

	// Modified message (sequence 1) should NOT have RawBytes.
	modified := msgs[1]
	if modified.RawBytes != nil {
		t.Error("modified RawBytes should be nil (not wire-observed)")
	}
	if modified.Metadata == nil || modified.Metadata["variant"] != "modified" {
		t.Error("modified should have variant=modified metadata")
	}
	// Modified should not have frame metadata.
	if _, ok := modified.Metadata["h2_frame_count"]; ok {
		t.Error("modified should not have h2_frame_count")
	}
}

func TestRecordInterceptDrop_WithRawFrames(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	frame1 := []byte{0xAA, 0xBB, 0xCC}

	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/dropped"}
	p := sendRecordParams{
		connID:     "conn-drop-raw",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "POST", Header: gohttp.Header{}},
		reqURL:     reqURL,
		reqBody:    []byte("drop-body"),
		rawFrames:  [][]byte{frame1},
	}

	handler.recordInterceptDrop(context.Background(), p, testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	send := entries[0].Send
	if !bytes.Equal(send.RawBytes, frame1) {
		t.Errorf("RawBytes = %v, want %v", send.RawBytes, frame1)
	}
	if send.Metadata == nil || send.Metadata["h2_frame_count"] != "1" {
		t.Errorf("expected h2_frame_count=1, got %v", send.Metadata)
	}
}

func TestRecordReceive_WithRawFrames(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// Create a send record first.
	reqURL := &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}
	sendResult := handler.recordSend(context.Background(), sendRecordParams{
		connID:     "conn-recv-raw",
		clientAddr: "127.0.0.1:1234",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:        &gohttp.Request{Method: "GET", Header: gohttp.Header{}},
		reqURL:     reqURL,
	}, testutil.DiscardLogger())

	respFrame1 := []byte{0x00, 0x00, 0x05, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01}
	respFrame2 := []byte{0x00, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}

	handler.recordReceive(context.Background(), sendResult, receiveRecordParams{
		start:      time.Now(),
		duration:   50 * time.Millisecond,
		serverAddr: "93.184.216.34:80",
		resp: &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{"Content-Type": {"text/plain"}},
		},
		respBody:  []byte("response"),
		rawFrames: [][]byte{respFrame1, respFrame2},
	}, testutil.DiscardLogger())

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	recv := entries[0].Receive
	if recv == nil {
		t.Fatal("receive message is nil")
	}

	// RawBytes should be the concatenation of response frames.
	expectedRaw := append([]byte{}, respFrame1...)
	expectedRaw = append(expectedRaw, respFrame2...)
	if !bytes.Equal(recv.RawBytes, expectedRaw) {
		t.Errorf("RawBytes = %v, want %v", recv.RawBytes, expectedRaw)
	}

	// Metadata should contain frame info.
	if recv.Metadata == nil {
		t.Fatal("Metadata is nil")
	}
	if recv.Metadata["h2_frame_count"] != "2" {
		t.Errorf("h2_frame_count = %q, want %q", recv.Metadata["h2_frame_count"], "2")
	}
}

// --- recordBlocked tests ---

func TestRecordBlocked_TargetScope(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	reqURL, _ := url.Parse("http://example.com/api/test")
	req, _ := gohttp.NewRequest("GET", reqURL.String(), nil)
	req.Host = "example.com"

	p := sendRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:12345",
		scheme:     "http",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:12345"},
		req:        req,
		reqURL:     reqURL,
		rawFrames:  [][]byte{{0x01, 0x02}},
	}

	handler.recordBlocked(ctx, p, "target_scope", nil, nil, handler.Logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.BlockedBy != "target_scope" {
		t.Errorf("blocked_by = %q, want %q", entry.Session.BlockedBy, "target_scope")
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Session.FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", entry.Session.FlowType, "unary")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "GET")
	}
	if entry.Send.URL.String() != reqURL.String() {
		t.Errorf("send URL = %q, want %q", entry.Send.URL.String(), reqURL.String())
	}
	if entry.Receive != nil {
		t.Error("blocked flow should not have a receive message")
	}
	// No safety tags for target_scope.
	if _, ok := entry.Session.Tags["safety_rule"]; ok {
		t.Error("target_scope block should not have safety_rule tag")
	}
	// RawBytes should be recorded.
	if len(entry.Send.RawBytes) == 0 {
		t.Error("send RawBytes should not be empty")
	}
}

func TestRecordBlocked_RateLimit(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	reqURL, _ := url.Parse("http://example.com/api/data")
	req, _ := gohttp.NewRequest("POST", reqURL.String(), nil)
	req.Host = "example.com"

	p := sendRecordParams{
		connID:     "conn-2",
		clientAddr: "127.0.0.1:23456",
		scheme:     "http",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:23456"},
		req:        req,
		reqURL:     reqURL,
		reqBody:    []byte("request-body"),
	}

	handler.recordBlocked(ctx, p, "rate_limit", nil, nil, handler.Logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.BlockedBy != "rate_limit" {
		t.Errorf("blocked_by = %q, want %q", entry.Session.BlockedBy, "rate_limit")
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "POST")
	}
	if string(entry.Send.Body) != "request-body" {
		t.Errorf("send body = %q, want %q", entry.Send.Body, "request-body")
	}
	if entry.Receive != nil {
		t.Error("blocked flow should not have a receive message")
	}
}

func TestRecordBlocked_RateLimitWithTags(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	reqURL, _ := url.Parse("http://example.com/api/data")
	req, _ := gohttp.NewRequest("POST", reqURL.String(), nil)
	req.Host = "example.com"

	p := sendRecordParams{
		connID:     "conn-rl-tags",
		clientAddr: "127.0.0.1:23456",
		scheme:     "http",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:23456"},
		req:        req,
		reqURL:     reqURL,
	}

	extraTags := map[string]string{
		"rate_limit_type":          "per_host",
		"rate_limit_effective_rps": "5.0",
	}

	handler.recordBlocked(ctx, p, "rate_limit", nil, extraTags, handler.Logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.BlockedBy != "rate_limit" {
		t.Errorf("blocked_by = %q, want %q", entry.Session.BlockedBy, "rate_limit")
	}
	if got := entry.Session.Tags["rate_limit_type"]; got != "per_host" {
		t.Errorf("rate_limit_type tag = %q, want %q", got, "per_host")
	}
	if got := entry.Session.Tags["rate_limit_effective_rps"]; got != "5.0" {
		t.Errorf("rate_limit_effective_rps tag = %q, want %q", got, "5.0")
	}
}

func TestRecordBlocked_SafetyFilter(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := context.Background()
	reqURL, _ := url.Parse("http://example.com/api/sql")
	req, _ := gohttp.NewRequest("POST", reqURL.String(), nil)
	req.Host = "example.com"

	p := sendRecordParams{
		connID:     "conn-3",
		clientAddr: "127.0.0.1:34567",
		scheme:     "http",
		start:      time.Now(),
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:34567"},
		req:        req,
		reqURL:     reqURL,
		reqBody:    []byte("DROP TABLE users"),
		rawFrames:  [][]byte{{0xAA, 0xBB}, {0xCC, 0xDD}},
	}

	violation := &safety.InputViolation{
		RuleID:    "destructive-sql",
		RuleName:  "Destructive SQL",
		Target:    safety.TargetBody,
		MatchedOn: "DROP TABLE",
	}

	handler.recordBlocked(ctx, p, "safety_filter", violation, nil, handler.Logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.BlockedBy != "safety_filter" {
		t.Errorf("blocked_by = %q, want %q", entry.Session.BlockedBy, "safety_filter")
	}
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if string(entry.Send.Body) != "DROP TABLE users" {
		t.Errorf("send body = %q, want %q", entry.Send.Body, "DROP TABLE users")
	}
	if entry.Receive != nil {
		t.Error("blocked flow should not have a receive message")
	}
	// Verify safety tags.
	if got := entry.Session.Tags["safety_rule"]; got != "destructive-sql" {
		t.Errorf("safety_rule tag = %q, want %q", got, "destructive-sql")
	}
	if got := entry.Session.Tags["safety_target"]; got != "body" {
		t.Errorf("safety_target tag = %q, want %q", got, "body")
	}
	// Verify raw bytes are recorded.
	expectedRaw := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	if !bytes.Equal(entry.Send.RawBytes, expectedRaw) {
		t.Errorf("RawBytes = %v, want %v", entry.Send.RawBytes, expectedRaw)
	}
}

func TestRecordBlocked_NilStore(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	ctx := context.Background()
	reqURL, _ := url.Parse("http://example.com/api")
	req, _ := gohttp.NewRequest("GET", reqURL.String(), nil)

	p := sendRecordParams{
		connID: "conn-nil",
		start:  time.Now(),
		req:    req,
		reqURL: reqURL,
	}

	// Should not panic with nil store.
	handler.recordBlocked(ctx, p, "target_scope", nil, nil, handler.Logger)
}

func TestRecordBlocked_CaptureScope(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// Set capture scope to only capture requests matching "/captured/".
	scope := proxy.NewCaptureScope()
	scope.SetRules([]proxy.ScopeRule{{URLPrefix: "/captured/"}}, nil)
	handler.SetCaptureScope(scope)

	ctx := context.Background()

	// Request outside capture scope.
	reqURL, _ := url.Parse("http://example.com/not-captured/api")
	req, _ := gohttp.NewRequest("GET", reqURL.String(), nil)

	p := sendRecordParams{
		connID: "conn-scope",
		start:  time.Now(),
		req:    req,
		reqURL: reqURL,
	}

	handler.recordBlocked(ctx, p, "rate_limit", nil, nil, handler.Logger)

	entries := store.Entries()
	if len(entries) != 0 {
		t.Errorf("expected 0 flow entries for out-of-scope request, got %d", len(entries))
	}
}
