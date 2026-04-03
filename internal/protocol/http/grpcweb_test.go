package http

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestIsGRPCWebRequest_NilHandler(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())
	// No grpcWebHandler set.

	headers := parser.RawHeaders{
		{Name: "Content-Type", Value: "application/grpc-web+proto"},
	}
	if h.isGRPCWebRequest(headers) {
		t.Error("isGRPCWebRequest should return false when grpcWebHandler is nil")
	}
}

func TestIsGRPCWebRequest_WithHandler(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, testutil.DiscardLogger()))

	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "grpc-web binary",
			contentType: "application/grpc-web",
			want:        true,
		},
		{
			name:        "grpc-web+proto",
			contentType: "application/grpc-web+proto",
			want:        true,
		},
		{
			name:        "grpc-web-text",
			contentType: "application/grpc-web-text",
			want:        true,
		},
		{
			name:        "grpc-web-text+proto",
			contentType: "application/grpc-web-text+proto",
			want:        true,
		},
		{
			name:        "grpc-web with params",
			contentType: "application/grpc-web+proto; charset=utf-8",
			want:        true,
		},
		{
			name:        "regular json",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "regular grpc (not grpc-web)",
			contentType: "application/grpc",
			want:        false,
		},
		{
			name:        "empty content-type",
			contentType: "",
			want:        false,
		},
		{
			name:        "text/html",
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := parser.RawHeaders{
				{Name: "Content-Type", Value: tt.contentType},
			}
			got := h.isGRPCWebRequest(headers)
			if got != tt.want {
				t.Errorf("isGRPCWebRequest(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

func TestIsGRPCWebRequest_CaseInsensitiveHeaderName(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, testutil.DiscardLogger()))

	// Wire may send mixed-case Content-Type header name.
	headers := parser.RawHeaders{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}
	if !h.isGRPCWebRequest(headers) {
		t.Error("isGRPCWebRequest should match case-insensitive header name")
	}
}

func TestSetGRPCWebHandler(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())

	if h.grpcWebHandler != nil {
		t.Fatal("grpcWebHandler should be nil initially")
	}

	gwh := grpcweb.NewHandler(store, testutil.DiscardLogger())
	h.SetGRPCWebHandler(gwh)

	if h.grpcWebHandler != gwh {
		t.Error("SetGRPCWebHandler did not set the handler")
	}
}

// TestGRPCWebIntercept_NoEngine verifies that gRPC-Web requests pass through
// when no intercept engine is configured (the common case).
func TestGRPCWebIntercept_NoEngine(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, testutil.DiscardLogger()))

	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/test.Service/Method",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Content-Type", Value: "application/grpc-web+proto"},
			{Name: "Host", Value: "example.com"},
		},
	}
	reqURL, _ := url.Parse("http://example.com/test.Service/Method")
	body := []byte("grpc-web-body")

	client, _ := net.Pipe()
	defer client.Close()

	result := h.applyIntercept(context.Background(), client, req, reqURL, body, nil, testutil.DiscardLogger())
	if result.Dropped {
		t.Error("expected no drop without intercept engine")
	}
	if result.IsRaw {
		t.Error("expected no raw mode without intercept engine")
	}
	if !bytes.Equal(result.RecordBody, body) {
		t.Errorf("body should be unchanged, got %q", result.RecordBody)
	}
}

// TestGRPCWebIntercept_Drop verifies that intercepted gRPC-Web requests can be dropped.
func TestGRPCWebIntercept_Drop(t *testing.T) {
	store := &mockStore{}
	logger := testutil.DiscardLogger()
	h := NewHandler(store, nil, logger)
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, logger))

	// Configure intercept engine with a path-matching rule.
	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "grpc-web-drop",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			PathPattern: ".*Service.*",
		},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	h.InterceptEngine = engine

	queue := intercept.NewQueue()
	h.InterceptQueue = queue

	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/test.Service/Method",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Content-Type", Value: "application/grpc-web+proto"},
			{Name: "Host", Value: "example.com"},
		},
	}
	reqURL, _ := url.Parse("http://example.com/test.Service/Method")
	body := []byte("grpc-web-body")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Release the intercepted request with drop action in a goroutine.
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			entries := queue.List()
			if len(entries) > 0 {
				queue.Respond(entries[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Drain the error response from client side (applyIntercept writes 502 to server).
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	result := h.applyIntercept(context.Background(), server, req, reqURL, body, nil, logger)
	if !result.Dropped {
		t.Error("expected request to be dropped")
	}
}

// TestGRPCWebIntercept_ModifyAndForward verifies that intercepted gRPC-Web
// requests can be modified and forwarded with header/body changes.
func TestGRPCWebIntercept_ModifyAndForward(t *testing.T) {
	store := &mockStore{}
	logger := testutil.DiscardLogger()
	h := NewHandler(store, nil, logger)
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, logger))

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "grpc-web-modify",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			PathPattern: ".*Service.*",
		},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	h.InterceptEngine = engine

	queue := intercept.NewQueue()
	h.InterceptQueue = queue

	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/test.Service/Method",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Content-Type", Value: "application/grpc-web+proto"},
			{Name: "Host", Value: "example.com"},
			{Name: "x-custom", Value: "original"},
		},
	}
	reqURL, _ := url.Parse("http://example.com/test.Service/Method")
	body := []byte("original-body")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	newBody := "modified-body"
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			entries := queue.List()
			if len(entries) > 0 {
				queue.Respond(entries[0].ID, intercept.InterceptAction{
					Type: intercept.ActionModifyAndForward,
					AddHeaders: map[string]string{
						"x-added": "intercepted",
					},
					OverrideBody: &newBody,
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	result := h.applyIntercept(context.Background(), server, req, reqURL, body, nil, logger)
	if result.Dropped {
		t.Fatal("expected request not to be dropped")
	}
	if result.IsRaw {
		t.Error("expected no raw mode")
	}

	// The body should be the modified version.
	if string(result.RecordBody) != newBody {
		t.Errorf("body = %q, want %q", result.RecordBody, newBody)
	}

	// The x-added header should have been set.
	got := result.Req.Headers.Get("x-added")
	if got != "intercepted" {
		t.Errorf("x-added header = %q, want %q", got, "intercepted")
	}
}

// TestGRPCWebIntercept_Release verifies that intercepted gRPC-Web requests
// pass through unchanged when released without modifications.
func TestGRPCWebIntercept_Release(t *testing.T) {
	store := &mockStore{}
	logger := testutil.DiscardLogger()
	h := NewHandler(store, nil, logger)
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, logger))

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "grpc-web-release",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			PathPattern: ".*Service.*",
		},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	h.InterceptEngine = engine

	queue := intercept.NewQueue()
	h.InterceptQueue = queue

	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/test.Service/Method",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Content-Type", Value: "application/grpc-web+proto"},
			{Name: "Host", Value: "example.com"},
		},
	}
	reqURL, _ := url.Parse("http://example.com/test.Service/Method")
	body := []byte("grpc-web-body")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			entries := queue.List()
			if len(entries) > 0 {
				queue.Respond(entries[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	result := h.applyIntercept(context.Background(), server, req, reqURL, body, nil, logger)
	if result.Dropped {
		t.Error("expected request not to be dropped on release")
	}
	if !bytes.Equal(result.RecordBody, body) {
		t.Errorf("body should be unchanged on release, got %q", result.RecordBody)
	}
}

// TestGRPCWebIntercept_URLOverrideBlockedByTargetScope verifies that
// a gRPC-Web intercept override URL is blocked when it violates target scope.
func TestGRPCWebIntercept_URLOverrideBlockedByTargetScope(t *testing.T) {
	store := &mockStore{}
	logger := testutil.DiscardLogger()
	h := NewHandler(store, nil, logger)
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, logger))

	// Configure target scope: only allow example.com.
	ts := proxy.NewTargetScope()
	if err := ts.SetAgentRules(
		[]proxy.TargetRule{{Hostname: "example.com"}},
		nil,
	); err != nil {
		t.Fatalf("set agent rules: %v", err)
	}
	h.TargetScope = ts

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "grpc-web-url-override",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			PathPattern: ".*Service.*",
		},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	h.InterceptEngine = engine

	queue := intercept.NewQueue()
	h.InterceptQueue = queue

	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/test.Service/Method",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Content-Type", Value: "application/grpc-web+proto"},
			{Name: "Host", Value: "example.com"},
		},
	}
	reqURL, _ := url.Parse("http://example.com/test.Service/Method")
	body := []byte("grpc-web-body")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Override URL to a host outside the target scope.
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			entries := queue.List()
			if len(entries) > 0 {
				queue.Respond(entries[0].ID, intercept.InterceptAction{
					Type:        intercept.ActionModifyAndForward,
					OverrideURL: "http://evil.com/test.Service/Method",
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Drain the blocked response from the client side (applyIntercept writes to server).
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	result := h.applyIntercept(context.Background(), server, req, reqURL, body, nil, logger)
	if !result.Dropped {
		t.Error("expected request to be dropped due to target scope violation")
	}
}

// TestGRPCWebIntercept_SnapshotPreservesOriginal verifies that the request
// snapshot captures the original headers and body before intercept modification.
func TestGRPCWebIntercept_SnapshotPreservesOriginal(t *testing.T) {
	originalHeaders := parser.RawHeaders{
		{Name: "Content-Type", Value: "application/grpc-web+proto"},
		{Name: "Host", Value: "example.com"},
		{Name: "x-custom", Value: "original-value"},
	}
	originalBody := []byte("original-grpc-web-body")

	snap := snapshotRawRequest(originalHeaders, originalBody)

	// Verify snapshot is a deep copy.
	if !bytes.Equal(snap.body, originalBody) {
		t.Errorf("snapshot body = %q, want %q", snap.body, originalBody)
	}
	if len(snap.headers) != len(originalHeaders) {
		t.Errorf("snapshot headers count = %d, want %d", len(snap.headers), len(originalHeaders))
	}

	// Modify original to verify snapshot independence.
	originalHeaders[2].Value = "modified-value"
	originalBody[0] = 'X'

	if snap.headers[2].Value != "original-value" {
		t.Error("snapshot header was mutated by original modification")
	}
	if snap.body[0] != 'o' {
		t.Error("snapshot body was mutated by original modification")
	}
}

// TestGRPCWebIntercept_VariantDetection verifies that requestModified correctly
// detects changes from intercept modifications on gRPC-Web requests.
func TestGRPCWebIntercept_VariantDetection(t *testing.T) {
	tests := []struct {
		name         string
		snapHeaders  parser.RawHeaders
		snapBody     []byte
		currHeaders  parser.RawHeaders
		currBody     []byte
		wantModified bool
	}{
		{
			name: "no modification",
			snapHeaders: parser.RawHeaders{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
			},
			snapBody: []byte("body"),
			currHeaders: parser.RawHeaders{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
			},
			currBody:     []byte("body"),
			wantModified: false,
		},
		{
			name: "body modified",
			snapHeaders: parser.RawHeaders{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
			},
			snapBody: []byte("original"),
			currHeaders: parser.RawHeaders{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
			},
			currBody:     []byte("modified"),
			wantModified: true,
		},
		{
			name: "header added",
			snapHeaders: parser.RawHeaders{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
			},
			snapBody: []byte("body"),
			currHeaders: parser.RawHeaders{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "x-added", Value: "intercepted"},
			},
			currBody:     []byte("body"),
			wantModified: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := requestSnapshot{headers: tt.snapHeaders, body: tt.snapBody}
			got := requestModified(snap, tt.currHeaders, tt.currBody)
			if got != tt.wantModified {
				t.Errorf("requestModified() = %v, want %v", got, tt.wantModified)
			}
		})
	}
}
