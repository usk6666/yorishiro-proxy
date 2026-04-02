package http

import (
	"context"
	gohttp "net/http"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestRecordHTTPSession_Basic(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()
	duration := 50 * time.Millisecond

	goReq, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req := goRequestToRaw(goReq)

	handler.recordHTTPSession(ctx, sessionRecordParams{
		connID:     "conn-1",
		clientAddr: "127.0.0.1:1234",
		serverAddr: "93.184.216.34:80",
		protocol:   "HTTP/1.x",
		start:      start,
		duration:   duration,
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234", ServerAddr: "93.184.216.34:80"},
		req:        req,
		reqBody:    []byte("request body"),
		resp:       testRawResponse(200, gohttp.Header{"Content-Type": {"text/plain"}}),
		respBody:   []byte("response body"),
	}, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/1.x")
	}
	if entry.Session.ConnID != "conn-1" {
		t.Errorf("connID = %q, want %q", entry.Session.ConnID, "conn-1")
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("method = %q, want %q", entry.Send.Method, "GET")
	}
	if string(entry.Send.Body) != "request body" {
		t.Errorf("request body = %q, want %q", entry.Send.Body, "request body")
	}
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

func TestRecordHTTPSession_NilStore(t *testing.T) {
	// When store is nil, recordHTTPSession should be a no-op.
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	goReq, _ := gohttp.NewRequest("GET", "http://example.com", nil)
	req := goRequestToRaw(goReq)

	// Should not panic.
	handler.recordHTTPSession(ctx, sessionRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		duration: time.Millisecond,
		req:      req,
		resp:     testRawResponse(200, gohttp.Header{}),
		respBody: []byte("ok"),
	}, logger)
}

func TestRecordHTTPSession_WithReqURL(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	goReq, _ := gohttp.NewRequest("POST", "https://example.com/api", nil)
	req := goRequestToRaw(goReq)

	// Provide an explicit reqURL to override the one from req.
	reqURL := &url.URL{
		Scheme:   "https",
		Host:     "example.com",
		Path:     "/api",
		RawQuery: "key=value",
	}

	handler.recordHTTPSession(ctx, sessionRecordParams{
		protocol: "HTTPS",
		start:    time.Now(),
		duration: time.Millisecond,
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		reqURL:   reqURL,
		reqBody:  []byte("body"),
		resp:     testRawResponse(201, gohttp.Header{}),
		respBody: []byte("created"),
	}, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Send.URL.RawQuery != "key=value" {
		t.Errorf("URL query = %q, want %q", entries[0].Send.URL.RawQuery, "key=value")
	}
}

func TestRecordHTTPSession_Tags(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	goReq, _ := gohttp.NewRequest("GET", "http://example.com", nil)
	req := goRequestToRaw(goReq)

	tags := map[string]string{"smuggling:cl_te_conflict": "true"}

	handler.recordHTTPSession(ctx, sessionRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		duration: time.Millisecond,
		tags:     tags,
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		resp:     testRawResponse(200, gohttp.Header{}),
		respBody: []byte("ok"),
	}, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Session.Tags["smuggling:cl_te_conflict"] != "true" {
		t.Errorf("tags = %v, want smuggling:cl_te_conflict=true", entries[0].Session.Tags)
	}
}

func TestRecordHTTPSession_TLSConnInfo(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	goReq, _ := gohttp.NewRequest("GET", "https://example.com", nil)
	req := goRequestToRaw(goReq)

	handler.recordHTTPSession(ctx, sessionRecordParams{
		protocol: "HTTPS",
		start:    time.Now(),
		duration: time.Millisecond,
		connInfo: &flow.ConnectionInfo{
			ClientAddr:           "127.0.0.1:1234",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=example.com",
		},
		req:      req,
		resp:     testRawResponse(200, gohttp.Header{}),
		respBody: []byte("ok"),
	}, logger)

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
	if ci.TLSServerCertSubject != "CN=example.com" {
		t.Errorf("TLSServerCertSubject = %q, want %q", ci.TLSServerCertSubject, "CN=example.com")
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
			req := &parser.RawRequest{
				Method:     "GET",
				RequestURI: "http://example.com/path",
				Proto:      "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "X-Custom", Value: "value"},
				},
			}
			if tt.host != "" {
				req.Headers.Set("Host", tt.host)
			}

			headers := requestHeaders(req)

			// Verify the original header is preserved.
			if headers.Get("X-Custom") != "value" {
				t.Errorf("X-Custom = %q, want %q", headers.Get("X-Custom"), "value")
			}

			if tt.wantHost == "" {
				if headers.Get("Host") != "" {
					t.Errorf("Host header should not be present for empty host")
				}
			} else {
				if headers.Get("Host") != tt.wantHost {
					t.Errorf("Host = %q, want %q", headers.Get("Host"), tt.wantHost)
				}
			}

			// requestHeaders now returns req.Headers directly (no mutation concern).
		})
	}
}

func TestRecordHTTPSession_HostHeader(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()

	goReq, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	req := goRequestToRaw(goReq)
	// Ensure Host header is set on the RawRequest.
	req.Headers.Set("Host", "example.com")

	handler.recordHTTPSession(ctx, sessionRecordParams{
		protocol: "HTTP/1.x",
		start:    time.Now(),
		duration: time.Millisecond,
		connInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:1234"},
		req:      req,
		resp:     testRawResponse(200, gohttp.Header{}),
		respBody: []byte("ok"),
	}, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	hostVals := entries[0].Send.Headers["Host"]
	if len(hostVals) != 1 || hostVals[0] != "example.com" {
		t.Errorf("Host header = %v, want [example.com]", hostVals)
	}
}
