package http

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestNormalizeRequestURL(t *testing.T) {
	tests := []struct {
		name       string
		reqURL     string
		reqHost    string
		wantHost   string
		wantScheme string
	}{
		{
			name:       "missing host is set from req.Host",
			reqURL:     "/path",
			reqHost:    "example.com",
			wantHost:   "example.com",
			wantScheme: "http",
		},
		{
			name:       "missing scheme defaults to http",
			reqURL:     "//example.com/path",
			reqHost:    "example.com",
			wantHost:   "example.com",
			wantScheme: "http",
		},
		{
			name:       "absolute URL preserved",
			reqURL:     "http://example.com/path",
			reqHost:    "example.com",
			wantHost:   "example.com",
			wantScheme: "http",
		},
		{
			name:       "https scheme preserved",
			reqURL:     "https://secure.example.com/path",
			reqHost:    "secure.example.com",
			wantHost:   "secure.example.com",
			wantScheme: "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.reqURL)
			req := &gohttp.Request{
				URL:  u,
				Host: tt.reqHost,
			}

			normalizeRequestURL(req)

			if req.URL.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", req.URL.Host, tt.wantHost)
			}
			if req.URL.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", req.URL.Scheme, tt.wantScheme)
			}
		})
	}
}

func TestReadAndCaptureRequestBody(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantBody      string
		wantTruncated bool
	}{
		{
			name:          "nil body returns empty result",
			body:          "",
			wantBody:      "",
			wantTruncated: false,
		},
		{
			name:          "small body captured fully",
			body:          "hello world",
			wantBody:      "hello world",
			wantTruncated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *gohttp.Request
			if tt.body == "" {
				req, _ = gohttp.NewRequest("GET", "http://example.com", nil)
			} else {
				req, _ = gohttp.NewRequest("POST", "http://example.com", strings.NewReader(tt.body))
			}

			logger := testutil.DiscardLogger()
			result := readAndCaptureRequestBody(req, logger)

			if tt.body == "" {
				if len(result.recordBody) != 0 {
					t.Errorf("recordBody = %q, want empty", result.recordBody)
				}
			} else {
				if string(result.recordBody) != tt.wantBody {
					t.Errorf("recordBody = %q, want %q", result.recordBody, tt.wantBody)
				}
			}

			if result.truncated != tt.wantTruncated {
				t.Errorf("truncated = %v, want %v", result.truncated, tt.wantTruncated)
			}

			// Verify the request body is re-readable after capture.
			if tt.body != "" {
				rereadBody, _ := io.ReadAll(req.Body)
				if string(rereadBody) != tt.body {
					t.Errorf("re-read body = %q, want %q", rereadBody, tt.body)
				}
			}
		})
	}
}

func TestReadAndCaptureRequestBody_Truncation(t *testing.T) {
	// Create a body larger than MaxBodySize to test truncation.
	bigBody := strings.Repeat("x", int(config.MaxBodySize)+100)
	req, _ := gohttp.NewRequest("POST", "http://example.com", strings.NewReader(bigBody))

	logger := testutil.DiscardLogger()
	result := readAndCaptureRequestBody(req, logger)

	if !result.truncated {
		t.Error("truncated = false, want true for body exceeding MaxBodySize")
	}
	if len(result.recordBody) != int(config.MaxBodySize) {
		t.Errorf("recordBody len = %d, want %d", len(result.recordBody), int(config.MaxBodySize))
	}

	// The req.Body should still contain the full body (not truncated).
	rereadBody, _ := io.ReadAll(req.Body)
	if len(rereadBody) != len(bigBody) {
		t.Errorf("re-read body len = %d, want %d", len(rereadBody), len(bigBody))
	}
}

func TestExtractRawRequest(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		captureStart int
		wantNil      bool
		wantLen      int
	}{
		{
			name:    "nil capture returns nil",
			wantNil: true,
		},
		{
			name:         "captures raw bytes correctly",
			input:        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			captureStart: 0,
			wantNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantNil {
				result := extractRawRequest(nil, 0, nil)
				if result != nil {
					t.Errorf("extractRawRequest(nil, 0, nil) = %v, want nil", result)
				}
				return
			}

			capture := &captureReader{r: strings.NewReader(tt.input)}
			reader := bufio.NewReader(capture)

			// Read through the reader to populate the capture buffer.
			buf := make([]byte, len(tt.input))
			io.ReadFull(reader, buf)

			result := extractRawRequest(capture, tt.captureStart, reader)
			if result == nil {
				t.Fatal("extractRawRequest returned nil, want non-nil")
			}
			if string(result) != tt.input {
				t.Errorf("raw request = %q, want %q", result, tt.input)
			}
		})
	}
}

func TestExtractRawRequest_WithOffset(t *testing.T) {
	// Simulate reading two requests from the same connection: the captureStart
	// for the second request is at the end of the first.
	firstReq := "GET /first HTTP/1.1\r\nHost: a.com\r\n\r\n"
	secondReq := "GET /second HTTP/1.1\r\nHost: b.com\r\n\r\n"
	combined := firstReq + secondReq

	capture := &captureReader{r: strings.NewReader(combined)}
	reader := bufio.NewReader(capture)

	// Read the first request.
	buf := make([]byte, len(combined))
	io.ReadFull(reader, buf)

	captureStart := len(firstReq)
	result := extractRawRequest(capture, captureStart, reader)
	if result == nil {
		t.Fatal("extractRawRequest returned nil")
	}
	if string(result) != secondReq {
		t.Errorf("raw second request = %q, want %q", result, secondReq)
	}
}

func TestApplyTransform_NilPipeline(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())
	req, _ := gohttp.NewRequest("GET", "http://example.com", nil)
	originalBody := []byte("original body")

	result := handler.applyTransform(req, originalBody)
	if !bytes.Equal(result, originalBody) {
		t.Errorf("applyTransform with nil pipeline changed body: got %q, want %q", result, originalBody)
	}
}

func TestLogHTTPRequest(t *testing.T) {
	// This is a smoke test to ensure logHTTPRequest doesn't panic.
	logger := testutil.DiscardLogger()
	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logHTTPRequest(logger, req, 200, 42)
}

func TestApplyIntercept_ModifyAndForward_OverrideURLBlockedByTargetScope(t *testing.T) {
	// When modify_and_forward overrides the URL to a host outside the target
	// scope, the request must be blocked (SSRF prevention, CWE-918).
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	// Configure target scope: only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	// Set up intercept engine with a catch-all rule.
	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	// Create the request targeting an allowed host.
	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	recordBody := []byte("test body")

	// Use net.Pipe for the connection so we can read the blocked response.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	// Start a goroutine to drain the client side of the pipe so that
	// writeBlockedResponse does not block on net.Pipe's synchronous writes.
	type clientResult struct {
		resp *gohttp.Response
		err  error
	}
	clientCh := make(chan clientResult, 1)
	go func() {
		reader := bufio.NewReader(clientConn)
		resp, err := gohttp.ReadResponse(reader, nil)
		clientCh <- clientResult{resp, err}
	}()

	// Run applyIntercept in a goroutine since interceptRequest blocks
	// waiting for a response from the queue.
	type result struct {
		req     *gohttp.Request
		body    []byte
		dropped bool
	}
	resultCh := make(chan result, 1)
	go func() {
		r, b, d := handler.applyIntercept(ctx, serverConn, req, recordBody, logger)
		resultCh <- result{r, b, d}
	}()

	// Wait for the request to appear in the queue.
	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	// Respond with modify_and_forward that redirects to a blocked host.
	err := queue.Respond(interceptedID, intercept.InterceptAction{
		Type:        intercept.ActionModifyAndForward,
		OverrideURL: "http://evil.internal:8080/admin",
	})
	if err != nil {
		t.Fatalf("queue respond: %v", err)
	}

	// Get the result.
	res := <-resultCh

	if !res.dropped {
		t.Fatal("expected request to be dropped after override_url to blocked host")
	}

	// Verify the blocked response written to the client connection.
	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("read blocked response: %v", cr.err)
	}
	defer cr.resp.Body.Close()

	if cr.resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", cr.resp.StatusCode, gohttp.StatusForbidden)
	}
}

func TestApplyIntercept_ModifyAndForward_OverrideURLAllowedByTargetScope(t *testing.T) {
	// When modify_and_forward overrides the URL to a host within the target
	// scope, the request should proceed normally (not dropped).
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	// Configure target scope: allow both example.com and allowed.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
		{Hostname: "allowed.com"},
	}, nil)
	handler.SetTargetScope(ts)

	// Set up intercept engine with a catch-all rule.
	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	recordBody := []byte("test body")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	type result struct {
		req     *gohttp.Request
		body    []byte
		dropped bool
	}
	resultCh := make(chan result, 1)
	go func() {
		r, b, d := handler.applyIntercept(ctx, serverConn, req, recordBody, logger)
		resultCh <- result{r, b, d}
	}()

	// Wait for the request to appear in the queue.
	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	// Respond with modify_and_forward to an allowed host.
	err := queue.Respond(interceptedID, intercept.InterceptAction{
		Type:        intercept.ActionModifyAndForward,
		OverrideURL: "http://allowed.com/new-path",
	})
	if err != nil {
		t.Fatalf("queue respond: %v", err)
	}

	res := <-resultCh

	if res.dropped {
		t.Fatal("expected request NOT to be dropped for override_url to allowed host")
	}
	if res.req.URL.Host != "allowed.com" {
		t.Errorf("URL host = %q, want %q", res.req.URL.Host, "allowed.com")
	}
	if res.req.URL.Path != "/new-path" {
		t.Errorf("URL path = %q, want %q", res.req.URL.Path, "/new-path")
	}
}

func TestApplyIntercept_ModifyAndForward_NoOverrideURL_SkipsRecheck(t *testing.T) {
	// When modify_and_forward does not override the URL, the target scope
	// re-check should be skipped (no performance penalty for header-only mods).
	logger := testutil.DiscardLogger()
	handler := NewHandler(&mockStore{}, nil, logger)

	// Configure target scope: only allow example.com.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "example.com"},
	}, nil)
	handler.SetTargetScope(ts)

	engine := intercept.NewEngine()
	if err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.InterceptEngine = engine

	queue := intercept.NewQueue()
	handler.InterceptQueue = queue

	req, _ := gohttp.NewRequest("GET", "http://example.com/path", nil)
	recordBody := []byte("test body")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx := context.Background()

	type result struct {
		req     *gohttp.Request
		body    []byte
		dropped bool
	}
	resultCh := make(chan result, 1)
	go func() {
		r, b, d := handler.applyIntercept(ctx, serverConn, req, recordBody, logger)
		resultCh <- result{r, b, d}
	}()

	var interceptedID string
	for i := 0; i < 200; i++ {
		items := queue.List()
		if len(items) > 0 {
			interceptedID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if interceptedID == "" {
		t.Fatal("intercepted request did not appear in queue")
	}

	// Respond with modify_and_forward without URL override (header-only change).
	err := queue.Respond(interceptedID, intercept.InterceptAction{
		Type:            intercept.ActionModifyAndForward,
		OverrideHeaders: map[string]string{"X-Test": "value"},
	})
	if err != nil {
		t.Fatalf("queue respond: %v", err)
	}

	res := <-resultCh

	if res.dropped {
		t.Fatal("expected request NOT to be dropped for modify_and_forward without URL override")
	}
	if res.req.URL.Host != "example.com" {
		t.Errorf("URL host = %q, want %q", res.req.URL.Host, "example.com")
	}
}

func TestComputeTiming(t *testing.T) {
	tests := []struct {
		name      string
		sendStart time.Time
		timing    *roundTripTiming
		recvEnd   time.Time
		wantSend  *int64
		wantWait  *int64
		wantRecv  *int64
	}{
		{
			name:      "nil timing returns all nil",
			sendStart: time.Now(),
			timing:    nil,
			recvEnd:   time.Now(),
			wantSend:  nil,
			wantWait:  nil,
			wantRecv:  nil,
		},
		{
			name:      "all timestamps present",
			sendStart: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			timing: &roundTripTiming{
				wroteRequest: time.Date(2025, 1, 1, 0, 0, 0, 10*int(time.Millisecond), time.UTC),
				gotFirstByte: time.Date(2025, 1, 1, 0, 0, 0, 60*int(time.Millisecond), time.UTC),
			},
			recvEnd:  time.Date(2025, 1, 1, 0, 0, 0, 90*int(time.Millisecond), time.UTC),
			wantSend: ptrInt64(10),
			wantWait: ptrInt64(50),
			wantRecv: ptrInt64(30),
		},
		{
			name:      "zero wroteRequest",
			sendStart: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			timing: &roundTripTiming{
				gotFirstByte: time.Date(2025, 1, 1, 0, 0, 0, 60*int(time.Millisecond), time.UTC),
			},
			recvEnd:  time.Date(2025, 1, 1, 0, 0, 0, 90*int(time.Millisecond), time.UTC),
			wantSend: nil,
			wantWait: nil,
			wantRecv: ptrInt64(30),
		},
		{
			name:      "zero gotFirstByte",
			sendStart: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			timing: &roundTripTiming{
				wroteRequest: time.Date(2025, 1, 1, 0, 0, 0, 10*int(time.Millisecond), time.UTC),
			},
			recvEnd:  time.Date(2025, 1, 1, 0, 0, 0, 90*int(time.Millisecond), time.UTC),
			wantSend: ptrInt64(10),
			wantWait: nil,
			wantRecv: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSend, gotWait, gotRecv := computeTiming(tt.sendStart, tt.timing, tt.recvEnd)
			checkInt64Ptr(t, "sendMs", gotSend, tt.wantSend)
			checkInt64Ptr(t, "waitMs", gotWait, tt.wantWait)
			checkInt64Ptr(t, "receiveMs", gotRecv, tt.wantRecv)
		})
	}
}

func ptrInt64(v int64) *int64 { return &v }

func checkInt64Ptr(t *testing.T, name string, got, want *int64) {
	t.Helper()
	if got == nil && want == nil {
		return
	}
	if got == nil {
		t.Errorf("%s = nil, want %d", name, *want)
		return
	}
	if want == nil {
		t.Errorf("%s = %d, want nil", name, *got)
		return
	}
	if *got != *want {
		t.Errorf("%s = %d, want %d", name, *got, *want)
	}
}
