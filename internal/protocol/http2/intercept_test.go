package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- SetInterceptEngine / SetInterceptQueue tests ---

func TestSetInterceptEngine(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	handler.SetInterceptEngine(engine)

	if handler.interceptEngine != engine {
		t.Error("interceptEngine was not set correctly")
	}
}

func TestSetInterceptQueue(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	queue := intercept.NewQueue()
	handler.SetInterceptQueue(queue)

	if handler.interceptQueue != queue {
		t.Error("interceptQueue was not set correctly")
	}
}

// --- interceptRequest unit tests ---

func TestInterceptRequest_NoEngineOrQueue(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	action, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)
	if intercepted {
		t.Error("expected not intercepted when engine/queue are nil")
	}
	if action.Type != intercept.ActionRelease {
		t.Errorf("expected zero-value action type, got %v", action.Type)
	}
}

func TestInterceptRequest_OnlyEngineNoQueue(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	handler.SetInterceptEngine(engine)
	// queue is nil

	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	_, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)
	if intercepted {
		t.Error("expected not intercepted when queue is nil")
	}
}

func TestInterceptRequest_OnlyQueueNoEngine(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	queue := intercept.NewQueue()
	handler.SetInterceptQueue(queue)
	// engine is nil

	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	_, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)
	if intercepted {
		t.Error("expected not intercepted when engine is nil")
	}
}

func TestInterceptRequest_NoMatchingRules(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	// Add a rule that won't match.
	err := engine.AddRule(intercept.Rule{
		ID:        "rule1",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "nomatch\\.example\\.com",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	req, _ := gohttp.NewRequest("GET", "http://different.example.com/test", nil)
	logger := testutil.DiscardLogger()

	_, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)
	if intercepted {
		t.Error("expected not intercepted when no rules match")
	}
}

func TestInterceptRequest_Release(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	err := engine.AddRule(intercept.Rule{
		ID:        "rule1",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	// Respond with release in a goroutine.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait for the item to appear in the queue.
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				err := queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				if err != nil {
					t.Errorf("Respond: %v", err)
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("timed out waiting for item in queue")
	}()

	action, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)
	wg.Wait()

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if action.Type != intercept.ActionRelease {
		t.Errorf("action type = %v, want ActionRelease", action.Type)
	}
}

func TestInterceptRequest_Drop(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	err := engine.AddRule(intercept.Rule{
		ID:        "rule1",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	// Respond with drop in a goroutine.
	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	action, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if action.Type != intercept.ActionDrop {
		t.Errorf("action type = %v, want ActionDrop", action.Type)
	}
}

func TestInterceptRequest_TimeoutAutoRelease(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoRelease)
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	err := engine.AddRule(intercept.Rule{
		ID:        "rule1",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	// Do not respond — let it timeout.
	action, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if action.Type != intercept.ActionRelease {
		t.Errorf("action type = %v, want ActionRelease (auto_release on timeout)", action.Type)
	}
}

func TestInterceptRequest_TimeoutAutoDrop(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoDrop)
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	err := engine.AddRule(intercept.Rule{
		ID:        "rule1",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	action, intercepted := handler.interceptRequest(context.Background(), req, nil, logger)

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if action.Type != intercept.ActionDrop {
		t.Errorf("action type = %v, want ActionDrop (auto_drop on timeout)", action.Type)
	}
}

func TestInterceptRequest_ContextCancellation(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(5 * time.Second) // long timeout, context will cancel first
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	err := engine.AddRule(intercept.Rule{
		ID:        "rule1",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: "example\\.com",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	logger := testutil.DiscardLogger()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	action, intercepted := handler.interceptRequest(ctx, req, nil, logger)

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if action.Type != intercept.ActionDrop {
		t.Errorf("action type = %v, want ActionDrop (context cancelled)", action.Type)
	}
}

// --- applyInterceptModifications tests ---

func TestApplyInterceptModifications_OverrideMethod(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	action := intercept.InterceptAction{
		OverrideMethod: "POST",
	}

	modified, err := applyInterceptModifications(req, action, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified.Method != "POST" {
		t.Errorf("method = %q, want %q", modified.Method, "POST")
	}
}

func TestApplyInterceptModifications_OverrideURL(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/old", nil)
	action := intercept.InterceptAction{
		OverrideURL: "https://other.com/new",
	}

	modified, err := applyInterceptModifications(req, action, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified.URL.String() != "https://other.com/new" {
		t.Errorf("URL = %q, want %q", modified.URL.String(), "https://other.com/new")
	}
	if modified.Host != "other.com" {
		t.Errorf("Host = %q, want %q", modified.Host, "other.com")
	}
}

func TestApplyInterceptModifications_InvalidURLScheme(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	action := intercept.InterceptAction{
		OverrideURL: "ftp://malicious.com/exploit",
	}

	_, err := applyInterceptModifications(req, action, nil)
	if err == nil {
		t.Fatal("expected error for unsupported URL scheme")
	}
}

func TestApplyInterceptModifications_Headers(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Original", "value")
	req.Header.Set("X-Remove-Me", "gone")

	action := intercept.InterceptAction{
		OverrideHeaders: map[string]string{"X-Override": "new-val"},
		AddHeaders:      map[string]string{"X-Added": "added-val"},
		RemoveHeaders:   []string{"X-Remove-Me"},
	}

	modified, err := applyInterceptModifications(req, action, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if modified.Header.Get("X-Override") != "new-val" {
		t.Errorf("X-Override = %q, want %q", modified.Header.Get("X-Override"), "new-val")
	}
	if modified.Header.Get("X-Added") != "added-val" {
		t.Errorf("X-Added = %q, want %q", modified.Header.Get("X-Added"), "added-val")
	}
	if modified.Header.Get("X-Remove-Me") != "" {
		t.Errorf("X-Remove-Me should be removed, got %q", modified.Header.Get("X-Remove-Me"))
	}
	if modified.Header.Get("X-Original") != "value" {
		t.Errorf("X-Original = %q, want %q", modified.Header.Get("X-Original"), "value")
	}
}

func TestApplyInterceptModifications_OverrideBody(t *testing.T) {
	req, _ := gohttp.NewRequest("POST", "http://example.com/test", bytes.NewReader([]byte("original")))

	newBody := "modified-body"
	action := intercept.InterceptAction{
		OverrideBody: &newBody,
	}

	modified, err := applyInterceptModifications(req, action, []byte("original"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := io.ReadAll(modified.Body)
	if string(body) != "modified-body" {
		t.Errorf("body = %q, want %q", body, "modified-body")
	}
	if modified.ContentLength != int64(len("modified-body")) {
		t.Errorf("content length = %d, want %d", modified.ContentLength, len("modified-body"))
	}
}

func TestApplyInterceptModifications_NoChanges(t *testing.T) {
	req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
	action := intercept.InterceptAction{} // all zero values

	modified, err := applyInterceptModifications(req, action, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified.Method != "GET" {
		t.Errorf("method = %q, want %q", modified.Method, "GET")
	}
	if modified.URL.String() != "http://example.com/test" {
		t.Errorf("URL = %q, want %q", modified.URL.String(), "http://example.com/test")
	}
}

func TestApplyInterceptModifications_CRLFValidation(t *testing.T) {
	tests := []struct {
		name            string
		overrideHeaders map[string]string
		addHeaders      map[string]string
		removeHeaders   []string
		wantErr         bool
		errContains     string
	}{
		{
			name:            "override header value with CR",
			overrideHeaders: map[string]string{"X-Test": "val\rue"},
			wantErr:         true,
			errContains:     "CR/LF",
		},
		{
			name:            "override header value with LF",
			overrideHeaders: map[string]string{"X-Test": "val\nue"},
			wantErr:         true,
			errContains:     "CR/LF",
		},
		{
			name:            "override header key with CRLF",
			overrideHeaders: map[string]string{"X-Te\r\nst": "value"},
			wantErr:         true,
			errContains:     "CR/LF",
		},
		{
			name:        "add header value with LF",
			addHeaders:  map[string]string{"X-Add": "val\nue"},
			wantErr:     true,
			errContains: "CR/LF",
		},
		{
			name:          "remove header key with CR",
			removeHeaders: []string{"X-Remove\rInjection"},
			wantErr:       true,
			errContains:   "CR/LF",
		},
		{
			name:          "remove header key with LF",
			removeHeaders: []string{"X-Remove\nInjection"},
			wantErr:       true,
			errContains:   "CR/LF",
		},
		{
			name:            "valid headers pass",
			overrideHeaders: map[string]string{"X-Valid": "safe-value"},
			addHeaders:      map[string]string{"X-Also-Valid": "also-safe"},
			removeHeaders:   []string{"X-Clean-Key"},
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
			action := intercept.InterceptAction{
				Type:            intercept.ActionModifyAndForward,
				OverrideHeaders: tt.overrideHeaders,
				AddHeaders:      tt.addHeaders,
				RemoveHeaders:   tt.removeHeaders,
			}

			_, err := applyInterceptModifications(req, action, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				errStr := err.Error()
				if tt.errContains != "" {
					found := false
					for i := 0; i <= len(errStr)-len(tt.errContains); i++ {
						if errStr[i:i+len(tt.errContains)] == tt.errContains {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("error %q should contain %q", errStr, tt.errContains)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// --- End-to-end intercept tests via handleStream ---

func TestHandleStream_InterceptRelease(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "released")
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
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: upstreamURL.Hostname(),
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	addr, cancel := startH2CProxyListener(t, handler, "test-intercept-release", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Release the intercepted request in a goroutine.
	go func() {
		for i := 0; i < 200; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "released" {
		t.Errorf("body = %q, want %q", body, "released")
	}

	// Verify session was recorded.
	time.Sleep(200 * time.Millisecond)
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}
	if entries[0].Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entries[0].Session.Protocol, "HTTP/2")
	}
}

func TestHandleStream_InterceptDrop(t *testing.T) {
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
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: upstreamURL.Hostname(),
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	addr, cancel := startH2CProxyListener(t, handler, "test-intercept-drop", "127.0.0.1:12345", "", tlsMetadata{})
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

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// HTTP/2 returns 502 for dropped requests.
	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}

	// Verify no session was recorded (request was dropped before forwarding).
	time.Sleep(200 * time.Millisecond)
	entries := store.Entries()
	if len(entries) != 0 {
		t.Errorf("expected 0 session entries when dropped, got %d", len(entries))
	}
}

func TestHandleStream_InterceptModifyAndForward(t *testing.T) {
	var receivedHeader string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		receivedHeader = r.Header.Get("X-Injected")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "modified")
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
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: upstreamURL.Hostname(),
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	addr, cancel := startH2CProxyListener(t, handler, "test-intercept-modify", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Modify and forward the intercepted request in a goroutine.
	go func() {
		for i := 0; i < 200; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{
					Type:            intercept.ActionModifyAndForward,
					OverrideHeaders: map[string]string{"X-Injected": "injected-value"},
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "modified" {
		t.Errorf("body = %q, want %q", body, "modified")
	}
	if receivedHeader != "injected-value" {
		t.Errorf("X-Injected = %q, want %q", receivedHeader, "injected-value")
	}
}

func TestHandleStream_InterceptTimeoutAutoRelease(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "auto-released")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(200 * time.Millisecond) // short timeout
	queue.SetTimeoutBehavior(intercept.TimeoutAutoRelease)
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	upstreamURL, _ := url.Parse(upstream.URL)

	err := engine.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: upstreamURL.Hostname(),
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	addr, cancel := startH2CProxyListener(t, handler, "test-intercept-timeout", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Do not respond — let it timeout and auto-release.
	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "auto-released" {
		t.Errorf("body = %q, want %q", body, "auto-released")
	}
}

func TestHandleStream_NoInterceptWithoutRules(t *testing.T) {
	// When intercept engine and queue are set but no rules are configured,
	// requests should pass through without being intercepted.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "no-intercept")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	// No rules added — nothing should match.

	addr, cancel := startH2CProxyListener(t, handler, "test-no-intercept", "127.0.0.1:12345", "", tlsMetadata{})
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

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "no-intercept" {
		t.Errorf("body = %q, want %q", body, "no-intercept")
	}

	// Queue should be empty (nothing intercepted).
	if queue.Len() != 0 {
		t.Errorf("queue length = %d, want 0", queue.Len())
	}
}

func TestHandleStream_InterceptMethodFilter(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok-%s", r.Method)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	upstreamURL, _ := url.Parse(upstream.URL)

	// Rule only matches POST requests.
	err := engine.AddRule(intercept.Rule{
		ID:        "post-only",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: upstreamURL.Hostname(),
			Methods:     []string{"POST"},
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	addr, cancel := startH2CProxyListener(t, handler, "test-method-filter", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// GET request should NOT be intercepted.
	getURL := fmt.Sprintf("%s/test", upstream.URL)
	getReq, _ := gohttp.NewRequestWithContext(ctx, "GET", getURL, nil)
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != gohttp.StatusOK {
		t.Errorf("GET status = %d, want %d", getResp.StatusCode, gohttp.StatusOK)
	}
	if string(getBody) != "ok-GET" {
		t.Errorf("GET body = %q, want %q", getBody, "ok-GET")
	}

	// Queue should still be empty.
	if queue.Len() != 0 {
		t.Errorf("queue length after GET = %d, want 0", queue.Len())
	}
}

func TestHandleStream_InterceptedRequestMetadata(t *testing.T) {
	// Verify that the intercepted request in the queue has correct metadata.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	handler := NewHandler(nil, testutil.DiscardLogger())

	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	upstreamURL, _ := url.Parse(upstream.URL)

	err := engine.AddRule(intercept.Rule{
		ID:        "meta-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			HostPattern: upstreamURL.Hostname(),
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	addr, cancel := startH2CProxyListener(t, handler, "test-meta", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Capture the intercepted request metadata before releasing.
	var interceptedReq *intercept.InterceptedRequest
	go func() {
		for i := 0; i < 200; i++ {
			items := queue.List()
			if len(items) > 0 {
				interceptedReq = items[0]
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	reqURL := fmt.Sprintf("%s/check-meta?q=test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader([]byte("test-body")))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	time.Sleep(200 * time.Millisecond)

	if interceptedReq == nil {
		t.Fatal("intercepted request is nil")
	}
	if interceptedReq.Method != "POST" {
		t.Errorf("intercepted method = %q, want %q", interceptedReq.Method, "POST")
	}
	if interceptedReq.URL == nil {
		t.Fatal("intercepted URL is nil")
	}
	if interceptedReq.URL.Path != "/check-meta" {
		t.Errorf("intercepted URL path = %q, want %q", interceptedReq.URL.Path, "/check-meta")
	}
	if interceptedReq.URL.RawQuery != "q=test" {
		t.Errorf("intercepted URL query = %q, want %q", interceptedReq.URL.RawQuery, "q=test")
	}
	if string(interceptedReq.Body) != "test-body" {
		t.Errorf("intercepted body = %q, want %q", interceptedReq.Body, "test-body")
	}
	if len(interceptedReq.MatchedRules) != 1 || interceptedReq.MatchedRules[0] != "meta-rule" {
		t.Errorf("matched rules = %v, want [meta-rule]", interceptedReq.MatchedRules)
	}
}
