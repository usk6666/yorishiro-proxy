//go:build e2e

package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// =============================================================================
// Transform Live Traffic Integration Tests (USK-527)
//
// These tests verify that auto-transform rules are actually applied to HTTP
// traffic flowing through the proxy, not just CRUD operations on the rules.
// =============================================================================

// startTransformProxy starts a proxy with a transform pipeline configured.
// Returns the listener, handler, and cancel function.
func startTransformProxy(t *testing.T, ctx context.Context, store flow.Store, pipeline *rules.Pipeline) (*proxy.Listener, *protohttp.Handler, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, nil, logger)
	httpHandler.SetTransformPipeline(pipeline)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener, httpHandler, proxyCancel
}

// newTransformStore creates a temporary SQLite store for transform tests.
func newTransformStore(t *testing.T, ctx context.Context) *flow.SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "transform-test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// sendViaProxy sends a raw HTTP request through the proxy and returns the parsed response.
func sendViaProxy(t *testing.T, proxyAddr string, rawReq string) *gohttp.Response {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := io.WriteString(conn, rawReq); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	return resp
}

// --- Request Transform Tests ---

func TestTransformLive_Request_SetHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream captures the received Authorization header.
	var gotAuth string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "inject-auth",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Conditions: rules.Conditions{
			URLPattern: "/api/admin.*",
		},
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "Authorization",
			Value:  "Bearer test-token-xyz",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/api/admin/users HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if gotAuth != "Bearer test-token-xyz" {
		t.Errorf("upstream received Authorization = %q, want %q", gotAuth, "Bearer test-token-xyz")
	}
}

func TestTransformLive_Request_RemoveHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream checks that X-Debug header is absent.
	var gotDebug string
	var debugPresent bool
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		gotDebug = r.Header.Get("X-Debug")
		_, debugPresent = r.Header["X-Debug"]
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "strip-debug",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionRemoveHeader,
			Header: "X-Debug",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"X-Debug: sensitive-info\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if debugPresent {
		t.Errorf("upstream received X-Debug header (value=%q), expected it to be removed", gotDebug)
	}
}

func TestTransformLive_Request_ReplaceBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream captures the received body.
	var gotBody string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "replace-host",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "production\\.example\\.com",
			Value:   "staging.example.com",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	body := `{"target":"production.example.com","action":"deploy"}`
	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"POST %s/api/deploy HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		upstream.URL, upstreamURL.Host, len(body), body)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	wantBody := `{"target":"staging.example.com","action":"deploy"}`
	if gotBody != wantBody {
		t.Errorf("upstream received body = %q, want %q", gotBody, wantBody)
	}
}

// --- Response Transform Tests ---

func TestTransformLive_Response_SetHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream sends a normal response without X-Proxy header.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "hello")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "add-proxy-header",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionResponse,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Proxy",
			Value:  "yorishiro",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Read the raw response to check for the injected header.
	// Since sendViaProxy parses via net/http, the header should be accessible.
	gotProxyHeader := resp.Header.Get("X-Proxy")
	if gotProxyHeader != "yorishiro" {
		t.Errorf("client received X-Proxy = %q, want %q", gotProxyHeader, "yorishiro")
	}
}

func TestTransformLive_Response_RemoveHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream sends security headers that should be stripped.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "<html>test</html>")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	// Add two rules to strip both security headers.
	err := pipeline.AddRule(rules.Rule{
		ID:        "strip-csp",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionResponse,
		Action: rules.Action{
			Type:   rules.ActionRemoveHeader,
			Header: "Content-Security-Policy",
		},
	})
	if err != nil {
		t.Fatalf("AddRule(strip-csp): %v", err)
	}
	err = pipeline.AddRule(rules.Rule{
		ID:        "strip-xframe",
		Enabled:   true,
		Priority:  20,
		Direction: rules.DirectionResponse,
		Action: rules.Action{
			Type:   rules.ActionRemoveHeader,
			Header: "X-Frame-Options",
		},
	})
	if err != nil {
		t.Fatalf("AddRule(strip-xframe): %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/page HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify security headers are removed.
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
		t.Errorf("client received Content-Security-Policy = %q, expected it to be removed", csp)
	}
	if xfo := resp.Header.Get("X-Frame-Options"); xfo != "" {
		t.Errorf("client received X-Frame-Options = %q, expected it to be removed", xfo)
	}

	// Content-Type should still be present (not affected by rules).
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// --- Non-matching / Side-effect Tests ---

func TestTransformLive_NonMatchingRequest_PassesUnmodified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream captures all headers.
	var receivedHeaders gohttp.Header
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "untouched")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	// Rule only matches /api/admin.*
	err := pipeline.AddRule(rules.Rule{
		ID:        "admin-auth",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Conditions: rules.Conditions{
			URLPattern: "/api/admin.*",
		},
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "Authorization",
			Value:  "Bearer admin-token",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	// Send request to /public which should NOT match the rule.
	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/public/page HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Authorization header should NOT be present.
	if auth := receivedHeaders.Get("Authorization"); auth != "" {
		t.Errorf("upstream received Authorization = %q on non-matching path, expected empty", auth)
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "untouched" {
		t.Errorf("body = %q, want %q", body, "untouched")
	}
}

func TestTransformLive_DisabledRule_NotApplied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var gotAuth string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	// Add a disabled rule.
	err := pipeline.AddRule(rules.Rule{
		ID:        "disabled-auth",
		Enabled:   false,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "Authorization",
			Value:  "Bearer should-not-appear",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if gotAuth != "" {
		t.Errorf("disabled rule should not inject header, but upstream received Authorization = %q", gotAuth)
	}
}

// --- Flow Recording Verification ---

func TestTransformLive_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Server", "upstream")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "recorded")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "inject-token",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Injected",
			Value:  "transform-test",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/api/test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify flow is recorded with correct protocol and state.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
	}
	if fl.State != "complete" {
		t.Errorf("flow state = %q, want %q", fl.State, "complete")
	}
	if fl.FlowType != "unary" {
		t.Errorf("flow type = %q, want %q", fl.FlowType, "unary")
	}

	// Verify messages are recorded.
	send, recv := pollFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}

	// Verify raw bytes are captured.
	if len(send.RawBytes) == 0 {
		t.Error("send.RawBytes is empty")
	}
	if len(recv.RawBytes) == 0 {
		t.Error("recv.RawBytes is empty")
	}
}

// --- URL Condition Matching ---

func TestTransformLive_Request_URLConditionMatching(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type requestResult struct {
		path string
		auth string
	}
	results := make(chan requestResult, 10)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		results <- requestResult{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
		}
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "api-auth",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Conditions: rules.Conditions{
			URLPattern: "/api/.*",
		},
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "Authorization",
			Value:  "Bearer api-token",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)

	tests := []struct {
		name     string
		path     string
		wantAuth string
	}{
		{name: "matching_path", path: "/api/users", wantAuth: "Bearer api-token"},
		{name: "non_matching_path", path: "/public/page", wantAuth: ""},
		{name: "matching_nested", path: "/api/admin/settings", wantAuth: "Bearer api-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawReq := fmt.Sprintf(
				"GET %s%s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Connection: close\r\n"+
					"\r\n",
				upstream.URL, tt.path, upstreamURL.Host)

			resp := sendViaProxy(t, listener.Addr(), rawReq)
			if resp.StatusCode != gohttp.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
			}

			select {
			case rr := <-results:
				if rr.auth != tt.wantAuth {
					t.Errorf("path %s: upstream Authorization = %q, want %q", tt.path, rr.auth, tt.wantAuth)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for upstream request")
			}
		})
	}
}

// --- Method Condition Matching ---

func TestTransformLive_Request_MethodCondition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type requestResult struct {
		method string
		auth   string
	}
	results := make(chan requestResult, 10)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		results <- requestResult{
			method: r.Method,
			auth:   r.Header.Get("X-Write-Token"),
		}
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	// Rule only applies to POST and PUT methods.
	err := pipeline.AddRule(rules.Rule{
		ID:        "write-token",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Conditions: rules.Conditions{
			Methods: []string{"POST", "PUT"},
		},
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Write-Token",
			Value:  "write-allowed",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)

	tests := []struct {
		name      string
		method    string
		wantToken string
		body      string
	}{
		{name: "GET_not_matched", method: "GET", wantToken: ""},
		{name: "POST_matched", method: "POST", wantToken: "write-allowed", body: "data"},
		{name: "PUT_matched", method: "PUT", wantToken: "write-allowed", body: "data"},
		{name: "DELETE_not_matched", method: "DELETE", wantToken: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rawReq string
			if tt.body != "" {
				rawReq = fmt.Sprintf(
					"%s %s/api/resource HTTP/1.1\r\n"+
						"Host: %s\r\n"+
						"Content-Length: %d\r\n"+
						"Connection: close\r\n"+
						"\r\n"+
						"%s",
					tt.method, upstream.URL, upstreamURL.Host, len(tt.body), tt.body)
			} else {
				rawReq = fmt.Sprintf(
					"%s %s/api/resource HTTP/1.1\r\n"+
						"Host: %s\r\n"+
						"Connection: close\r\n"+
						"\r\n",
					tt.method, upstream.URL, upstreamURL.Host)
			}

			resp := sendViaProxy(t, listener.Addr(), rawReq)
			if resp.StatusCode != gohttp.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
			}

			select {
			case rr := <-results:
				if rr.auth != tt.wantToken {
					t.Errorf("method %s: upstream X-Write-Token = %q, want %q", tt.method, rr.auth, tt.wantToken)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for upstream request")
			}
		})
	}
}

// --- Multiple Rules / Priority ---

func TestTransformLive_MultipleRules_PriorityOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var receivedHeaders gohttp.Header
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	// Low priority adds a header.
	err := pipeline.AddRule(rules.Rule{
		ID:        "add-first",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Token",
			Value:  "first-value",
		},
	})
	if err != nil {
		t.Fatalf("AddRule(add-first): %v", err)
	}
	// Higher priority overwrites the same header.
	err = pipeline.AddRule(rules.Rule{
		ID:        "overwrite-second",
		Enabled:   true,
		Priority:  20,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Token",
			Value:  "second-value",
		},
	})
	if err != nil {
		t.Fatalf("AddRule(overwrite-second): %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The second rule (priority 20) runs after first (priority 10),
	// so the final value should be from the second rule.
	if got := receivedHeaders.Get("X-Token"); got != "second-value" {
		t.Errorf("X-Token = %q, want %q (second rule should overwrite first)", got, "second-value")
	}
}

// --- Both Direction ---

func TestTransformLive_BothDirection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var upstreamGotProxy string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamGotProxy = r.Header.Get("X-Via-Proxy")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	pipeline := rules.NewPipeline()
	// Rule with direction=both should apply to both request and response.
	err := pipeline.AddRule(rules.Rule{
		ID:        "both-direction",
		Enabled:   true,
		Priority:  10,
		Direction: rules.DirectionBoth,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Via-Proxy",
			Value:  "true",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	store := newTransformStore(t, ctx)
	listener, _, proxyCancel := startTransformProxy(t, ctx, store, pipeline)
	defer proxyCancel()

	upstreamURL := mustParseURL(upstream.URL)
	rawReq := fmt.Sprintf(
		"GET %s/test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, upstreamURL.Host)

	resp := sendViaProxy(t, listener.Addr(), rawReq)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Request side: upstream should have received the header.
	if upstreamGotProxy != "true" {
		t.Errorf("upstream X-Via-Proxy = %q, want %q", upstreamGotProxy, "true")
	}

	// Response side: client should also receive the header.
	if got := resp.Header.Get("X-Via-Proxy"); got != "true" {
		t.Errorf("client X-Via-Proxy = %q, want %q", got, "true")
	}
}
