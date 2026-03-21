package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newBlockEngine creates a safety engine with a single block rule matching the given pattern.
func newBlockEngine(t *testing.T, pattern string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{{
			ID:      "test-block",
			Name:    "test block rule",
			Pattern: pattern,
			Targets: []string{"body", "url", "query"},
			Action:  "block",
		}},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// newLogOnlyEngine creates a safety engine with a single log_only rule.
func newLogOnlyEngine(t *testing.T, pattern string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{{
			ID:      "test-logonly",
			Name:    "test log_only rule",
			Pattern: pattern,
			Targets: []string{"body", "url", "query"},
			Action:  "log_only",
		}},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestHTTP2SafetyFilter_BlocksMatchingRequest(t *testing.T) {
	// Upstream should never be reached.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		t.Error("upstream should not be reached for blocked requests")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(ctx, "test-safety-h2c")
				hctx = proxy.ContextWithClientAddr(hctx, conn.RemoteAddr().String())
				handler.Handle(hctx, conn)
			}()
		}
	}()

	client := newH2CClientForAddr(ln.Addr().String())
	body := "DROP TABLE users"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api", upstream.URL), bytes.NewReader([]byte(body)))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Verify 403 response.
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Verify response headers.
	if got := resp.Header.Get("X-Blocked-By"); got != "yorishiro-proxy" {
		t.Errorf("X-Blocked-By = %q, want %q", got, "yorishiro-proxy")
	}
	if got := resp.Header.Get("X-Block-Reason"); got != "safety_filter" {
		t.Errorf("X-Block-Reason = %q, want %q", got, "safety_filter")
	}

	// Verify response body.
	bodyStr := string(respBody)
	for _, want := range []string{`"blocked_by":"safety_filter"`, `"rule":"test-block"`, `"error":"blocked by safety filter"`} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("body missing %q: got %s", want, bodyStr)
		}
	}

	// Verify flow recording: blocked request should be recorded.
	time.Sleep(200 * time.Millisecond)
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
	if entry.Send.Method != "POST" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "POST")
	}
	if entry.Receive != nil {
		t.Error("blocked flow should not have a receive message")
	}
	// Verify safety tags.
	if got := entry.Session.Tags["safety_rule"]; got != "test-block" {
		t.Errorf("safety_rule tag = %q, want %q", got, "test-block")
	}
	if _, ok := entry.Session.Tags["safety_target"]; !ok {
		t.Error("safety_target tag is missing")
	}
}

func TestHTTP2SafetyFilter_LogOnlyPassesThrough(t *testing.T) {
	var upstreamReached atomic.Bool
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamReached.Store(true)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newLogOnlyEngine(t, `DROP\s+TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(ctx, "test-safety-logonly")
				hctx = proxy.ContextWithClientAddr(hctx, conn.RemoteAddr().String())
				handler.Handle(hctx, conn)
			}()
		}
	}()

	client := newH2CClientForAddr(ln.Addr().String())
	body := "DROP TABLE users"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api", upstream.URL), bytes.NewReader([]byte(body)))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !upstreamReached.Load() {
		t.Error("upstream was not reached with log_only action")
	}
}

func TestHTTP2SafetyFilter_NoEnginePassesThrough(t *testing.T) {
	var upstreamReached atomic.Bool
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamReached.Store(true)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// No safety engine set.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(ctx, "test-safety-none")
				hctx = proxy.ContextWithClientAddr(hctx, conn.RemoteAddr().String())
				handler.Handle(hctx, conn)
			}()
		}
	}()

	client := newH2CClientForAddr(ln.Addr().String())
	body := "DROP TABLE users"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api", upstream.URL), bytes.NewReader([]byte(body)))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !upstreamReached.Load() {
		t.Error("upstream was not reached without safety engine")
	}
}

func TestHTTP2TargetScope_BlockedFlowRecording(t *testing.T) {
	// Upstream should never be reached.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		t.Error("upstream should not be reached for blocked requests")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// Create a target scope that denies the upstream host.
	scope := proxy.NewTargetScope()
	scope.SetAgentRules(nil, []proxy.TargetRule{{Hostname: "127.0.0.1"}})
	handler.SetTargetScope(scope)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addr, cancelLn := startH2CProxyListener(t, handler, "test-scope-block", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancelLn()

	client := newH2CClientForAddr(addr)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/test", upstream.URL), nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Verify flow recording.
	time.Sleep(200 * time.Millisecond)
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
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "GET")
	}
	if entry.Receive != nil {
		t.Error("blocked flow should not have a receive message")
	}
}

func TestHTTP2RateLimit_BlockedFlowRecording(t *testing.T) {
	// Upstream should not be reached for rate-limited requests.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// Create a rate limiter with a very low limit (0.001 RPS = effectively blocked).
	rl := proxy.NewRateLimiter()
	rl.SetPolicyLimits(proxy.RateLimitConfig{MaxRequestsPerSecond: 0.001})
	handler.SetRateLimiter(rl)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addr, cancelLn := startH2CProxyListener(t, handler, "test-ratelimit-block", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancelLn()

	client := newH2CClientForAddr(addr)

	// First request consumes the token. Send it and ignore the result.
	req1, _ := gohttp.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/first", upstream.URL), nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("first h2c request failed: %v", err)
	}
	resp1.Body.Close()

	// Second request should be rate-limited.
	req2, _ := gohttp.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/second", upstream.URL), bytes.NewReader([]byte("rate-limited-body")))
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second h2c request failed: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != gohttp.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", resp2.StatusCode, gohttp.StatusTooManyRequests)
	}

	// Verify flow recording — should have 2 entries (1 normal + 1 rate-limited).
	time.Sleep(200 * time.Millisecond)
	entries := store.Entries()

	var rateLimitedEntry *mockEntry
	for i := range entries {
		if entries[i].Session.BlockedBy == "rate_limit" {
			rateLimitedEntry = &entries[i]
			break
		}
	}

	if rateLimitedEntry == nil {
		t.Fatalf("no rate_limit blocked flow found among %d entries", len(entries))
	}

	if rateLimitedEntry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", rateLimitedEntry.Session.State, "complete")
	}
	if rateLimitedEntry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", rateLimitedEntry.Session.Protocol, "HTTP/2")
	}
	if rateLimitedEntry.Send == nil {
		t.Fatal("send message is nil")
	}
	if rateLimitedEntry.Send.Method != "POST" {
		t.Errorf("send method = %q, want %q", rateLimitedEntry.Send.Method, "POST")
	}
	if rateLimitedEntry.Receive != nil {
		t.Error("blocked flow should not have a receive message")
	}
}
