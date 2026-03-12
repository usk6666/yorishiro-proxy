package http

import (
	"bufio"
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

func TestSafetyFilter_BlocksMatchingRequest(t *testing.T) {
	// Upstream should never be reached.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		t.Error("upstream should not be reached for blocked requests")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Send a request with a destructive SQL payload in the body.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	body := "DROP TABLE users"
	reqStr := fmt.Sprintf("POST %s/api HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"), len(body), body)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	// Verify 403 response.
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Check response headers.
	if got := resp.Header.Get("X-Blocked-By"); got != "yorishiro-proxy" {
		t.Errorf("X-Blocked-By = %q, want %q", got, "yorishiro-proxy")
	}
	if got := resp.Header.Get("X-Block-Reason"); got != "safety_filter" {
		t.Errorf("X-Block-Reason = %q, want %q", got, "safety_filter")
	}

	// Check response body contains expected fields.
	respBody, _ := io.ReadAll(resp.Body)
	bodyStr := string(respBody)
	for _, want := range []string{`"blocked_by":"safety_filter"`, `"rule":"test-block"`, `"error":"blocked by safety filter"`} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("body missing %q: got %s", want, bodyStr)
		}
	}

	// Verify flow was recorded with safety_filter blockedBy.
	time.Sleep(50 * time.Millisecond) // allow goroutine to finish recording
	entries := store.Entries()
	if len(entries) == 0 {
		t.Fatal("no flows recorded")
	}
	found := false
	for _, e := range entries {
		if e.Session.BlockedBy == "safety_filter" {
			found = true
			if e.Session.Tags == nil {
				t.Error("safety_filter flow has nil tags")
			} else {
				if e.Session.Tags["safety_rule"] != "test-block" {
					t.Errorf("safety_rule tag = %q, want %q", e.Session.Tags["safety_rule"], "test-block")
				}
				if e.Session.Tags["safety_target"] == "" {
					t.Error("safety_target tag is empty")
				}
			}
			break
		}
	}
	if !found {
		t.Error("no flow with BlockedBy=safety_filter found")
	}
}

func TestSafetyFilter_LogOnlyPassesThrough(t *testing.T) {
	var upstreamReached atomic.Bool
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamReached.Store(true)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	handler.SetSafetyEngine(newLogOnlyEngine(t, `DROP\s+TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	body := "DROP TABLE users"
	reqStr := fmt.Sprintf("POST %s/api HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"), len(body), body)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	// log_only: request should pass through.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !upstreamReached.Load() {
		t.Error("upstream was not reached with log_only action")
	}
}

func TestSafetyFilter_NoEnginePassesThrough(t *testing.T) {
	var upstreamReached atomic.Bool
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamReached.Store(true)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// No safety engine set.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	body := "DROP TABLE users"
	reqStr := fmt.Sprintf("POST %s/api HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"), len(body), body)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !upstreamReached.Load() {
		t.Error("upstream was not reached without safety engine")
	}
}

func TestSafetyFilter_NoMatchPassesThrough(t *testing.T) {
	var upstreamReached atomic.Bool
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamReached.Store(true)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send a harmless request body.
	body := `{"action":"select","table":"users"}`
	reqStr := fmt.Sprintf("POST %s/api HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"), len(body), body)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !upstreamReached.Load() {
		t.Error("upstream was not reached for non-matching request")
	}
}

func TestSafetyFilter_BlocksURLMatch(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		t.Error("upstream should not be reached for blocked URL match")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// Use a pattern that matches URL-encoded content (.*  matches %20 encoding).
	handler.SetSafetyEngine(newBlockEngine(t, `DROP.*TABLE`))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Put the destructive payload in the URL query (URL-encoded spaces).
	reqStr := fmt.Sprintf("GET %s/api?q=DROP%%20TABLE%%20users HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"))
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}
}
