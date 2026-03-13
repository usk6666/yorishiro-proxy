package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newOutputMaskEngine creates a safety engine with output rules that mask the given pattern.
func newOutputMaskEngine(t *testing.T, pattern, replacement string, targets []string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{{
			ID:          "test-output-mask",
			Name:        "test output mask rule",
			Pattern:     pattern,
			Targets:     targets,
			Action:      "mask",
			Replacement: replacement,
		}},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func TestOutputFilter_MasksResponseBody(t *testing.T) {
	// Upstream returns a response body containing sensitive data.
	sensitiveBody := `{"user":"alice","ssn":"123-45-6789","email":"alice@example.com"}`
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, sensitiveBody)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// Mask SSN pattern in response body.
	handler.SetSafetyEngine(newOutputMaskEngine(t, `\d{3}-\d{2}-\d{4}`, "***-**-****", []string{"body"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	reqStr := fmt.Sprintf("GET %s/api HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"))
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	bodyStr := string(respBody)

	// Client should receive masked body.
	if strings.Contains(bodyStr, "123-45-6789") {
		t.Errorf("response body should not contain raw SSN, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "***-**-****") {
		t.Errorf("response body should contain masked SSN, got: %s", bodyStr)
	}

	// Content-Length should match the actual masked body length.
	cl := resp.Header.Get("Content-Length")
	if cl != "" {
		clInt, _ := strconv.Atoi(cl)
		if clInt != len(respBody) {
			t.Errorf("Content-Length = %d, want %d", clInt, len(respBody))
		}
	}

	// Verify flow store has raw (unmasked) data.
	time.Sleep(50 * time.Millisecond)
	entries := store.Entries()
	if len(entries) == 0 {
		t.Fatal("no flows recorded")
	}
	for _, e := range entries {
		if e.Receive != nil {
			storedBody := string(e.Receive.Body)
			if !strings.Contains(storedBody, "123-45-6789") {
				t.Errorf("flow store body should contain raw SSN, got: %s", storedBody)
			}
			if strings.Contains(storedBody, "***-**-****") {
				t.Errorf("flow store body should NOT contain masked SSN, got: %s", storedBody)
			}
			break
		}
	}
}

func TestOutputFilter_MasksResponseHeaders(t *testing.T) {
	// Upstream returns a response with sensitive data in a custom header.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-User-Token", "secret-token-abc123")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// Mask token pattern in response headers.
	handler.SetSafetyEngine(newOutputMaskEngine(t, `secret-token-\w+`, "[REDACTED]", []string{"headers"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	reqStr := fmt.Sprintf("GET %s/api HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"))
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	// Client should receive masked header.
	got := resp.Header.Get("X-User-Token")
	if strings.Contains(got, "secret-token") {
		t.Errorf("response header should be masked, got: %s", got)
	}
	if got != "[REDACTED]" {
		t.Errorf("response header = %q, want %q", got, "[REDACTED]")
	}
}

func TestOutputFilter_ContentLengthRecalculated(t *testing.T) {
	// The original body is longer than the masked version.
	originalBody := "My SSN is 123-45-6789 and that is private"
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(originalBody)))
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, originalBody)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// Mask SSN — replacement is same length, so Content-Length should stay the same.
	handler.SetSafetyEngine(newOutputMaskEngine(t, `\d{3}-\d{2}-\d{4}`, "***-**-****", []string{"body"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	reqStr := fmt.Sprintf("GET %s/data HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"))
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Content-Length must match the actual body length delivered.
	cl := resp.Header.Get("Content-Length")
	if cl == "" {
		t.Fatal("Content-Length header missing")
	}
	clInt, _ := strconv.Atoi(cl)
	if clInt != len(respBody) {
		t.Errorf("Content-Length = %d, want %d (body length)", clInt, len(respBody))
	}
}

func TestOutputFilter_NoEnginePassesThrough(t *testing.T) {
	expectedBody := "sensitive data 123-45-6789"
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, expectedBody)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// No safety engine set — output filter should be a no-op.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	reqStr := fmt.Sprintf("GET %s/api HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"))
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != expectedBody {
		t.Errorf("body = %q, want %q", string(respBody), expectedBody)
	}
}

func TestOutputFilter_NoMatchPassesThrough(t *testing.T) {
	expectedBody := `{"action":"list","status":"ok"}`
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, expectedBody)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// Engine configured but pattern won't match the response.
	handler.SetSafetyEngine(newOutputMaskEngine(t, `\d{3}-\d{2}-\d{4}`, "***-**-****", []string{"body"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	reqStr := fmt.Sprintf("GET %s/api HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, strings.TrimPrefix(upstream.URL, "http://"))
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != expectedBody {
		t.Errorf("body = %q, want %q", string(respBody), expectedBody)
	}
}
