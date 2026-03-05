package mcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunHTTP_StartAndShutdown(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	// Wait for the HTTP server to start accepting connections.
	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		cancel()
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// Cancel context to trigger graceful shutdown.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunHTTP returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunHTTP did not return within timeout after context cancellation")
	}
}

func TestRunHTTP_AcceptsMCPRequests(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)

	// Pick a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// Send a valid MCP initialize request via POST with correct Accept headers.
	// The StreamableHTTPHandler requires both application/json and text/event-stream.
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}`
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/mcp", addr), strings.NewReader(initReq))
	if err != nil {
		t.Fatalf("create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST initialize: %v", err)
	}
	defer resp.Body.Close()

	// The StreamableHTTPHandler should respond with 200 for a valid initialize request.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("POST initialize status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

func TestRunHTTP_InvalidAddress(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use an invalid address that will fail to bind.
	err := s.RunHTTP(ctx, "127.0.0.1:-1")
	if err == nil {
		t.Fatal("RunHTTP with invalid address should return error")
	}
}

func TestRunHTTP_RejectsNonLoopbackAddress(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tests := []struct {
		name string
		addr string
	}{
		{"all_interfaces", ":3000"},
		{"explicit_all", "0.0.0.0:3000"},
		{"external_ip", "192.168.1.1:3000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.RunHTTP(ctx, tt.addr)
			if err == nil {
				t.Fatalf("RunHTTP(%q) should reject non-loopback address", tt.addr)
			}
		})
	}
}

func TestRunHTTP_GracefulShutdownTimeout(t *testing.T) {
	// Override the shutdown timeout for this test.
	origTimeout := shutdownTimeout
	shutdownTimeout = 1 * time.Second
	t.Cleanup(func() { shutdownTimeout = origTimeout })

	s := NewServer(context.Background(), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		cancel()
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// Cancel and verify shutdown completes within a reasonable time
	// (the reduced 1s timeout + some buffer).
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunHTTP returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunHTTP did not shut down within expected timeout")
	}
}

func TestRunHTTP_MethodNotAllowed(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// PUT is not a valid MCP method. Include proper Accept headers so the
	// request reaches the method check in the StreamableHTTPHandler.
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/mcp", addr), nil)
	if err != nil {
		t.Fatalf("create PUT request: %v", err)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestRunHTTP_ServesWebUI(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// GET / should return the embedded index.html without authentication.
	resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "yorishiro-proxy") {
		t.Errorf("GET / body does not contain 'yorishiro-proxy': %s", body)
	}
}

func TestRunHTTP_WebUI_SPAFallback(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// GET /nonexistent/path should return index.html via SPA fallback.
	resp, err := http.Get(fmt.Sprintf("http://%s/nonexistent/path", addr))
	if err != nil {
		t.Fatalf("GET /nonexistent/path: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /nonexistent/path status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "yorishiro-proxy") {
		t.Errorf("GET /nonexistent/path body does not contain 'yorishiro-proxy': %s", body)
	}
}

func TestRunHTTP_WebUI_NoAuthRequired(t *testing.T) {
	// Set up middleware that requires Bearer auth (simulating production setup).
	token := "test-secret-token"
	s := NewServer(context.Background(), nil, nil, nil,
		WithMiddleware(func(next http.Handler) http.Handler {
			return BearerAuthMiddleware(next, token)
		}),
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// GET / should succeed without any auth header (WebUI is public).
	resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("GET / without auth status = %d, want %d; body = %s",
			resp.StatusCode, http.StatusOK, body)
	}
}

func TestRunHTTP_MCP_RequiresAuth(t *testing.T) {
	token := "test-secret-token"
	s := NewServer(context.Background(), nil, nil, nil,
		WithMiddleware(func(next http.Handler) http.Handler {
			return BearerAuthMiddleware(next, token)
		}),
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	// POST /mcp without auth should return 401.
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}`
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/mcp", addr), strings.NewReader(initReq))
	if err != nil {
		t.Fatalf("create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /mcp without auth status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestRunHTTP_WithUIDir(t *testing.T) {
	// Create a temp directory with a custom index.html.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/index.html", []byte("<h1>Custom UI</h1>"), 0644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}

	s := NewServer(context.Background(), nil, nil, nil, WithUIDir(dir))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		t.Fatalf("HTTP server did not start: %v", err)
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Custom UI") {
		t.Errorf("GET / body = %q, want to contain %q", string(body), "Custom UI")
	}
}

func TestRunHTTP_OnListeningCallback(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	callbackCh := make(chan string, 1)
	onListening := func(listenAddr string) {
		callbackCh <- listenAddr
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr, onListening)
	}()

	// Wait for the callback to be invoked.
	select {
	case gotAddr := <-callbackCh:
		if gotAddr == "" {
			t.Error("onListening callback received empty address")
		}
		// Verify the server is actually accepting connections at this point.
		conn, err := net.DialTimeout("tcp", gotAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("server not accepting connections after onListening: %v", err)
		}
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("onListening callback was not invoked within timeout")
	}
}

func TestRunHTTP_OnListeningNilCallback(t *testing.T) {
	// Verify that nil callback does not cause panic.
	s := NewServer(context.Background(), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr, nil)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		cancel()
		t.Fatalf("HTTP server did not start: %v", err)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunHTTP returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunHTTP did not return within timeout")
	}
}

func TestRunHTTP_NoCallback(t *testing.T) {
	// Verify backward compatibility: RunHTTP works without onListening argument.
	s := NewServer(context.Background(), nil, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunHTTP(ctx, addr)
	}()

	if err := waitForServer(t, addr, 3*time.Second); err != nil {
		cancel()
		t.Fatalf("HTTP server did not start: %v", err)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunHTTP returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunHTTP did not return within timeout")
	}
}

// waitForServer polls until the server at addr is accepting TCP connections.
func waitForServer(t *testing.T, addr string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("server at %s not reachable within %v", addr, timeout)
}
