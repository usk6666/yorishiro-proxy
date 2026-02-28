package mcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/", addr), strings.NewReader(initReq))
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
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/", addr), nil)
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
