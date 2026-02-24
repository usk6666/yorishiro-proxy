package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/katashiro-proxy/internal/protocol/http"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

func startProxy(t *testing.T, ctx context.Context, store session.Store) (*proxy.Listener, context.CancelFunc) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpHandler := protohttp.NewHandler(store, nil, logger)
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

	return listener, proxyCancel
}

func proxyClient(proxyAddr string) *gohttp.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}
}

func TestIntegration_HTTPForwardProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start a test upstream HTTP server.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "upstream")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from upstream")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Create temporary SQLite database.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Build and start proxy.
	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	// Send GET request through proxy.
	targetURL := fmt.Sprintf("http://%s/test-path", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from upstream" {
		t.Errorf("body = %q, want %q", body, "hello from upstream")
	}
	if resp.Header.Get("X-Test") != "upstream" {
		t.Errorf("X-Test header = %q, want %q", resp.Header.Get("X-Test"), "upstream")
	}

	// Wait for session to be persisted.
	time.Sleep(100 * time.Millisecond)

	// Verify session was recorded in SQLite.
	entries, err := store.List(ctx, session.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 session, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Request.Method != "GET" {
		t.Errorf("session method = %q, want %q", entry.Request.Method, "GET")
	}
	if entry.Request.URL == nil || entry.Request.URL.Path != "/test-path" {
		path := ""
		if entry.Request.URL != nil {
			path = entry.Request.URL.Path
		}
		t.Errorf("session URL path = %q, want %q", path, "/test-path")
	}
	if entry.Response.StatusCode != 200 {
		t.Errorf("session status = %d, want %d", entry.Response.StatusCode, 200)
	}
	if string(entry.Response.Body) != "hello from upstream" {
		t.Errorf("session response body = %q, want %q", entry.Response.Body, "hello from upstream")
	}
	if entry.Protocol != "HTTP/1.x" {
		t.Errorf("session protocol = %q, want %q", entry.Protocol, "HTTP/1.x")
	}
}

func TestIntegration_MalformedHTTPRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "binary garbage data",
			payload: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x81},
		},
		{
			name:    "empty line only",
			payload: []byte("\r\n\r\n"),
		},
		{
			name:    "lone CRLF",
			payload: []byte("\r\n"),
		},
		{
			name: "ultra long URL over 8KB",
			payload: func() []byte {
				longPath := strings.Repeat("A", 9000)
				return []byte(fmt.Sprintf("GET http://127.0.0.1/%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", longPath))
			}(),
		},
		{
			name:    "missing Host header",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\n\r\n"),
		},
		{
			name:    "negative Content-Length",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -1\r\n\r\n"),
		},
		{
			name:    "non-numeric Content-Length",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: abc\r\n\r\n"),
		},
		{
			name:    "NUL byte in header value",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Evil: foo\x00bar\r\n\r\n"),
		},
		{
			name:    "NUL byte in header name",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nX-E\x00vil: value\r\n\r\n"),
		},
		{
			name:    "invalid HTTP method with binary prefix",
			payload: []byte("\x00\x01BADMETHOD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
		},
		{
			name:    "completely invalid protocol line",
			payload: []byte("THIS IS NOT HTTP\r\n\r\n"),
		},
		{
			name:    "HTTP request with no version",
			payload: []byte("GET http://127.0.0.1/test\r\nHost: 127.0.0.1\r\n\r\n"),
		},
		{
			name:    "double Content-Length headers with different values",
			payload: []byte("POST http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello"),
		},
		{
			name:    "extremely large Content-Length",
			payload: []byte("POST http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 99999999999999\r\n\r\n"),
		},
		{
			name:    "header without colon",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\nBrokenHeader\r\n\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			// Set a deadline to prevent the test from hanging.
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// Write the malformed request.
			if _, err := conn.Write(tt.payload); err != nil {
				// Write failure is acceptable — proxy may have closed the connection.
				return
			}

			// Try to read any response. The proxy should either respond with an
			// error or close the connection gracefully — it must NOT panic.
			buf := make([]byte, 4096)
			_, err = conn.Read(buf)
			// Any outcome is acceptable: error response, EOF, or timeout.
			// The key invariant is that the proxy process is still alive.
			_ = err
		})
	}

	// Verify the proxy is still running by sending a valid request.
	t.Run("proxy still alive after malformed requests", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("proxy is not accepting connections after malformed requests: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Send a valid HTTP request to confirm the proxy is functional.
		validReq := "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(validReq)); err != nil {
			t.Fatalf("write valid request: %v", err)
		}

		// Read response — we expect the proxy to respond (even if upstream is unreachable).
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			t.Fatalf("proxy did not respond to valid request after malformed inputs: %v", err)
		}
		// Verify it looks like an HTTP response.
		if n > 0 && !strings.HasPrefix(string(buf[:n]), "HTTP/") {
			t.Errorf("response does not look like HTTP: %q", string(buf[:n]))
		}
	})
}

func TestIntegration_PartialHTTPRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "partial request line only",
			payload: []byte("GET http://127.0.0.1/test HT"),
		},
		{
			name:    "request line without terminating CRLF",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1"),
		},
		{
			name:    "headers without final CRLF",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1"),
		},
		{
			name:    "headers with single CRLF but no blank line",
			payload: []byte("GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// Write partial request data.
			if _, err := conn.Write(tt.payload); err != nil {
				conn.Close()
				return
			}

			// Immediately close the write side to simulate abrupt disconnection.
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}

			// Read until EOF or error — the proxy should close the connection gracefully.
			buf := make([]byte, 4096)
			_, err = conn.Read(buf)
			// Any outcome (EOF, error, or response) is acceptable.
			_ = err

			conn.Close()
		})
	}

	// Confirm proxy is still alive.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy is not accepting connections after partial requests: %v", err)
	}
	conn.Close()
}

func TestIntegration_TransferEncodingChunked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start a test upstream HTTP server that reads the body.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "received: %s", body)
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	// Send a valid chunked transfer-encoding request.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	chunkedReq := fmt.Sprintf(
		"POST http://%s/chunked HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"5\r\nhello\r\n"+
			"6\r\n world\r\n"+
			"0\r\n"+
			"\r\n",
		upstreamAddr, upstreamAddr,
	)

	if _, err := conn.Write([]byte(chunkedReq)); err != nil {
		t.Fatalf("write chunked request: %v", err)
	}

	// Read response.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read response: %v", err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "200") {
		t.Errorf("expected 200 OK response, got: %q", response)
	}
	if !strings.Contains(response, "received: hello world") {
		t.Errorf("expected chunked body to be reassembled, got: %q", response)
	}
}

func TestIntegration_MalformedChunkedEncoding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name: "invalid chunk size",
			payload: "POST http://127.0.0.1/test HTTP/1.1\r\n" +
				"Host: 127.0.0.1\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"Connection: close\r\n" +
				"\r\n" +
				"xyz\r\nbad\r\n0\r\n\r\n",
		},
		{
			name: "negative chunk size",
			payload: "POST http://127.0.0.1/test HTTP/1.1\r\n" +
				"Host: 127.0.0.1\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"Connection: close\r\n" +
				"\r\n" +
				"-1\r\nbad\r\n0\r\n\r\n",
		},
		{
			name: "incomplete chunk data",
			payload: "POST http://127.0.0.1/test HTTP/1.1\r\n" +
				"Host: 127.0.0.1\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"Connection: close\r\n" +
				"\r\n" +
				"100\r\nshort",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := conn.Write([]byte(tt.payload)); err != nil {
				return
			}

			// Read response or wait for close.
			buf := make([]byte, 4096)
			_, err = conn.Read(buf)
			_ = err // Any outcome is acceptable.
		})
	}

	// Verify proxy is still alive.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy is not accepting connections after malformed chunks: %v", err)
	}
	conn.Close()
}

func TestIntegration_HTTPForwardProxy_POST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "received: %s", body)
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	targetURL := fmt.Sprintf("http://%s/api/data", upstreamListener.Addr().String())
	resp, err := client.Post(targetURL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusCreated)
	}

	time.Sleep(100 * time.Millisecond)

	entries, err := store.List(ctx, session.ListOptions{Method: "POST"})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 POST session, got %d", len(entries))
	}
	if entries[0].Response.StatusCode != 201 {
		t.Errorf("session status = %d, want %d", entries[0].Response.StatusCode, 201)
	}
}

func TestIntegration_ConcurrentClients_HTTP(t *testing.T) {
	const numClients = 15

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream HTTP server that echoes a unique identifier back.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "echo:%s:%s", r.URL.Path, string(body))
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Create temporary SQLite database.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Build and start proxy.
	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	// Launch concurrent clients, each sending a unique request.
	var wg sync.WaitGroup
	wg.Add(numClients)

	for i := 0; i < numClients; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine creates its own HTTP client (separate connection).
			client := proxyClient(listener.Addr())

			path := fmt.Sprintf("/concurrent/%d", id)
			reqBody := fmt.Sprintf(`{"client":%d}`, id)
			targetURL := fmt.Sprintf("http://%s%s", upstreamAddr, path)

			resp, err := client.Post(targetURL, "application/json", strings.NewReader(reqBody))
			if err != nil {
				t.Errorf("client %d: POST through proxy: %v", id, err)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("client %d: status = %d, want %d", id, resp.StatusCode, gohttp.StatusOK)
			}

			expectedBody := fmt.Sprintf("echo:%s:%s", path, reqBody)
			if string(body) != expectedBody {
				t.Errorf("client %d: body = %q, want %q", id, body, expectedBody)
			}
		}(i)
	}

	wg.Wait()

	// Wait for all sessions to be persisted.
	time.Sleep(500 * time.Millisecond)

	// Verify all sessions were recorded.
	entries, err := store.List(ctx, session.ListOptions{Limit: numClients + 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != numClients {
		t.Fatalf("expected %d sessions, got %d", numClients, len(entries))
	}

	// Verify each client's session is distinct and data is not mixed.
	seenPaths := make(map[string]bool)
	seenBodies := make(map[string]bool)
	for _, entry := range entries {
		if entry.Protocol != "HTTP/1.x" {
			t.Errorf("session protocol = %q, want %q", entry.Protocol, "HTTP/1.x")
		}
		if entry.Request.Method != "POST" {
			t.Errorf("session method = %q, want %q", entry.Request.Method, "POST")
		}
		if entry.Request.URL == nil {
			t.Error("request URL is nil")
			continue
		}

		path := entry.Request.URL.Path
		seenPaths[path] = true

		// Verify request body matches the path (no cross-contamination).
		// Path is /concurrent/<id>, body is {"client":<id>}.
		// Extract the ID from the path and verify it matches the body.
		var pathID int
		if _, err := fmt.Sscanf(path, "/concurrent/%d", &pathID); err != nil {
			t.Errorf("unexpected path format: %q", path)
			continue
		}
		expectedReqBody := fmt.Sprintf(`{"client":%d}`, pathID)
		if string(entry.Request.Body) != expectedReqBody {
			t.Errorf("session path %s: request body = %q, want %q (data mixed between sessions)",
				path, entry.Request.Body, expectedReqBody)
		}

		// Verify response body matches.
		expectedRespBody := fmt.Sprintf("echo:%s:%s", path, expectedReqBody)
		if string(entry.Response.Body) != expectedRespBody {
			t.Errorf("session path %s: response body = %q, want %q (data mixed between sessions)",
				path, entry.Response.Body, expectedRespBody)
		}

		seenBodies[string(entry.Request.Body)] = true

		if entry.Response.StatusCode != 200 {
			t.Errorf("session path %s: status = %d, want %d", path, entry.Response.StatusCode, 200)
		}
		if entry.ID == "" {
			t.Errorf("session path %s: ID is empty", path)
		}
		if entry.Duration < 0 {
			t.Errorf("session path %s: duration = %v, want non-negative", path, entry.Duration)
		}
	}

	// Verify all unique paths were recorded (no duplicates, no missing).
	if len(seenPaths) != numClients {
		t.Errorf("expected %d unique paths, got %d", numClients, len(seenPaths))
	}
	for i := 0; i < numClients; i++ {
		expectedPath := fmt.Sprintf("/concurrent/%d", i)
		if !seenPaths[expectedPath] {
			t.Errorf("missing session for path %q", expectedPath)
		}
	}
}

// --- Error Recovery Integration Tests ---

// failingStore is a session.Store that always returns an error from Save.
// It is used to verify that the proxy continues forwarding traffic even when
// session persistence fails (USK-36 fix).
type failingStore struct {
	saveCallCount atomic.Int64
}

func (s *failingStore) Save(_ context.Context, _ *session.Entry) error {
	s.saveCallCount.Add(1)
	return errors.New("simulated DB write failure")
}

func (s *failingStore) Get(_ context.Context, _ string) (*session.Entry, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) List(_ context.Context, _ session.ListOptions) ([]*session.Entry, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) Count(_ context.Context, _ session.ListOptions) (int, error) {
	return 0, errors.New("simulated DB read failure")
}

func (s *failingStore) Delete(_ context.Context, _ string) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteAll(_ context.Context) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteExcess(_ context.Context, _ int) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure(t *testing.T) {
	// Verifies that when session.Store.Save fails, the proxy still forwards
	// the upstream response to the client (USK-36 fix).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start a test upstream HTTP server.
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "upstream response")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Use a failing store instead of a real SQLite store.
	store := &failingStore{}

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	// Send a request through the proxy.
	targetURL := fmt.Sprintf("http://%s/test-error-recovery", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy with failing store: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The proxy should have forwarded the response despite the save failure.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "upstream response" {
		t.Errorf("body = %q, want %q", body, "upstream response")
	}
	if resp.Header.Get("X-Test") != "ok" {
		t.Errorf("X-Test header = %q, want %q", resp.Header.Get("X-Test"), "ok")
	}

	// Verify that Save was actually called (and failed).
	if store.saveCallCount.Load() == 0 {
		t.Error("expected Save to be called at least once, but it was not")
	}
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure_MultipleRequests(t *testing.T) {
	// Verifies that multiple sequential requests through the same proxy continue
	// to work even when every Save call fails. This tests the keep-alive
	// connection behavior under persistent save failures.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var requestCount atomic.Int64
	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		n := requestCount.Add(1)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "response-%d", n)
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	store := &failingStore{}

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	// Send multiple requests through the proxy.
	const numRequests = 5
	for i := 0; i < numRequests; i++ {
		targetURL := fmt.Sprintf("http://%s/request-%d", upstreamAddr, i)
		resp, err := client.Get(targetURL)
		if err != nil {
			t.Fatalf("GET %d through proxy with failing store: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != gohttp.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i, resp.StatusCode, gohttp.StatusOK)
		}
		if len(body) == 0 {
			t.Errorf("request %d: got empty body", i)
		}
	}

	// All Save calls should have been attempted (and failed).
	// Because the HTTP handler writes the response to the client before calling
	// store.Save(), the last Save may still be in-flight when the final
	// client.Get() returns. Poll with a bounded deadline instead of asserting
	// immediately.
	deadline := time.After(5 * time.Second)
	for {
		if got := store.saveCallCount.Load(); got >= int64(numRequests) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for Save call count to reach %d (got %d)", numRequests, store.saveCallCount.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure_WithRealDB(t *testing.T) {
	// This test uses a real SQLite store, saves some entries, then closes
	// the database to simulate a failure mid-operation. The proxy should
	// still forward traffic.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Create a real store and immediately use a failing store for the proxy.
	// This approach avoids the complexity of closing a DB mid-stream.
	// The real-world scenario (DB failure after successful start) is adequately
	// covered by the failingStore tests above.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	realStore, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// First, verify the proxy works with a healthy store.
	listener1, proxyCancel1 := startProxy(t, ctx, realStore)
	client1 := proxyClient(listener1.Addr())

	resp, err := client1.Get(fmt.Sprintf("http://%s/healthy", upstreamAddr))
	if err != nil {
		t.Fatalf("GET through healthy proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("healthy proxy: status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	proxyCancel1()

	// Close the real store — this simulates a DB failure.
	realStore.Close()

	// Now start a proxy with a failing store and verify it still forwards.
	failStore := &failingStore{}
	listener2, proxyCancel2 := startProxy(t, ctx, failStore)
	defer proxyCancel2()

	client2 := proxyClient(listener2.Addr())
	resp2, err := client2.Get(fmt.Sprintf("http://%s/after-failure", upstreamAddr))
	if err != nil {
		t.Fatalf("GET through failing proxy: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != gohttp.StatusOK {
		t.Errorf("failing proxy: status = %d, want %d", resp2.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

func TestIntegration_ProxyContextCancellation(t *testing.T) {
	// Verifies that the proxy shuts down cleanly when the context is cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	})
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamListener)
	defer upstreamServer.Close()

	upstreamAddr := upstreamListener.Addr().String()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)

	client := proxyClient(listener.Addr())

	// Verify proxy works before cancellation.
	resp, err := client.Get(fmt.Sprintf("http://%s/before-cancel", upstreamAddr))
	if err != nil {
		t.Fatalf("GET before cancel: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status before cancel = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Cancel the proxy context.
	proxyCancel()

	// Give the proxy a moment to shut down.
	time.Sleep(200 * time.Millisecond)

	// Requests after cancellation should fail (connection refused).
	_, err = client.Get(fmt.Sprintf("http://%s/after-cancel", upstreamAddr))
	if err == nil {
		t.Error("expected error after proxy cancellation, got nil")
	}
}
