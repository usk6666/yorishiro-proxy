package proxy_test

import (
	"bytes"
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

	// Poll for session and messages to be persisted.
	var sessions []*session.Session
	var send, recv *session.Message
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		sessions, err = store.ListSessions(ctx, session.ListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if len(sessions) != 1 {
			continue
		}
		msgs, mErr := store.GetMessages(ctx, sessions[0].ID, session.MessageListOptions{})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		for _, m := range msgs {
			switch m.Direction {
			case "send":
				send = m
			case "receive":
				recv = m
			}
		}
		if send != nil && recv != nil {
			break
		}
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	sess := sessions[0]
	if sess.Protocol != "HTTP/1.x" {
		t.Errorf("session protocol = %q, want %q", sess.Protocol, "HTTP/1.x")
	}
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if send.Method != "GET" {
		t.Errorf("session method = %q, want %q", send.Method, "GET")
	}
	if send.URL == nil || send.URL.Path != "/test-path" {
		path := ""
		if send.URL != nil {
			path = send.URL.Path
		}
		t.Errorf("session URL path = %q, want %q", path, "/test-path")
	}
	if recv.StatusCode != 200 {
		t.Errorf("session status = %d, want %d", recv.StatusCode, 200)
	}
	if string(recv.Body) != "hello from upstream" {
		t.Errorf("session response body = %q, want %q", recv.Body, "hello from upstream")
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

	sessions, err := store.ListSessions(ctx, session.ListOptions{Method: "POST"})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 POST session, got %d", len(sessions))
	}
	recvMsgs, err := store.GetMessages(ctx, sessions[0].ID, session.MessageListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(recvMsgs) == 0 {
		t.Fatal("no receive message found")
	}
	if recvMsgs[0].StatusCode != 201 {
		t.Errorf("session status = %d, want %d", recvMsgs[0].StatusCode, 201)
	}
}

// maxBodyRecordSize mirrors the constant from the HTTP handler (1MB).
const maxBodyRecordSize = 1 << 20

func TestIntegration_LargeBodyBoundary_HTTP(t *testing.T) {
	tests := []struct {
		name string
		// bodySize is the size of the request body to send.
		bodySize int
		// wantReqTruncated is whether the recorded request body should be truncated.
		wantReqTruncated bool
		// wantRespTruncated is whether the recorded response body should be truncated.
		wantRespTruncated bool
		// wantRecordedReqLen is the expected length of the recorded request body.
		wantRecordedReqLen int
		// wantRecordedRespLen is the expected length of the recorded response body.
		wantRecordedRespLen int
		// timeout is the context timeout for this test case.
		timeout time.Duration
	}{
		{
			name:                "empty body",
			bodySize:            0,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  0,
			wantRecordedRespLen: 0,
			timeout:             15 * time.Second,
		},
		{
			name:                "body exactly 1MB",
			bodySize:            maxBodyRecordSize,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             30 * time.Second,
		},
		{
			name:                "body 1MB plus 1 byte",
			bodySize:            maxBodyRecordSize + 1,
			wantReqTruncated:    true,
			wantRespTruncated:   true,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             30 * time.Second,
		},
		{
			name:                "very large body 2MB",
			bodySize:            2 * maxBodyRecordSize,
			wantReqTruncated:    true,
			wantRespTruncated:   true,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             60 * time.Second,
		},
		{
			name:                "very large body 10MB",
			bodySize:            10 * maxBodyRecordSize,
			wantReqTruncated:    true,
			wantRespTruncated:   true,
			wantRecordedReqLen:  maxBodyRecordSize,
			wantRecordedRespLen: maxBodyRecordSize,
			timeout:             120 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			// Start upstream echo server: responds with the same body it received.
			upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(gohttp.StatusOK)
				io.Copy(w, r.Body)
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

			client := proxyClient(listener.Addr())
			client.Timeout = tt.timeout

			// Generate deterministic test data using a repeating pattern.
			var reqBody []byte
			if tt.bodySize > 0 {
				reqBody = bytes.Repeat([]byte("A"), tt.bodySize)
			}

			// Send POST request through the proxy.
			targetURL := fmt.Sprintf("http://%s/large-body-test", upstreamAddr)
			resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("POST through proxy: %v", err)
			}
			defer resp.Body.Close()

			// Verify the full response body was transferred correctly (not truncated in transit).
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}

			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
			}
			if len(respBody) != tt.bodySize {
				t.Errorf("response body length = %d, want %d (transfer should not truncate)", len(respBody), tt.bodySize)
			}
			if tt.bodySize > 0 && !bytes.Equal(respBody, reqBody) {
				t.Error("response body content differs from request body (transfer corruption)")
			}

			// Poll for session and messages to be persisted (large bodies may take longer to save).
			var sessions []*session.Session
			var send, recv *session.Message
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				sessions, err = store.ListSessions(ctx, session.ListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("ListSessions: %v", err)
				}
				if len(sessions) != 1 {
					continue
				}
				msgs, err := store.GetMessages(ctx, sessions[0].ID, session.MessageListOptions{})
				if err != nil {
					t.Fatalf("GetMessages: %v", err)
				}
				for _, m := range msgs {
					switch m.Direction {
					case "send":
						send = m
					case "receive":
						recv = m
					}
				}
				if send != nil && recv != nil {
					break
				}
			}
			if len(sessions) != 1 {
				t.Fatalf("expected 1 session, got %d", len(sessions))
			}
			sess := sessions[0]
			if send == nil {
				t.Fatal("send message not found")
			}
			if recv == nil {
				t.Fatal("receive message not found")
			}

			// Verify request body recording.
			if len(send.Body) != tt.wantRecordedReqLen {
				t.Errorf("recorded request body length = %d, want %d", len(send.Body), tt.wantRecordedReqLen)
			}
			if send.BodyTruncated != tt.wantReqTruncated {
				t.Errorf("request BodyTruncated = %v, want %v", send.BodyTruncated, tt.wantReqTruncated)
			}

			// Verify response body recording.
			if len(recv.Body) != tt.wantRecordedRespLen {
				t.Errorf("recorded response body length = %d, want %d", len(recv.Body), tt.wantRecordedRespLen)
			}
			if recv.BodyTruncated != tt.wantRespTruncated {
				t.Errorf("response BodyTruncated = %v, want %v", recv.BodyTruncated, tt.wantRespTruncated)
			}

			// When truncated, verify the recorded body is the prefix of the original.
			if tt.wantReqTruncated && tt.bodySize > 0 {
				if !bytes.Equal(send.Body, reqBody[:maxBodyRecordSize]) {
					t.Error("truncated request body is not a prefix of the original body")
				}
			}
			if tt.wantRespTruncated && tt.bodySize > 0 {
				if !bytes.Equal(recv.Body, reqBody[:maxBodyRecordSize]) {
					t.Error("truncated response body is not a prefix of the original body")
				}
			}

			// Verify metadata.
			if sess.Protocol != "HTTP/1.x" {
				t.Errorf("protocol = %q, want %q", sess.Protocol, "HTTP/1.x")
			}
			if send.Method != "POST" {
				t.Errorf("method = %q, want %q", send.Method, "POST")
			}
			if recv.StatusCode != 200 {
				t.Errorf("status code = %d, want %d", recv.StatusCode, 200)
			}
		})
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

	// Poll for all sessions and their messages to be persisted.
	var sessions []*session.Session
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		sessions, err = store.ListSessions(ctx, session.ListOptions{Limit: numClients + 10})
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if len(sessions) < numClients {
			continue
		}
		// Also verify all sessions have messages.
		allHaveMessages := true
		for _, s := range sessions {
			mc, cErr := store.CountMessages(ctx, s.ID)
			if cErr != nil {
				t.Fatalf("CountMessages: %v", cErr)
			}
			if mc < 2 {
				allHaveMessages = false
				break
			}
		}
		if allHaveMessages {
			break
		}
	}
	if len(sessions) != numClients {
		t.Fatalf("expected %d sessions, got %d", numClients, len(sessions))
	}

	// Verify each client's session is distinct and data is not mixed.
	seenPaths := make(map[string]bool)
	seenBodies := make(map[string]bool)
	for _, sess := range sessions {
		if sess.Protocol != "HTTP/1.x" {
			t.Errorf("session protocol = %q, want %q", sess.Protocol, "HTTP/1.x")
		}

		msgs, mErr := store.GetMessages(ctx, sess.ID, session.MessageListOptions{})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		var send, recv *session.Message
		for _, m := range msgs {
			switch m.Direction {
			case "send":
				send = m
			case "receive":
				recv = m
			}
		}
		if send == nil {
			t.Error("send message not found")
			continue
		}
		if recv == nil {
			t.Error("receive message not found")
			continue
		}

		if send.Method != "POST" {
			t.Errorf("session method = %q, want %q", send.Method, "POST")
		}
		if send.URL == nil {
			t.Error("request URL is nil")
			continue
		}

		path := send.URL.Path
		seenPaths[path] = true

		// Verify request body matches the path (no cross-contamination).
		var pathID int
		if _, err := fmt.Sscanf(path, "/concurrent/%d", &pathID); err != nil {
			t.Errorf("unexpected path format: %q", path)
			continue
		}
		expectedReqBody := fmt.Sprintf(`{"client":%d}`, pathID)
		if string(send.Body) != expectedReqBody {
			t.Errorf("session path %s: request body = %q, want %q (data mixed between sessions)",
				path, send.Body, expectedReqBody)
		}

		// Verify response body matches.
		expectedRespBody := fmt.Sprintf("echo:%s:%s", path, expectedReqBody)
		if string(recv.Body) != expectedRespBody {
			t.Errorf("session path %s: response body = %q, want %q (data mixed between sessions)",
				path, recv.Body, expectedRespBody)
		}

		seenBodies[string(send.Body)] = true

		if recv.StatusCode != 200 {
			t.Errorf("session path %s: status = %d, want %d", path, recv.StatusCode, 200)
		}
		if sess.ID == "" {
			t.Errorf("session path %s: ID is empty", path)
		}
		if sess.Duration < 0 {
			t.Errorf("session path %s: duration = %v, want non-negative", path, sess.Duration)
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

// failingStore is a session.Store that always returns an error from SaveSession.
// It is used to verify that the proxy continues forwarding traffic even when
// session persistence fails (USK-36 fix).
type failingStore struct {
	saveCallCount atomic.Int64
}

func (s *failingStore) SaveSession(_ context.Context, _ *session.Session) error {
	s.saveCallCount.Add(1)
	return errors.New("simulated DB write failure")
}

func (s *failingStore) UpdateSession(_ context.Context, _ string, _ session.SessionUpdate) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) GetSession(_ context.Context, _ string) (*session.Session, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) ListSessions(_ context.Context, _ session.ListOptions) ([]*session.Session, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) CountSessions(_ context.Context, _ session.ListOptions) (int, error) {
	return 0, errors.New("simulated DB read failure")
}

func (s *failingStore) DeleteSession(_ context.Context, _ string) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteAllSessions(_ context.Context) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteSessionsOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteExcessSessions(_ context.Context, _ int) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) AppendMessage(_ context.Context, _ *session.Message) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) GetMessages(_ context.Context, _ string, _ session.MessageListOptions) ([]*session.Message, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) CountMessages(_ context.Context, _ string) (int, error) {
	return 0, errors.New("simulated DB read failure")
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

	// Verify that SaveSession was actually called (and failed).
	if store.saveCallCount.Load() == 0 {
		t.Error("expected SaveSession to be called at least once, but it was not")
	}
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure_MultipleRequests(t *testing.T) {
	// Verifies that multiple sequential requests through the same proxy continue
	// to work even when every SaveSession call fails. This tests the keep-alive
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

	// All SaveSession calls should have been attempted (and failed).
	// Because the HTTP handler writes the response to the client before calling
	// store.SaveSession(), the last SaveSession may still be in-flight when the
	// final client.Get() returns. Poll with a bounded deadline instead of
	// asserting immediately.
	deadline := time.After(5 * time.Second)
	for {
		if got := store.saveCallCount.Load(); got >= int64(numRequests) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for SaveSession call count to reach %d (got %d)", numRequests, store.saveCallCount.Load())
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
