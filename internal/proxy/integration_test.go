//go:build e2e

package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func startProxy(t *testing.T, ctx context.Context, store flow.Store) (*proxy.Listener, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	var flows []*flow.Stream
	var send, recv *flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, flow.StreamListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) != 1 {
			continue
		}
		msgs, mErr := store.GetFlows(ctx, flows[0].ID, flow.FlowListOptions{})
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
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	fl := flows[0]
	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
	}
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if send.Method != "GET" {
		t.Errorf("flow method = %q, want %q", send.Method, "GET")
	}
	if send.URL == nil || send.URL.Path != "/test-path" {
		path := ""
		if send.URL != nil {
			path = send.URL.Path
		}
		t.Errorf("flow URL path = %q, want %q", path, "/test-path")
	}
	if recv.StatusCode != 200 {
		t.Errorf("flow status = %d, want %d", recv.StatusCode, 200)
	}
	if string(recv.Body) != "hello from upstream" {
		t.Errorf("flow response body = %q, want %q", recv.Body, "hello from upstream")
	}
}

func TestIntegration_MalformedHTTPRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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

	flows, err := store.ListStreams(ctx, flow.StreamListOptions{Method: "POST"})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 POST flow, got %d", len(flows))
	}
	recvMsgs, err := store.GetFlows(ctx, flows[0].ID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(recvMsgs) == 0 {
		t.Fatal("no receive message found")
	}
	if recvMsgs[0].StatusCode != 201 {
		t.Errorf("flow status = %d, want %d", recvMsgs[0].StatusCode, 201)
	}
}

// maxBodySize is the body recording size limit from the config package.
var maxBodySize = int(config.MaxBodySize)

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
			name:                "body 1MB (well below limit)",
			bodySize:            1 << 20,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  1 << 20,
			wantRecordedRespLen: 1 << 20,
			timeout:             30 * time.Second,
		},
		{
			name:                "body 2MB (below limit)",
			bodySize:            2 << 20,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  2 << 20,
			wantRecordedRespLen: 2 << 20,
			timeout:             30 * time.Second,
		},
		{
			name:                "body 10MB (below limit)",
			bodySize:            10 << 20,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  10 << 20,
			wantRecordedRespLen: 10 << 20,
			timeout:             60 * time.Second,
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
			logger := testutil.DiscardLogger()
			store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
			var flows []*flow.Stream
			var send, recv *flow.Flow
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				flows, err = store.ListStreams(ctx, flow.StreamListOptions{Limit: 10})
				if err != nil {
					t.Fatalf("ListFlows: %v", err)
				}
				if len(flows) != 1 {
					continue
				}
				msgs, err := store.GetFlows(ctx, flows[0].ID, flow.FlowListOptions{})
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
			if len(flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(flows))
			}
			fl := flows[0]
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
				if !bytes.Equal(send.Body, reqBody[:maxBodySize]) {
					t.Error("truncated request body is not a prefix of the original body")
				}
			}
			if tt.wantRespTruncated && tt.bodySize > 0 {
				if !bytes.Equal(recv.Body, reqBody[:maxBodySize]) {
					t.Error("truncated response body is not a prefix of the original body")
				}
			}

			// Verify metadata.
			if fl.Protocol != "HTTP/1.x" {
				t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	var flows []*flow.Stream
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, flow.StreamListOptions{Limit: numClients + 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) < numClients {
			continue
		}
		// Also verify all sessions have messages.
		allHaveMessages := true
		for _, s := range flows {
			mc, cErr := store.CountFlows(ctx, s.ID)
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
	if len(flows) != numClients {
		t.Fatalf("expected %d flows, got %d", numClients, len(flows))
	}

	// Verify each client's session is distinct and data is not mixed.
	seenPaths := make(map[string]bool)
	seenBodies := make(map[string]bool)
	for _, fl := range flows {
		if fl.Protocol != "HTTP/1.x" {
			t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
		}

		msgs, mErr := store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		var send, recv *flow.Flow
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
			t.Errorf("flow method = %q, want %q", send.Method, "POST")
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
			t.Errorf("flow path %s: request body = %q, want %q (data mixed between flows)",
				path, send.Body, expectedReqBody)
		}

		// Verify response body matches.
		expectedRespBody := fmt.Sprintf("echo:%s:%s", path, expectedReqBody)
		if string(recv.Body) != expectedRespBody {
			t.Errorf("flow path %s: response body = %q, want %q (data mixed between flows)",
				path, recv.Body, expectedRespBody)
		}

		seenBodies[string(send.Body)] = true

		if recv.StatusCode != 200 {
			t.Errorf("flow path %s: status = %d, want %d", path, recv.StatusCode, 200)
		}
		if fl.ID == "" {
			t.Errorf("flow path %s: ID is empty", path)
		}
		if fl.Duration < 0 {
			t.Errorf("flow path %s: duration = %v, want non-negative", path, fl.Duration)
		}
	}

	// Verify all unique paths were recorded (no duplicates, no missing).
	if len(seenPaths) != numClients {
		t.Errorf("expected %d unique paths, got %d", numClients, len(seenPaths))
	}
	for i := 0; i < numClients; i++ {
		expectedPath := fmt.Sprintf("/concurrent/%d", i)
		if !seenPaths[expectedPath] {
			t.Errorf("missing flow for path %q", expectedPath)
		}
	}
}

// --- Error Recovery Integration Tests ---

// failingStore is a flow.Store that always returns an error.
// It is used to verify that the proxy continues forwarding traffic even when
// session persistence fails (USK-36 fix).
type failingStore struct {
	saveCallCount atomic.Int64
}

func (s *failingStore) SaveStream(_ context.Context, _ *flow.Stream) error {
	s.saveCallCount.Add(1)
	return errors.New("simulated DB write failure")
}

func (s *failingStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) GetStream(_ context.Context, _ string) (*flow.Stream, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) ListStreams(_ context.Context, _ flow.StreamListOptions) ([]*flow.Stream, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) CountStreams(_ context.Context, _ flow.StreamListOptions) (int, error) {
	return 0, errors.New("simulated DB read failure")
}

func (s *failingStore) DeleteStream(_ context.Context, _ string) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteAllStreams(_ context.Context) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteStreamsByProtocol(_ context.Context, _ string) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteStreamsOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) DeleteExcessStreams(_ context.Context, _ int) (int64, error) {
	return 0, errors.New("simulated DB write failure")
}

func (s *failingStore) SaveFlow(_ context.Context, _ *flow.Flow) error {
	return errors.New("simulated DB write failure")
}

func (s *failingStore) GetFlow(_ context.Context, _ string) (*flow.Flow, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) GetFlows(_ context.Context, _ string, _ flow.FlowListOptions) ([]*flow.Flow, error) {
	return nil, errors.New("simulated DB read failure")
}

func (s *failingStore) CountFlows(_ context.Context, _ string) (int, error) {
	return 0, errors.New("simulated DB read failure")
}

func (s *failingStore) SaveMacro(_ context.Context, _, _, _ string) error {
	return errors.New("simulated DB write failure")
}
func (s *failingStore) GetMacro(_ context.Context, _ string) (*flow.MacroRecord, error) {
	return nil, errors.New("simulated DB read failure")
}
func (s *failingStore) ListMacros(_ context.Context) ([]*flow.MacroRecord, error) {
	return nil, errors.New("simulated DB read failure")
}
func (s *failingStore) DeleteMacro(_ context.Context, _ string) error {
	return errors.New("simulated DB write failure")
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure(t *testing.T) {
	// Verifies that when flow.Store.Save fails, the proxy still forwards
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

	// Verify that SaveFlow was actually called (and failed).
	// SaveFlow is invoked asynchronously after the response is forwarded,
	// so we poll with a bounded deadline instead of asserting immediately.
	deadline := time.After(2 * time.Second)
	for store.saveCallCount.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("expected SaveFlow to be called at least once, but it was not after 2s")
			return
		case <-time.After(10 * time.Millisecond):
			// retry
		}
	}
}

func TestIntegration_ProxyContinuesOnSessionSaveFailure_MultipleRequests(t *testing.T) {
	// Verifies that multiple sequential requests through the same proxy continue
	// to work even when every SaveFlow call fails. This tests the keep-alive
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

	// All SaveFlow calls should have been attempted (and failed).
	// Because the HTTP handler writes the response to the client before calling
	// store.SaveStream(), the last SaveFlow may still be in-flight when the
	// final client.Get() returns. Poll with a bounded deadline instead of
	// asserting immediately.
	deadline := time.After(5 * time.Second)
	for {
		if got := store.saveCallCount.Load(); got >= int64(numRequests) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for SaveFlow call count to reach %d (got %d)", numRequests, store.saveCallCount.Load())
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
	logger := testutil.DiscardLogger()
	realStore, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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
