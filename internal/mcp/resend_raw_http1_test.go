package mcp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- isHTTP1Protocol tests ---

func TestIsHTTP1Protocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		protocol string
		want     bool
	}{
		{"HTTP", true},
		{"HTTPS", true},
		{"HTTP/2", false},
		{"gRPC", false},
		{"WebSocket", false},
		{"Raw TCP", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			if got := isHTTP1Protocol(tt.protocol); got != tt.want {
				t.Errorf("isHTTP1Protocol(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

// --- readHTTP1RawResponse unit tests ---

func TestReadHTTP1RawResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rawReq     []byte
		serverResp string
		wantBody   string
		wantErr    bool
	}{
		{
			name:       "content-length response",
			rawReq:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			serverResp: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
			wantBody:   "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
		},
		{
			name:       "chunked transfer encoding",
			rawReq:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			serverResp: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantBody:   "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		},
		{
			name:       "HEAD request with content-length (no body)",
			rawReq:     []byte("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			serverResp: "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n",
			wantBody:   "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n",
		},
		{
			name:       "empty body 204 response",
			rawReq:     []byte("DELETE /item HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			serverResp: "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
			wantBody:   "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:    "invalid HTTP response",
			rawReq:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server, client := net.Pipe()
			defer client.Close()

			// Write server response in background.
			go func() {
				defer server.Close()
				if tt.serverResp != "" {
					server.Write([]byte(tt.serverResp))
				}
			}()

			got, err := readHTTP1RawResponse(client, tt.rawReq)
			if (err != nil) != tt.wantErr {
				t.Fatalf("readHTTP1RawResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if string(got) != tt.wantBody {
					t.Errorf("readHTTP1RawResponse() =\n%q\nwant:\n%q", string(got), tt.wantBody)
				}
			}
		})
	}
}

// --- Integration test: HTTP/1.x keep-alive server does not cause timeout ---

// newKeepAliveHTTPServer creates a TCP server that sends an HTTP/1.1 response
// with Connection: keep-alive and does NOT close the connection after writing.
// This reproduces the bug where io.ReadAll blocks until deadline.
func newKeepAliveHTTPServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				// Read request headers.
				for {
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				// Send response with keep-alive (default for HTTP/1.1).
				// Do NOT close the connection — wait for the client to close.
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\nhello keepaliv"
				c.Write([]byte(resp))
				// Block to keep connection open (simulating keep-alive).
				// The connection will be closed when the listener closes.
				buf := make([]byte, 1)
				c.Read(buf) //nolint:errcheck // intentional block
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func TestResendRaw_HTTP1KeepAlive_NoTimeout(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newKeepAliveHTTPServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse(fmt.Sprintf("http://%s:%s/test", host, port))

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	// Use a short timeout so the test fails fast if the bug regresses.
	timeoutMs := 3000
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"timeout_ms":  timeoutMs,
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the response was captured correctly (ResponseData is base64-encoded).
	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}

	if !bytes.Contains(respBytes, []byte("200 OK")) {
		t.Errorf("response should contain '200 OK', got: %q", string(respBytes))
	}
	if !bytes.Contains(respBytes, []byte("hello keepaliv")) {
		t.Errorf("response should contain body 'hello keepaliv', got: %q", string(respBytes))
	}

	// Verify the response was received well before the timeout,
	// indicating http.ReadResponse correctly detected the response boundary.
	if out.DurationMs > int64(timeoutMs-500) {
		t.Errorf("response took %dms, expected well under %dms (keep-alive timeout fix)", out.DurationMs, timeoutMs)
	}
}

func TestResendRaw_HTTPS_UsesHTTP1Parser(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	// Use a plain TCP server (no TLS) but set Protocol to HTTPS with use_tls=false override.
	addr, cleanup := newKeepAliveHTTPServer(t)
	defer cleanup()

	rawReq := []byte("GET / HTTP/1.1\r\nHost: secure.example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse(fmt.Sprintf("https://%s:%s/", host, port))

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTPS",
			Timestamp: time.Now(),
			Duration:  50 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	timeoutMs := 3000
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"use_tls":     false, // Override TLS for testing without actual TLS server.
			"timeout_ms":  timeoutMs,
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if !bytes.Contains(respBytes, []byte("200 OK")) {
		t.Errorf("response should contain '200 OK', got: %q", string(respBytes))
	}
}
