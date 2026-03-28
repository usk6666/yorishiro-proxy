package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// h2OnlyTLSTransport simulates a TLS transport where the server negotiates h2.
type h2OnlyTLSTransport struct{}

func (h *h2OnlyTLSTransport) TLSConnect(_ context.Context, conn net.Conn, _ string) (net.Conn, string, error) {
	return conn, "h2", nil
}

func TestWsHTTP1Transport_StandardTransport(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())
	handler.tlsTransport = &httputil.StandardTransport{
		InsecureSkipVerify: true,
	}

	transport := handler.wsHTTP1Transport()
	st, ok := transport.(*httputil.StandardTransport)
	if !ok {
		t.Fatalf("expected *httputil.StandardTransport, got %T", transport)
	}
	if !st.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be preserved")
	}
	if len(st.NextProtos) != 1 || st.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want [http/1.1]", st.NextProtos)
	}
}

func TestWsHTTP1Transport_NonStandardTransport(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())
	mock := &mockTLSTransport{}
	handler.tlsTransport = mock

	transport := handler.wsHTTP1Transport()
	if transport != mock {
		t.Error("non-StandardTransport should be returned as-is")
	}
}

func TestWsHTTP1Transport_FallbackStandardTransport(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())
	// No explicit TLS transport set — falls back to StandardTransport.

	transport := handler.wsHTTP1Transport()
	st, ok := transport.(*httputil.StandardTransport)
	if !ok {
		t.Fatalf("expected *httputil.StandardTransport, got %T", transport)
	}
	if len(st.NextProtos) != 1 || st.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want [http/1.1]", st.NextProtos)
	}
}

// TestWSS_H2OnlyServer_Returns502 verifies that when the upstream server
// negotiates HTTP/2 via ALPN, the WSS handler returns 502 with a clear error
// instead of a cryptic "malformed HTTP response" error.
func TestWSS_H2OnlyServer_Returns502(t *testing.T) {
	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	// Set up a mock upstream that accepts TCP connections (so dial succeeds)
	// but whose TLS transport reports h2 negotiation.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstreamLn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Accept connections in the background and keep them open until context ends.
	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Hold connection open until test context ends.
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Second):
				}
			}()
		}
	}()

	// Use the upstream listener's actual address as CONNECT target so
	// dialUpstream succeeds.
	connectHost := upstreamLn.Addr().String()
	handler.tlsTransport = &h2OnlyTLSTransport{}

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	// Send a WebSocket upgrade request over the TLS tunnel.
	wsReq := "GET /ws HTTP/1.1\r\n" +
		"Host: " + connectHost + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"
	_, err = tlsConn.Write([]byte(wsReq))
	if err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	// Read the 502 Bad Gateway response.
	resp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}

	// Wait for recording.
	time.Sleep(200 * time.Millisecond)

	// Verify error flow was recorded with ALPN mismatch info.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry (error), got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "WebSocket")
	}
	errTag := entry.Session.Tags["error"]
	if !strings.Contains(errTag, "HTTP/2") || !strings.Contains(errTag, "ALPN") {
		t.Errorf("error tag = %q, should mention HTTP/2 and ALPN", errTag)
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name: "valid websocket upgrade",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "websocket",
			},
			want: true,
		},
		{
			name: "case insensitive upgrade value",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "WebSocket",
			},
			want: true,
		},
		{
			name: "case insensitive connection value",
			headers: map[string]string{
				"Connection": "upgrade",
				"Upgrade":    "websocket",
			},
			want: true,
		},
		{
			name: "connection with multiple values",
			headers: map[string]string{
				"Connection": "keep-alive, Upgrade",
				"Upgrade":    "websocket",
			},
			want: true,
		},
		{
			name: "missing upgrade header",
			headers: map[string]string{
				"Connection": "Upgrade",
			},
			want: false,
		},
		{
			name: "missing connection header",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			want: false,
		},
		{
			name: "wrong upgrade protocol",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "h2c",
			},
			want: false,
		},
		{
			name: "connection without upgrade token",
			headers: map[string]string{
				"Connection": "keep-alive",
				"Upgrade":    "websocket",
			},
			want: false,
		},
		{
			name:    "no headers",
			headers: map[string]string{},
			want:    false,
		},
		{
			name: "upgrade with whitespace",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    " websocket ",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &gohttp.Request{
				Header: gohttp.Header{},
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := isWebSocketUpgrade(req)
			if got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHeaderContains(t *testing.T) {
	tests := []struct {
		name   string
		header string
		token  string
		want   bool
	}{
		{"single match", "Upgrade", "upgrade", true},
		{"comma separated", "keep-alive, Upgrade", "upgrade", true},
		{"no match", "keep-alive", "upgrade", false},
		{"empty header", "", "upgrade", false},
		{"empty token", "Upgrade", "", false},
		{"multiple commas", "keep-alive, Upgrade, foo", "upgrade", true},
		{"partial match", "Upgrade-Insecure-Requests", "upgrade", false},
		{"with whitespace", " Upgrade ", "upgrade", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := headerContains(tt.header, tt.token)
			if got != tt.want {
				t.Errorf("headerContains(%q, %q) = %v, want %v", tt.header, tt.token, got, tt.want)
			}
		})
	}
}

func TestRecordWebSocketError_Basic(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	ep := wsErrorRecordParams{
		connID:     "conn-ws-1",
		clientAddr: "127.0.0.1:5000",
		start:      start,
		connInfo:   &flow.ConnectionInfo{ClientAddr: "127.0.0.1:5000"},
		req:        goRequestToRaw(req),
		reqURL:     req.URL,
	}

	upstreamErr := fmt.Errorf("dial websocket upstream example.com:80: connection refused")
	handler.recordWebSocketError(ctx, ep, upstreamErr, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "WebSocket")
	}
	if entry.Session.FlowType != "bidirectional" {
		t.Errorf("sessionType = %q, want %q", entry.Session.FlowType, "bidirectional")
	}
	if entry.Session.ConnID != "conn-ws-1" {
		t.Errorf("connID = %q, want %q", entry.Session.ConnID, "conn-ws-1")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
	}
	if entry.Session.Tags == nil || entry.Session.Tags["error"] == "" {
		t.Error("flow should have 'error' tag with error message")
	}
	if !strings.Contains(entry.Session.Tags["error"], "connection refused") {
		t.Errorf("error tag = %q, should contain 'connection refused'", entry.Session.Tags["error"])
	}

	// Verify send message is present.
	if entry.Send == nil {
		t.Fatal("send message should be present")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("method = %q, want %q", entry.Send.Method, "GET")
	}
	if entry.Send.URL == nil || entry.Send.URL.Path != "/ws" {
		t.Errorf("URL path = %v, want /ws", entry.Send.URL)
	}

	// Verify no receive message.
	if entry.Receive != nil {
		t.Error("receive message should be nil for error session")
	}
}

func TestRecordWebSocketError_NilStore(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "http://example.com/ws", nil)

	ep := wsErrorRecordParams{
		start: start,
		req:   goRequestToRaw(req),
	}

	// Should not panic.
	handler.recordWebSocketError(ctx, ep, fmt.Errorf("error"), logger)
}

func TestRecordWebSocketError_WithTLSConnInfo(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx := context.Background()
	logger := testutil.DiscardLogger()
	start := time.Now()

	req, _ := gohttp.NewRequest("GET", "wss://example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	ep := wsErrorRecordParams{
		connID:     "conn-wss-1",
		clientAddr: "127.0.0.1:5000",
		start:      start,
		connInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:5000",
			TLSVersion: "TLS 1.3",
			TLSCipher:  "TLS_AES_128_GCM_SHA256",
			TLSALPN:    "http/1.1",
		},
		req: goRequestToRaw(req),
	}

	upstreamErr := fmt.Errorf("wss upstream TLS handshake: tls: handshake failure")
	handler.recordWebSocketError(ctx, ep, upstreamErr, logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "WebSocket")
	}

	ci := entry.Session.ConnInfo
	if ci == nil {
		t.Fatal("ConnInfo is nil")
	}
	if ci.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want %q", ci.TLSVersion, "TLS 1.3")
	}
	if ci.TLSCipher != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("TLSCipher = %q, want %q", ci.TLSCipher, "TLS_AES_128_GCM_SHA256")
	}
}

// TestWS_UpstreamDialFailure_RecordsSession verifies that when a WebSocket
// upstream dial fails, the proxy records the flow with State="error" and
// the upgrade request as a send message.
func TestWS_UpstreamDialFailure_RecordsSession(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Connect to the proxy and send a WebSocket upgrade request to a
	// non-existent upstream (port 1 on localhost).
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	wsReq := "GET http://127.0.0.1:1/ws HTTP/1.1\r\n" +
		"Host: 127.0.0.1:1\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"
	conn.Write([]byte(wsReq))

	// Read the 502 Bad Gateway response.
	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}

	// Wait for async recording to complete.
	time.Sleep(200 * time.Millisecond)

	// Verify flow was recorded with error state.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry (error), got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "WebSocket")
	}
	if entry.Session.Tags == nil || entry.Session.Tags["error"] == "" {
		t.Error("flow should have 'error' tag with error message")
	}

	// Verify send message is present.
	if entry.Send == nil {
		t.Fatal("send message should be present for error sessions")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "GET")
	}

	// Verify no receive message.
	if entry.Receive != nil {
		t.Error("receive message should be nil for error sessions")
	}
}

// TestWSS_UpstreamDialFailure_RecordsSession verifies that when a WSS upstream
// dial fails through a CONNECT tunnel, the proxy records the flow with
// State="error" and the upgrade request as a send message.
func TestWSS_UpstreamDialFailure_RecordsSession(t *testing.T) {
	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	// Use a transport that will always fail to connect upstream.
	handler.Transport = &gohttp.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("simulated connection refused")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, "localhost:443", rootCAs)
	defer tlsConn.Close()

	// Send a WebSocket upgrade request over the TLS tunnel.
	wsReq := "GET /ws HTTP/1.1\r\n" +
		"Host: localhost:443\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"
	if _, err := tlsConn.Write([]byte(wsReq)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	// Read the 502 Bad Gateway response.
	resp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}

	// Wait for recording.
	time.Sleep(200 * time.Millisecond)

	// Verify error flow was recorded.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry (error), got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.State != "error" {
		t.Errorf("flow state = %q, want %q", entry.Session.State, "error")
	}
	if entry.Session.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "WebSocket")
	}
	if entry.Send == nil {
		t.Fatal("send message should be present for WSS error sessions")
	}
	if entry.Send.Method != "GET" {
		t.Errorf("send method = %q, want %q", entry.Send.Method, "GET")
	}
	if entry.Receive != nil {
		t.Error("receive message should be nil for error sessions")
	}
}

// TestWS_NilStore_NoRecording verifies that when the store is nil,
// WebSocket error paths do not record sessions and do not panic.
func TestWS_NilStore_NoRecording(t *testing.T) {
	handler := NewHandler(nil, nil, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send WebSocket upgrade to unreachable upstream.
	wsReq := "GET http://127.0.0.1:1/ws HTTP/1.1\r\n" +
		"Host: 127.0.0.1:1\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n"
	conn.Write([]byte(wsReq))

	// Read response -- should get 502 without panicking.
	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}
}
