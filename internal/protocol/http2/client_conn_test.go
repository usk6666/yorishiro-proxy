package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- buildHTTPRequest tests ---

func TestBuildHTTPRequest(t *testing.T) {
	tests := []struct {
		name       string
		headers    []hpack.HeaderField
		body       []byte
		wantMethod string
		wantScheme string
		wantHost   string
		wantPath   string
		wantQuery  string
		wantErr    bool
	}{
		{
			name: "simple GET",
			headers: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/api/test"},
				{Name: "accept", Value: "application/json"},
			},
			wantMethod: "GET",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/api/test",
		},
		{
			name: "POST with body",
			headers: []hpack.HeaderField{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: "localhost:8080"},
				{Name: ":path", Value: "/submit"},
				{Name: "content-type", Value: "application/json"},
			},
			body:       []byte(`{"key":"value"}`),
			wantMethod: "POST",
			wantScheme: "http",
			wantHost:   "localhost:8080",
			wantPath:   "/submit",
		},
		{
			name: "path with query string",
			headers: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/search?q=hello&lang=en"},
			},
			wantMethod: "GET",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/search",
			wantQuery:  "q=hello&lang=en",
		},
		{
			name: "missing method",
			headers: []hpack.HeaderField{
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/test"},
			},
			wantErr: true,
		},
		{
			name: "missing path for non-CONNECT",
			headers: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
			},
			wantErr: true,
		},
		{
			name: "CONNECT without path is valid",
			headers: []hpack.HeaderField{
				{Name: ":method", Value: "CONNECT"},
				{Name: ":authority", Value: "example.com:443"},
			},
			wantMethod: "CONNECT",
			wantScheme: "http", // default when not specified
			wantHost:   "example.com:443",
		},
		{
			name: "default scheme is http",
			headers: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
			},
			wantMethod: "GET",
			wantScheme: "http",
			wantHost:   "example.com",
			wantPath:   "/",
		},
		{
			name: "multiple regular headers",
			headers: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
				{Name: "accept", Value: "text/html"},
				{Name: "accept-encoding", Value: "gzip"},
				{Name: "user-agent", Value: "test/1.0"},
			},
			wantMethod: "GET",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := buildHTTPRequest(context.Background(), tt.headers, tt.body)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Method != tt.wantMethod {
				t.Errorf("method = %q, want %q", req.Method, tt.wantMethod)
			}
			if req.URL.Scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", req.URL.Scheme, tt.wantScheme)
			}
			if req.URL.Host != tt.wantHost {
				t.Errorf("host = %q, want %q", req.URL.Host, tt.wantHost)
			}
			if req.URL.Path != tt.wantPath {
				t.Errorf("path = %q, want %q", req.URL.Path, tt.wantPath)
			}
			if req.URL.RawQuery != tt.wantQuery {
				t.Errorf("query = %q, want %q", req.URL.RawQuery, tt.wantQuery)
			}
			if req.Host != tt.wantHost {
				t.Errorf("req.Host = %q, want %q", req.Host, tt.wantHost)
			}
			if tt.body != nil {
				body, _ := io.ReadAll(req.Body)
				if !bytes.Equal(body, tt.body) {
					t.Errorf("body = %q, want %q", body, tt.body)
				}
			}
			if req.ProtoMajor != 2 {
				t.Errorf("ProtoMajor = %d, want 2", req.ProtoMajor)
			}
		})
	}
}

// --- isConnectionClosed tests ---

func TestIsConnectionClosed(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "generic error",
			err:  fmt.Errorf("some error"),
			want: false,
		},
		{
			name: "closed connection",
			err:  fmt.Errorf("use of closed network connection"),
			want: true,
		},
		{
			name: "connection reset",
			err:  fmt.Errorf("connection reset by peer"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isConnectionClosed(tt.err); got != tt.want {
				t.Errorf("isConnectionClosed(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// --- frameResponseWriter tests ---

func TestFrameResponseWriter_Header(t *testing.T) {
	cc := newClientConn(context.Background(), nil, testutil.DiscardLogger(), nil)
	rw := newFrameResponseWriter(cc, 1)

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("X-Custom", "test")

	if got := rw.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	if got := rw.Header().Get("X-Custom"); got != "test" {
		t.Errorf("X-Custom = %q, want %q", got, "test")
	}
}

func TestFrameResponseWriter_WriteHeader(t *testing.T) {
	cc := newClientConn(context.Background(), nil, testutil.DiscardLogger(), nil)
	rw := newFrameResponseWriter(cc, 1)

	rw.WriteHeader(gohttp.StatusNotFound)

	rw.mu.Lock()
	if !rw.wroteHeader {
		t.Error("wroteHeader = false after WriteHeader")
	}
	if rw.statusCode != 404 {
		t.Errorf("statusCode = %d, want 404", rw.statusCode)
	}
	rw.mu.Unlock()

	// Second WriteHeader should be ignored.
	rw.WriteHeader(gohttp.StatusOK)
	rw.mu.Lock()
	if rw.statusCode != 404 {
		t.Errorf("statusCode = %d after second WriteHeader, want 404", rw.statusCode)
	}
	rw.mu.Unlock()
}

func TestFrameResponseWriter_WriteImplicitHeader(t *testing.T) {
	// Use a pipe so Write() can send frames without nil-pointer panic.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Drain the client side in background to prevent blocking.
	go io.Copy(io.Discard, client)

	cc := newClientConn(context.Background(), server, testutil.DiscardLogger(), nil)
	rw := newFrameResponseWriter(cc, 1)

	// Write without explicit WriteHeader should default to 200.
	rw.Write([]byte("hello"))

	rw.mu.Lock()
	if !rw.wroteHeader {
		t.Error("wroteHeader should be true after Write")
	}
	if rw.statusCode != 200 {
		t.Errorf("statusCode = %d, want 200", rw.statusCode)
	}
	if !rw.headersSent {
		t.Error("headersSent should be true after Write")
	}
	rw.mu.Unlock()
}

// --- Connection preface tests ---

func TestReadClientPreface_Valid(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	cc := newClientConn(context.Background(), server, testutil.DiscardLogger(), nil)

	go func() {
		client.Write([]byte(clientMagic))
	}()

	err := cc.readClientPreface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadClientPreface_Invalid(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	cc := newClientConn(context.Background(), server, testutil.DiscardLogger(), nil)

	go func() {
		client.Write([]byte("GET / HTTP/1.1\r\n\r\n        "))
	}()

	err := cc.readClientPreface()
	if err == nil {
		t.Fatal("expected error for invalid preface")
	}
	if !strings.Contains(err.Error(), "invalid connection preface") {
		t.Errorf("unexpected error: %v", err)
	}
}

// h2cTestConn is a helper that manages a TCP listener-based h2c test connection.
// Using TCP instead of net.Pipe() avoids synchronous pipe deadlocks.
type h2cTestConn struct {
	ln         net.Listener
	serverDone chan error
	cancel     context.CancelFunc
	clientConn net.Conn
	writer     *frame.Writer
	reader     *frame.Reader
	encoder    *hpack.Encoder
	decoder    *hpack.Decoder
}

// newH2CTestConn sets up an h2c test: starts a clientConn server on a TCP listener,
// connects as a client, performs the HTTP/2 handshake, and returns the ready-to-use test connection.
func newH2CTestConn(t *testing.T, handler func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request)) *h2cTestConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	serverDone := make(chan error, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		cc := newClientConn(ctx, conn, testutil.DiscardLogger(), handler)
		serverDone <- cc.serve()
		conn.Close()
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		cancel()
		ln.Close()
		t.Fatalf("dial: %v", err)
	}

	tc := &h2cTestConn{
		ln:         ln,
		serverDone: serverDone,
		cancel:     cancel,
		clientConn: clientConn,
		writer:     frame.NewWriter(clientConn),
		reader:     frame.NewReader(clientConn),
		encoder:    hpack.NewEncoder(4096, false),
		decoder:    hpack.NewDecoder(4096),
	}

	// Perform HTTP/2 handshake.
	// 1. Send connection preface + client SETTINGS (combined, non-blocking on TCP).
	clientConn.Write([]byte(clientMagic))
	tc.writer.WriteSettings(nil)

	// 2. Read server SETTINGS.
	f, err := tc.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read server SETTINGS: %v", err)
	}
	if f.Header.Type != frame.TypeSettings || f.Header.Flags.Has(frame.FlagAck) {
		t.Fatalf("expected non-ACK SETTINGS, got type=%s flags=0x%02x", f.Header.Type, f.Header.Flags)
	}

	// 3. Read server SETTINGS ACK (for our client SETTINGS).
	f, err = tc.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read server SETTINGS ACK: %v", err)
	}
	if f.Header.Type != frame.TypeSettings || !f.Header.Flags.Has(frame.FlagAck) {
		t.Fatalf("expected SETTINGS ACK, got type=%s flags=0x%02x", f.Header.Type, f.Header.Flags)
	}

	// 4. Send client SETTINGS ACK.
	tc.writer.WriteSettingsAck()

	return tc
}

func (tc *h2cTestConn) close(t *testing.T) {
	t.Helper()
	tc.clientConn.Close()
	tc.cancel()
	tc.ln.Close()
	select {
	case <-tc.serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not terminate in time")
	}
}

// --- Integration test: full h2c connection via clientConn ---

func TestClientConn_FullH2CExchange(t *testing.T) {
	type receivedReq struct {
		method string
		path   string
		body   string
	}
	var mu sync.Mutex
	var received []receivedReq

	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		received = append(received, receivedReq{
			method: req.Method,
			path:   req.URL.Path,
			body:   string(body),
		})
		mu.Unlock()
		w.Header().Set("X-Custom", "test")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("hello from handler"))
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send a simple GET request (HEADERS with END_STREAM + END_HEADERS).
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/test"},
		{Name: "accept", Value: "text/plain"},
	})
	tc.writer.WriteHeaders(1, true, true, headerBlock)

	// Read response HEADERS.
	f, err := tc.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read response HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("expected HEADERS, got %s", f.Header.Type)
	}
	if f.Header.StreamID != 1 {
		t.Errorf("stream ID = %d, want 1", f.Header.StreamID)
	}

	respHeaders, err := tc.decoder.Decode(f.Payload)
	if err != nil {
		t.Fatalf("decode response headers: %v", err)
	}
	var statusValue string
	for _, hf := range respHeaders {
		if hf.Name == ":status" {
			statusValue = hf.Value
		}
	}
	if statusValue != "200" {
		t.Errorf(":status = %q, want %q", statusValue, "200")
	}

	// If END_STREAM was not on HEADERS, read DATA frame.
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		f, err = tc.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read response DATA: %v", err)
		}
		if f.Header.Type != frame.TypeData {
			t.Fatalf("expected DATA, got %s", f.Header.Type)
		}
		data, _ := f.DataPayload()
		if string(data) != "hello from handler" {
			t.Errorf("response body = %q, want %q", data, "hello from handler")
		}
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(received) != 1 {
		t.Fatalf("expected 1 request, got %d", len(received))
	}
	if received[0].method != "GET" {
		t.Errorf("method = %q, want %q", received[0].method, "GET")
	}
	if received[0].path != "/test" {
		t.Errorf("path = %q, want %q", received[0].path, "/test")
	}
	mu.Unlock()
}

// TestClientConn_POSTWithBody tests a POST request with a body (HEADERS + DATA frames).
func TestClientConn_POSTWithBody(t *testing.T) {
	var mu sync.Mutex
	var receivedBody string

	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		receivedBody = string(body)
		mu.Unlock()
		w.WriteHeader(gohttp.StatusCreated)
		w.Write([]byte("created"))
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send HEADERS without END_STREAM (body follows).
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/submit"},
		{Name: "content-type", Value: "application/json"},
	})
	tc.writer.WriteHeaders(1, false, true, headerBlock)

	// Send DATA with END_STREAM.
	body := []byte(`{"key":"value"}`)
	tc.writer.WriteData(1, true, body)

	// Read response frames. The server may send WINDOW_UPDATE frames before
	// the response HEADERS due to flow control replenishment. DATA may arrive
	// in multiple frames (Write sends immediately, finish sends END_STREAM).
	var status string
	var respBodyBuf bytes.Buffer
	gotEndStream := false
	for !gotEndStream {
		f, err := tc.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read response frame: %v", err)
		}
		switch f.Header.Type {
		case frame.TypeWindowUpdate:
			// Expected after DATA frame; skip.
			continue
		case frame.TypeHeaders:
			respHeaders, _ := tc.decoder.Decode(f.Payload)
			for _, hf := range respHeaders {
				if hf.Name == ":status" {
					status = hf.Value
				}
			}
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
		case frame.TypeData:
			data, _ := f.DataPayload()
			respBodyBuf.Write(data)
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
		default:
			t.Fatalf("unexpected frame type: %s", f.Header.Type)
		}
	}

	if status != "201" {
		t.Errorf(":status = %q, want %q", status, "201")
	}
	if respBodyBuf.String() != "created" {
		t.Errorf("response body = %q, want %q", respBodyBuf.String(), "created")
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if receivedBody != `{"key":"value"}` {
		t.Errorf("received body = %q, want %q", receivedBody, `{"key":"value"}`)
	}
	mu.Unlock()
}

// TestClientConn_MultipleStreams tests concurrent stream handling.
func TestClientConn_MultipleStreams(t *testing.T) {
	var mu sync.Mutex
	var paths []string

	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		mu.Lock()
		paths = append(paths, req.URL.Path)
		mu.Unlock()
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("ok"))
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send 3 streams sequentially (streams 1, 3, 5).
	for _, streamID := range []uint32{1, 3, 5} {
		headerBlock := tc.encoder.Encode([]hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: fmt.Sprintf("/stream-%d", streamID)},
		})
		tc.writer.WriteHeaders(streamID, true, true, headerBlock)
	}

	// Read responses for all 3 streams (HEADERS + optional DATA per stream).
	framesRead := 0
	for framesRead < 3 {
		f, err := tc.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read response frame: %v", err)
		}
		if f.Header.Flags.Has(frame.FlagEndStream) {
			framesRead++
		}
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if len(paths) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(paths))
	}
	mu.Unlock()
}

// TestClientConn_PingPong tests PING frame handling.
func TestClientConn_PingPong(t *testing.T) {
	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send PING.
	pingData := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	tc.writer.WritePing(false, pingData)

	// Read PING ACK.
	f, err := tc.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read PING ACK: %v", err)
	}
	if f.Header.Type != frame.TypePing {
		t.Fatalf("expected PING, got %s", f.Header.Type)
	}
	if !f.Header.Flags.Has(frame.FlagAck) {
		t.Fatal("expected PING ACK flag")
	}
	ackData, _ := f.PingData()
	if ackData != pingData {
		t.Errorf("PING ACK data = %v, want %v", ackData, pingData)
	}
}

// TestClientConn_GoAway tests GOAWAY handling.
func TestClientConn_GoAway(t *testing.T) {
	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}

	tc := newH2CTestConn(t, handler)

	// Send GOAWAY.
	tc.writer.WriteGoAway(0, 0, nil)

	// Server should terminate.
	select {
	case <-tc.serverDone:
		// OK, server terminated.
	case <-time.After(5 * time.Second):
		t.Fatal("server did not terminate after GOAWAY")
	}
	tc.clientConn.Close()
	tc.cancel()
	tc.ln.Close()
}

// TestClientConn_InvalidPreface tests that invalid connection preface is rejected.
func TestClientConn_InvalidPreface(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		cc := newClientConn(ctx, conn, testutil.DiscardLogger(), handler)
		serverDone <- cc.serve()
		conn.Close()
	}()

	// Connect and send garbage instead of preface.
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()
	clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))

	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("expected error for invalid preface")
		}
		if !strings.Contains(err.Error(), "invalid connection preface") {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not terminate")
	}
}

// TestClientConn_EvenStreamIDRejected tests that even-numbered client streams are rejected.
func TestClientConn_EvenStreamIDRejected(t *testing.T) {
	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send HEADERS with even stream ID (2).
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
	})
	tc.writer.WriteHeaders(2, true, true, headerBlock)

	// Server should send GOAWAY.
	f, err := tc.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if f.Header.Type != frame.TypeGoAway {
		t.Fatalf("expected GOAWAY, got %s", f.Header.Type)
	}
}

// TestClientConn_WindowUpdate tests that WINDOW_UPDATE frames are handled.
func TestClientConn_WindowUpdate(t *testing.T) {
	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send WINDOW_UPDATE for connection (stream 0).
	tc.writer.WriteWindowUpdate(0, 1024)

	// Send a request to verify the connection still works.
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/after-window-update"},
	})
	tc.writer.WriteHeaders(1, true, true, headerBlock)

	// Read response.
	f, err := tc.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("expected HEADERS, got %s", f.Header.Type)
	}
}

// TestClientConn_WriteChunking tests that large response bodies are chunked
// into DATA frames respecting the peer's MaxFrameSize.
func TestClientConn_WriteChunking(t *testing.T) {
	// Create a body larger than the default MaxFrameSize (16384).
	bodySize := frame.DefaultMaxFrameSize + 1000
	largeBody := make([]byte, bodySize)
	for i := range largeBody {
		largeBody[i] = byte(i % 256)
	}

	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(largeBody)
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send a GET request.
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/large"},
	})
	tc.writer.WriteHeaders(1, true, true, headerBlock)

	// Read response frames: expect HEADERS + multiple DATA frames.
	var respBody bytes.Buffer
	dataFrameCount := 0
	gotEndStream := false
	for !gotEndStream {
		f, err := tc.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read response frame: %v", err)
		}
		switch f.Header.Type {
		case frame.TypeHeaders:
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
		case frame.TypeData:
			data, _ := f.DataPayload()
			if len(data) > 0 {
				dataFrameCount++
			}
			// Each non-empty DATA frame payload must not exceed MaxFrameSize.
			if len(data) > int(frame.DefaultMaxFrameSize) {
				t.Errorf("DATA frame payload %d exceeds MaxFrameSize %d",
					len(data), frame.DefaultMaxFrameSize)
			}
			respBody.Write(data)
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
		case frame.TypeWindowUpdate:
			continue
		default:
			t.Fatalf("unexpected frame type: %s", f.Header.Type)
		}
	}

	// Body was larger than one frame, so we expect at least 2 DATA frames.
	if dataFrameCount < 2 {
		t.Errorf("expected at least 2 DATA frames for chunking, got %d", dataFrameCount)
	}

	if respBody.Len() != bodySize {
		t.Errorf("response body size = %d, want %d", respBody.Len(), bodySize)
	}
	if !bytes.Equal(respBody.Bytes(), largeBody) {
		t.Error("response body content mismatch")
	}
}

// TestClientConn_StreamingFlush tests that Flush() sends HEADERS immediately,
// supporting gRPC-style streaming where Write+Flush cycles send data progressively.
func TestClientConn_StreamingFlush(t *testing.T) {
	ready := make(chan struct{})
	done := make(chan struct{})

	handler := func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.(gohttp.Flusher).Flush()

		// Signal that first flush is done.
		close(ready)

		// Write some data.
		w.Write([]byte("chunk1"))
		w.(gohttp.Flusher).Flush()

		w.Write([]byte("chunk2"))
		w.(gohttp.Flusher).Flush()

		<-done
	}

	tc := newH2CTestConn(t, handler)
	defer tc.close(t)

	// Send a request.
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/stream"},
		{Name: "content-type", Value: "application/grpc"},
	})
	tc.writer.WriteHeaders(1, true, true, headerBlock)

	// Wait for handler to flush headers.
	<-ready

	// Read HEADERS frame — should arrive before handler returns.
	f, err := tc.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("expected HEADERS, got %s", f.Header.Type)
	}

	// Read DATA frames for chunk1 and chunk2.
	var body bytes.Buffer
	for i := 0; i < 2; i++ {
		f, err = tc.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read DATA frame %d: %v", i, err)
		}
		if f.Header.Type != frame.TypeData {
			t.Fatalf("expected DATA, got %s", f.Header.Type)
		}
		data, _ := f.DataPayload()
		body.Write(data)
	}

	if body.String() != "chunk1chunk2" {
		t.Errorf("streamed body = %q, want %q", body.String(), "chunk1chunk2")
	}

	// Let handler finish.
	close(done)
}
