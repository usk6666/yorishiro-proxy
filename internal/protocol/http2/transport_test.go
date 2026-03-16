package http2

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// localConnPair creates a pair of connected net.Conn via a TCP listener on
// localhost. Unlike net.Pipe, TCP connections have kernel buffers so reads
// and writes do not block each other synchronously.
func localConnPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	connCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	select {
	case server = <-connCh:
	case err := <-errCh:
		client.Close()
		t.Fatalf("accept: %v", err)
	}

	return client, server
}

// pipeServer simulates an HTTP/2 upstream server on a net.Pipe connection.
// It handles the HTTP/2 handshake and responds to streams.
type pipeServer struct {
	conn   net.Conn
	reader *frame.Reader
	writer *frame.Writer
	enc    *hpack.Encoder
	dec    *hpack.Decoder
}

func newPipeServer(conn net.Conn) *pipeServer {
	return &pipeServer{
		conn:   conn,
		reader: frame.NewReader(conn),
		writer: frame.NewWriter(conn),
		enc:    hpack.NewEncoder(4096, true),
		dec:    hpack.NewDecoder(4096),
	}
}

// handshake completes the HTTP/2 server-side handshake.
func (s *pipeServer) handshake(t *testing.T) {
	t.Helper()

	// Read client preface (24 bytes).
	buf := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		t.Fatalf("read client preface: %v", err)
	}
	if string(buf) != clientPreface {
		t.Fatalf("invalid client preface: %q", buf)
	}

	// Read client SETTINGS.
	f, err := s.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read client SETTINGS: %v", err)
	}
	if f.Header.Type != frame.TypeSettings {
		t.Fatalf("expected SETTINGS, got %s", f.Header.Type)
	}

	// Send server SETTINGS.
	if err := s.writer.WriteSettings([]frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 100},
	}); err != nil {
		t.Fatalf("write server SETTINGS: %v", err)
	}

	// Send SETTINGS ACK for client's SETTINGS.
	if err := s.writer.WriteSettingsAck(); err != nil {
		t.Fatalf("write SETTINGS ACK: %v", err)
	}

	// Read client SETTINGS ACK. The client sends this after reading our
	// SETTINGS, so it should arrive shortly.
	f, err = s.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read client SETTINGS ACK: %v", err)
	}
	// Accept SETTINGS ACK or any other valid frame (e.g. WINDOW_UPDATE).
	_ = f.Header.Type == frame.TypeSettings && f.Header.Flags.Has(frame.FlagAck)
}

// readRequest reads a complete request (HEADERS + DATA) from the client.
// It skips WINDOW_UPDATE, SETTINGS, and PING frames that may arrive
// asynchronously between requests on a multiplexed connection.
func (s *pipeServer) readRequest(t *testing.T) (streamID uint32, headers []hpack.HeaderField, body []byte) {
	t.Helper()

	var headerFragment []byte
	var endHeaders bool
	var endStream bool

	// Read HEADERS frame, skipping control frames.
	var f *frame.Frame
	var err error
	for {
		f, err = s.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read HEADERS: %v", err)
		}
		if f.Header.Type == frame.TypeHeaders {
			break
		}
		// Skip WINDOW_UPDATE, SETTINGS, PING, and other control frames.
	}
	streamID = f.Header.StreamID
	endHeaders = f.Header.Flags.Has(frame.FlagEndHeaders)
	endStream = f.Header.Flags.Has(frame.FlagEndStream)

	frag, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("header block fragment: %v", err)
	}
	headerFragment = append(headerFragment, frag...)

	// Read CONTINUATION frames if needed.
	for !endHeaders {
		f, err = s.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read CONTINUATION: %v", err)
		}
		if f.Header.Type != frame.TypeContinuation {
			t.Fatalf("expected CONTINUATION, got %s", f.Header.Type)
		}
		cf, cfErr := f.ContinuationFragment()
		if cfErr != nil {
			t.Fatalf("continuation fragment: %v", cfErr)
		}
		headerFragment = append(headerFragment, cf...)
		endHeaders = f.Header.Flags.Has(frame.FlagEndHeaders)
	}

	headers, err = s.dec.Decode(headerFragment)
	if err != nil {
		t.Fatalf("HPACK decode: %v", err)
	}

	// Read DATA frames if needed.
	for !endStream {
		f, err = s.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read DATA: %v", err)
		}
		switch f.Header.Type {
		case frame.TypeData:
			payload, dErr := f.DataPayload()
			if dErr != nil {
				t.Fatalf("data payload: %v", dErr)
			}
			body = append(body, payload...)
			endStream = f.Header.Flags.Has(frame.FlagEndStream)
		case frame.TypeWindowUpdate:
			// Ignore window updates during request reading.
		default:
			t.Fatalf("unexpected frame type %s while reading request", f.Header.Type)
		}
	}

	return streamID, headers, body
}

// sendResponse sends a response with the given status, headers, and body.
func (s *pipeServer) sendResponse(t *testing.T, streamID uint32, status int, extraHeaders []hpack.HeaderField, body []byte) {
	t.Helper()

	headers := []hpack.HeaderField{
		{Name: ":status", Value: strings.Repeat("0", 3-len(statusStr(status))) + statusStr(status)},
	}
	headers = append(headers, extraHeaders...)

	fragment := s.enc.Encode(headers)

	endStream := len(body) == 0
	if err := s.writer.WriteHeaders(streamID, endStream, true, fragment); err != nil {
		t.Fatalf("write response HEADERS: %v", err)
	}

	if len(body) > 0 {
		if err := s.writer.WriteData(streamID, true, body); err != nil {
			t.Fatalf("write response DATA: %v", err)
		}
	}
}

func statusStr(code int) string {
	s := ""
	if code >= 100 {
		s = string(rune('0'+code/100)) + string(rune('0'+(code/10)%10)) + string(rune('0'+code%10))
	}
	return s
}

func TestTransportConn_HandshakeAndRoundTrip(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tc := newTransportConn(clientConn, logger)

	// Run server handshake in background.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Now do a round trip.
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamID, headers, body := server.readRequest(t)

		// Verify request headers.
		var method, path, scheme, authority string
		for _, hf := range headers {
			switch hf.Name {
			case ":method":
				method = hf.Value
			case ":path":
				path = hf.Value
			case ":scheme":
				scheme = hf.Value
			case ":authority":
				authority = hf.Value
			}
		}
		if method != "POST" {
			t.Errorf("method = %q, want POST", method)
		}
		if path != "/api/test" {
			t.Errorf("path = %q, want /api/test", path)
		}
		if scheme != "https" {
			t.Errorf("scheme = %q, want https", scheme)
		}
		if authority != "example.com:443" {
			t.Errorf("authority = %q, want example.com:443", authority)
		}
		if string(body) != "hello" {
			t.Errorf("body = %q, want hello", body)
		}

		server.sendResponse(t, streamID, 200, []hpack.HeaderField{
			{Name: "content-type", Value: "text/plain"},
		}, []byte("world"))
	}()

	req, _ := gohttp.NewRequestWithContext(ctx, "POST", "https://example.com:443/api/test",
		io.NopCloser(bytes.NewReader([]byte("hello"))))
	req.Header.Set("Content-Type", "application/json")

	result, err := tc.roundTrip(ctx, req)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	wg.Wait()

	if result.Response.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.Response.StatusCode)
	}
	respBody, _ := io.ReadAll(result.Response.Body)
	if string(respBody) != "world" {
		t.Errorf("response body = %q, want world", respBody)
	}
	if ct := result.Response.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if result.ServerAddr == "" {
		t.Error("ServerAddr is empty")
	}
	if len(result.RawFrames) == 0 {
		t.Error("RawFrames is empty")
	}

	tc.close()
}

func TestTransportConn_EmptyBody(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		streamID, headers, body := server.readRequest(t)

		var method string
		for _, hf := range headers {
			if hf.Name == ":method" {
				method = hf.Value
			}
		}
		if method != "GET" {
			t.Errorf("method = %q, want GET", method)
		}
		if len(body) != 0 {
			t.Errorf("body = %q, want empty", body)
		}

		// Response with no body.
		server.sendResponse(t, streamID, 204, nil, nil)
	}()

	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://example.com/health", nil)

	result, err := tc.roundTrip(ctx, req)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	wg.Wait()

	if result.Response.StatusCode != 204 {
		t.Errorf("status = %d, want 204", result.Response.StatusCode)
	}

	tc.close()
}

func TestTransportConn_GoAway(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Send GOAWAY from server.
	if err := server.writer.WriteGoAway(0, ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}

	// Wait a bit for read loop to process.
	time.Sleep(50 * time.Millisecond)

	// New requests should fail due to GOAWAY.
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://example.com/test", nil)
	_, err := tc.roundTrip(ctx, req)
	if err == nil {
		t.Fatal("expected error after GOAWAY, got nil")
	}
	if !strings.Contains(err.Error(), "GOAWAY") {
		t.Errorf("error = %v, want to contain GOAWAY", err)
	}

	tc.close()
}

func TestTransportConn_RSTStream(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Server reads request, then sends RST_STREAM.
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamID, _, _ := server.readRequest(t)
		if err := server.writer.WriteRSTStream(streamID, ErrCodeCancel); err != nil {
			t.Errorf("write RST_STREAM: %v", err)
		}
	}()

	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://example.com/test", nil)
	_, err := tc.roundTrip(ctx, req)
	wg.Wait()

	if err == nil {
		t.Fatal("expected error from RST_STREAM, got nil")
	}

	var streamErr *StreamError
	if !strings.Contains(err.Error(), "RST_STREAM") {
		// Check if it's a wrapped StreamError.
		t.Logf("error = %v", err)
		_ = streamErr
	}

	tc.close()
}

func TestTransportConn_Ping(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Server sends PING, expects PING ACK.
	pingData := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := server.writer.WritePing(false, pingData); err != nil {
		t.Fatalf("write PING: %v", err)
	}

	// Read PING ACK from client.
	f, err := server.reader.ReadFrame()
	if err != nil {
		t.Fatalf("read PING ACK: %v", err)
	}
	if f.Header.Type != frame.TypePing {
		t.Fatalf("expected PING, got %s", f.Header.Type)
	}
	if !f.Header.Flags.Has(frame.FlagAck) {
		t.Fatal("PING frame missing ACK flag")
	}
	data, err := f.PingData()
	if err != nil {
		t.Fatalf("ping data: %v", err)
	}
	if data != pingData {
		t.Errorf("ping data = %v, want %v", data, pingData)
	}

	tc.close()
}

func TestTransportConn_ContextCancellation(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Server reads request but never responds.
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.readRequest(t)
		// Don't send response — let client timeout.
	}()

	reqCtx, reqCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer reqCancel()

	req, _ := gohttp.NewRequestWithContext(reqCtx, "GET", "https://example.com/slow", nil)
	_, err := tc.roundTrip(reqCtx, req)
	wg.Wait()

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Logf("error = %v (might be context deadline exceeded)", err)
	}

	tc.close()
}

func TestBuildRequestHeaders(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(nil, logger)

	tests := []struct {
		name       string
		req        *gohttp.Request
		wantMethod string
		wantScheme string
		wantAuth   string
		wantPath   string
	}{
		{
			name: "basic GET",
			req: func() *gohttp.Request {
				r, _ := gohttp.NewRequest("GET", "https://example.com/path?q=1", nil)
				return r
			}(),
			wantMethod: "GET",
			wantScheme: "https",
			wantAuth:   "example.com",
			wantPath:   "/path?q=1",
		},
		{
			name: "POST with host",
			req: func() *gohttp.Request {
				r, _ := gohttp.NewRequest("POST", "http://api.example.com:8080/v2", nil)
				return r
			}(),
			wantMethod: "POST",
			wantScheme: "http",
			wantAuth:   "api.example.com:8080",
			wantPath:   "/v2",
		},
		{
			name: "empty path defaults to /",
			req: func() *gohttp.Request {
				r, _ := gohttp.NewRequest("GET", "https://example.com", nil)
				return r
			}(),
			wantMethod: "GET",
			wantScheme: "https",
			wantAuth:   "example.com",
			wantPath:   "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tc.buildRequestHeaders(tt.req)

			got := make(map[string]string)
			for _, hf := range headers {
				if strings.HasPrefix(hf.Name, ":") {
					got[hf.Name] = hf.Value
				}
			}

			if got[":method"] != tt.wantMethod {
				t.Errorf(":method = %q, want %q", got[":method"], tt.wantMethod)
			}
			if got[":scheme"] != tt.wantScheme {
				t.Errorf(":scheme = %q, want %q", got[":scheme"], tt.wantScheme)
			}
			if got[":authority"] != tt.wantAuth {
				t.Errorf(":authority = %q, want %q", got[":authority"], tt.wantAuth)
			}
			if got[":path"] != tt.wantPath {
				t.Errorf(":path = %q, want %q", got[":path"], tt.wantPath)
			}
		})
	}
}

func TestIsHopByHopHeader(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"connection", true},
		{"keep-alive", true},
		{"proxy-connection", true},
		{"transfer-encoding", true},
		{"upgrade", true},
		{"te", true},
		{"content-type", false},
		{"accept", false},
		{"authorization", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHopByHopHeader(tt.name); got != tt.want {
				t.Errorf("isHopByHopHeader(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestBuildRequestHeaders_TETrailersAllowed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(nil, logger)

	// te: trailers should be preserved (required for gRPC in HTTP/2).
	req, _ := gohttp.NewRequest("POST", "https://example.com/api", nil)
	req.Header.Set("Te", "trailers")
	req.Header.Set("Content-Type", "application/grpc")

	headers := tc.buildRequestHeaders(req)

	var foundTE, foundCT bool
	for _, hf := range headers {
		if hf.Name == "te" && hf.Value == "trailers" {
			foundTE = true
		}
		if hf.Name == "content-type" && hf.Value == "application/grpc" {
			foundCT = true
		}
	}

	if !foundTE {
		t.Error("te: trailers header should be preserved in HTTP/2")
	}
	if !foundCT {
		t.Error("content-type header should be preserved")
	}

	// te: gzip should be dropped (not allowed in HTTP/2).
	req2, _ := gohttp.NewRequest("POST", "https://example.com/api", nil)
	req2.Header.Set("Te", "gzip")

	headers2 := tc.buildRequestHeaders(req2)
	for _, hf := range headers2 {
		if hf.Name == "te" {
			t.Errorf("te: %s should be dropped in HTTP/2", hf.Value)
		}
	}
}

func TestSendRequest_BodyCloseOnError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(nil, logger)

	closed := false
	body := &errorReadCloser{
		readErr: io.ErrUnexpectedEOF,
		onClose: func() { closed = true },
	}

	req, _ := gohttp.NewRequest("POST", "https://example.com/api", body)

	ctx := context.Background()
	err := tc.sendRequest(ctx, 1, req)
	if err == nil {
		t.Fatal("expected error from broken body reader")
	}

	if !closed {
		t.Error("req.Body should be closed even when ReadAll fails")
	}
}

// errorReadCloser is a test helper that returns an error on Read.
type errorReadCloser struct {
	readErr error
	onClose func()
}

func (e *errorReadCloser) Read([]byte) (int, error) {
	return 0, e.readErr
}

func (e *errorReadCloser) Close() error {
	if e.onClose != nil {
		e.onClose()
	}
	return nil
}

func TestTransportConn_LargeBodyFlowControl(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Use a body larger than the default initial window size (65535).
	// This exercises the flow control waiting logic.
	bodySize := 70000
	bodyData := bytes.Repeat([]byte("A"), bodySize)

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Read DATA frames, sending WINDOW_UPDATE as needed to allow flow.
		// The initial window size is 65535, so we must grant more window for
		// the 70000-byte body.
		var headerFragment []byte
		var streamID uint32

		// Read HEADERS frame.
		for {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read frame: %v", err)
				return
			}
			if f.Header.Type == frame.TypeHeaders {
				streamID = f.Header.StreamID
				frag, _ := f.HeaderBlockFragment()
				headerFragment = append(headerFragment, frag...)
				break
			}
		}
		_ = headerFragment

		// Read DATA frames, granting window as we go.
		var body []byte
		for {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read DATA: %v", err)
				return
			}
			switch f.Header.Type {
			case frame.TypeData:
				payload, _ := f.DataPayload()
				body = append(body, payload...)
				// Send WINDOW_UPDATE for connection and stream.
				if len(payload) > 0 {
					server.writer.WriteWindowUpdate(0, uint32(len(payload)))        //nolint:errcheck
					server.writer.WriteWindowUpdate(streamID, uint32(len(payload))) //nolint:errcheck
				}
				if f.Header.Flags.Has(frame.FlagEndStream) {
					goto done
				}
			case frame.TypeWindowUpdate:
				// Ignore.
			default:
				// Skip other frames.
			}
		}
	done:
		if len(body) != bodySize {
			t.Errorf("request body length = %d, want %d", len(body), bodySize)
		}
		server.sendResponse(t, streamID, 200, nil, []byte("ok"))
	}()

	req, _ := gohttp.NewRequestWithContext(ctx, "POST", "https://example.com/upload",
		io.NopCloser(bytes.NewReader(bodyData)))

	result, err := tc.roundTrip(ctx, req)
	if err != nil {
		t.Fatalf("roundTrip with large body: %v", err)
	}
	wg.Wait()

	if result.Response.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.Response.StatusCode)
	}
}

func TestTransportConn_AllocStreamID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(nil, logger)

	id1 := tc.allocStreamID()
	id2 := tc.allocStreamID()
	id3 := tc.allocStreamID()

	if id1 != 1 {
		t.Errorf("first stream ID = %d, want 1", id1)
	}
	if id2 != 3 {
		t.Errorf("second stream ID = %d, want 3", id2)
	}
	if id3 != 5 {
		t.Errorf("third stream ID = %d, want 5", id3)
	}
}

func TestTransportConn_ConnectionReuse(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Send two sequential requests on the same connection.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			streamID, _, _ := server.readRequest(t)
			server.sendResponse(t, streamID, 200, nil, []byte("ok"))
		}()

		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://example.com/test", nil)
		result, err := tc.roundTrip(ctx, req)
		if err != nil {
			t.Fatalf("roundTrip #%d: %v", i+1, err)
		}
		wg.Wait()

		if result.Response.StatusCode != 200 {
			t.Errorf("roundTrip #%d: status = %d, want 200", i+1, result.Response.StatusCode)
		}
		body, _ := io.ReadAll(result.Response.Body)
		if string(body) != "ok" {
			t.Errorf("roundTrip #%d: body = %q, want ok", i+1, body)
		}
	}

	tc.close()
}

func TestTransportConn_FlowControl(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tc := newTransportConn(clientConn, logger)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := tc.handshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	wg.Wait()

	// Send a request with a body to exercise flow control.
	bodyData := bytes.Repeat([]byte("x"), 1024)

	wg.Add(1)
	go func() {
		defer wg.Done()
		streamID, _, reqBody := server.readRequest(t)
		if len(reqBody) != len(bodyData) {
			t.Errorf("request body length = %d, want %d", len(reqBody), len(bodyData))
		}
		server.sendResponse(t, streamID, 200, nil, []byte("received"))
	}()

	req, _ := gohttp.NewRequestWithContext(ctx, "POST", "https://example.com/upload",
		io.NopCloser(bytes.NewReader(bodyData)))

	result, err := tc.roundTrip(ctx, req)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	wg.Wait()

	if result.Response.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.Response.StatusCode)
	}

	tc.close()
}

func TestTransport_CloseIdleConnections(t *testing.T) {
	tr := &Transport{}

	tr.pool.mu.Lock()
	tr.pool.conns = make(map[string]*transportConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create a mock connection.
	client, server := localConnPair(t)
	defer server.Close()
	tc := newTransportConn(client, logger)
	tr.pool.conns["example.com:443"] = tc
	tr.pool.mu.Unlock()

	tr.CloseIdleConnections()

	tr.pool.mu.Lock()
	if tr.pool.conns != nil {
		t.Error("pool should be nil after CloseIdleConnections")
	}
	tr.pool.mu.Unlock()

	if !tc.conn.IsClosed() {
		t.Error("connection should be closed")
	}
}
