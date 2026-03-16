package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// --- Unit tests ---

func TestInferFlowUseTLS(t *testing.T) {
	tests := []struct {
		name string
		fl   *flow.Flow
		want bool
	}{
		{
			name: "HTTP/2 with TLS version in ConnInfo",
			fl: &flow.Flow{
				Protocol: "HTTP/2",
				ConnInfo: &flow.ConnectionInfo{TLSVersion: "TLS 1.3", TLSALPN: "h2"},
			},
			want: true,
		},
		{
			name: "HTTP/2 with ALPN h2 only",
			fl: &flow.Flow{
				Protocol: "HTTP/2",
				ConnInfo: &flow.ConnectionInfo{TLSALPN: "h2"},
			},
			want: true,
		},
		{
			name: "HTTP/2 h2c with empty ConnInfo TLS fields",
			fl: &flow.Flow{
				Protocol: "HTTP/2",
				ConnInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:12345", ServerAddr: "127.0.0.1:8080"},
			},
			want: false,
		},
		{
			name: "HTTP/2 without ConnInfo falls back to protocol",
			fl:   &flow.Flow{Protocol: "HTTP/2"},
			want: false,
		},
		{
			name: "HTTPS without ConnInfo falls back to protocol",
			fl:   &flow.Flow{Protocol: "HTTPS"},
			want: true,
		},
		{
			name: "gRPC without ConnInfo",
			fl:   &flow.Flow{Protocol: "gRPC"},
			want: false,
		},
		{
			name: "gRPC with TLS ConnInfo",
			fl: &flow.Flow{
				Protocol: "gRPC",
				ConnInfo: &flow.ConnectionInfo{TLSVersion: "TLS 1.3"},
			},
			want: true,
		},
		{
			name: "HTTP/1.x without ConnInfo",
			fl:   &flow.Flow{Protocol: "HTTP/1.x"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferFlowUseTLS(tt.fl)
			if got != tt.want {
				t.Errorf("inferFlowUseTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHTTP2Protocol(t *testing.T) {
	tests := []struct {
		protocol string
		want     bool
	}{
		{"HTTP/2", true},
		{"gRPC", true},
		{"HTTP/1.x", false},
		{"HTTPS", false},
		{"TCP", false},
		{"WebSocket", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			got := isHTTP2Protocol(tt.protocol)
			if got != tt.want {
				t.Errorf("isHTTP2Protocol(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

func TestAppendRawCapped(t *testing.T) {
	tests := []struct {
		name    string
		dst     []byte
		src     []byte
		wantLen int
	}{
		{
			name:    "append within limit",
			dst:     make([]byte, 0),
			src:     []byte("hello"),
			wantLen: 5,
		},
		{
			name:    "append to existing",
			dst:     []byte("abc"),
			src:     []byte("def"),
			wantLen: 6,
		},
		{
			name:    "nil src",
			dst:     []byte("abc"),
			src:     nil,
			wantLen: 3,
		},
		{
			name:    "empty src",
			dst:     []byte("abc"),
			src:     []byte{},
			wantLen: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendRawCapped(tt.dst, tt.src)
			if len(got) != tt.wantLen {
				t.Errorf("appendRawCapped() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// TestH2Handshake tests the HTTP/2 handshake over a TCP connection.
// net.Pipe is not used because its synchronous nature can cause deadlocks
// when both sides need to write simultaneously during the handshake.
func TestH2Handshake(t *testing.T) {
	// Use a real TCP connection to avoid net.Pipe deadlocks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer serverConn.Close()

		// Read client connection preface.
		prefaceBuf := make([]byte, len(h2ClientPreface))
		if _, err := io.ReadFull(serverConn, prefaceBuf); err != nil {
			errCh <- err
			return
		}
		if string(prefaceBuf) != h2ClientPreface {
			errCh <- io.ErrUnexpectedEOF
			return
		}

		serverReader := frame.NewReader(serverConn)
		serverWriter := frame.NewWriter(serverConn)

		// Read client initial SETTINGS.
		f, err := serverReader.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if f.Header.Type != frame.TypeSettings {
			errCh <- io.ErrUnexpectedEOF
			return
		}

		// Send server SETTINGS.
		if err := serverWriter.WriteSettings([]frame.Setting{
			{ID: frame.SettingMaxConcurrentStreams, Value: 100},
			{ID: frame.SettingInitialWindowSize, Value: 65535},
		}); err != nil {
			errCh <- err
			return
		}

		// Send SETTINGS ACK for client's settings.
		if err := serverWriter.WriteSettingsAck(); err != nil {
			errCh <- err
			return
		}

		// Read client's SETTINGS ACK.
		f, err = serverReader.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if f.Header.Type != frame.TypeSettings || !f.Header.Flags.Has(frame.FlagAck) {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- nil
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	// Client side: perform handshake.
	reader, hErr := h2Handshake(clientConn)
	if hErr != nil {
		t.Fatalf("h2Handshake() error: %v", hErr)
	}
	if reader == nil {
		t.Fatal("h2Handshake() returned nil reader")
	}

	// Check server goroutine for errors.
	if serverErr := <-errCh; serverErr != nil {
		t.Fatalf("server side error: %v", serverErr)
	}
}

// TestReadH2ResponseFrames_HeadersEndStream tests reading a HEADERS frame with END_STREAM.
func TestReadH2ResponseFrames_HeadersEndStream(t *testing.T) {
	var buf bytes.Buffer
	writer := frame.NewWriter(&buf)

	// Write a HEADERS frame with END_STREAM and END_HEADERS.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/plain"},
	}
	fragment := encoder.Encode(headers)
	if err := writer.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	reader := frame.NewReader(&buf)
	respData, err := readH2ResponseFrames(reader)
	if err != nil {
		t.Fatalf("readH2ResponseFrames() error: %v", err)
	}
	if len(respData) == 0 {
		t.Fatal("readH2ResponseFrames() returned empty data")
	}
	// The response data should contain the raw HEADERS frame bytes.
	if len(respData) < frame.HeaderSize {
		t.Errorf("response data too short: %d bytes", len(respData))
	}
}

// TestReadH2ResponseFrames_DataEndStream tests reading HEADERS + DATA with END_STREAM.
func TestReadH2ResponseFrames_DataEndStream(t *testing.T) {
	var buf bytes.Buffer
	writer := frame.NewWriter(&buf)

	// Write a HEADERS frame (no END_STREAM) + DATA frame with END_STREAM.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
	}
	fragment := encoder.Encode(headers)
	if err := writer.WriteHeaders(1, false, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if err := writer.WriteData(1, true, []byte("response body")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	reader := frame.NewReader(&buf)
	respData, err := readH2ResponseFrames(reader)
	if err != nil {
		t.Fatalf("readH2ResponseFrames() error: %v", err)
	}
	if len(respData) == 0 {
		t.Fatal("readH2ResponseFrames() returned empty data")
	}
}

// TestReadH2ResponseFrames_GoAway tests reading a GOAWAY frame.
func TestReadH2ResponseFrames_GoAway(t *testing.T) {
	var buf bytes.Buffer
	writer := frame.NewWriter(&buf)

	if err := writer.WriteGoAway(0, 0, nil); err != nil {
		t.Fatalf("WriteGoAway: %v", err)
	}

	reader := frame.NewReader(&buf)
	respData, err := readH2ResponseFrames(reader)
	if err != nil {
		t.Fatalf("readH2ResponseFrames() error: %v", err)
	}
	if len(respData) == 0 {
		t.Fatal("readH2ResponseFrames() returned empty data for GOAWAY")
	}
}

// TestReadH2ResponseFrames_RSTStream tests reading a RST_STREAM frame.
func TestReadH2ResponseFrames_RSTStream(t *testing.T) {
	var buf bytes.Buffer
	writer := frame.NewWriter(&buf)

	if err := writer.WriteRSTStream(1, 0); err != nil {
		t.Fatalf("WriteRSTStream: %v", err)
	}

	reader := frame.NewReader(&buf)
	respData, err := readH2ResponseFrames(reader)
	if err != nil {
		t.Fatalf("readH2ResponseFrames() error: %v", err)
	}
	if len(respData) == 0 {
		t.Fatal("readH2ResponseFrames() returned empty data for RST_STREAM")
	}
}

// TestReadH2ResponseFrames_SkipsControlFrames tests that SETTINGS and WINDOW_UPDATE are skipped.
func TestReadH2ResponseFrames_SkipsControlFrames(t *testing.T) {
	var buf bytes.Buffer
	writer := frame.NewWriter(&buf)

	// Write control frames followed by a HEADERS with END_STREAM.
	if err := writer.WriteSettingsAck(); err != nil {
		t.Fatalf("WriteSettingsAck: %v", err)
	}
	if err := writer.WriteWindowUpdate(0, 1024); err != nil {
		t.Fatalf("WriteWindowUpdate: %v", err)
	}

	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
	}
	fragment := encoder.Encode(headers)
	if err := writer.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	reader := frame.NewReader(&buf)
	respData, err := readH2ResponseFrames(reader)
	if err != nil {
		t.Fatalf("readH2ResponseFrames() error: %v", err)
	}
	// respData should only contain the HEADERS frame, not the control frames.
	if len(respData) == 0 {
		t.Fatal("readH2ResponseFrames() returned empty data")
	}
}

// TestReadH2ResponseFrames_EOF tests graceful handling of EOF.
func TestReadH2ResponseFrames_EOF(t *testing.T) {
	reader := frame.NewReader(bytes.NewReader(nil))
	respData, err := readH2ResponseFrames(reader)
	if err != nil {
		t.Fatalf("readH2ResponseFrames() should not return error on EOF, got: %v", err)
	}
	if len(respData) != 0 {
		t.Errorf("expected empty respData on EOF, got %d bytes", len(respData))
	}
}

// --- Integration-style tests using MCP tool invocation ---

// newH2EchoServer creates a TCP server that speaks HTTP/2 (without TLS, for testing).
// It performs the server-side handshake and responds to the first request with a simple response.
func newH2EchoServer(t *testing.T) (string, func()) {
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
			go handleH2EchoConn(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// handleH2EchoConn handles a single HTTP/2 connection for the echo server.
func handleH2EchoConn(conn net.Conn) {
	defer conn.Close()

	// Read client connection preface.
	prefaceBuf := make([]byte, len(h2ClientPreface))
	if _, err := io.ReadFull(conn, prefaceBuf); err != nil {
		return
	}

	reader := frame.NewReader(conn)
	writer := frame.NewWriter(conn)
	decoder := hpack.NewDecoder(4096)
	encoder := hpack.NewEncoder(4096, true)

	// Read client initial SETTINGS.
	f, err := reader.ReadFrame()
	if err != nil || f.Header.Type != frame.TypeSettings {
		return
	}

	// Send server SETTINGS.
	writer.WriteSettings([]frame.Setting{ //nolint:errcheck
		{ID: frame.SettingMaxConcurrentStreams, Value: 100},
	})

	// Send SETTINGS ACK.
	writer.WriteSettingsAck() //nolint:errcheck

	// Read frames until we get request HEADERS + END_STREAM (or HEADERS + DATA + END_STREAM).
	var gotEndStream bool
	var streamID uint32
	for !gotEndStream {
		f, err := reader.ReadFrame()
		if err != nil {
			return
		}
		switch f.Header.Type {
		case frame.TypeSettings:
			if !f.Header.Flags.Has(frame.FlagAck) {
				writer.WriteSettingsAck() //nolint:errcheck
			}
		case frame.TypeHeaders:
			streamID = f.Header.StreamID
			// Decode to advance HPACK state.
			if f.Header.Flags.Has(frame.FlagEndHeaders) {
				if frag, fErr := f.HeaderBlockFragment(); fErr == nil {
					decoder.Decode(frag) //nolint:errcheck
				}
			}
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
		case frame.TypeData:
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
			// Send WINDOW_UPDATE for flow control.
			if f.Header.Length > 0 {
				writer.WriteWindowUpdate(0, f.Header.Length)                 //nolint:errcheck
				writer.WriteWindowUpdate(f.Header.StreamID, f.Header.Length) //nolint:errcheck
			}
		case frame.TypeWindowUpdate:
			// Ignore.
		}
	}

	// Send response HEADERS + DATA + END_STREAM.
	respHeaders := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/plain"},
	}
	fragment := encoder.Encode(respHeaders)
	writer.WriteHeaders(streamID, false, true, fragment) //nolint:errcheck
	writer.WriteData(streamID, true, []byte("h2-echo"))  //nolint:errcheck
}

// TestResendRawH2_ViaServer tests the full resend_raw flow for HTTP/2 via the MCP server.
func TestResendRawH2_ViaServer(t *testing.T) {
	// Start an HTTP/2 echo server (no TLS for simplicity).
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	// Build raw HTTP/2 frames that represent a GET request on stream 1.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/test"},
	}
	fragment := encoder.Encode(headers)

	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	rawBytes := rawBuf.Bytes()

	// Set up the flow store with an HTTP/2 flow.
	store := newTestStore(t)
	ctx := context.Background()

	parsedURL, _ := url.Parse("https://" + echoAddr + "/test")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		RawBytes:  rawBytes,
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Set up MCP server with a raw dialer (no TLS since our echo server doesn't use TLS).
	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// Call resend with action=resend_raw, use_tls=false (no TLS for test).
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":     fl.ID,
				"use_tls":     false,
				"target_addr": echoAddr,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		var errText string
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				errText = tc.Text
			}
		}
		t.Fatalf("resend_raw returned error: %s", errText)
	}

	// Parse the result.
	var rawResult resendRawResult
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			if err := json.Unmarshal([]byte(tc.Text), &rawResult); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
		}
	}

	if rawResult.NewFlowID == "" {
		t.Error("expected non-empty NewFlowID")
	}
	if rawResult.ResponseSize == 0 {
		t.Error("expected non-zero ResponseSize")
	}
	if rawResult.DurationMs < 0 {
		t.Error("expected non-negative DurationMs")
	}

	// Verify the response data contains HTTP/2 frame bytes.
	respBytes, err := base64.StdEncoding.DecodeString(rawResult.ResponseData)
	if err != nil {
		t.Fatalf("decode response data: %v", err)
	}
	if len(respBytes) == 0 {
		t.Error("expected non-empty response bytes")
	}
}

// TestResendRawH2_DryRun tests dry-run mode for HTTP/2 resend_raw.
func TestResendRawH2_DryRun(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Build raw frames.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	parsedURL, _ := url.Parse("https://example.com/")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		RawBytes:  rawBuf.Bytes(),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	s := NewServer(ctx, nil, store, nil)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id": fl.ID,
				"dry_run": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		var errText string
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				errText = tc.Text
			}
		}
		t.Fatalf("dry_run returned error: %s", errText)
	}

	// Parse the dry-run result.
	var dryResult resendRawDryRunResult
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			if err := json.Unmarshal([]byte(tc.Text), &dryResult); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
		}
	}

	if !dryResult.DryRun {
		t.Error("expected DryRun=true")
	}
	if dryResult.RawPreview == nil {
		t.Fatal("expected non-nil RawPreview")
	}
	if dryResult.RawPreview.DataSize == 0 {
		t.Error("expected non-zero DataSize")
	}
}

// TestResendRawH2_WithPatches tests raw_patch for HTTP/2 flows.
func TestResendRawH2_WithPatches(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Build raw frames with a known text pattern.
	// Use useHuffman=false so the path appears as literal ASCII in the HPACK block,
	// making it possible to find/replace with text patches.
	encoder := hpack.NewEncoder(4096, false)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/original"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	originalRaw := rawBuf.Bytes()

	parsedURL, _ := url.Parse("https://example.com/original")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		RawBytes:  originalRaw,
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	s := NewServer(ctx, nil, store, nil)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// Use dry_run with text find/replace patch to verify patching works.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id": fl.ID,
				"dry_run": true,
				"patches": []map[string]any{
					{
						"find_text":    "/original",
						"replace_text": "/patched_",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		var errText string
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				errText = tc.Text
			}
		}
		t.Fatalf("dry_run with patches returned error: %s", errText)
	}

	var dryResult resendRawDryRunResult
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			if err := json.Unmarshal([]byte(tc.Text), &dryResult); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
		}
	}

	if dryResult.RawPreview == nil {
		t.Fatal("expected non-nil RawPreview")
	}
	if dryResult.RawPreview.PatchesApplied != 1 {
		t.Errorf("PatchesApplied = %d, want 1", dryResult.RawPreview.PatchesApplied)
	}

	// Verify the patched data contains "/patched_" instead of "/original".
	patchedBytes, err := base64.StdEncoding.DecodeString(dryResult.RawPreview.DataBase64)
	if err != nil {
		t.Fatalf("decode patched data: %v", err)
	}
	if !bytes.Contains(patchedBytes, []byte("/patched_")) {
		t.Error("expected patched bytes to contain '/patched_'")
	}
	if bytes.Contains(patchedBytes, []byte("/original")) {
		t.Error("patched bytes should not contain '/original'")
	}
}

// TestResendRawH2_GRPCProtocol tests that gRPC flows also route through the HTTP/2 handler.
func TestResendRawH2_GRPCProtocol(t *testing.T) {
	// Start an HTTP/2 echo server.
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	// Build raw frames.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/grpc.Service/Method"},
		{Name: "content-type", Value: "application/grpc"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	parsedURL, _ := url.Parse("https://" + echoAddr + "/grpc.Service/Method")
	fl := &flow.Flow{
		Protocol:  "gRPC",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       parsedURL,
		RawBytes:  rawBuf.Bytes(),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":     fl.ID,
				"use_tls":     false,
				"target_addr": echoAddr,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		var errText string
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				errText = tc.Text
			}
		}
		t.Fatalf("resend_raw gRPC returned error: %s", errText)
	}

	var rawResult resendRawResult
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			if err := json.Unmarshal([]byte(tc.Text), &rawResult); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
		}
	}

	if rawResult.NewFlowID == "" {
		t.Error("expected non-empty NewFlowID")
	}
	if rawResult.ResponseSize == 0 {
		t.Error("expected non-zero ResponseSize")
	}
}

// TestResendRawH2_OverrideRawBase64 tests override_raw_base64 for HTTP/2 flows.
func TestResendRawH2_OverrideRawBase64(t *testing.T) {
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	// Build raw frames — the original.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/old"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	parsedURL, _ := url.Parse("https://example.com/old")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		RawBytes:  rawBuf.Bytes(),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Build override raw frames pointing to the echo server.
	encoder2 := hpack.NewEncoder(4096, true)
	overrideHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/new"},
	}
	overrideFragment := encoder2.Encode(overrideHeaders)
	var overrideBuf bytes.Buffer
	w2 := frame.NewWriter(&overrideBuf)
	if err := w2.WriteHeaders(1, true, true, overrideFragment); err != nil {
		t.Fatalf("WriteHeaders override: %v", err)
	}
	overrideB64 := base64.StdEncoding.EncodeToString(overrideBuf.Bytes())

	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":             fl.ID,
				"use_tls":             false,
				"target_addr":         echoAddr,
				"override_raw_base64": overrideB64,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		var errText string
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				errText = tc.Text
			}
		}
		t.Fatalf("resend_raw with override returned error: %s", errText)
	}

	var rawResult resendRawResult
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			if err := json.Unmarshal([]byte(tc.Text), &rawResult); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
		}
	}

	if rawResult.NewFlowID == "" {
		t.Error("expected non-empty NewFlowID")
	}
	if rawResult.ResponseSize == 0 {
		t.Error("expected non-zero ResponseSize")
	}
}

// TestResendRawH2_H2CInferTLS tests that h2c flows (HTTP/2 over cleartext) correctly
// infer useTLS=false from ConnInfo when use_tls is not explicitly specified.
// This prevents the bug where h2c flows would default to TLS and fail to connect.
func TestResendRawH2_H2CInferTLS(t *testing.T) {
	// Start an HTTP/2 echo server (no TLS).
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	// Build raw HTTP/2 frames.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/h2c-test"},
	}
	fragment := encoder.Encode(headers)

	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	rawBytes := rawBuf.Bytes()

	parsedURL, _ := url.Parse("http://" + echoAddr + "/h2c-test")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
		// ConnInfo with no TLS fields → h2c.
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:54321",
			ServerAddr: echoAddr,
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		RawBytes:  rawBytes,
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Set up MCP server — do NOT set use_tls; let the server infer from ConnInfo.
	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// Call resend_raw without use_tls — should infer h2c from ConnInfo.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":     fl.ID,
				"target_addr": echoAddr,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		var errText string
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				errText = tc.Text
			}
		}
		t.Fatalf("resend_raw h2c returned error: %s", errText)
	}

	var h2cResult resendRawResult
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			if err := json.Unmarshal([]byte(tc.Text), &h2cResult); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
		}
	}

	if h2cResult.NewFlowID == "" {
		t.Error("expected non-empty NewFlowID")
	}
	if h2cResult.ResponseSize == 0 {
		t.Error("expected non-zero ResponseSize")
	}
}
