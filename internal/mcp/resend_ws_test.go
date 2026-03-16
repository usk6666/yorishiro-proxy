package mcp

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/ws"
)

// newWebSocketEchoServer creates a TCP server that accepts HTTP Upgrade requests,
// performs the WebSocket handshake, and echoes back any received frames.
func newWebSocketEchoServer(t *testing.T) (string, func()) {
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
			go handleWSEchoConn(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// handleWSEchoConn handles a single WebSocket echo connection.
func handleWSEchoConn(conn net.Conn) {
	defer conn.Close()

	// Set a generous deadline.
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read the HTTP Upgrade request.
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// Validate WebSocket upgrade.
	if req.Header.Get("Upgrade") != "websocket" {
		resp := "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
		conn.Write([]byte(resp))
		return
	}

	// Send 101 Switching Protocols response.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dummy-accept-key\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	// Read WebSocket frames and echo them back.
	for {
		frame, err := ws.ReadFrame(reader)
		if err != nil {
			return
		}

		if frame.Opcode == ws.OpcodeClose {
			// Echo close frame back.
			closeFrame := &ws.Frame{
				Fin:     true,
				Opcode:  ws.OpcodeClose,
				Payload: frame.Payload,
			}
			ws.WriteFrame(conn, closeFrame)
			return
		}

		// Echo the frame back (server-to-client frames are not masked).
		echoFrame := &ws.Frame{
			Fin:     true,
			Opcode:  frame.Opcode,
			Payload: frame.Payload,
		}
		if err := ws.WriteFrame(conn, echoFrame); err != nil {
			return
		}
	}
}

// setupWSResendSession creates an MCP session configured for WebSocket resend testing.
func setupWSResendSession(t *testing.T, store flow.Store) *gomcp.ClientSession {
	t.Helper()
	return setupMultiProtoExecSession(t, store)
}

// seedWebSocketFlow creates a WebSocket flow with Upgrade request/response and a data message.
func seedWebSocketFlow(t *testing.T, store flow.Store, id, targetAddr string) {
	t.Helper()
	ctx := context.Background()

	host, port, _ := net.SplitHostPort(targetAddr)
	wsURL, _ := url.Parse(fmt.Sprintf("ws://%s:%s/echo", host, port))

	fl := &flow.Flow{
		ID:        id,
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: targetAddr},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// seq=0: Upgrade request (send).
	upgradeReq := &flow.Message{
		FlowID:    id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       wsURL,
		Headers: map[string][]string{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Host":                  {fmt.Sprintf("%s:%s", host, port)},
		},
	}
	if err := store.AppendMessage(ctx, upgradeReq); err != nil {
		t.Fatalf("AppendMessage(upgrade request): %v", err)
	}

	// seq=1: Upgrade response (receive).
	upgradeResp := &flow.Message{
		FlowID:     id,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 101,
		Headers: map[string][]string{
			"Upgrade":              {"websocket"},
			"Connection":           {"Upgrade"},
			"Sec-Websocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
		},
	}
	if err := store.AppendMessage(ctx, upgradeResp); err != nil {
		t.Fatalf("AppendMessage(upgrade response): %v", err)
	}

	// seq=2: Data frame (send).
	dataMsg := &flow.Message{
		FlowID:    id,
		Sequence:  2,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("hello websocket"),
		Metadata:  map[string]string{"opcode": "1", "fin": "true", "masked": "true"},
	}
	if err := store.AppendMessage(ctx, dataMsg); err != nil {
		t.Fatalf("AppendMessage(data): %v", err)
	}
}

// --- Tests ---

func TestWebSocketResend_Success(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	seedWebSocketFlow(t, store, "ws-echo-1", addr)

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-echo-1",
			"message_sequence": 2,
			"tag":              "ws-test",
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendWebSocketResult
	unmarshalExecMultiProtoResult(t, result, &out)

	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}
	if out.MessageSequence != 2 {
		t.Errorf("message_sequence = %d, want 2", out.MessageSequence)
	}
	if out.ResponseSize == 0 {
		t.Error("response_size should be > 0")
	}
	if out.Tag != "ws-test" {
		t.Errorf("tag = %q, want ws-test", out.Tag)
	}

	// Verify the response payload is the echoed message.
	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if string(respBytes) != "hello websocket" {
		t.Errorf("response payload = %q, want %q", string(respBytes), "hello websocket")
	}

	// Verify recorded flow has 4 messages (upgrade req, upgrade resp, send frame, recv frame).
	ctx := context.Background()
	msgs, err := store.GetMessages(ctx, out.NewFlowID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) != 4 {
		t.Errorf("recorded message count = %d, want 4", len(msgs))
	}

	// Verify seq=0 is Upgrade request with URL and Method.
	if msgs[0].Sequence != 0 || msgs[0].Direction != "send" || msgs[0].Method != "GET" {
		t.Errorf("msg[0]: seq=%d dir=%s method=%s, want seq=0 dir=send method=GET",
			msgs[0].Sequence, msgs[0].Direction, msgs[0].Method)
	}
	if msgs[0].URL == nil {
		t.Error("msg[0] should have a URL")
	}

	// Verify seq=1 is Upgrade response with StatusCode 101.
	if msgs[1].Sequence != 1 || msgs[1].Direction != "receive" || msgs[1].StatusCode != 101 {
		t.Errorf("msg[1]: seq=%d dir=%s status=%d, want seq=1 dir=receive status=101",
			msgs[1].Sequence, msgs[1].Direction, msgs[1].StatusCode)
	}

	// Verify seq=2 is the sent data frame.
	if msgs[2].Sequence != 2 || msgs[2].Direction != "send" || string(msgs[2].Body) != "hello websocket" {
		t.Errorf("msg[2]: seq=%d dir=%s body=%q, want seq=2 dir=send body='hello websocket'",
			msgs[2].Sequence, msgs[2].Direction, string(msgs[2].Body))
	}

	// Verify seq=3 is the received data frame.
	if msgs[3].Sequence != 3 || msgs[3].Direction != "receive" || string(msgs[3].Body) != "hello websocket" {
		t.Errorf("msg[3]: seq=%d dir=%s body=%q, want seq=3 dir=receive body='hello websocket'",
			msgs[3].Sequence, msgs[3].Direction, string(msgs[3].Body))
	}
}

func TestWebSocketResend_OverrideBody(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	seedWebSocketFlow(t, store, "ws-override-1", addr)

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-override-1",
			"message_sequence": 2,
			"override_body":    "overridden message",
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendWebSocketResult
	unmarshalExecMultiProtoResult(t, result, &out)

	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if string(respBytes) != "overridden message" {
		t.Errorf("response payload = %q, want %q", string(respBytes), "overridden message")
	}
}

func TestWebSocketResend_OverrideBodyBase64(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	seedWebSocketFlow(t, store, "ws-b64-1", addr)

	encoded := base64.StdEncoding.EncodeToString([]byte("base64 payload"))

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":              "ws-b64-1",
			"message_sequence":     2,
			"override_body_base64": encoded,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendWebSocketResult
	unmarshalExecMultiProtoResult(t, result, &out)

	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if string(respBytes) != "base64 payload" {
		t.Errorf("response payload = %q, want %q", string(respBytes), "base64 payload")
	}
}

func TestWebSocketResend_BinaryFrame(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	ctx := context.Background()
	host, port, _ := net.SplitHostPort(addr)
	wsURL, _ := url.Parse(fmt.Sprintf("ws://%s:%s/echo", host, port))

	fl := &flow.Flow{
		ID:        "ws-binary-1",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: addr},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Upgrade request.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-binary-1", Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: wsURL,
		Headers: map[string][]string{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Host":                  {fmt.Sprintf("%s:%s", host, port)},
		},
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade request): %v", err)
	}

	// Upgrade response.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-binary-1", Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 101,
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade response): %v", err)
	}

	// Binary data frame with opcode=2.
	binaryPayload := []byte{0x00, 0x01, 0x02, 0x03}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-binary-1", Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(), Body: binaryPayload,
		Metadata: map[string]string{"opcode": "2", "fin": "true", "masked": "true"},
	}); err != nil {
		t.Fatalf("AppendMessage(binary data): %v", err)
	}

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-binary-1",
			"message_sequence": 2,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendWebSocketResult
	unmarshalExecMultiProtoResult(t, result, &out)

	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if len(respBytes) != 4 || respBytes[0] != 0x00 || respBytes[3] != 0x03 {
		t.Errorf("binary response mismatch: got %v", respBytes)
	}

	// Verify the received frame is stored in RawBytes (binary), not Body.
	msgs, err := store.GetMessages(ctx, out.NewFlowID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) < 4 {
		t.Fatalf("expected 4 messages, got %d", len(msgs))
	}
	recvMsg := msgs[3]
	if recvMsg.Body != nil {
		t.Error("binary frame should have nil Body")
	}
	if len(recvMsg.RawBytes) != 4 {
		t.Errorf("binary frame RawBytes length = %d, want 4", len(recvMsg.RawBytes))
	}
}

func TestWebSocketResend_NoUpgradeMessage(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Create a WebSocket flow without the Upgrade request message.
	fl := &flow.Flow{
		ID:        "ws-no-upgrade",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "127.0.0.1:9999"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Only a data frame at seq=2 (no upgrade request at seq=0).
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-no-upgrade", Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(), Body: []byte("hello"),
		Metadata: map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-no-upgrade",
			"message_sequence": 2,
		},
	})
	if !result.IsError {
		t.Fatal("expected error when upgrade request message is missing")
	}
}

func TestWebSocketResend_TargetAddrFromURL(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	ctx := context.Background()
	host, port, _ := net.SplitHostPort(addr)
	wsURL, _ := url.Parse(fmt.Sprintf("ws://%s:%s/echo", host, port))

	// Create a flow with no ConnInfo (target addr must be resolved from URL).
	fl := &flow.Flow{
		ID:        "ws-url-resolve",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-url-resolve", Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: wsURL,
		Headers: map[string][]string{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Host":                  {wsURL.Host},
		},
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade request): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-url-resolve", Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 101,
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade response): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-url-resolve", Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(), Body: []byte("url resolved"),
		Metadata: map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage(data): %v", err)
	}

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-url-resolve",
			"message_sequence": 2,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendWebSocketResult
	unmarshalExecMultiProtoResult(t, result, &out)

	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if string(respBytes) != "url resolved" {
		t.Errorf("response = %q, want %q", string(respBytes), "url resolved")
	}
}

func TestWebSocketResend_ExplicitTargetAddr(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	ctx := context.Background()
	wsURL, _ := url.Parse("ws://original-host:9999/echo")

	fl := &flow.Flow{
		ID:        "ws-explicit-addr",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "original-host:9999"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-explicit-addr", Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: wsURL,
		Headers: map[string][]string{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Host":                  {"original-host:9999"},
		},
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade request): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-explicit-addr", Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 101,
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade response): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-explicit-addr", Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(), Body: []byte("redirected"),
		Metadata: map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage(data): %v", err)
	}

	cs := setupWSResendSession(t, store)

	// Use target_addr to redirect to the actual echo server.
	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-explicit-addr",
			"message_sequence": 2,
			"target_addr":      addr,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendWebSocketResult
	unmarshalExecMultiProtoResult(t, result, &out)

	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if string(respBytes) != "redirected" {
		t.Errorf("response = %q, want %q", string(respBytes), "redirected")
	}
}

// --- Unit tests for helper functions ---

func TestResolveWebSocketOpcode(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		want     byte
	}{
		{"nil metadata", nil, ws.OpcodeText},
		{"no opcode key", map[string]string{"fin": "true"}, ws.OpcodeText},
		{"text opcode", map[string]string{"opcode": "1"}, ws.OpcodeText},
		{"binary opcode", map[string]string{"opcode": "2"}, ws.OpcodeBinary},
		{"invalid opcode", map[string]string{"opcode": "abc"}, ws.OpcodeText},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := &flow.Message{Metadata: tc.metadata}
			got := resolveWebSocketOpcode(msg)
			if got != tc.want {
				t.Errorf("resolveWebSocketOpcode() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestEnsureWebSocketHeaders(t *testing.T) {
	// Test with empty headers.
	h := make(http.Header)
	ensureWebSocketHeaders(h)

	if h.Get("Upgrade") != "websocket" {
		t.Errorf("Upgrade = %q, want websocket", h.Get("Upgrade"))
	}
	if h.Get("Connection") != "Upgrade" {
		t.Errorf("Connection = %q, want Upgrade", h.Get("Connection"))
	}
	if h.Get("Sec-WebSocket-Version") != "13" {
		t.Errorf("Sec-WebSocket-Version = %q, want 13", h.Get("Sec-WebSocket-Version"))
	}
	if h.Get("Sec-WebSocket-Key") == "" {
		t.Error("Sec-WebSocket-Key should be set")
	}

	// Test that existing headers are not overwritten.
	h2 := make(http.Header)
	h2.Set("Upgrade", "custom")
	h2.Set("Sec-WebSocket-Key", "my-key")
	ensureWebSocketHeaders(h2)

	if h2.Get("Upgrade") != "custom" {
		t.Errorf("Upgrade should be preserved: got %q", h2.Get("Upgrade"))
	}
	if h2.Get("Sec-WebSocket-Key") != "my-key" {
		t.Errorf("Sec-WebSocket-Key should be preserved: got %q", h2.Get("Sec-WebSocket-Key"))
	}
}

func TestClassifyWebSocketPayload(t *testing.T) {
	payload := []byte("hello")

	body, raw := classifyWebSocketPayload(payload, ws.OpcodeText)
	if string(body) != "hello" || raw != nil {
		t.Errorf("text: body=%v, raw=%v", body, raw)
	}

	body, raw = classifyWebSocketPayload(payload, ws.OpcodeBinary)
	if body != nil || string(raw) != "hello" {
		t.Errorf("binary: body=%v, raw=%v", body, raw)
	}
}

func TestFindUpgradeRequestMessage_NotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Flow{
		ID: "ws-no-seq0", Protocol: "WebSocket", FlowType: "bidirectional",
		State: "complete", Timestamp: time.Now().UTC(),
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Only a receive message at seq=0.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-no-seq0", Sequence: 0, Direction: "receive",
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	_, err := findUpgradeRequestMessage(ctx, store, "ws-no-seq0")
	if err == nil {
		t.Fatal("expected error when seq=0 is not a send message")
	}
}

// newWebSocketHeaderCaptureServer creates a WebSocket echo server that captures
// the received HTTP Upgrade request for header verification.
func newWebSocketHeaderCaptureServer(t *testing.T) (addr string, receivedReq func() *http.Request, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	reqCh := make(chan *http.Request, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		reqCh <- req

		// Send 101 response.
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: dummy-accept-key\r\n" +
			"\r\n"
		conn.Write([]byte(resp))

		// Echo one frame.
		frame, err := ws.ReadFrame(reader)
		if err != nil {
			return
		}
		ws.WriteFrame(conn, &ws.Frame{Fin: true, Opcode: frame.Opcode, Payload: frame.Payload})
	}()

	return ln.Addr().String(), func() *http.Request {
		select {
		case r := <-reqCh:
			return r
		case <-time.After(3 * time.Second):
			t.Fatal("timeout waiting for request")
			return nil
		}
	}, func() { ln.Close() }
}

func TestWebSocketResend_OverrideHeaders(t *testing.T) {
	store := newTestStore(t)
	addr, getReq, cleanup := newWebSocketHeaderCaptureServer(t)
	defer cleanup()

	seedWebSocketFlow(t, store, "ws-oh-1", addr)

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-oh-1",
			"message_sequence": 2,
			"override_headers": []map[string]string{
				{"key": "Host", "value": "custom-host:8080"},
			},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	req := getReq()
	if got := req.Header.Get("Host"); got != "custom-host:8080" {
		// Go's net/http puts Host in req.Host, not req.Header.
		if req.Host != "custom-host:8080" {
			t.Errorf("Host = %q (header: %q), want custom-host:8080", req.Host, got)
		}
	}
}

func TestWebSocketResend_AddHeaders(t *testing.T) {
	store := newTestStore(t)
	addr, getReq, cleanup := newWebSocketHeaderCaptureServer(t)
	defer cleanup()

	seedWebSocketFlow(t, store, "ws-ah-1", addr)

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-ah-1",
			"message_sequence": 2,
			"add_headers": []map[string]string{
				{"key": "X-Custom-Header", "value": "custom-value"},
			},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	req := getReq()
	if got := req.Header.Get("X-Custom-Header"); got != "custom-value" {
		t.Errorf("X-Custom-Header = %q, want custom-value", got)
	}
}

func TestWebSocketResend_RemoveHeaders(t *testing.T) {
	store := newTestStore(t)
	addr, getReq, cleanup := newWebSocketHeaderCaptureServer(t)
	defer cleanup()

	// Seed flow with a custom header that we will remove.
	ctx := context.Background()
	host, port, _ := net.SplitHostPort(addr)
	wsURL, _ := url.Parse(fmt.Sprintf("ws://%s:%s/echo", host, port))

	fl := &flow.Flow{
		ID:        "ws-rh-1",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: addr},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-rh-1", Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: wsURL,
		Headers: map[string][]string{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Host":                  {fmt.Sprintf("%s:%s", host, port)},
			"X-Remove-Me":           {"should-be-removed"},
		},
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-rh-1", Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 101,
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade resp): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-rh-1", Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(), Body: []byte("test remove"),
		Metadata: map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage(data): %v", err)
	}

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-rh-1",
			"message_sequence": 2,
			"remove_headers":   []string{"X-Remove-Me"},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	req := getReq()
	if got := req.Header.Get("X-Remove-Me"); got != "" {
		t.Errorf("X-Remove-Me should be removed, got %q", got)
	}
}

func TestWebSocketResend_OverrideURL(t *testing.T) {
	store := newTestStore(t)
	addr, getReq, cleanup := newWebSocketHeaderCaptureServer(t)
	defer cleanup()

	ctx := context.Background()
	// Create flow pointing to a non-existent host.
	wsURL, _ := url.Parse("ws://original-host:9999/original-path")

	fl := &flow.Flow{
		ID:        "ws-ou-1",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "original-host:9999"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-ou-1", Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: wsURL,
		Headers: map[string][]string{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key":     {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Host":                  {"original-host:9999"},
		},
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-ou-1", Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 101,
	}); err != nil {
		t.Fatalf("AppendMessage(upgrade resp): %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: "ws-ou-1", Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(), Body: []byte("url override test"),
		Metadata: map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage(data): %v", err)
	}

	cs := setupWSResendSession(t, store)

	// Override URL to point to the actual echo server.
	overrideURL := fmt.Sprintf("ws://%s/new-path?q=1", addr)
	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-ou-1",
			"message_sequence": 2,
			"override_url":     overrideURL,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	req := getReq()
	// Verify the request URI was updated.
	if req.RequestURI != "/new-path?q=1" {
		t.Errorf("RequestURI = %q, want /new-path?q=1", req.RequestURI)
	}
	// Verify Host was updated to the override URL's host.
	if req.Host != addr {
		t.Errorf("Host = %q, want %q", req.Host, addr)
	}

	// Verify the recorded flow has the override URL.
	var out resendWebSocketResult
	unmarshalExecMultiProtoResult(t, result, &out)

	msgs, err := store.GetMessages(ctx, out.NewFlowID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if msgs[0].URL == nil {
		t.Fatal("recorded upgrade message should have URL")
	}
	if msgs[0].URL.Path != "/new-path" {
		t.Errorf("recorded URL path = %q, want /new-path", msgs[0].URL.Path)
	}
	if msgs[0].URL.RawQuery != "q=1" {
		t.Errorf("recorded URL query = %q, want q=1", msgs[0].URL.RawQuery)
	}
}

func TestWebSocketResend_NoOverrides_PreservesOriginalHeaders(t *testing.T) {
	store := newTestStore(t)
	addr, getReq, cleanup := newWebSocketHeaderCaptureServer(t)
	defer cleanup()

	seedWebSocketFlow(t, store, "ws-no-override-1", addr)

	cs := setupWSResendSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-no-override-1",
			"message_sequence": 2,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	req := getReq()
	// Original headers should be preserved.
	if got := req.Header.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade = %q, want websocket", got)
	}
	if got := req.Header.Get("Connection"); got != "Upgrade" {
		t.Errorf("Connection = %q, want Upgrade", got)
	}
	if got := req.Header.Get("Sec-Websocket-Version"); got != "13" {
		t.Errorf("Sec-Websocket-Version = %q, want 13", got)
	}
}

func TestCopyHTTPResponseHeaders(t *testing.T) {
	// Nil response.
	if h := copyHTTPResponseHeaders(nil); h != nil {
		t.Errorf("nil response: got %v, want nil", h)
	}

	// Nil headers in response.
	resp := &http.Response{}
	if h := copyHTTPResponseHeaders(resp); h != nil {
		t.Errorf("nil headers: got %v, want nil", h)
	}

	// Normal headers.
	resp = &http.Response{
		Header: http.Header{"X-Test": {"value1", "value2"}},
	}
	h := copyHTTPResponseHeaders(resp)
	if len(h["X-Test"]) != 2 || h["X-Test"][0] != "value1" {
		t.Errorf("headers mismatch: %v", h)
	}
}
