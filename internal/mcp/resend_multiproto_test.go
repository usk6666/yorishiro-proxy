package mcp

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// setupMultiProtoExecSession creates a connected MCP client session for multi-protocol execute tests.
func setupMultiProtoExecSession(t *testing.T, store flow.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	s := NewServer(ctx, ca, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// callExecMultiProto invokes the execute tool with map-based args.
func callExecMultiProto(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	var rawArgs map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawArgs); err != nil {
		t.Fatalf("unmarshal to raw: %v", err)
	}

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend",
		Arguments: rawArgs,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// unmarshalExecMultiProtoResult extracts JSON from CallToolResult content.
func unmarshalExecMultiProtoResult(t *testing.T, result *gomcp.CallToolResult, dest any) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	if err := json.Unmarshal([]byte(text.Text), dest); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
}

// --- Test: tcp_replay action ---

func TestExecuteMultiProto_TCPReplay_RequiresFlowID(t *testing.T) {
	store := newTestStore(t)
	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for missing flow_id")
	}
}

func TestExecuteMultiProto_TCPReplay_RequiresTCPProtocol(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "http-1", "HTTPS", "GET", "https://example.com", 200)

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"flow_id": "http-1",
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for non-TCP session")
	}
}

func TestExecuteMultiProto_TCPReplay_NoSendMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        "tcp-empty",
		Protocol:  "TCP",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "127.0.0.1:9999"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"flow_id": "tcp-empty",
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for no send messages")
	}
}

func TestExecuteMultiProto_TCPReplay_NoTargetAddr(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        "tcp-no-target",
		Protocol:  "TCP",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &flow.Message{
		ID:        "tcp-no-target-send",
		FlowID:    "tcp-no-target",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("hello"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"flow_id": "tcp-no-target",
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for no target address")
	}
}

func TestExecuteMultiProto_TCPReplay_WithTargetAddr(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	addr, cleanup := newRawEchoServer(t)
	t.Cleanup(cleanup)

	fl := &flow.Flow{
		ID:        "tcp-replay",
		Protocol:  "TCP",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "original:1234"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &flow.Message{
		ID:        "tcp-replay-send",
		FlowID:    "tcp-replay",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"flow_id":     "tcp-replay",
			"target_addr": addr,
			"tag":         "test-replay",
		},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out resendReplayRawResult
	unmarshalExecMultiProtoResult(t, result, &out)

	if out.NewFlowID == "" {
		t.Error("new_flow_id should not be empty")
	}
	if out.MessagesSent != 1 {
		t.Errorf("messages_sent = %d, want 1", out.MessagesSent)
	}
	if out.TotalBytesSent == 0 {
		t.Error("total_bytes_sent should be > 0")
	}
	if out.TotalBytesReceived == 0 {
		t.Error("total_bytes_received should be > 0")
	}
	if out.Tag != "test-replay" {
		t.Errorf("tag = %q, want test-replay", out.Tag)
	}
}

func TestExecuteMultiProto_TCPReplay_NilStore(t *testing.T) {
	cs := setupMultiProtoExecSession(t, nil)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "tcp_replay",
		"params": map[string]any{
			"flow_id": "any",
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

// --- Test: resend for WebSocket flows ---

func TestExecuteMultiProto_Resend_WebSocket_RequiresMessageSequence(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        "ws-resend-1",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "127.0.0.1:9999"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": "ws-resend-1",
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true when message_sequence is missing for WebSocket")
	}
}

func TestExecuteMultiProto_Resend_WebSocket_MessageNotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        "ws-resend-2",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "127.0.0.1:9999"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &flow.Message{
		ID:        "ws-msg-0",
		FlowID:    "ws-resend-2",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("hello"),
		Metadata:  map[string]string{"opcode": "1"},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-resend-2",
			"message_sequence": 99,
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent message sequence")
	}
}

func TestExecuteMultiProto_Resend_WebSocket_ReceiveMessage(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        "ws-resend-3",
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		ConnInfo:  &flow.ConnectionInfo{ServerAddr: "127.0.0.1:9999"},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	recvMsg := &flow.Message{
		ID:        "ws-msg-1",
		FlowID:    "ws-resend-3",
		Sequence:  1,
		Direction: "receive",
		Timestamp: time.Now().UTC(),
		Body:      []byte("server msg"),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMultiProtoExecSession(t, store)

	result := callExecMultiProto(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":          "ws-resend-3",
			"message_sequence": 1,
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for receive message")
	}
}

// --- Test: proxy_start tcp_forwards and protocols validation ---

func TestValidateTCPForwards(t *testing.T) {
	tests := []struct {
		name     string
		forwards map[string]string
		wantErr  bool
	}{
		{
			name:     "valid single",
			forwards: map[string]string{"3306": "db.example.com:3306"},
			wantErr:  false,
		},
		{
			name:     "valid multiple",
			forwards: map[string]string{"3306": "db:3306", "6379": "redis:6379"},
			wantErr:  false,
		},
		{
			name:     "empty port key",
			forwards: map[string]string{"": "db:3306"},
			wantErr:  true,
		},
		{
			name:     "empty target",
			forwards: map[string]string{"3306": ""},
			wantErr:  true,
		},
		{
			name:     "invalid target format",
			forwards: map[string]string{"3306": "no-port"},
			wantErr:  true,
		},
		{
			name:     "non-numeric port key",
			forwards: map[string]string{"abc": "db:3306"},
			wantErr:  true,
		},
		{
			name:     "port key zero allowed for listen",
			forwards: map[string]string{"0": "db:3306"},
			wantErr:  false,
		},
		{
			name:     "port key exceeds 65535",
			forwards: map[string]string{"99999": "db:3306"},
			wantErr:  true,
		},
		{
			name:     "port key negative",
			forwards: map[string]string{"-1": "db:3306"},
			wantErr:  true,
		},
		{
			name:     "port key boundary 1",
			forwards: map[string]string{"1": "db:3306"},
			wantErr:  false,
		},
		{
			name:     "port key boundary 65535",
			forwards: map[string]string{"65535": "db:3306"},
			wantErr:  false,
		},
		{
			name:     "target port non-numeric",
			forwards: map[string]string{"3306": "db:abc"},
			wantErr:  true,
		},
		{
			name:     "target port zero",
			forwards: map[string]string{"3306": "db:0"},
			wantErr:  true,
		},
		{
			name:     "target port exceeds 65535",
			forwards: map[string]string{"3306": "db:70000"},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTCPForwards(tc.forwards)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTCPForwards() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateProtocols(t *testing.T) {
	tests := []struct {
		name      string
		protocols []string
		wantErr   bool
	}{
		{
			name:      "valid single",
			protocols: []string{"HTTP/1.x"},
			wantErr:   false,
		},
		{
			name:      "valid all",
			protocols: []string{"HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "TCP"},
			wantErr:   false,
		},
		{
			name:      "invalid protocol",
			protocols: []string{"HTTP/1.x", "QUIC"},
			wantErr:   true,
		},
		{
			name:      "empty value",
			protocols: []string{""},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProtocols(tc.protocols)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateProtocols() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// mockTLSTransportForResend implements httputil.TLSTransport for testing.
type mockTLSTransportForResend struct {
	called     bool
	serverName string
}

func (m *mockTLSTransportForResend) TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	m.called = true
	m.serverName = serverName
	return conn, "http/1.1", nil
}

func TestUpgradeTLS_UsesProvidedTransport(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	mock := &mockTLSTransportForResend{}

	go func() {
		// upgradeTLS will call TLSConnect which will return the pipe conn.
		// The mock doesn't actually do TLS, just passes through.
		_, _ = upgradeTLS(context.Background(), client, "example.com:443", mock)
	}()

	// Give time for the goroutine to call upgradeTLS.
	time.Sleep(50 * time.Millisecond)

	if !mock.called {
		t.Error("TLSTransport.TLSConnect was not called")
	}
	if mock.serverName != "example.com" {
		t.Errorf("serverName = %q, want %q", mock.serverName, "example.com")
	}
}

func TestUpgradeTLS_NilTransportFallsBackToStandard(t *testing.T) {
	// With nil transport, upgradeTLS should fall back to StandardTransport.
	// We can't easily test the actual handshake without a TLS server,
	// but we verify it doesn't panic with nil transport.
	server, client := net.Pipe()
	defer server.Close()

	go func() {
		// This will fail the handshake because there's no TLS server on the pipe,
		// but it should not panic — it should return an error.
		_, err := upgradeTLS(context.Background(), client, "example.com:443", nil)
		if err == nil {
			t.Error("expected error for TLS handshake on plain pipe")
		}
	}()

	// Read some data from the server side to avoid blocking.
	buf := make([]byte, 1024)
	server.Read(buf)
	server.Close()
}
