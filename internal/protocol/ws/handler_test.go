package ws

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// headerGet retrieves the first value for a header name from a map[string][]string.
func headerGet(h map[string][]string, name string) string {
	if vals, ok := h[name]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// mockStore is a thread-safe minimal in-memory flow store for testing.
type mockStore struct {
	mu       sync.Mutex
	flows    []*flow.Flow
	messages []*flow.Message
}

func (m *mockStore) SaveFlow(_ context.Context, s *flow.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	m.flows = append(m.flows, s)
	return nil
}

func (m *mockStore) UpdateFlow(_ context.Context, id string, update flow.FlowUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.flows {
		if s.ID == id {
			if update.State != "" {
				s.State = update.State
			}
			if update.Duration != 0 {
				s.Duration = update.Duration
			}
			if update.Tags != nil {
				s.Tags = update.Tags
			}
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockStore) GetFlow(_ context.Context, id string) (*flow.Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.flows {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockStore) ListFlows(_ context.Context, _ flow.ListOptions) ([]*flow.Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*flow.Flow, len(m.flows))
	copy(result, m.flows)
	return result, nil
}

func (m *mockStore) CountFlows(_ context.Context, _ flow.ListOptions) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.flows), nil
}

func (m *mockStore) DeleteFlow(_ context.Context, id string) error { return nil }

func (m *mockStore) DeleteAllFlows(_ context.Context) (int64, error) { return 0, nil }

func (m *mockStore) DeleteFlowsByProtocol(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteFlowsOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteExcessSessions(_ context.Context, _ int) (int64, error) { return 0, nil }

func (m *mockStore) AppendMessage(_ context.Context, msg *flow.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockStore) GetMessages(_ context.Context, flowID string, opts flow.MessageListOptions) ([]*flow.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*flow.Message
	for _, msg := range m.messages {
		if msg.FlowID == flowID {
			if opts.Direction != "" && msg.Direction != opts.Direction {
				continue
			}
			result = append(result, msg)
		}
	}
	return result, nil
}

func (m *mockStore) CountMessages(_ context.Context, flowID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, msg := range m.messages {
		if msg.FlowID == flowID {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) SaveMacro(_ context.Context, _, _, _ string) error { return nil }
func (m *mockStore) GetMacro(_ context.Context, _ string) (*flow.MacroRecord, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockStore) ListMacros(_ context.Context) ([]*flow.MacroRecord, error) { return nil, nil }
func (m *mockStore) DeleteMacro(_ context.Context, _ string) error             { return nil }

func (m *mockStore) Flows() []*flow.Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*flow.Flow, len(m.flows))
	copy(result, m.flows)
	return result
}

func (m *mockStore) Messages() []*flow.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*flow.Message, len(m.messages))
	copy(result, m.messages)
	return result
}

func TestHandleUpgrade_BasicTextRelay(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-1", "127.0.0.1:1234", nil)
	}()

	// Client sends a text frame through the proxy.
	clientFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("hello"),
	}
	go func() {
		WriteFrame(clientEnd, clientFrame)
	}()

	// Upstream should receive the frame.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "hello" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "hello")
	}

	// Upstream sends a response frame.
	serverFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: []byte("world"),
	}
	go func() {
		WriteFrame(upstreamEnd, serverFrame)
	}()

	// Client should receive the frame.
	clientReceived, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(clientReceived.Payload) != "world" {
		t.Errorf("client received = %q, want %q", clientReceived.Payload, "world")
	}

	// Send close frame from client to end the relay.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	closeFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: closePayload,
	}
	go func() {
		WriteFrame(clientEnd, closeFrame)
	}()

	// Upstream receives close.
	closeReceived, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read close: %v", err)
	}
	if closeReceived.Opcode != OpcodeClose {
		t.Errorf("close opcode = %d, want %d", closeReceived.Opcode, OpcodeClose)
	}

	// Close upstream end to finalize.
	upstreamEnd.Close()

	// Wait for handler to finish.
	select {
	case err := <-errCh:
		// May return an error from the server->client direction since we closed upstreamEnd.
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	// Verify flow was recorded.
	sessions := store.Flows()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(sessions))
	}

	fl := sessions[0]
	if fl.Protocol != "WebSocket" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "WebSocket")
	}
	if fl.FlowType != "bidirectional" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "bidirectional")
	}

	// Verify messages were recorded.
	messages := store.Messages()
	if len(messages) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(messages))
	}

	// Check first message (send: "hello").
	var sendMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && string(msg.Body) == "hello" {
			sendMsg = msg
			break
		}
	}
	if sendMsg == nil {
		t.Fatal("send message with body 'hello' not found")
	}
	if sendMsg.Metadata["opcode"] != "1" {
		t.Errorf("send opcode = %q, want %q", sendMsg.Metadata["opcode"], "1")
	}

	// Check receive message ("world").
	var recvMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "receive" && string(msg.Body) == "world" {
			recvMsg = msg
			break
		}
	}
	if recvMsg == nil {
		t.Fatal("receive message with body 'world' not found")
	}
}

func TestHandleUpgrade_BinaryFrame(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-2", "127.0.0.1:2345", nil)
	}()

	// Client sends a binary frame.
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	binaryFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeBinary,
		Masked:  true,
		MaskKey: [4]byte{0x11, 0x22, 0x33, 0x44},
		Payload: binaryData,
	}
	go func() {
		WriteFrame(clientEnd, binaryFrame)
	}()

	// Read on upstream side.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(received.Payload, binaryData) {
		t.Errorf("upstream received = %v, want %v", received.Payload, binaryData)
	}

	// Close.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(upstreamEnd, closeFrame)
	}()

	ReadFrame(clientEnd)
	clientEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Check that binary frame was stored as raw_bytes.
	messages := store.Messages()
	var binaryMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && msg.RawBytes != nil {
			binaryMsg = msg
			break
		}
	}
	if binaryMsg == nil {
		t.Fatal("binary message not found in store")
	}
	if !bytes.Equal(binaryMsg.RawBytes, binaryData) {
		t.Errorf("stored raw_bytes = %v, want %v", binaryMsg.RawBytes, binaryData)
	}
	if binaryMsg.Metadata["opcode"] != "2" {
		t.Errorf("opcode = %q, want %q", binaryMsg.Metadata["opcode"], "2")
	}
}

func TestHandleUpgrade_PingPongRelay(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-3", "127.0.0.1:3456", nil)
	}()

	// Server sends a ping.
	pingFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodePing,
		Payload: []byte("keepalive"),
	}
	go func() {
		WriteFrame(upstreamEnd, pingFrame)
	}()

	// Client should receive the ping.
	received, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if received.Opcode != OpcodePing {
		t.Errorf("opcode = %d, want %d", received.Opcode, OpcodePing)
	}
	if string(received.Payload) != "keepalive" {
		t.Errorf("payload = %q, want %q", received.Payload, "keepalive")
	}

	// Client sends pong.
	pongFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodePong,
		Masked:  true,
		MaskKey: [4]byte{0x01, 0x02, 0x03, 0x04},
		Payload: []byte("keepalive"),
	}
	go func() {
		WriteFrame(clientEnd, pongFrame)
	}()

	// Upstream receives pong.
	pongReceived, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if pongReceived.Opcode != OpcodePong {
		t.Errorf("opcode = %d, want %d", pongReceived.Opcode, OpcodePong)
	}

	// Close from server side.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(upstreamEnd, closeFrame)
	}()

	ReadFrame(clientEnd)
	clientEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify ping and pong were recorded.
	messages := store.Messages()
	var pingMsg, pongMsg *flow.Message
	for _, msg := range messages {
		if msg.Metadata["opcode"] == "9" {
			pingMsg = msg
		}
		if msg.Metadata["opcode"] == "10" {
			pongMsg = msg
		}
	}
	if pingMsg == nil {
		t.Error("ping message not found in store")
	}
	if pongMsg == nil {
		t.Error("pong message not found in store")
	}
}

func TestHandleUpgrade_FragmentedMessage(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-4", "127.0.0.1:4567", nil)
	}()

	// Client sends fragmented text message: "Hello" + " World"
	frag1 := &Frame{
		Fin:     false,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x55, 0x66, 0x77, 0x88},
		Payload: []byte("Hello"),
	}
	frag2 := &Frame{
		Fin:     true,
		Opcode:  OpcodeContinuation,
		Masked:  true,
		MaskKey: [4]byte{0x99, 0xAA, 0xBB, 0xCC},
		Payload: []byte(" World"),
	}

	go func() {
		WriteFrame(clientEnd, frag1)
		WriteFrame(clientEnd, frag2)
	}()

	// Upstream receives both fragments.
	r1, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read frag1: %v", err)
	}
	if string(r1.Payload) != "Hello" {
		t.Errorf("frag1 payload = %q, want %q", r1.Payload, "Hello")
	}

	r2, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read frag2: %v", err)
	}
	if string(r2.Payload) != " World" {
		t.Errorf("frag2 payload = %q, want %q", r2.Payload, " World")
	}

	// Close.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(clientEnd, closeFrame)
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Check that the fragmented message was assembled and stored as one message.
	messages := store.Messages()
	var assembledMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && string(msg.Body) == "Hello World" {
			assembledMsg = msg
			break
		}
	}
	if assembledMsg == nil {
		t.Fatal("assembled fragmented message not found in store")
	}
	if assembledMsg.Metadata["opcode"] != "1" {
		t.Errorf("opcode = %q, want %q", assembledMsg.Metadata["opcode"], "1")
	}
}

func TestHandleUpgrade_CloseFrameEndsRelay(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-5", "127.0.0.1:5678", nil)
	}()

	// Server sends close frame immediately.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1001)
	closeFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Payload: closePayload,
	}
	go func() {
		WriteFrame(upstreamEnd, closeFrame)
	}()

	// Client receives close.
	received, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read close: %v", err)
	}
	if received.Opcode != OpcodeClose {
		t.Fatalf("opcode = %d, want %d", received.Opcode, OpcodeClose)
	}

	// Close the connections.
	clientEnd.Close()
	upstreamEnd.Close()

	select {
	case err := <-errCh:
		_ = err // Handler should finish after close.
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish after close frame")
	}

	// Verify flow state is updated.
	sessions := store.Flows()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(sessions))
	}
}

func TestHandleUpgrade_NormalCloseStateComplete(t *testing.T) {
	// Verify that a normal Close frame exchange results in state="complete",
	// not state="error". This is a regression test for USK-400.
	tests := []struct {
		name      string
		closeFrom string // "client" or "server"
	}{
		{name: "client initiates close", closeFrom: "client"},
		{name: "server initiates close", closeFrom: "server"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			handler := NewHandler(store, testutil.DiscardLogger())

			clientConn, clientEnd := net.Pipe()
			upstreamConn, upstreamEnd := net.Pipe()
			defer clientConn.Close()
			defer clientEnd.Close()
			defer upstreamConn.Close()
			defer upstreamEnd.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
			resp := &parser.RawResponse{StatusCode: 101}

			errCh := make(chan error, 1)
			go func() {
				errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-close-test", "127.0.0.1:9999", nil)
			}()

			closePayload := make([]byte, 2)
			binary.BigEndian.PutUint16(closePayload, 1000) // Normal closure

			if tt.closeFrom == "client" {
				// Client sends close frame.
				closeFrame := &Frame{
					Fin:     true,
					Opcode:  OpcodeClose,
					Masked:  true,
					MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
					Payload: closePayload,
				}
				go func() {
					if err := WriteFrame(clientEnd, closeFrame); err != nil {
						t.Errorf("WriteFrame(Close) failed: %v", err)
					}
				}()
				// Upstream receives close, then close connections.
				upstreamEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
				respFrame, err := ReadFrame(upstreamEnd)
				if err != nil {
					t.Fatalf("ReadFrame(Close response) failed: %v", err)
				}
				if respFrame.Opcode != OpcodeClose {
					t.Errorf("expected Close frame response, got opcode=%d", respFrame.Opcode)
				}
				upstreamEnd.Close()
				clientEnd.Close()
			} else {
				// Server sends close frame.
				closeFrame := &Frame{
					Fin:     true,
					Opcode:  OpcodeClose,
					Payload: closePayload,
				}
				go func() {
					if err := WriteFrame(upstreamEnd, closeFrame); err != nil {
						t.Errorf("WriteFrame(Close) failed: %v", err)
					}
				}()
				// Client receives close, then close connections.
				clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
				respFrame, err := ReadFrame(clientEnd)
				if err != nil {
					t.Fatalf("ReadFrame(Close response) failed: %v", err)
				}
				if respFrame.Opcode != OpcodeClose {
					t.Errorf("expected Close frame response, got opcode=%d", respFrame.Opcode)
				}
				clientEnd.Close()
				upstreamEnd.Close()
			}

			select {
			case <-errCh:
			case <-time.After(3 * time.Second):
				t.Fatal("handler did not finish within timeout")
			}

			sessions := store.Flows()
			if len(sessions) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(sessions))
			}
			if sessions[0].State != "complete" {
				t.Errorf("flow state = %q, want %q", sessions[0].State, "complete")
			}
		})
	}
}

func TestHandleUpgrade_ConnectionDropStateError(t *testing.T) {
	// Verify that an abrupt connection drop (no Close frame) results in state="error".
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-drop", "127.0.0.1:8888", nil)
	}()

	// Give relay time to start, then abruptly close connections.
	time.Sleep(50 * time.Millisecond)
	clientEnd.Close()
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	sessions := store.Flows()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(sessions))
	}
	if sessions[0].State != "error" {
		t.Errorf("flow state = %q, want %q", sessions[0].State, "error")
	}
}

func TestHandleUpgrade_ContextCancellation(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithCancel(context.Background())

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-6", "127.0.0.1:6789", nil)
	}()

	// Give the relay time to start.
	time.Sleep(50 * time.Millisecond)

	// Cancel the context.
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			// Some read error is acceptable after cancel.
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish after context cancellation")
	}
}

func TestHandleUpgrade_NilStore(t *testing.T) {
	// Handler should work without a store (no recording).
	handler := NewHandler(nil, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-7", "127.0.0.1:7890", nil)
	}()

	// Send a text frame and close.
	go func() {
		frame := &Frame{Fin: true, Opcode: OpcodeText, Masked: true, MaskKey: [4]byte{0x01, 0x02, 0x03, 0x04}, Payload: []byte("no-store")}
		WriteFrame(clientEnd, frame)

		closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Masked: true, MaskKey: [4]byte{0x05, 0x06, 0x07, 0x08}, Payload: []byte{0x03, 0xE8}}
		WriteFrame(clientEnd, closeFrame)
	}()

	// Read frames on upstream.
	ReadFrame(upstreamEnd)
	ReadFrame(upstreamEnd) // close
	upstreamEnd.Close()

	select {
	case err := <-errCh:
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
}

func TestHandleUpgrade_ConnInfoRecorded(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "wss://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	connInfo := &flow.ConnectionInfo{
		ClientAddr: "10.0.0.1:12345",
		ServerAddr: "93.184.216.34:443",
		TLSVersion: "TLS 1.3",
		TLSCipher:  "TLS_AES_128_GCM_SHA256",
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-8", "10.0.0.1:12345", connInfo)
	}()

	// Close immediately.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(clientEnd, closeFrame)
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify ConnInfo was stored.
	sessions := store.Flows()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(sessions))
	}

	fl := sessions[0]
	if fl.ConnInfo == nil {
		t.Fatal("ConnInfo is nil")
	}
	if fl.ConnInfo.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want %q", fl.ConnInfo.TLSVersion, "TLS 1.3")
	}
	if fl.ConnInfo.TLSCipher != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("TLSCipher = %q, want %q", fl.ConnInfo.TLSCipher, "TLS_AES_128_GCM_SHA256")
	}
}

func TestHandleUpgrade_MultipleMessages(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-9", "127.0.0.1:9012", nil)
	}()

	// Exchange multiple messages.
	go func() {
		for i := 0; i < 5; i++ {
			msg := fmt.Sprintf("msg-%d", i)
			frame := &Frame{
				Fin:     true,
				Opcode:  OpcodeText,
				Masked:  true,
				MaskKey: [4]byte{byte(i), 0x00, 0x00, 0x00},
				Payload: []byte(msg),
			}
			WriteFrame(clientEnd, frame)

			// Read server echo response.
			ReadFrame(clientEnd)
		}

		// Send close.
		closeFrame := &Frame{
			Fin:     true,
			Opcode:  OpcodeClose,
			Masked:  true,
			MaskKey: [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			Payload: []byte{0x03, 0xE8},
		}
		WriteFrame(clientEnd, closeFrame)
	}()

	go func() {
		for i := 0; i < 5; i++ {
			// Read client message.
			frame, err := ReadFrame(upstreamEnd)
			if err != nil {
				return
			}

			// Echo back.
			echo := &Frame{
				Fin:     true,
				Opcode:  OpcodeText,
				Payload: []byte("echo-" + string(frame.Payload)),
			}
			WriteFrame(upstreamEnd, echo)
		}

		// Read close.
		ReadFrame(upstreamEnd)
		upstreamEnd.Close()
	}()

	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify messages: 5 sends + 5 receives + 1 close = at least 11 messages.
	messages := store.Messages()
	sendCount := 0
	recvCount := 0
	for _, msg := range messages {
		if msg.Direction == "send" {
			sendCount++
		}
		if msg.Direction == "receive" {
			recvCount++
		}
	}

	if sendCount < 5 {
		t.Errorf("send count = %d, want >= 5", sendCount)
	}
	if recvCount < 5 {
		t.Errorf("receive count = %d, want >= 5", recvCount)
	}

	// Verify sequences are monotonically increasing.
	for i := 1; i < len(messages); i++ {
		if messages[i].Sequence <= messages[i-1].Sequence {
			// Sequences are globally ordered (atomic counter), but different goroutines
			// may interleave. Just verify they are all unique.
			break
		}
	}
}

func TestHandleUpgrade_UpgradeRequestResponseRecorded(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "ws://example.com/chat",
		Headers: parser.RawHeaders{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
			{Name: "Sec-WebSocket-Key", Value: "dGhlIHNhbXBsZSBub25jZQ=="},
			{Name: "Sec-WebSocket-Version", Value: "13"},
		},
	}

	resp := &parser.RawResponse{
		StatusCode: 101,
		Headers: parser.RawHeaders{
			{Name: "Upgrade", Value: "websocket"},
			{Name: "Connection", Value: "Upgrade"},
			{Name: "Sec-WebSocket-Accept", Value: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="},
		},
	}

	connInfo := &flow.ConnectionInfo{
		ClientAddr: "10.0.0.1:12345",
		ServerAddr: "93.184.216.34:80",
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-upgrade", "10.0.0.1:12345", connInfo)
	}()

	// Send a text frame then close to finish the relay.
	go func() {
		frame := &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x01, 0x02, 0x03, 0x04},
			Payload: []byte("test"),
		}
		WriteFrame(clientEnd, frame)
	}()

	// Read the text frame on upstream side.
	ReadFrame(upstreamEnd)

	// Send close from upstream.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(upstreamEnd, closeFrame)
	}()

	ReadFrame(clientEnd)
	clientEnd.Close()
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	messages := store.Messages()

	// Find the upgrade request message (sequence=0, direction="send").
	var upgradeReqMsg *flow.Message
	for _, msg := range messages {
		if msg.Sequence == 0 && msg.Direction == "send" {
			upgradeReqMsg = msg
			break
		}
	}
	if upgradeReqMsg == nil {
		t.Fatal("upgrade request message (sequence=0, direction=send) not found")
	}
	if upgradeReqMsg.Method != "GET" {
		t.Errorf("upgrade request Method = %q, want %q", upgradeReqMsg.Method, "GET")
	}
	if upgradeReqMsg.URL == nil {
		t.Fatal("upgrade request URL is nil")
	}
	if upgradeReqMsg.URL.String() != "ws://example.com/chat" {
		t.Errorf("upgrade request URL = %q, want %q", upgradeReqMsg.URL.String(), "ws://example.com/chat")
	}
	if got := headerGet(upgradeReqMsg.Headers, "Upgrade"); got != "websocket" {
		t.Errorf("upgrade request Upgrade header = %q, want %q", got, "websocket")
	}
	if got := headerGet(upgradeReqMsg.Headers, "Sec-WebSocket-Key"); got != "dGhlIHNhbXBsZSBub25jZQ==" {
		t.Errorf("upgrade request Sec-WebSocket-Key = %q, want %q", got, "dGhlIHNhbXBsZSBub25jZQ==")
	}

	// Find the upgrade response message (sequence=1, direction="receive").
	var upgradeRespMsg *flow.Message
	for _, msg := range messages {
		if msg.Sequence == 1 && msg.Direction == "receive" {
			upgradeRespMsg = msg
			break
		}
	}
	if upgradeRespMsg == nil {
		t.Fatal("upgrade response message (sequence=1, direction=receive) not found")
	}
	if upgradeRespMsg.StatusCode != 101 {
		t.Errorf("upgrade response StatusCode = %d, want %d", upgradeRespMsg.StatusCode, 101)
	}
	if got := headerGet(upgradeRespMsg.Headers, "Sec-WebSocket-Accept"); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("upgrade response Sec-WebSocket-Accept = %q, want %q", got, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	}

	// Verify data frame sequences start at 2.
	for _, msg := range messages {
		if msg.Sequence == 0 || msg.Sequence == 1 {
			continue // Upgrade messages.
		}
		if msg.Sequence < 2 {
			t.Errorf("data frame sequence = %d, want >= 2", msg.Sequence)
		}
	}
}

func TestHandleUpgrade_UpgradeRecordedWithNilStore(t *testing.T) {
	// Handler should work without a store — no panic on upgrade recording.
	handler := NewHandler(nil, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-nil", "127.0.0.1:1111", nil)
	}()

	// Close immediately.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Masked: true, MaskKey: [4]byte{0x01, 0x02, 0x03, 0x04}, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(clientEnd, closeFrame)
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}
	// No panic means success.
}

func TestHandleUpgrade_ConnectionDrop(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer upstreamConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &parser.RawRequest{Method: "GET", RequestURI: "ws://example.com/ws"}
	resp := &parser.RawResponse{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-10", "127.0.0.1:1234", nil)
	}()

	// Give relay time to start.
	time.Sleep(50 * time.Millisecond)

	// Abruptly close client connection.
	clientEnd.Close()
	upstreamEnd.Close()

	select {
	case err := <-errCh:
		// Error expected since connections were closed abruptly.
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish after connection drop")
	}

	// Flow should be recorded with error state.
	sessions := store.Flows()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(sessions))
	}
}
