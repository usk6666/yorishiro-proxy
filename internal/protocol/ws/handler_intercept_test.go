package ws

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// setupInterceptHandler creates a Handler with InterceptEngine and InterceptQueue
// configured for testing.
func setupInterceptHandler(t *testing.T, rules []intercept.Rule) (*Handler, *intercept.Engine, *intercept.Queue) {
	t.Helper()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine := intercept.NewEngine()
	for _, r := range rules {
		if err := engine.AddRule(r); err != nil {
			t.Fatalf("add rule: %v", err)
		}
	}
	queue := intercept.NewQueue()

	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	return handler, engine, queue
}

// sendCloseFrame writes a Close frame on the given conn.
func sendCloseFrame(conn net.Conn) {
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	WriteFrame(conn, &Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: closePayload,
	})
}

func TestInterceptFrame_HoldAndRelease(t *testing.T) {
	rule := intercept.Rule{
		ID:        "ws-rule-1",
		Enabled:   true,
		Direction: "both",
		Conditions: intercept.Conditions{
			UpgradeURLPattern: ".*",
		},
	}
	handler, _, queue := setupInterceptHandler(t, []intercept.Rule{rule})

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

	// Client sends a text frame.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("intercepted-hello"),
		})
	}()

	// Wait for the frame to be enqueued.
	var items []*intercept.InterceptedRequest
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		items = queue.List()
		if len(items) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(items) == 0 {
		t.Fatal("expected intercepted frame in queue")
	}

	item := items[0]
	if item.Phase != intercept.PhaseWebSocketFrame {
		t.Errorf("phase = %q, want %q", item.Phase, intercept.PhaseWebSocketFrame)
	}
	if string(item.Body) != "intercepted-hello" {
		t.Errorf("body = %q, want %q", item.Body, "intercepted-hello")
	}
	if item.WSDirection != "client_to_server" {
		t.Errorf("ws_direction = %q, want %q", item.WSDirection, "client_to_server")
	}

	// Release the frame.
	if err := queue.Respond(item.ID, intercept.InterceptAction{Type: intercept.ActionRelease}); err != nil {
		t.Fatalf("respond: %v", err)
	}

	// Upstream should receive the released frame.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "intercepted-hello" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "intercepted-hello")
	}

	// Clean up by sending close frame.
	go sendCloseFrame(clientEnd)
	ReadFrame(upstreamEnd) // consume close frame
}

func TestInterceptFrame_HoldAndModify(t *testing.T) {
	rule := intercept.Rule{
		ID:        "ws-rule-mod",
		Enabled:   true,
		Direction: "both",
		Conditions: intercept.Conditions{
			UpgradeURLPattern: ".*",
		},
	}
	handler, _, queue := setupInterceptHandler(t, []intercept.Rule{rule})

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

	go func() {
		handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-1", "127.0.0.1:1234", nil)
	}()

	// Client sends a text frame.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("original"),
		})
	}()

	// Wait for the frame to be enqueued.
	var items []*intercept.InterceptedRequest
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		items = queue.List()
		if len(items) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(items) == 0 {
		t.Fatal("expected intercepted frame in queue")
	}

	// Modify and forward.
	modified := "modified-payload"
	if err := queue.Respond(items[0].ID, intercept.InterceptAction{
		Type:         intercept.ActionModifyAndForward,
		OverrideBody: &modified,
	}); err != nil {
		t.Fatalf("respond: %v", err)
	}

	// Upstream should receive the modified frame.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "modified-payload" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "modified-payload")
	}

	go sendCloseFrame(clientEnd)
	ReadFrame(upstreamEnd)
}

func TestInterceptFrame_HoldAndDrop(t *testing.T) {
	rule := intercept.Rule{
		ID:        "ws-rule-drop",
		Enabled:   true,
		Direction: "request",
		Conditions: intercept.Conditions{
			UpgradeURLPattern: ".*",
		},
	}
	handler, _, queue := setupInterceptHandler(t, []intercept.Rule{rule})

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

	go func() {
		handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-1", "127.0.0.1:1234", nil)
	}()

	// Client sends a text frame.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("drop-me"),
		})
	}()

	// Wait for the frame to be enqueued.
	var items []*intercept.InterceptedRequest
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		items = queue.List()
		if len(items) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(items) == 0 {
		t.Fatal("expected intercepted frame in queue")
	}

	// Drop the frame.
	if err := queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop}); err != nil {
		t.Fatalf("respond: %v", err)
	}

	// Send a second frame that should also be intercepted.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("second-frame"),
		})
	}()

	// Wait for the second frame to be intercepted.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		items = queue.List()
		if len(items) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(items) == 0 {
		t.Fatal("expected second intercepted frame in queue")
	}

	// Release the second frame — this verifies that the first dropped frame
	// did not block subsequent frames.
	if err := queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease}); err != nil {
		t.Fatalf("respond: %v", err)
	}

	// Upstream should receive only the second frame.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "second-frame" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "second-frame")
	}

	go sendCloseFrame(clientEnd)
	ReadFrame(upstreamEnd)
}

func TestInterceptFrame_ReverseDirectionNotHeld(t *testing.T) {
	// Rule only matches client_to_server (request direction).
	rule := intercept.Rule{
		ID:        "ws-rule-send-only",
		Enabled:   true,
		Direction: "request",
		Conditions: intercept.Conditions{
			UpgradeURLPattern: ".*",
		},
	}
	handler, _, queue := setupInterceptHandler(t, []intercept.Rule{rule})

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

	go func() {
		handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-1", "127.0.0.1:1234", nil)
	}()

	// Server sends a text frame (reverse direction, should NOT be intercepted).
	go func() {
		WriteFrame(upstreamEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Payload: []byte("server-msg"),
		})
	}()

	// Client should receive the frame immediately without intercept hold.
	clientReceived, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(clientReceived.Payload) != "server-msg" {
		t.Errorf("client received = %q, want %q", clientReceived.Payload, "server-msg")
	}

	// Verify nothing was queued.
	items := queue.List()
	if len(items) != 0 {
		t.Errorf("expected 0 queued items, got %d", len(items))
	}

	go sendCloseFrame(upstreamEnd)
	ReadFrame(clientEnd)
}

func TestInterceptFrame_NoMatchPassesThrough(t *testing.T) {
	// Rule that won't match the URL.
	rule := intercept.Rule{
		ID:        "ws-rule-nomatch",
		Enabled:   true,
		Direction: "both",
		Conditions: intercept.Conditions{
			UpgradeURLPattern: "^ws://other\\.com/.*$",
		},
	}
	handler, _, queue := setupInterceptHandler(t, []intercept.Rule{rule})

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

	go func() {
		handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-1", "127.0.0.1:1234", nil)
	}()

	// Client sends a text frame — should pass through without intercept.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("pass-through"),
		})
	}()

	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "pass-through" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "pass-through")
	}

	// Verify nothing was queued.
	items := queue.List()
	if len(items) != 0 {
		t.Errorf("expected 0 queued items, got %d", len(items))
	}

	go sendCloseFrame(clientEnd)
	ReadFrame(upstreamEnd)
}

func TestInterceptFrame_QueueCapacityAutoRelease(t *testing.T) {
	rule := intercept.Rule{
		ID:        "ws-rule-cap",
		Enabled:   true,
		Direction: "both",
		Conditions: intercept.Conditions{
			UpgradeURLPattern: ".*",
		},
	}
	handler, _, queue := setupInterceptHandler(t, []intercept.Rule{rule})

	// Set max queue items to 1 so that the second enqueue triggers auto-release.
	queue.SetMaxItems(1)

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

	go func() {
		handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-1", "127.0.0.1:1234", nil)
	}()

	// Fill the queue with one item from another source.
	_, otherCh := queue.EnqueueWebSocketFrame(
		int(OpcodeText), "client_to_server", "other-flow", "ws://other.com/ws", 0, []byte("filler"), []string{"rule-x"},
	)
	// The otherCh should not be auto-released since queue had capacity.
	select {
	case <-otherCh:
		// This is the filler item, might have been auto-released if capacity was already hit.
	default:
		// Good, item is held.
	}

	// Now send a frame — since queue is at capacity, it should be auto-released.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("auto-released"),
		})
	}()

	// Upstream should receive the frame (auto-released due to queue capacity).
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "auto-released" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "auto-released")
	}

	go sendCloseFrame(clientEnd)
	ReadFrame(upstreamEnd)
}
