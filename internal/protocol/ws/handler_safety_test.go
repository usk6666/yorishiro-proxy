package ws

import (
	"context"
	"encoding/binary"
	"net"
	gohttp "net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newBlockEngine creates a safety engine that blocks patterns matching the
// given regex in request bodies.
func newBlockEngine(t *testing.T, pattern string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "test-block",
				Name:    "test block rule",
				Pattern: pattern,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create block engine: %v", err)
	}
	return engine
}

// newLogOnlyEngine creates a safety engine that logs (but does not block)
// patterns matching the given regex.
func newLogOnlyEngine(t *testing.T, pattern string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "test-log-only",
				Name:    "test log_only rule",
				Pattern: pattern,
				Targets: []string{"body"},
				Action:  "log_only",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create log_only engine: %v", err)
	}
	return engine
}

// newOutputMaskEngine creates a safety engine with an output mask rule.
func newOutputMaskEngine(t *testing.T, pattern, replacement string) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				ID:          "test-mask",
				Name:        "test mask rule",
				Pattern:     pattern,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: replacement,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create output mask engine: %v", err)
	}
	return engine
}

// runWSRelay starts the WS handler relay and returns a function to read received frames
// from the other end. The caller must send a Close frame to terminate the relay.
func runWSRelay(t *testing.T, handler *Handler, clientEnd, upstreamEnd net.Conn) chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101}

	errCh := make(chan error, 1)
	go func() {
		defer cancel()
		errCh <- handler.HandleUpgrade(ctx, clientEnd, upstreamEnd, nil, req, resp, "conn-test", "127.0.0.1:1234", nil)
	}()
	return errCh
}

// writeCloseFrame writes a Close frame to end the relay.
// It does not use t.Fatal so it is safe to call from goroutines.
func writeCloseFrame(conn net.Conn) error {
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	closeFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: closePayload,
	}
	return WriteFrame(conn, closeFrame)
}

func TestSafetyFilter_TextFrame_BlockedByInputFilter(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// Client sends a text frame with destructive SQL.
	maliciousFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("DROP TABLE users"),
	}
	if err := WriteFrame(clientEnd, maliciousFrame); err != nil {
		t.Fatalf("failed to write malicious frame: %v", err)
	}

	// Send a benign frame to confirm the connection is still alive.
	benignFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("SELECT * FROM users"),
	}
	go func() {
		WriteFrame(clientEnd, benignFrame)
	}()

	// Upstream should receive the benign frame (not the malicious one).
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "SELECT * FROM users" {
		t.Errorf("upstream received = %q, want benign message", received.Payload)
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd) // consume close frame
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	// Verify blocked frame was recorded with safety metadata.
	messages := store.Messages()
	var blockedMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && msg.Metadata["safety_blocked"] == "true" {
			blockedMsg = msg
			break
		}
	}
	if blockedMsg == nil {
		t.Fatal("expected a blocked message with safety_blocked metadata")
	}
	if blockedMsg.Metadata["safety_rule_id"] != "test-block" {
		t.Errorf("safety_rule_id = %q, want %q", blockedMsg.Metadata["safety_rule_id"], "test-block")
	}
	if blockedMsg.Metadata["safety_matched_on"] != "DROP TABLE" {
		t.Errorf("safety_matched_on = %q, want %q", blockedMsg.Metadata["safety_matched_on"], "DROP TABLE")
	}
	if string(blockedMsg.Body) != "DROP TABLE users" {
		t.Errorf("blocked msg body = %q, want %q", blockedMsg.Body, "DROP TABLE users")
	}
}

func TestSafetyFilter_TextFrame_PIIMasking(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newOutputMaskEngine(t, `\d{3}-\d{2}-\d{4}`, "***-**-****"))

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// Upstream sends a text frame with PII (SSN-like pattern).
	piiFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Payload: []byte("SSN: 123-45-6789"),
	}
	go func() {
		WriteFrame(upstreamEnd, piiFrame)
	}()

	// Client should receive the masked frame.
	received, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(received.Payload) != "SSN: ***-**-****" {
		t.Errorf("client received = %q, want masked SSN", received.Payload)
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd) // consume close frame
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	// Verify the raw (unmasked) data was recorded in the flow store.
	messages := store.Messages()
	var recvMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "receive" && len(msg.Body) > 0 {
			recvMsg = msg
			break
		}
	}
	if recvMsg == nil {
		t.Fatal("expected a receive message")
	}
	if string(recvMsg.Body) != "SSN: 123-45-6789" {
		t.Errorf("recorded body = %q, want raw unmasked data", recvMsg.Body)
	}
}

func TestSafetyFilter_BinaryFrame_Skipped(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// Client sends a binary frame with destructive SQL content.
	// Binary frames should NOT be filtered.
	binaryFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeBinary,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("DROP TABLE users"),
	}
	go func() {
		WriteFrame(clientEnd, binaryFrame)
	}()

	// Upstream should receive the binary frame unmodified.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "DROP TABLE users" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "DROP TABLE users")
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd) // consume close frame
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	// Verify no safety metadata on recorded messages.
	messages := store.Messages()
	for _, msg := range messages {
		if msg.Metadata["safety_blocked"] == "true" {
			t.Error("binary frame should not have safety_blocked metadata")
		}
	}
}

func TestSafetyFilter_LogOnly_ForwardsAndRecords(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newLogOnlyEngine(t, `DROP\s+TABLE`))

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// Client sends a text frame with destructive SQL.
	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("DROP TABLE users"),
	}
	go func() {
		WriteFrame(clientEnd, frame)
	}()

	// In log_only mode, frame should be forwarded.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "DROP TABLE users" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "DROP TABLE users")
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd) // consume close frame
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	// Verify safety_logged metadata was recorded.
	messages := store.Messages()
	var loggedMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && msg.Metadata["safety_logged"] == "true" {
			loggedMsg = msg
			break
		}
	}
	if loggedMsg == nil {
		t.Fatal("expected a message with safety_logged metadata")
	}
	if loggedMsg.Metadata["safety_rule_id"] != "test-log-only" {
		t.Errorf("safety_rule_id = %q, want %q", loggedMsg.Metadata["safety_rule_id"], "test-log-only")
	}
	if loggedMsg.Metadata["safety_matched_on"] != "DROP TABLE" {
		t.Errorf("safety_matched_on = %q, want %q", loggedMsg.Metadata["safety_matched_on"], "DROP TABLE")
	}
}

func TestSafetyFilter_NoEngine_PassesThrough(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// No safety engine set.

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// Client sends a text frame that would match a safety rule.
	frame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("DROP TABLE users"),
	}
	go func() {
		WriteFrame(clientEnd, frame)
	}()

	// Without engine, frame should pass through.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "DROP TABLE users" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "DROP TABLE users")
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd) // consume close frame
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}
}

func TestSafetyFilter_FragmentedTextFrame(t *testing.T) {
	// Safety filter is applied per-frame, so each fragment is checked individually.
	// This test verifies that a fragmented text message passes through when
	// individual fragments do not match any safety rule.
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// Send first fragment (text, not FIN) with benign content.
	frag1 := &Frame{
		Fin:     false,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("hello "),
	}
	go func() {
		WriteFrame(clientEnd, frag1)
	}()

	// Upstream should receive the first fragment (benign, not blocked).
	received1, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read frag1: %v", err)
	}
	if string(received1.Payload) != "hello " {
		t.Errorf("frag1 = %q, want %q", received1.Payload, "hello ")
	}

	// Send continuation frame (FIN) with benign content.
	frag2 := &Frame{
		Fin:     true,
		Opcode:  OpcodeContinuation,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("world"),
	}
	go func() {
		WriteFrame(clientEnd, frag2)
	}()

	// Upstream should receive the continuation frame.
	received2, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read frag2: %v", err)
	}
	if string(received2.Payload) != "world" {
		t.Errorf("frag2 = %q, want %q", received2.Payload, "world")
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd) // consume close frame
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}
}

func TestSafetyFilter_InputAndOutputCombined(t *testing.T) {
	// Test that both input (block) and output (mask) filters work together.
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "block-sql",
				Name:    "block destructive SQL",
				Pattern: `DROP\s+TABLE`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
		OutputRules: []safety.RuleConfig{
			{
				ID:          "mask-ssn",
				Name:        "mask SSN",
				Pattern:     `\d{3}-\d{2}-\d{4}`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "***-**-****",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// 1. Client sends benign text — should pass through.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin: true, Opcode: OpcodeText, Masked: true,
			MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello"),
		})
	}()
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "hello" {
		t.Errorf("upstream = %q, want %q", received.Payload, "hello")
	}

	// 2. Upstream responds with PII — should be masked to client.
	go func() {
		WriteFrame(upstreamEnd, &Frame{
			Fin: true, Opcode: OpcodeText, Payload: []byte("SSN: 123-45-6789"),
		})
	}()
	clientReceived, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(clientReceived.Payload) != "SSN: ***-**-****" {
		t.Errorf("client = %q, want masked", clientReceived.Payload)
	}

	// 3. Client sends malicious SQL — should be blocked.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin: true, Opcode: OpcodeText, Masked: true,
			MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("DROP TABLE foo"),
		})
	}()

	// 4. Send another benign message to verify connection is alive.
	go func() {
		// Small delay to ensure ordering.
		time.Sleep(50 * time.Millisecond)
		WriteFrame(clientEnd, &Frame{
			Fin: true, Opcode: OpcodeText, Masked: true,
			MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("benign"),
		})
	}()

	received2, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read2: %v", err)
	}
	if string(received2.Payload) != "benign" {
		t.Errorf("upstream2 = %q, want %q", received2.Payload, "benign")
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	// Verify blocked message is recorded with metadata.
	messages := store.Messages()
	var blocked *flow.Message
	for _, msg := range messages {
		if msg.Metadata["safety_blocked"] == "true" {
			blocked = msg
			break
		}
	}
	if blocked == nil {
		t.Fatal("expected a blocked message")
	}
	if blocked.Metadata["safety_rule_id"] != "block-sql" {
		t.Errorf("safety_rule_id = %q, want %q", blocked.Metadata["safety_rule_id"], "block-sql")
	}
}

func TestSafetyFilter_BlockedFragmentedTextFrame_DropsContinuation(t *testing.T) {
	// When a non-FIN text frame is blocked by the safety filter, subsequent
	// continuation frames must also be dropped to prevent protocol violation
	// (upstream would receive continuations without the initial text frame).
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetSafetyEngine(newBlockEngine(t, `DROP\s+TABLE`))

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	errCh := runWSRelay(t, handler, clientConn, upstreamConn)

	// Send non-FIN text frame with blocked content (start of fragmented message).
	frag1 := &Frame{
		Fin:     false,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("DROP TABLE users"),
	}
	if err := WriteFrame(clientEnd, frag1); err != nil {
		t.Fatalf("failed to write frag1: %v", err)
	}

	// Send continuation frame (should also be dropped).
	contFrame := &Frame{
		Fin:     false,
		Opcode:  OpcodeContinuation,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte(" more data"),
	}
	if err := WriteFrame(clientEnd, contFrame); err != nil {
		t.Fatalf("failed to write continuation: %v", err)
	}

	// Send final continuation frame with FIN (should also be dropped, resetting state).
	finalContFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeContinuation,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte(" end"),
	}
	if err := WriteFrame(clientEnd, finalContFrame); err != nil {
		t.Fatalf("failed to write final continuation: %v", err)
	}

	// Send a benign non-fragmented frame to verify connection is alive and
	// the dropping state was properly reset.
	go func() {
		WriteFrame(clientEnd, &Frame{
			Fin:     true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
			Payload: []byte("SELECT 1"),
		})
	}()

	// Upstream should only receive the benign frame, nothing else.
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(received.Payload) != "SELECT 1" {
		t.Errorf("upstream received = %q, want %q", received.Payload, "SELECT 1")
	}

	// Close the relay.
	go writeCloseFrame(clientEnd)
	_, _ = ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish within timeout")
	}

	// Verify the blocked initial frame was recorded with safety metadata.
	messages := store.Messages()
	var blockedMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && msg.Metadata["safety_blocked"] == "true" {
			blockedMsg = msg
			break
		}
	}
	if blockedMsg == nil {
		t.Fatal("expected a blocked message with safety_blocked metadata")
	}
	if string(blockedMsg.Body) != "DROP TABLE users" {
		t.Errorf("blocked msg body = %q, want %q", blockedMsg.Body, "DROP TABLE users")
	}
}
