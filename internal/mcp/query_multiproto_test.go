package mcp

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// seedStreamingSession creates a streaming flow with multiple messages for testing.
func seedStreamingSession(t *testing.T, store flow.Store, id, protocol, sessionType string, msgCount int, metadata map[string]string) {
	t.Helper()
	ctx := context.Background()

	fl := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  500 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow(%s): %v", id, err)
	}

	for i := 0; i < msgCount; i++ {
		dir := "send"
		if i%2 == 1 {
			dir = "receive"
		}
		msg := &flow.Flow{
			ID:        fmt.Sprintf("%s-msg-%d", id, i),
			StreamID:  id,
			Sequence:  i,
			Direction: dir,
			Timestamp: time.Now().UTC(),
			Body:      []byte(fmt.Sprintf("message-%d", i)),
			Metadata:  metadata,
		}
		if err := store.SaveFlow(ctx, msg); err != nil {
			t.Fatalf("AppendMessage(%d): %v", i, err)
		}
	}
}

// --- Test: sessions with protocol filter for multi-protocol ---

func TestQuery_Sessions_FilterByProtocol_WebSocket(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "http-1", "http", "GET", "https://example.com", 200)
	seedStreamingSession(t, store, "ws-1", "ws", "bidirectional", 4, map[string]string{"opcode": "1"})

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Protocol: "ws"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].Protocol != "ws" {
		t.Errorf("protocol = %q, want ws", out.Flows[0].Protocol)
	}
}

func TestQuery_Sessions_FilterByProtocol_TCP(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "http-1", "http", "GET", "https://example.com", 200)
	seedStreamingSession(t, store, "tcp-1", "raw", "bidirectional", 4, nil)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Protocol: "raw"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].Protocol != "raw" {
		t.Errorf("protocol = %q, want raw", out.Flows[0].Protocol)
	}
}

func TestQuery_Sessions_FilterByProtocol_GRPC(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "http-1", "http", "GET", "https://example.com", 200)
	seedStreamingSession(t, store, "grpc-1", "grpc", "unary", 2, map[string]string{"service": "UserService", "method": "GetUser", "grpc_status": "0"})

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Protocol: "grpc"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].Protocol != "grpc" {
		t.Errorf("protocol = %q, want grpc", out.Flows[0].Protocol)
	}
}

// --- Test: protocol summary in sessions ---

func TestQuery_Sessions_ProtocolSummary_WebSocket(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedStreamingSession(t, store, "ws-1", "ws", "bidirectional", 3, map[string]string{"opcode": "1"})

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	summary := out.Flows[0].ProtocolSummary
	if summary == nil {
		t.Fatal("protocol_summary should not be nil for WebSocket")
	}
	if summary["message_count"] != "3" {
		t.Errorf("message_count = %q, want 3", summary["message_count"])
	}
}

func TestQuery_Sessions_ProtocolSummary_TCP(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Stream{
		ID:        "tcp-1",
		Protocol:  "raw",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &flow.Flow{
		ID:        "tcp-1-send",
		StreamID:  "tcp-1",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("hello"),
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	recvMsg := &flow.Flow{
		ID:        "tcp-1-recv",
		StreamID:  "tcp-1",
		Sequence:  1,
		Direction: "receive",
		Timestamp: time.Now().UTC(),
		Body:      []byte("world!"),
	}
	if err := store.SaveFlow(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	summary := out.Flows[0].ProtocolSummary
	if summary == nil {
		t.Fatal("protocol_summary should not be nil for TCP")
	}
	if summary["send_bytes"] != "5" {
		t.Errorf("send_bytes = %q, want 5", summary["send_bytes"])
	}
	if summary["receive_bytes"] != "6" {
		t.Errorf("receive_bytes = %q, want 6", summary["receive_bytes"])
	}
}

func TestQuery_Sessions_ProtocolSummary_GRPC(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Stream{
		ID:        "grpc-1",
		Protocol:  "grpc",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	parsedURL, _ := url.Parse("https://example.com/pkg.UserService/GetUser")
	sendMsg := &flow.Flow{
		ID:        "grpc-1-send",
		StreamID:  "grpc-1",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       parsedURL,
		Body:      []byte("grpc-request"),
		Metadata:  map[string]string{"service": "UserService", "method": "GetUser"},
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	recvMsg := &flow.Flow{
		ID:        "grpc-1-recv",
		StreamID:  "grpc-1",
		Sequence:  1,
		Direction: "receive",
		Timestamp: time.Now().UTC(),
		Body:      []byte("grpc-response"),
		Metadata:  map[string]string{"grpc_status": "0"},
	}
	if err := store.SaveFlow(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	summary := out.Flows[0].ProtocolSummary
	if summary == nil {
		t.Fatal("protocol_summary should not be nil for gRPC")
	}
	if summary["service"] != "UserService" {
		t.Errorf("service = %q, want UserService", summary["service"])
	}
	if summary["method"] != "GetUser" {
		t.Errorf("method = %q, want GetUser", summary["method"])
	}
	if summary["grpc_status"] != "0" {
		t.Errorf("grpc_status = %q, want 0", summary["grpc_status"])
	}
	if summary["grpc_status_name"] != "OK" {
		t.Errorf("grpc_status_name = %q, want OK", summary["grpc_status_name"])
	}
}

// --- Test: flow resource for streaming flows ---

func TestQuery_Session_StreamingPreview(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedStreamingSession(t, store, "ws-detail", "ws", "bidirectional", 15, map[string]string{"opcode": "1"})

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "ws-detail",
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	if out.ID != "ws-detail" {
		t.Errorf("id = %q, want ws-detail", out.ID)
	}
	if out.MessageCount != 15 {
		t.Errorf("message_count = %d, want 15", out.MessageCount)
	}
	// Preview should be limited to 10 messages.
	if len(out.MessagePreview) != 10 {
		t.Errorf("message_preview len = %d, want 10", len(out.MessagePreview))
	}
	// Verify metadata is included in preview.
	if out.MessagePreview[0].Metadata == nil {
		t.Error("preview[0].metadata should not be nil")
	}
	if out.MessagePreview[0].Metadata["opcode"] != "1" {
		t.Errorf("preview[0].metadata.opcode = %q, want 1", out.MessagePreview[0].Metadata["opcode"])
	}
	// Protocol summary should be present.
	if out.ProtocolSummary == nil {
		t.Error("protocol_summary should not be nil")
	}
}

func TestQuery_Session_UnaryNoPreview(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "http-detail", "HTTPS", "GET", "https://example.com/api", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "http-detail",
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	// Unary sessions should NOT have message_preview.
	if out.MessagePreview != nil {
		t.Errorf("message_preview should be nil for unary sessions, got %d entries", len(out.MessagePreview))
	}
}

func TestQuery_Session_StreamingPreview_FewMessages(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedStreamingSession(t, store, "ws-small", "WebSocket", "bidirectional", 3, map[string]string{"opcode": "1"})

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "ws-small",
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	if out.MessageCount != 3 {
		t.Errorf("message_count = %d, want 3", out.MessageCount)
	}
	// Preview should include all messages when less than 10.
	if len(out.MessagePreview) != 3 {
		t.Errorf("message_preview len = %d, want 3", len(out.MessagePreview))
	}
}

// --- Test: messages with direction filter ---

func TestQuery_Messages_DirectionFilter_Send(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedStreamingSession(t, store, "ws-msgs", "WebSocket", "bidirectional", 6, map[string]string{"opcode": "1"})

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "ws-msgs",
		Filter:   &queryFilter{Direction: "send"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	// 6 messages total, alternating send/receive (0,2,4 are send)
	if out.Count != 3 {
		t.Errorf("count = %d, want 3", out.Count)
	}
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}
	for _, msg := range out.Messages {
		if msg.Direction != "send" {
			t.Errorf("message direction = %q, want send", msg.Direction)
		}
	}
}

func TestQuery_Messages_DirectionFilter_Receive(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedStreamingSession(t, store, "ws-msgs", "WebSocket", "bidirectional", 6, map[string]string{"opcode": "1"})

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "ws-msgs",
		Filter:   &queryFilter{Direction: "receive"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	// 6 messages total, alternating send/receive (1,3,5 are receive)
	if out.Count != 3 {
		t.Errorf("count = %d, want 3", out.Count)
	}
	for _, msg := range out.Messages {
		if msg.Direction != "receive" {
			t.Errorf("message direction = %q, want receive", msg.Direction)
		}
	}
}

func TestQuery_Messages_DirectionFilter_Invalid(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedStreamingSession(t, store, "ws-msgs", "WebSocket", "bidirectional", 4, nil)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "ws-msgs",
		Filter:   &queryFilter{Direction: "invalid"},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for invalid direction")
	}
}

// --- Test: messages with metadata ---

func TestQuery_Messages_Metadata(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Stream{
		ID:        "ws-meta",
		Protocol:  "WebSocket",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	msg := &flow.Flow{
		ID:        "ws-meta-msg-0",
		StreamID:  "ws-meta",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("hello"),
		Metadata:  map[string]string{"opcode": "1"},
	}
	if err := store.SaveFlow(ctx, msg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "ws-meta",
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	if out.Messages[0].Metadata == nil {
		t.Fatal("metadata should not be nil")
	}
	if out.Messages[0].Metadata["opcode"] != "1" {
		t.Errorf("metadata.opcode = %q, want 1", out.Messages[0].Metadata["opcode"])
	}
}

func TestQuery_Messages_GRPC_Metadata(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Stream{
		ID:        "grpc-meta",
		Protocol:  "gRPC",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &flow.Flow{
		ID:        "grpc-meta-send",
		StreamID:  "grpc-meta",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("grpc-body"),
		Metadata:  map[string]string{"service": "UserService", "method": "GetUser", "grpc_encoding": "identity"},
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "grpc-meta",
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	meta := out.Messages[0].Metadata
	if meta == nil {
		t.Fatal("metadata should not be nil")
	}
	if meta["service"] != "UserService" {
		t.Errorf("metadata.service = %q, want UserService", meta["service"])
	}
	if meta["method"] != "GetUser" {
		t.Errorf("metadata.method = %q, want GetUser", meta["method"])
	}
}

// --- Test: config with TCP forwards and enabled protocols ---

func TestQuery_Config_WithTCPForwards(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	ctx := context.Background()
	ca := newTestCA(t)
	s := newServer(ctx, ca, store, nil)
	s.connector.tcpForwards = map[string]*config.ForwardConfig{"3306": {Target: "db.example.com:3306", Protocol: "raw"}}
	s.connector.enabledProtocols = []string{"HTTP/1.x", "HTTPS", "gRPC"}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)

	if out.TCPForwards == nil {
		t.Fatal("tcp_forwards should not be nil")
	}
	if fc := out.TCPForwards["3306"]; fc == nil || fc.Target != "db.example.com:3306" {
		var got string
		if fc != nil {
			got = fc.Target
		}
		t.Errorf("tcp_forwards[3306].Target = %q, want db.example.com:3306", got)
	}
	if len(out.EnabledProtocols) != 3 {
		t.Errorf("enabled_protocols len = %d, want 3", len(out.EnabledProtocols))
	}
}
