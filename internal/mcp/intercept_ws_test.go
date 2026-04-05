package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

func TestQueryInterceptQueue_WebSocketFrame(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Enqueue a WebSocket text frame.
	queue.EnqueueWebSocketFrame(
		1, // opcode: Text
		"client_to_server",
		"flow-abc",
		"wss://example.com/ws/chat",
		42,
		[]byte(`{"action":"hello"}`),
		[]string{"ws-rule-1"},
	)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: mustMarshal(t, queryInput{
			Resource: "intercept_queue",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	var queueResult queryInterceptQueueResult
	extractResult(t, result, &queueResult)
	if queueResult.Count != 1 {
		t.Fatalf("expected 1 item, got %d", queueResult.Count)
	}

	entry := queueResult.Items[0]
	if entry.Phase != "websocket_frame" {
		t.Errorf("expected phase websocket_frame, got %q", entry.Phase)
	}
	if entry.Protocol != "websocket" {
		t.Errorf("expected protocol websocket, got %q", entry.Protocol)
	}
	if entry.Opcode != "Text" {
		t.Errorf("expected opcode Text, got %q", entry.Opcode)
	}
	if entry.Direction != "client_to_server" {
		t.Errorf("expected direction client_to_server, got %q", entry.Direction)
	}
	if entry.StreamID != "flow-abc" {
		t.Errorf("expected flow_id flow-abc, got %q", entry.StreamID)
	}
	if entry.UpgradeURL != "wss://example.com/ws/chat" {
		t.Errorf("expected upgrade_url wss://example.com/ws/chat, got %q", entry.UpgradeURL)
	}
	if entry.Sequence != 42 {
		t.Errorf("expected sequence 42, got %d", entry.Sequence)
	}
	if entry.Body != `{"action":"hello"}` {
		t.Errorf("expected body {\"action\":\"hello\"}, got %q", entry.Body)
	}
	if entry.BodyEncoding != "text" {
		t.Errorf("expected body_encoding text, got %q", entry.BodyEncoding)
	}
	if len(entry.MatchedRules) != 1 || entry.MatchedRules[0] != "ws-rule-1" {
		t.Errorf("expected matched_rules [ws-rule-1], got %v", entry.MatchedRules)
	}
	// HTTP-specific fields should be empty for WebSocket frames.
	if entry.Method != "" {
		t.Errorf("expected empty method for WebSocket frame, got %q", entry.Method)
	}
	if entry.URL != "" {
		t.Errorf("expected empty URL for WebSocket frame, got %q", entry.URL)
	}
}

func TestQueryInterceptQueue_WebSocketBinaryFrame(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Enqueue a WebSocket binary frame with non-UTF8 payload.
	binaryPayload := []byte{0x00, 0x01, 0xFF, 0xFE}
	queue.EnqueueWebSocketFrame(
		2, // opcode: Binary
		"server_to_client",
		"flow-bin",
		"wss://example.com/ws/data",
		7,
		binaryPayload,
		nil,
	)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: mustMarshal(t, queryInput{
			Resource: "intercept_queue",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	var queueResult queryInterceptQueueResult
	extractResult(t, result, &queueResult)
	if queueResult.Count != 1 {
		t.Fatalf("expected 1 item, got %d", queueResult.Count)
	}

	entry := queueResult.Items[0]
	if entry.Opcode != "Binary" {
		t.Errorf("expected opcode Binary, got %q", entry.Opcode)
	}
	if entry.BodyEncoding != "base64" {
		t.Errorf("expected body_encoding base64 for binary payload, got %q", entry.BodyEncoding)
	}
	if entry.Direction != "server_to_client" {
		t.Errorf("expected direction server_to_client, got %q", entry.Direction)
	}
}

func TestQueryInterceptQueue_MixedHTTPAndWebSocket(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Enqueue an HTTP request.
	queue.Enqueue("GET", nil, nil, nil, nil)
	// Enqueue a WebSocket frame.
	queue.EnqueueWebSocketFrame(1, "client_to_server", "flow-mix", "wss://example.com/ws", 1, []byte("hello"), nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: mustMarshal(t, queryInput{
			Resource: "intercept_queue",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	var queueResult queryInterceptQueueResult
	extractResult(t, result, &queueResult)
	if queueResult.Count != 2 {
		t.Fatalf("expected 2 items, got %d", queueResult.Count)
	}

	// Check that both protocols are represented.
	protocols := map[string]bool{}
	for _, item := range queueResult.Items {
		protocols[item.Protocol] = true
	}
	if !protocols["http"] || !protocols["websocket"] {
		t.Errorf("expected both http and websocket protocols, got %v", protocols)
	}
}

func TestExecuteRelease_WebSocketFrame(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	id, actionCh := queue.EnqueueWebSocketFrame(
		1, "client_to_server", "flow-rel", "wss://example.com/ws", 5,
		[]byte(`{"msg":"test"}`), []string{"rule-ws"},
	)

	done := make(chan struct{})
	var callResult *gomcp.CallToolResult
	go func() {
		defer close(done)
		var err error
		callResult, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "intercept",
			Arguments: mustMarshal(t, interceptInput{
				Action: "release",
				Params: interceptParams{
					InterceptID: id,
				},
			}),
		})
		if err != nil {
			t.Errorf("CallTool error: %v", err)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionRelease {
			t.Errorf("expected ActionRelease, got %v", action.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for action")
	}

	<-done

	if callResult.IsError {
		t.Fatalf("unexpected error: %v", callResult.Content)
	}

	// Verify the result contains WebSocket metadata.
	var result executeInterceptResult
	extractResult(t, callResult, &result)
	if result.Protocol != "websocket" {
		t.Errorf("expected protocol websocket, got %q", result.Protocol)
	}
	if result.Phase != "websocket_frame" {
		t.Errorf("expected phase websocket_frame, got %q", result.Phase)
	}
	if result.Opcode != "Text" {
		t.Errorf("expected opcode Text, got %q", result.Opcode)
	}
	if result.Direction != "client_to_server" {
		t.Errorf("expected direction client_to_server, got %q", result.Direction)
	}
	if result.StreamID != "flow-rel" {
		t.Errorf("expected flow_id flow-rel, got %q", result.StreamID)
	}
	if result.Action != "release" {
		t.Errorf("expected action release, got %q", result.Action)
	}
}

func TestExecuteModifyAndForward_WebSocketFrame(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	id, actionCh := queue.EnqueueWebSocketFrame(
		1, "client_to_server", "flow-mod", "wss://example.com/ws", 10,
		[]byte(`{"msg":"original"}`), nil,
	)

	modifiedPayload := `{"msg":"modified"}`
	done := make(chan struct{})
	var callResult *gomcp.CallToolResult
	go func() {
		defer close(done)
		var err error
		callResult, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "intercept",
			Arguments: mustMarshal(t, interceptInput{
				Action: "modify_and_forward",
				Params: interceptParams{
					InterceptID:  id,
					OverrideBody: &modifiedPayload,
				},
			}),
		})
		if err != nil {
			t.Errorf("CallTool error: %v", err)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionModifyAndForward {
			t.Errorf("expected ActionModifyAndForward, got %v", action.Type)
		}
		if action.OverrideBody == nil || *action.OverrideBody != modifiedPayload {
			t.Errorf("expected body override %q, got %v", modifiedPayload, action.OverrideBody)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for action")
	}

	<-done

	if callResult.IsError {
		t.Fatalf("unexpected error: %v", callResult.Content)
	}

	var result executeInterceptResult
	extractResult(t, callResult, &result)
	if result.Protocol != "websocket" {
		t.Errorf("expected protocol websocket, got %q", result.Protocol)
	}
	if result.Opcode != "Text" {
		t.Errorf("expected opcode Text, got %q", result.Opcode)
	}
	if result.Sequence != 10 {
		t.Errorf("expected sequence 10, got %d", result.Sequence)
	}
}

func TestExecuteDrop_WebSocketFrame(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	id, actionCh := queue.EnqueueWebSocketFrame(
		1, "server_to_client", "flow-drop", "wss://example.com/ws", 3,
		[]byte("drop me"), nil,
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "intercept",
			Arguments: mustMarshal(t, interceptInput{
				Action: "drop",
				Params: interceptParams{
					InterceptID: id,
				},
			}),
		})
		if err != nil {
			t.Errorf("CallTool error: %v", err)
			return
		}
		if result.IsError {
			t.Errorf("unexpected error: %v", result.Content)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionDrop {
			t.Errorf("expected ActionDrop, got %v", action.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for action")
	}

	<-done
}

func TestWsOpcodeNameFromInt(t *testing.T) {
	tests := []struct {
		opcode int
		want   string
	}{
		{0, "Continuation"},
		{1, "Text"},
		{2, "Binary"},
		{8, "Close"},
		{9, "Ping"},
		{10, "Pong"},
		{99, "Unknown(99)"},
	}
	for _, tt := range tests {
		got := wsOpcodeNameFromInt(tt.opcode)
		if got != tt.want {
			t.Errorf("wsOpcodeNameFromInt(%d) = %q, want %q", tt.opcode, got, tt.want)
		}
	}
}

// TestBuildInterceptResult_WebSocketFrame verifies the result builder includes WS metadata.
func TestBuildInterceptResult_WebSocketFrame(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)

	item := &intercept.InterceptedRequest{
		ID:           "test-ws-id",
		Phase:        intercept.PhaseWebSocketFrame,
		Body:         []byte(`{"test":"data"}`),
		WSOpcode:     1,
		WSDirection:  "client_to_server",
		WSFlowID:     "flow-build",
		WSUpgradeURL: "wss://example.com/ws",
		WSSequence:   99,
		MatchedRules: []string{"rule-1"},
	}

	result := s.buildInterceptResult(item, "release", "released")

	if result.Protocol != "websocket" {
		t.Errorf("expected protocol websocket, got %q", result.Protocol)
	}
	if result.Phase != "websocket_frame" {
		t.Errorf("expected phase websocket_frame, got %q", result.Phase)
	}
	if result.Opcode != "Text" {
		t.Errorf("expected opcode Text, got %q", result.Opcode)
	}
	if result.Direction != "client_to_server" {
		t.Errorf("expected direction client_to_server, got %q", result.Direction)
	}
	if result.StreamID != "flow-build" {
		t.Errorf("expected flow_id flow-build, got %q", result.StreamID)
	}
	if result.UpgradeURL != "wss://example.com/ws" {
		t.Errorf("expected upgrade_url wss://example.com/ws, got %q", result.UpgradeURL)
	}
	if result.Sequence != 99 {
		t.Errorf("expected sequence 99, got %d", result.Sequence)
	}
	// HTTP-specific fields should be empty.
	if result.Method != "" {
		t.Errorf("expected empty method, got %q", result.Method)
	}
	if result.Headers != nil {
		t.Errorf("expected nil headers, got %v", result.Headers)
	}

	// Verify JSON serialization includes WS fields.
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if m["protocol"] != "websocket" {
		t.Errorf("JSON protocol = %v, want websocket", m["protocol"])
	}
	if m["opcode"] != "Text" {
		t.Errorf("JSON opcode = %v, want Text", m["opcode"])
	}
}
