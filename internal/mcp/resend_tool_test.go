package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// setupTestSessionWithExecuteDoer creates an MCP client flow with a custom HTTP doer for execute replay testing.
func setupTestSessionWithExecuteDoer(t *testing.T, store flow.Store, doer httpDoer) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, store, nil)
	s.deps.replayDoer = doer
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

// setupTestSessionWithExecuteRawDialer creates an MCP client flow with a custom raw dialer for execute replay_raw testing.
func setupTestSessionWithExecuteRawDialer(t *testing.T, store flow.Store, dialer rawDialer) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, store, nil)
	s.deps.rawReplayDialer = dialer
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

// executeCallTool is a helper that calls the execute tool with the given arguments.
func executeCallTool(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// manageCallTool is a helper that calls the manage tool with the given arguments.
func manageCallTool(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "manage",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// --- Replay action tests ---

func TestExecute_Replay_Success(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			Duration:  250 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}, "X-Custom": {"original"}},
			Body:      []byte(`{"key":"value"}`),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
			Body:       []byte(`{"status":"ok"}`),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendActionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}
	if out.NewFlowID == entry.Session.ID {
		t.Error("new_flow_id should differ from original flow_id")
	}
	if out.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", out.StatusCode)
	}
	if out.ResponseBodyEncoding != "text" {
		t.Errorf("response_body_encoding = %q, want text", out.ResponseBodyEncoding)
	}
	if out.DurationMs < 0 {
		t.Errorf("duration_ms = %d, should be >= 0", out.DurationMs)
	}

	// Verify the echo server received the right data.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}
	if echo["method"] != "POST" {
		t.Errorf("echo method = %q, want POST", echo["method"])
	}
	if echo["body"] != `{"key":"value"}` {
		t.Errorf("echo body = %q, want {\"key\":\"value\"}", echo["body"])
	}

	// Verify the replay was recorded as a new flow.
	newFl, err := store.GetFlow(context.Background(), out.NewFlowID)
	if err != nil {
		t.Fatalf("get new flow: %v", err)
	}
	if newFl.FlowType != "unary" {
		t.Errorf("flow_type = %q, want unary", newFl.FlowType)
	}
	if newFl.State != "complete" {
		t.Errorf("state = %q, want complete", newFl.State)
	}
}

func TestExecute_Replay_AllOverrides(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/original")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Accept": {"text/html"}},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())
	overrideBody := `{"all":"overridden"}`
	overrideURL := echoServer.URL + "/new-path"

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id":         entry.Session.ID,
			"override_method": "PATCH",
			"override_url":    overrideURL,
			"override_headers": map[string]any{
				"Content-Type": "application/json",
			},
			"override_body": overrideBody,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendActionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received overridden values.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}
	if echo["method"] != "PATCH" {
		t.Errorf("echo method = %q, want PATCH", echo["method"])
	}
	if echo["url"] != "/new-path" {
		t.Errorf("echo url = %q, want /new-path", echo["url"])
	}
	if echo["body"] != overrideBody {
		t.Errorf("echo body = %q, want %q", echo["body"], overrideBody)
	}
}

func TestExecute_Replay_EmptyFlowID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id": "",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for empty flow_id")
	}
}

func TestExecute_Replay_NonexistentSession(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id": "nonexistent-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestExecute_Replay_NilStore(t *testing.T) {
	t.Parallel()
	cs := setupTestSessionWithExecuteDoer(t, nil, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id": "some-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nil store")
	}
}

func TestExecute_Replay_InvalidOverrideURL(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	tests := []struct {
		name string
		url  string
	}{
		{name: "missing scheme", url: "example.com/test"},
		{name: "ftp scheme", url: "ftp://example.com/test"},
		{name: "file scheme", url: "file:///etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := executeCallTool(t, cs, map[string]any{
				"action": "replay",
				"params": map[string]any{
					"flow_id":      entry.Session.ID,
					"override_url": tt.url,
				},
			})
			if !result.IsError {
				t.Fatalf("expected error for URL %q", tt.url)
			}
		})
	}
}

func TestExecute_Replay_NoSendMessages(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		nil, // no send message
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for flow with no send messages")
	}
}

func TestExecute_Replay_GRPCStreamingUnsupported(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		flowType string
	}{
		{"server_streaming", "stream"},
		{"bidirectional", "bidirectional"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)

			u, _ := url.Parse("http://localhost:50051/test.Service/Method")
			entry := saveTestEntry(t, store,
				&flow.Flow{
					Protocol:  "gRPC",
					FlowType:  tt.flowType,
					Timestamp: time.Now(),
					Duration:  100 * time.Millisecond,
				},
				&flow.Message{
					Sequence:  0,
					Direction: "send",
					Timestamp: time.Now(),
					Method:    "POST",
					URL:       u,
					Headers:   map[string][]string{"Content-Type": {"application/grpc"}},
					Body:      []byte("grpc-frame"),
				},
				&flow.Message{
					Sequence:   1,
					Direction:  "receive",
					Timestamp:  time.Now(),
					StatusCode: 200,
					Headers:    map[string][]string{"Content-Type": {"application/grpc"}},
					Body:       []byte("grpc-response"),
				},
			)

			cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

			result := executeCallTool(t, cs, map[string]any{
				"action": "replay",
				"params": map[string]any{
					"flow_id": entry.Session.ID,
				},
			})
			if !result.IsError {
				t.Fatal("expected error for gRPC streaming flow")
			}

			textContent := result.Content[0].(*gomcp.TextContent)
			if !strings.Contains(textContent.Text, "not yet supported") {
				t.Errorf("error message should mention 'not yet supported', got: %s", textContent.Text)
			}
			if !strings.Contains(textContent.Text, tt.flowType) {
				t.Errorf("error message should mention flow type %q, got: %s", tt.flowType, textContent.Text)
			}
		})
	}
}

func TestExecute_Replay_GRPCUnaryAllowed(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/test.Service/Method")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "gRPC",
			FlowType:  "unary",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/grpc"}},
			Body:      []byte("grpc-frame"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/grpc"}},
			Body:       []byte("grpc-response"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success for gRPC unary flow, got error: %v", result.Content)
	}
}

func TestExecute_Replay_GRPCDataFrameBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/test.Service/Method")

	// Create a gRPC flow with sequence 0 = headers (empty body),
	// sequence 1+ = data frame messages with protobuf payloads.
	fl := &flow.Flow{
		Protocol:  "gRPC",
		FlowType:  "unary",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	ctx := context.Background()
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Sequence 0: header message (no body, as in real gRPC recording)
	headerMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"application/grpc"}},
	}
	if err := store.AppendMessage(ctx, headerMsg); err != nil {
		t.Fatalf("AppendMessage(header): %v", err)
	}

	// Sequence 1: data frame message with protobuf payload
	payload := []byte("test-protobuf-payload")
	dataMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  1,
		Direction: "send",
		Timestamp: time.Now(),
		Body:      payload,
	}
	if err := store.AppendMessage(ctx, dataMsg); err != nil {
		t.Fatalf("AppendMessage(data): %v", err)
	}

	// Sequence 2: receive message
	recvMsg := &flow.Message{
		FlowID:     fl.ID,
		Sequence:   2,
		Direction:  "receive",
		Timestamp:  time.Now(),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/grpc"}},
		Body:       []byte("grpc-response"),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": fl.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendActionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received a non-empty body containing the
	// gRPC length-prefixed frame.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}
	echoBody, ok := echo["body"].(string)
	if !ok || echoBody == "" {
		t.Fatal("echo body is empty; gRPC data frame was not sent")
	}
	// The body should contain the gRPC frame: 5-byte header + payload
	if len(echoBody) != 5+len(payload) {
		t.Errorf("echo body length = %d, want %d (5-byte header + %d-byte payload)", len(echoBody), 5+len(payload), len(payload))
	}
}

func TestExecute_Replay_GRPCTrailersRecorded(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Create a test server that returns gRPC response with grpc-status
	// as a regular response header (not HTTP/1.1 trailer). This simulates
	// gRPC-over-HTTP/1.1 where trailers are sent as regular headers.
	// Real gRPC typically uses HTTP/2 where trailers are part of the
	// HEADERS frame; the UpstreamRouter handles this via ALPN routing.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "OK")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("grpc-response-body"))
	}))
	t.Cleanup(server.Close)

	u, _ := url.Parse(server.URL + "/test.Service/Method")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "gRPC",
			FlowType:  "unary",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/grpc"}},
			Body:      []byte("grpc-frame"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/grpc"}},
			Body:       []byte("grpc-response"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendActionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify that a trailers message was recorded as sequence 2.
	msgs, err := store.GetMessages(context.Background(), out.NewFlowID, flow.MessageListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}

	var trailerMsg *flow.Message
	for _, msg := range msgs {
		if msg.Metadata != nil && msg.Metadata["grpc_type"] == "trailers" {
			trailerMsg = msg
			break
		}
	}
	if trailerMsg == nil {
		t.Fatal("no trailers message recorded for gRPC resend")
	}
	if trailerMsg.Sequence != 2 {
		t.Errorf("trailer message sequence = %d, want 2", trailerMsg.Sequence)
	}
	if trailerMsg.Direction != "receive" {
		t.Errorf("trailer message direction = %q, want receive", trailerMsg.Direction)
	}
	if trailerMsg.Metadata["grpc_status"] != "0" {
		t.Errorf("trailer grpc_status = %q, want 0", trailerMsg.Metadata["grpc_status"])
	}
	if trailerMsg.Metadata["grpc_message"] != "OK" {
		t.Errorf("trailer grpc_message = %q, want OK", trailerMsg.Metadata["grpc_message"])
	}
	grpcStatusHeader := trailerMsg.Headers["Grpc-Status"]
	if len(grpcStatusHeader) == 0 || grpcStatusHeader[0] != "0" {
		t.Errorf("trailer headers Grpc-Status = %v, want [0]", grpcStatusHeader)
	}
}

func TestExecute_Replay_GRPCBodyPatchesRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/test.Service/Method")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "gRPC",
			FlowType:  "unary",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/grpc"}},
			Body:      []byte("grpc-frame"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/grpc"}},
			Body:       []byte("grpc-response"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"body_patches": []map[string]any{
				{"regex": "old", "replace": "new"},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for body_patches on gRPC flow")
	}

	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "body_patches is not yet supported for gRPC") {
		t.Errorf("error = %q, want to contain 'body_patches is not yet supported for gRPC'", textContent.Text)
	}
}

// --- ReplayRaw action tests ---

func TestExecute_ReplayRaw_Success(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /raw-test HTTP/1.1\r\nHost: example.com\r\nX-Custom: preserved\r\n\r\n")

	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/raw-test")

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Host": {"example.com"}, "X-Custom": {"preserved"}},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
	if out.DurationMs < 0 {
		t.Errorf("duration_ms = %d, should be >= 0", out.DurationMs)
	}

	// Decode and verify the response contains our echo.
	respBytes, err := base64.StdEncoding.DecodeString(out.ResponseData)
	if err != nil {
		t.Fatalf("decode response_data: %v", err)
	}
	if !strings.Contains(string(respBytes), "hello world") {
		t.Errorf("response doesn't contain 'hello world': %q", string(respBytes))
	}
	if !strings.Contains(string(respBytes), "X-Echo: raw") {
		t.Errorf("response doesn't contain echo header: %q", string(respBytes))
	}
}

func TestExecute_ReplayRaw_NoRawBytes(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	u, _ := url.Parse("http://example.com/no-raw")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for session without raw bytes")
	}
}

func TestExecute_ReplayRaw_EmptyFlowID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"flow_id": "",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for empty flow_id")
	}
}

func TestExecute_ReplayRaw_NonexistentSession(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"flow_id": "nonexistent-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestExecute_ReplayRaw_NilStore(t *testing.T) {
	t.Parallel()
	cs := setupTestSessionWithExecuteRawDialer(t, nil, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"flow_id": "some-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nil store")
	}
}

func TestExecute_ReplayRaw_InferTargetFromURL(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	// No target_addr provided; should infer from URL.
	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
}

// --- DeleteFlows action tests ---

func TestExecute_DeleteFlows_ByID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteFlowsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", out.DeletedCount)
	}

	// Verify the flow was actually deleted.
	_, err := store.GetFlow(context.Background(), entry.Session.ID)
	if err == nil {
		t.Error("expected error when getting deleted flow")
	}
}

func TestExecute_DeleteFlows_All(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/api/test")
	for i := 0; i < 3; i++ {
		saveTestEntry(t, store,
			&flow.Flow{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now(),
				Duration:  100 * time.Millisecond,
			},
			&flow.Message{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now(),
				Method:    "GET",
				URL:       u,
				Headers:   map[string][]string{},
			},
			&flow.Message{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now(),
				StatusCode: 200,
				Headers:    map[string][]string{},
				Body:       []byte("ok"),
			},
		)
	}

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteFlowsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 3 {
		t.Errorf("deleted_count = %d, want 3", out.DeletedCount)
	}

	// Verify all sessions were deleted.
	remaining, err := store.ListFlows(context.Background(), flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining sessions, got %d", len(remaining))
	}
}

func TestExecute_DeleteFlows_OlderThanDays(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	now := time.Now().UTC()
	u, _ := url.Parse("http://example.com/test")

	// Insert old session (5 days ago).
	saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-120 * time.Hour),
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: now.Add(-120 * time.Hour),
			Method:    "GET",
			URL:       u,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  now.Add(-120 * time.Hour),
			StatusCode: 200,
		},
	)

	// Insert recent session (1 hour ago).
	saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-1 * time.Hour),
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: now.Add(-1 * time.Hour),
			Method:    "GET",
			URL:       u,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  now.Add(-1 * time.Hour),
			StatusCode: 200,
		},
	)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"older_than_days": 3,
			"confirm":         true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteFlowsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", out.DeletedCount)
	}
	if out.CutoffTime == "" {
		t.Error("cutoff_time should be set for older_than_days deletion")
	}

	// Verify only the recent session remains.
	remaining, err := store.ListFlows(context.Background(), flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining flow, got %d", len(remaining))
	}
}

func TestExecute_DeleteFlows_OlderThanDays_InvalidDays(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"older_than_days": 0,
			"confirm":         true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for older_than_days=0")
	}
}

func TestExecute_DeleteFlows_OlderThanDays_RequiresConfirm(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"older_than_days": 7,
			"confirm":         false,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for confirm=false with older_than_days")
	}
}

func TestExecute_DeleteFlows_NoParamsError(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error when no deletion criteria specified")
	}
}

func TestExecute_DeleteFlows_NonexistentSession(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"flow_id": "nonexistent-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent flow_id")
	}
}

func TestExecute_DeleteFlows_NilStore(t *testing.T) {
	t.Parallel()
	cs := setupTestSessionWithExecuteDoer(t, nil, newPermissiveClient())

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"flow_id": "some-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nil store")
	}
}

// --- Invalid action tests ---

func TestExecute_InvalidAction(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := executeCallTool(t, cs, map[string]any{
		"action": "unknown_action",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid action")
	}

	// Verify comma-separated format (not Go slice format like "[a b c]").
	textContent := result.Content[0].(*gomcp.TextContent)
	if strings.Contains(textContent.Text, "[") {
		t.Errorf("error message should use comma-separated format, got %q", textContent.Text)
	}
	if !strings.Contains(textContent.Text, "resend, resend_raw") {
		t.Errorf("error message = %q, want comma-separated actions", textContent.Text)
	}
}

func TestExecute_EmptyAction(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := executeCallTool(t, cs, map[string]any{
		"action": "",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error for empty action")
	}

	// Verify the error message uses "action is required" (consistent with query tool's "resource is required").
	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "action is required") {
		t.Errorf("error message = %q, want to contain %q", textContent.Text, "action is required")
	}
}

func TestExecute_DeleteFlows_ByProtocol(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/api/test")
	// Create sessions with different protocols.
	for i := 0; i < 2; i++ {
		saveTestEntry(t, store,
			&flow.Flow{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now(),
				Duration:  100 * time.Millisecond,
			},
			&flow.Message{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now(),
				Method:    "GET",
				URL:       u,
				Headers:   map[string][]string{},
			},
			&flow.Message{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now(),
				StatusCode: 200,
				Headers:    map[string][]string{},
				Body:       []byte("ok"),
			},
		)
	}
	saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "TCP",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 0,
			Headers:    map[string][]string{},
			Body:       []byte("raw data"),
		},
	)
	saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "WebSocket",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 101,
			Headers:    map[string][]string{},
			Body:       []byte("ws data"),
		},
	)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"protocol": "TCP",
			"confirm":  true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteFlowsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", out.DeletedCount)
	}

	// Verify only TCP sessions were deleted, others remain.
	remaining, err := store.ListFlows(context.Background(), flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 3 {
		t.Errorf("expected 3 remaining sessions, got %d", len(remaining))
	}
	// Verify no TCP sessions remain.
	for _, s := range remaining {
		if s.Protocol == "TCP" {
			t.Error("found TCP session after protocol-based deletion")
		}
	}
}

func TestExecute_DeleteFlows_ByProtocol_RequiresConfirm(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"protocol": "TCP",
			"confirm":  false,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for protocol deletion without confirm")
	}
	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "confirm must be true") {
		t.Errorf("error = %q, want to contain 'confirm must be true'", textContent.Text)
	}
}

func TestExecute_DeleteFlows_ByProtocol_NoMatches(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/api/test")
	saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"protocol": "gRPC",
			"confirm":  true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteFlowsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 0 {
		t.Errorf("deleted_count = %d, want 0", out.DeletedCount)
	}

	// Verify no sessions were deleted.
	remaining, err := store.ListFlows(context.Background(), flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining flow, got %d", len(remaining))
	}
}

func TestExecute_DeleteFlows_NothingToDelete(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/recent")
	saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now().UTC(),
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now().UTC(),
			Method:    "GET",
			URL:       u,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now().UTC(),
			StatusCode: 200,
		},
	)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"older_than_days": 30,
			"confirm":         true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteFlowsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 0 {
		t.Errorf("deleted_count = %d, want 0", out.DeletedCount)
	}
}

// --- safeCheckRedirect tests ---

// --- regenerate_ca_cert action tests ---

// setupTestSessionForRegenerate creates an MCP client flow with CA and issuer
// for regenerate_ca_cert testing.
func setupTestSessionForRegenerate(t *testing.T, ca *cert.CA, issuer *cert.Issuer) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if issuer != nil {
		opts = append(opts, WithIssuer(issuer))
	}
	s := NewServer(ctx, ca, nil, nil, opts...)
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

func TestExecute_RegenerateCA_AutoPersistMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca := newTestCA(t)
	// Save the initial CA and set source as auto-persisted (using default paths).
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("save CA: %v", err)
	}
	ca.SetSource(cert.CASource{
		Persisted: true,
		CertPath:  certPath,
		KeyPath:   keyPath,
	})

	// Set default paths to match our test paths so the handler doesn't reject as "user-provided".
	// We override DefaultCACertPath/DefaultCAKeyPath via the source matching logic.
	// Since our paths differ from DefaultCACertPath(), the handler would reject.
	// We need to ensure our paths match what the handler compares against.
	// Instead, test with ephemeral mode which should always succeed.

	issuer := cert.NewIssuer(ca)
	// Populate some cache entries.
	if _, err := issuer.GetCertificate("example.com"); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if issuer.CacheLen() != 1 {
		t.Fatalf("CacheLen = %d, want 1", issuer.CacheLen())
	}

	originalFingerprint := sha256.Sum256(ca.Certificate().Raw)

	cs := setupTestSessionForRegenerate(t, ca, issuer)

	result := manageCallTool(t, cs, map[string]any{
		"action": "regenerate_ca_cert",
		"params": map[string]any{},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeRegenerateCACertResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	if out.Subject == "" {
		t.Error("subject should not be empty")
	}
	if out.NotAfter == "" {
		t.Error("not_after should not be empty")
	}

	// Fingerprint should have changed.
	newFingerprint := sha256.Sum256(ca.Certificate().Raw)
	if originalFingerprint == newFingerprint {
		t.Error("CA fingerprint did not change after regeneration")
	}

	// Issuer cache should have been cleared.
	if issuer.CacheLen() != 0 {
		t.Errorf("CacheLen = %d after regeneration, want 0", issuer.CacheLen())
	}

	// Persisted should be true and file should be updated.
	if !out.Persisted {
		t.Error("persisted = false, want true")
	}

	if out.InstallHint == "" {
		t.Error("install_hint should not be empty")
	}
}

func TestExecute_RegenerateCA_ExplicitMode_Error(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	// Simulate explicit mode: persisted with user-provided paths.
	ca.SetSource(cert.CASource{
		Persisted: true,
		CertPath:  "/custom/path/ca.crt",
		KeyPath:   "/custom/path/ca.key",
		Explicit:  true,
	})

	cs := setupTestSessionForRegenerate(t, ca, nil)

	result := manageCallTool(t, cs, map[string]any{
		"action": "regenerate_ca_cert",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error for explicit mode regeneration")
	}

	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "cannot regenerate user-provided CA") {
		t.Errorf("error = %q, want 'cannot regenerate user-provided CA'", textContent.Text)
	}
}

func TestExecute_RegenerateCA_EphemeralMode(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	// Ephemeral mode: no source set (Persisted=false).

	issuer := cert.NewIssuer(ca)
	originalFingerprint := sha256.Sum256(ca.Certificate().Raw)

	cs := setupTestSessionForRegenerate(t, ca, issuer)

	result := manageCallTool(t, cs, map[string]any{
		"action": "regenerate_ca_cert",
		"params": map[string]any{},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeRegenerateCACertResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Fingerprint should have changed.
	newFingerprint := sha256.Sum256(ca.Certificate().Raw)
	if originalFingerprint == newFingerprint {
		t.Error("CA fingerprint did not change after regeneration")
	}

	if out.Persisted {
		t.Error("persisted = true, want false for ephemeral mode")
	}

	if !strings.Contains(out.InstallHint, "in memory") {
		t.Errorf("install_hint = %q, should mention 'in memory'", out.InstallHint)
	}
}

func TestExecute_RegenerateCA_NilCA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewServer(ctx, nil, nil, nil)
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

	result := manageCallTool(t, cs, map[string]any{
		"action": "regenerate_ca_cert",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error for nil CA")
	}
}

func TestSafeCheckRedirect(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		scheme  string
		via     int // number of prior redirects
		wantErr bool
		errMsg  string
	}{
		{name: "http allowed", scheme: "http", via: 0, wantErr: false},
		{name: "https allowed", scheme: "https", via: 0, wantErr: false},
		{name: "ftp blocked", scheme: "ftp", via: 0, wantErr: true, errMsg: "non-HTTP scheme"},
		{name: "file blocked", scheme: "file", via: 0, wantErr: true, errMsg: "non-HTTP scheme"},
		{name: "gopher blocked", scheme: "gopher", via: 0, wantErr: true, errMsg: "non-HTTP scheme"},
		{name: "at redirect limit", scheme: "https", via: maxRedirects, wantErr: true, errMsg: "too many redirects"},
		{name: "within redirect limit", scheme: "https", via: maxRedirects - 1, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{Scheme: tt.scheme, Host: "example.com"},
			}
			via := make([]*http.Request, tt.via)
			for i := range via {
				via[i] = &http.Request{}
			}

			err := safeCheckRedirect(req, via)
			if (err != nil) != tt.wantErr {
				t.Errorf("safeCheckRedirect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
			}
		})
	}
}

// --- gRPC-Web Resend tests ---

func TestResend_GRPCWeb_Success(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Server that responds with gRPC-Web style response.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc-web")
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "OK")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("grpc-web-response"))
	}))
	t.Cleanup(server.Close)

	u, _ := url.Parse(server.URL + "/test.Svc/DoStuff")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "gRPC-Web",
			FlowType:  "unary",
			Timestamp: time.Now(),
			Duration:  50 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/grpc-web"}},
			Body:      []byte("grpc-web-body"),
			RawBytes:  []byte("grpc-web-body"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/grpc-web"}},
			Body:       []byte("grpc-web-resp"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendActionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.NewFlowID == "" {
		t.Error("NewFlowID is empty")
	}
	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}

	// Verify trailers were recorded.
	msgs, err := store.GetMessages(context.Background(), out.NewFlowID, flow.MessageListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}

	var trailerMsg *flow.Message
	for _, msg := range msgs {
		if msg.Metadata != nil && msg.Metadata["grpc_type"] == "trailers" {
			trailerMsg = msg
			break
		}
	}
	if trailerMsg == nil {
		t.Fatal("no trailers message recorded for gRPC-Web resend")
	}
	if trailerMsg.Metadata["grpc_status"] != "0" {
		t.Errorf("trailer grpc_status = %q, want 0", trailerMsg.Metadata["grpc_status"])
	}
}

func TestResend_GRPCWeb_BodyPatchesRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/test.Svc/Method")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "gRPC-Web",
			FlowType:  "unary",
			Timestamp: time.Now(),
			Duration:  50 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/grpc-web"}},
			Body:      []byte("grpc-web-frame"),
			RawBytes:  []byte("grpc-web-frame"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/grpc-web"}},
			Body:       []byte("resp"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"body_patches": []map[string]any{
				{"regex": "old", "replace": "new"},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for body_patches on gRPC-Web flow")
	}

	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "body_patches is not yet supported for gRPC-Web") {
		t.Errorf("error = %q, want to contain 'body_patches is not yet supported for gRPC-Web'", textContent.Text)
	}
}

func TestResend_GRPCWeb_StreamingRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/test.Svc/Method")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "gRPC-Web",
			FlowType:  "server-streaming",
			Timestamp: time.Now(),
			Duration:  50 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/grpc-web"}},
			Body:      []byte("frame"),
			RawBytes:  []byte("frame"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/grpc-web"}},
			Body:       []byte("resp"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for streaming gRPC-Web flow")
	}

	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "gRPC-Web streaming flows") {
		t.Errorf("error = %q, want to contain 'gRPC-Web streaming flows'", textContent.Text)
	}
}

func TestIsGRPCWebFlow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		protocol string
		want     bool
	}{
		{"gRPC-Web", true},
		{"gRPC", false},
		{"HTTP/1.x", false},
		{"HTTP/2", false},
		{"WebSocket", false},
	}
	for _, tt := range tests {
		if got := isGRPCWebFlow(tt.protocol); got != tt.want {
			t.Errorf("isGRPCWebFlow(%q) = %v, want %v", tt.protocol, got, tt.want)
		}
	}
}

func TestBuildGRPCWebRequestBody_FromRawBytes(t *testing.T) {
	t.Parallel()

	rawData := []byte("original-wire-data")
	msgs := []*flow.Message{
		{
			Sequence:  0,
			Direction: "send",
			Body:      []byte("decoded-frame"),
			RawBytes:  rawData,
		},
	}

	got := buildGRPCWebRequestBody(msgs)
	if string(got) != string(rawData) {
		t.Errorf("buildGRPCWebRequestBody = %q, want %q (should use RawBytes)", got, rawData)
	}
}

func TestBuildGRPCWebRequestBody_FallbackToBody(t *testing.T) {
	t.Parallel()

	msgs := []*flow.Message{
		{
			Sequence:  0,
			Direction: "send",
			Body:      []byte("frame-payload"),
		},
	}

	got := buildGRPCWebRequestBody(msgs)
	// Should produce gRPC-Web encoded frames.
	if len(got) == 0 {
		t.Error("buildGRPCWebRequestBody returned empty body")
	}
	// Verify it's a valid frame (5-byte header + payload).
	if len(got) < 5 {
		t.Fatalf("body too short: %d bytes", len(got))
	}
}

func TestBuildGRPCWebRequestBody_Empty(t *testing.T) {
	t.Parallel()

	got := buildGRPCWebRequestBody(nil)
	if got != nil {
		t.Errorf("buildGRPCWebRequestBody(nil) = %v, want nil", got)
	}
}
