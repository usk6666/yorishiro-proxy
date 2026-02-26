package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// setupTestSessionWithExecuteDoer creates an MCP client session with a custom HTTP doer for execute replay testing.
func setupTestSessionWithExecuteDoer(t *testing.T, store session.Store, doer httpDoer) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, store, nil)
	s.replayDoer = doer
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

// setupTestSessionWithExecuteRawDialer creates an MCP client session with a custom raw dialer for execute replay_raw testing.
func setupTestSessionWithExecuteRawDialer(t *testing.T, store session.Store, dialer rawDialer) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, store, nil)
	s.rawReplayDialer = dialer
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
		Name:      "execute",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// --- Replay action tests ---

func TestExecute_Replay_Success(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			Duration:  250 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}, "X-Custom": {"original"}},
			Body:      []byte(`{"key":"value"}`),
		},
		&session.Message{
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
			"session_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.NewSessionID == "" {
		t.Error("expected non-empty new_session_id")
	}
	if out.NewSessionID == entry.Session.ID {
		t.Error("new_session_id should differ from original session_id")
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

	// Verify the replay was recorded as a new session.
	newSess, err := store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	if newSess.SessionType != "unary" {
		t.Errorf("session_type = %q, want unary", newSess.SessionType)
	}
	if newSess.State != "complete" {
		t.Errorf("state = %q, want complete", newSess.State)
	}
}

func TestExecute_Replay_AllOverrides(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/original")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Accept": {"text/html"}},
		},
		&session.Message{
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
			"session_id":      entry.Session.ID,
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

	var out executeResendResult
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

func TestExecute_Replay_EmptySessionID(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"session_id": "",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for empty session_id")
	}
}

func TestExecute_Replay_NonexistentSession(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"session_id": "nonexistent-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestExecute_Replay_NilStore(t *testing.T) {
	cs := setupTestSessionWithExecuteDoer(t, nil, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay",
		"params": map[string]any{
			"session_id": "some-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nil store")
	}
}

func TestExecute_Replay_InvalidOverrideURL(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&session.Message{
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
					"session_id":   entry.Session.ID,
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
	store := newTestStore(t)

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		nil, // no send message
		&session.Message{
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
			"session_id": entry.Session.ID,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for session with no send messages")
	}
}

// --- ReplayRaw action tests ---

func TestExecute_ReplayRaw_Success(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /raw-test HTTP/1.1\r\nHost: example.com\r\nX-Custom: preserved\r\n\r\n")

	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/raw-test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Host": {"example.com"}, "X-Custom": {"preserved"}},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":  entry.Session.ID,
			"target_addr": addr,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendRawResult
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
	store := newTestStore(t)

	u, _ := url.Parse("http://example.com/no-raw")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&session.Message{
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
			"session_id": entry.Session.ID,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for session without raw bytes")
	}
}

func TestExecute_ReplayRaw_EmptySessionID(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"session_id": "",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for empty session_id")
	}
}

func TestExecute_ReplayRaw_NonexistentSession(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"session_id": "nonexistent-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestExecute_ReplayRaw_NilStore(t *testing.T) {
	cs := setupTestSessionWithExecuteRawDialer(t, nil, &testDialer{})

	result := executeCallTool(t, cs, map[string]any{
		"action": "replay_raw",
		"params": map[string]any{
			"session_id": "some-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nil store")
	}
}

func TestExecute_ReplayRaw_InferTargetFromURL(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
}

// --- DeleteSessions action tests ---

func TestExecute_DeleteSessions_ByID(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/api/test")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"session_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", out.DeletedCount)
	}

	// Verify the session was actually deleted.
	_, err := store.GetSession(context.Background(), entry.Session.ID)
	if err == nil {
		t.Error("expected error when getting deleted session")
	}
}

func TestExecute_DeleteSessions_All(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/api/test")
	for i := 0; i < 3; i++ {
		saveTestEntry(t, store,
			&session.Session{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now(),
				Duration:  100 * time.Millisecond,
			},
			&session.Message{
				Sequence:  0,
				Direction: "send",
				Timestamp: time.Now(),
				Method:    "GET",
				URL:       u,
				Headers:   map[string][]string{},
			},
			&session.Message{
				Sequence:   1,
				Direction:  "receive",
				Timestamp:  time.Now(),
				StatusCode: 200,
				Headers:    map[string][]string{},
				Body:       []byte("ok"),
			},
		)
	}

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 3 {
		t.Errorf("deleted_count = %d, want 3", out.DeletedCount)
	}

	// Verify all sessions were deleted.
	remaining, err := store.ListSessions(context.Background(), session.ListOptions{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining sessions, got %d", len(remaining))
	}
}

func TestExecute_DeleteSessions_OlderThanDays(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	now := time.Now().UTC()
	u, _ := url.Parse("http://example.com/test")

	// Insert old session (5 days ago).
	saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-120 * time.Hour),
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: now.Add(-120 * time.Hour),
			Method:    "GET",
			URL:       u,
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  now.Add(-120 * time.Hour),
			StatusCode: 200,
		},
	)

	// Insert recent session (1 hour ago).
	saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-1 * time.Hour),
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: now.Add(-1 * time.Hour),
			Method:    "GET",
			URL:       u,
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  now.Add(-1 * time.Hour),
			StatusCode: 200,
		},
	)

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"older_than_days": 3,
			"confirm":         true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteSessionsResult
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
	remaining, err := store.ListSessions(context.Background(), session.ListOptions{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining session, got %d", len(remaining))
	}
}

func TestExecute_DeleteSessions_OlderThanDays_InvalidDays(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"older_than_days": 0,
			"confirm":         true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for older_than_days=0")
	}
}

func TestExecute_DeleteSessions_OlderThanDays_RequiresConfirm(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"older_than_days": 7,
			"confirm":         false,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for confirm=false with older_than_days")
	}
}

func TestExecute_DeleteSessions_NoParamsError(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error when no deletion criteria specified")
	}
}

func TestExecute_DeleteSessions_NonexistentSession(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"session_id": "nonexistent-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent session_id")
	}
}

func TestExecute_DeleteSessions_NilStore(t *testing.T) {
	cs := setupTestSessionWithExecuteDoer(t, nil, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"session_id": "some-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nil store")
	}
}

// --- Invalid action tests ---

func TestExecute_InvalidAction(t *testing.T) {
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
}

func TestExecute_EmptyAction(t *testing.T) {
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

func TestExecute_DeleteSessions_NothingToDelete(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	u, _ := url.Parse("http://example.com/recent")
	saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now().UTC(),
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now().UTC(),
			Method:    "GET",
			URL:       u,
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now().UTC(),
			StatusCode: 200,
		},
	)

	result := executeCallTool(t, cs, map[string]any{
		"action": "delete_sessions",
		"params": map[string]any{
			"older_than_days": 30,
			"confirm":         true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteSessionsResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.DeletedCount != 0 {
		t.Errorf("deleted_count = %d, want 0", out.DeletedCount)
	}
}

// --- safeCheckRedirect tests ---

func TestSafeCheckRedirect(t *testing.T) {
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
