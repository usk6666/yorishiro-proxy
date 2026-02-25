package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// roundTripFunc is an adapter to use a function as an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// setupTestSessionWithReplayDoer creates an MCP client session with a custom HTTP doer for replay testing.
func setupTestSessionWithReplayDoer(t *testing.T, store session.Store, doer httpDoer) *gomcp.ClientSession {
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

// newPermissiveClient returns an HTTP client without SSRF protection,
// suitable for tests that need to connect to localhost echo servers.
func newPermissiveClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newEchoServer creates a test HTTP server that echoes back request details as JSON.
func newEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp := map[string]any{
			"method":  r.Method,
			"url":     r.URL.String(),
			"headers": r.Header,
			"body":    string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", "true")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestReplayRequest_Success(t *testing.T) {
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the response.
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
	_, err = store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	newMsgs, err := store.GetMessages(context.Background(), out.NewSessionID, session.MessageListOptions{})
	if err != nil {
		t.Fatalf("get new session messages: %v", err)
	}
	var newSend, newRecv *session.Message
	for _, m := range newMsgs {
		switch m.Direction {
		case "send":
			newSend = m
		case "receive":
			newRecv = m
		}
	}
	if newSend == nil || newSend.Method != "POST" {
		method := ""
		if newSend != nil {
			method = newSend.Method
		}
		t.Errorf("recorded method = %q, want POST", method)
	}
	if newRecv == nil || newRecv.StatusCode != 200 {
		status := 0
		if newRecv != nil {
			status = newRecv.StatusCode
		}
		t.Errorf("recorded status = %d, want 200", status)
	}
}

func TestReplayRequest_OverrideHeaders(t *testing.T) {
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
			Headers:   map[string][]string{"Authorization": {"Bearer old-token"}, "Accept": {"text/html"}},
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_request",
		Arguments: map[string]any{
			"session_id": entry.Session.ID,
			"override_headers": map[string]any{
				"Authorization": "Bearer new-token",
				"X-New-Header":  "added",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received overridden headers.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}

	headers, ok := echo["headers"].(map[string]any)
	if !ok {
		t.Fatal("expected headers in echo response")
	}

	// Check Authorization was overridden.
	authValues, ok := headers["Authorization"].([]any)
	if !ok || len(authValues) == 0 {
		t.Fatal("expected Authorization header in echo response")
	}
	if authValues[0] != "Bearer new-token" {
		t.Errorf("Authorization = %q, want Bearer new-token", authValues[0])
	}

	// Check new header was added.
	newValues, ok := headers["X-New-Header"].([]any)
	if !ok || len(newValues) == 0 {
		t.Fatal("expected X-New-Header in echo response")
	}
	if newValues[0] != "added" {
		t.Errorf("X-New-Header = %q, want added", newValues[0])
	}

	// Check original Accept header was preserved.
	acceptValues, ok := headers["Accept"].([]any)
	if !ok || len(acceptValues) == 0 {
		t.Fatal("expected Accept header in echo response")
	}
	if acceptValues[0] != "text/html" {
		t.Errorf("Accept = %q, want text/html", acceptValues[0])
	}
}

func TestReplayRequest_OverrideBody(t *testing.T) {
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
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"original":"body"}`),
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())
	overrideBody := `{"override":"body"}`

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_request",
		Arguments: map[string]any{
			"session_id":    entry.Session.ID,
			"override_body": overrideBody,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received the overridden body.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}
	if echo["body"] != overrideBody {
		t.Errorf("echo body = %q, want %q", echo["body"], overrideBody)
	}

	// Verify the recorded session has the overridden body.
	_, err = store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	newSendMsgs, err := store.GetMessages(context.Background(), out.NewSessionID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("get send messages: %v", err)
	}
	if len(newSendMsgs) == 0 {
		t.Fatal("no send message in replay session")
	}
	if string(newSendMsgs[0].Body) != overrideBody {
		t.Errorf("recorded body = %q, want %q", newSendMsgs[0].Body, overrideBody)
	}
}

func TestReplayRequest_OverrideEmptyBody(t *testing.T) {
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
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"original":"body"}`),
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())
	emptyBody := ""

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_request",
		Arguments: map[string]any{
			"session_id":    entry.Session.ID,
			"override_body": emptyBody,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received an empty body.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}
	if echo["body"] != "" {
		t.Errorf("echo body = %q, want empty", echo["body"])
	}
}

func TestReplayRequest_OverrideURL(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	// Original URL points to a different path.
	u, _ := url.Parse(echoServer.URL + "/original-path")
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())
	overrideURL := echoServer.URL + "/overridden-path"

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_request",
		Arguments: map[string]any{
			"session_id":   entry.Session.ID,
			"override_url": overrideURL,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received the overridden URL path.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}
	if echo["url"] != "/overridden-path" {
		t.Errorf("echo url = %q, want /overridden-path", echo["url"])
	}

	// Verify recorded session has the overridden URL.
	_, err = store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	newSendMsgs, err := store.GetMessages(context.Background(), out.NewSessionID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("get send messages: %v", err)
	}
	if len(newSendMsgs) == 0 {
		t.Fatal("no send message in replay session")
	}
	if newSendMsgs[0].URL == nil || newSendMsgs[0].URL.Path != "/overridden-path" {
		path := ""
		if newSendMsgs[0].URL != nil {
			path = newSendMsgs[0].URL.Path
		}
		t.Errorf("recorded URL path = %q, want /overridden-path", path)
	}
}

func TestReplayRequest_OverrideMethod(t *testing.T) {
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_request",
		Arguments: map[string]any{
			"session_id":      entry.Session.ID,
			"override_method": "PUT",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received PUT method.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo response: %v", err)
	}
	if echo["method"] != "PUT" {
		t.Errorf("echo method = %q, want PUT", echo["method"])
	}

	// Verify recorded session has PUT method.
	_, err = store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	newSendMsgs, err := store.GetMessages(context.Background(), out.NewSessionID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("get send messages: %v", err)
	}
	if len(newSendMsgs) == 0 {
		t.Fatal("no send message in replay session")
	}
	if newSendMsgs[0].Method != "PUT" {
		t.Errorf("recorded method = %q, want PUT", newSendMsgs[0].Method)
	}
}

func TestReplayRequest_AllOverrides(t *testing.T) {
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
			Body:      nil,
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())
	overrideBody := `{"all":"overridden"}`
	overrideURL := echoServer.URL + "/new-path"

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_request",
		Arguments: map[string]any{
			"session_id":      entry.Session.ID,
			"override_method": "PATCH",
			"override_url":    overrideURL,
			"override_headers": map[string]any{
				"Content-Type": "application/json",
			},
			"override_body": overrideBody,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

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

func TestReplayRequest_NonexistentSession(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithReplayDoer(t, store, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": "nonexistent-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent session")
	}
}

func TestReplayRequest_EmptySessionID(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithReplayDoer(t, store, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": ""},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty session_id")
	}
}

func TestReplayRequest_NilStore(t *testing.T) {
	cs := setupTestSessionWithReplayDoer(t, nil, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": "some-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

func TestReplayRequest_InvalidOverrideURL(t *testing.T) {
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

	cs := setupTestSessionWithReplayDoer(t, store, nil)

	tests := []struct {
		name string
		url  string
	}{
		{
			name: "missing scheme",
			url:  "example.com/path",
		},
		{
			name: "relative path only",
			url:  "/just-a-path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "replay_request",
				Arguments: map[string]any{
					"session_id":   entry.Session.ID,
					"override_url": tt.url,
				},
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected IsError=true for invalid override_url %q", tt.url)
			}
		})
	}
}

func TestReplayRequest_NilOriginalURL(t *testing.T) {
	store := newTestStore(t)

	// Create an entry without a URL (nil URL).
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
			URL:       nil,
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

	cs := setupTestSessionWithReplayDoer(t, store, nil)

	// Without override_url, should fail because original URL is nil.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil original URL without override")
	}
}

func TestReplayRequest_NetworkError(t *testing.T) {
	store := newTestStore(t)

	// Point to a non-routable address to trigger a connection error.
	u, _ := url.Parse("http://192.0.2.1:1/unreachable")
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

	// Use an HTTP client with a very short timeout.
	shortTimeoutDoer := &http.Client{
		Timeout: 100 * time.Millisecond,
	}
	cs := setupTestSessionWithReplayDoer(t, store, shortTimeoutDoer)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for network error")
	}
}

func TestReplayRequest_PreservesProtocol(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTPS",
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the new session preserves the protocol from the original.
	newSess, err := store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	if newSess.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want HTTPS", newSess.Protocol)
	}
}

func TestReplayRequest_ResponseFieldsComplete(t *testing.T) {
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	// Verify JSON structure has all expected fields.
	textContent := result.Content[0].(*gomcp.TextContent)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(textContent.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	requiredFields := []string{
		"new_session_id",
		"status_code",
		"response_headers",
		"response_body",
		"response_body_encoding",
		"duration_ms",
	}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("response JSON missing required field %q", field)
		}
	}
}

func TestReplayRequest_ServerReturnsNon200(t *testing.T) {
	store := newTestStore(t)

	// Create a server that returns 500.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal server error")
	}))
	t.Cleanup(server.Close)

	u, _ := url.Parse(server.URL + "/api/test")
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// Non-200 responses are valid results, not errors.
	if result.IsError {
		t.Fatalf("expected success even for 500 response, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.StatusCode != 500 {
		t.Errorf("status_code = %d, want 500", out.StatusCode)
	}
	if out.ResponseBody != "internal server error" {
		t.Errorf("response_body = %q, want 'internal server error'", out.ResponseBody)
	}
}

// --- Security tests for S-1, S-2, S-3 ---

func TestReplayRequest_RejectsNonHTTPScheme(t *testing.T) {
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	tests := []struct {
		name string
		url  string
	}{
		{name: "file scheme", url: "file:///etc/passwd"},
		{name: "gopher scheme", url: "gopher://localhost:70/"},
		{name: "ftp scheme", url: "ftp://example.com/file"},
		{name: "javascript scheme", url: "javascript://example.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name: "replay_request",
				Arguments: map[string]any{
					"session_id":   entry.Session.ID,
					"override_url": tt.url,
				},
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected IsError=true for scheme in %q", tt.url)
			}
		})
	}
}

func TestReplayRequest_RejectsNonHTTPSchemeInOriginalURL(t *testing.T) {
	store := newTestStore(t)

	// Store a session with a file:// scheme URL.
	u, _ := url.Parse("file:///etc/passwd")
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for file:// scheme in original URL")
	}
}

func TestDenyPrivateNetwork(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{name: "loopback IPv4", address: "127.0.0.1:80", wantErr: true},
		{name: "loopback IPv6", address: "[::1]:80", wantErr: true},
		{name: "private 10.x", address: "10.0.0.1:80", wantErr: true},
		{name: "private 172.16.x", address: "172.16.0.1:80", wantErr: true},
		{name: "private 192.168.x", address: "192.168.1.1:80", wantErr: true},
		{name: "link-local IPv4", address: "169.254.169.254:80", wantErr: true},
		{name: "link-local IPv6", address: "[fe80::1]:80", wantErr: true},
		{name: "unspecified IPv4", address: "0.0.0.0:80", wantErr: true},
		{name: "unspecified IPv6", address: "[::]:80", wantErr: true},
		{name: "public IPv4", address: "93.184.216.34:80", wantErr: false},
		{name: "public IPv4 other", address: "8.8.8.8:53", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := denyPrivateNetwork("tcp", tt.address, nil)
			if tt.wantErr && err == nil {
				t.Errorf("denyPrivateNetwork(%q) = nil, want error", tt.address)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("denyPrivateNetwork(%q) = %v, want nil", tt.address, err)
			}
		})
	}
}

func TestReplayRequest_SSRFBlocksLoopback(t *testing.T) {
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

	// Use nil doer so the production SSRF-protected client is used.
	cs := setupTestSessionWithReplayDoer(t, store, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// The request should fail because the echo server is on loopback,
	// which is blocked by the SSRF protection.
	if !result.IsError {
		t.Fatal("expected IsError=true when replaying to loopback address")
	}
}

func TestValidateURLScheme(t *testing.T) {
	tests := []struct {
		scheme  string
		wantErr bool
	}{
		{"http", false},
		{"https", false},
		{"file", true},
		{"ftp", true},
		{"gopher", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			u := &url.URL{Scheme: tt.scheme, Host: "example.com"}
			err := validateURLScheme(u)
			if tt.wantErr && err == nil {
				t.Errorf("validateURLScheme(%q) = nil, want error", tt.scheme)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateURLScheme(%q) = %v, want nil", tt.scheme, err)
			}
		})
	}
}

func TestReplayRequest_ResponseBodySizeLimit(t *testing.T) {
	store := newTestStore(t)

	// Create a server that returns a body larger than 1MB.
	largeSize := maxReplayResponseSize + 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// Write a body larger than maxReplayResponseSize.
		w.Write(bytes.Repeat([]byte("A"), largeSize))
	}))
	t.Cleanup(server.Close)

	u, _ := url.Parse(server.URL + "/large-response")
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

	cs := setupTestSessionWithReplayDoer(t, store, newPermissiveClient())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_request",
		Arguments: map[string]any{"session_id": entry.Session.ID},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRequestResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// The response body should be truncated to maxReplayResponseSize (1MB).
	// Since the body is base64-encoded (non-UTF8 repeated 'A' bytes are actually UTF8,
	// so it will be text encoding), check the length.
	_, err = store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	newRecvMsgs, err := store.GetMessages(context.Background(), out.NewSessionID, session.MessageListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("get receive messages: %v", err)
	}
	if len(newRecvMsgs) == 0 {
		t.Fatal("no receive message in replay session")
	}
	if len(newRecvMsgs[0].Body) > maxReplayResponseSize {
		t.Errorf("response body size = %d, want <= %d", len(newRecvMsgs[0].Body), maxReplayResponseSize)
	}
	if len(newRecvMsgs[0].Body) != maxReplayResponseSize {
		t.Errorf("response body size = %d, want exactly %d (truncated by LimitReader)", len(newRecvMsgs[0].Body), maxReplayResponseSize)
	}
}

// --- replay_raw tests ---

// testDialer wraps a net.Dialer to satisfy the rawDialer interface for tests.
// It allows connections to localhost (bypassing SSRF protection).
type testDialer struct{}

func (d *testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
}

// setupTestSessionWithRawDialer creates an MCP client session with a custom raw dialer for replay_raw testing.
func setupTestSessionWithRawDialer(t *testing.T, store session.Store, dialer rawDialer) *gomcp.ClientSession {
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

// newRawEchoServer creates a TCP server that reads HTTP-like data and echoes back a simple response.
func newRawEchoServer(t *testing.T) (string, func()) {
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
			go func(c net.Conn) {
				defer c.Close()
				// Read the request.
				reader := bufio.NewReader(c)
				var reqBuf bytes.Buffer
				for {
					line, err := reader.ReadString('\n')
					reqBuf.WriteString(line)
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				// Send a simple response.
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-Echo: raw\r\n\r\nhello world"
				c.Write([]byte(resp))
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func TestReplayRaw_Success(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /raw-test HTTP/1.1\r\nHost: example.com\r\nX-Custom: preserved\r\n\r\n")

	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse(fmt.Sprintf("http://%s:%s/raw-test", host, port))

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

	cs := setupTestSessionWithRawDialer(t, store, &testDialer{})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_raw",
		Arguments: map[string]any{
			"session_id":  entry.Session.ID,
			"target_addr": addr,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out replayRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify we got a response.
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

func TestReplayRaw_NoRawBytes(t *testing.T) {
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

	cs := setupTestSessionWithRawDialer(t, store, &testDialer{})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_raw",
		Arguments: map[string]any{
			"session_id": entry.Session.ID,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for session without raw bytes")
	}
}

func TestReplayRaw_EmptySessionID(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithRawDialer(t, store, &testDialer{})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_raw",
		Arguments: map[string]any{"session_id": ""},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for empty session_id")
	}
}

func TestReplayRaw_NonexistentSession(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSessionWithRawDialer(t, store, &testDialer{})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_raw",
		Arguments: map[string]any{"session_id": "nonexistent-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent session")
	}
}

func TestReplayRaw_NilStore(t *testing.T) {
	cs := setupTestSessionWithRawDialer(t, nil, &testDialer{})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "replay_raw",
		Arguments: map[string]any{"session_id": "some-id"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

func TestReplayRaw_SSRFBlocksLoopback(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")
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

	// Use nil dialer so the production SSRF-protected dialer is used.
	cs := setupTestSessionWithRawDialer(t, store, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "replay_raw",
		Arguments: map[string]any{
			"session_id":  entry.Session.ID,
			"target_addr": addr,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when replaying to loopback address")
	}
}
