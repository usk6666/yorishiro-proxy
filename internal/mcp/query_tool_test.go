package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// setupQueryTestSession creates an MCP client session for query tool tests.
// It accepts optional ServerOption values for configuring scope, passthrough, etc.
func setupQueryTestSession(t *testing.T, store session.Store, opts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	s := NewServer(ctx, ca, store, nil, opts...)
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

// callQuery invokes the query tool and returns the raw CallToolResult.
func callQuery(t *testing.T, cs *gomcp.ClientSession, input queryInput) *gomcp.CallToolResult {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// unmarshalQueryResult extracts the JSON result from CallToolResult content.
func unmarshalQueryResult(t *testing.T, result *gomcp.CallToolResult, dest any) {
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

// seedSession creates a session and its messages in the store for testing.
func seedSession(t *testing.T, store session.Store, id, protocol, method, urlStr string, statusCode int) {
	t.Helper()
	ctx := context.Background()

	sess := &session.Session{
		ID:          id,
		ConnID:      "conn-" + id,
		Protocol:    protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    150 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)

	sendMsg := &session.Message{
		ID:        id + "-send",
		SessionID: id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    method,
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      []byte("request body"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	recvMsg := &session.Message{
		ID:         id + "-recv",
		SessionID:  id,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: statusCode,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"ok":true}`),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}
}

// --- Test: unknown and empty resource ---

func TestQuery_EmptyResource(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{})
	if !result.IsError {
		t.Fatal("expected IsError=true for empty resource")
	}
}

func TestQuery_UnknownResource(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "unknown"})
	if !result.IsError {
		t.Fatal("expected IsError=true for unknown resource")
	}
	// Verify error message includes available resources.
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	if !strings.Contains(text.Text, "sessions") || !strings.Contains(text.Text, "ca_cert") {
		t.Errorf("error message should list available resources, got: %s", text.Text)
	}
}

// --- Test: sessions resource ---

func TestQuery_Sessions_Empty(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "sessions"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 0 {
		t.Errorf("count = %d, want 0", out.Count)
	}
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
	if len(out.Sessions) != 0 {
		t.Errorf("sessions len = %d, want 0", len(out.Sessions))
	}
}

func TestQuery_Sessions_WithData(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "sess-1", "HTTPS", "GET", "https://example.com/api", 200)
	seedSession(t, store, "sess-2", "HTTP/1.x", "POST", "http://example.com/form", 302)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "sessions"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}

	// Verify fields are populated (sessions returned newest first).
	found := false
	for _, s := range out.Sessions {
		if s.ID == "sess-1" {
			found = true
			if s.Protocol != "HTTPS" {
				t.Errorf("protocol = %q, want HTTPS", s.Protocol)
			}
			if s.Method != "GET" {
				t.Errorf("method = %q, want GET", s.Method)
			}
			if s.StatusCode != 200 {
				t.Errorf("status_code = %d, want 200", s.StatusCode)
			}
			if s.MessageCount != 2 {
				t.Errorf("message_count = %d, want 2", s.MessageCount)
			}
			if s.SessionType != "unary" {
				t.Errorf("session_type = %q, want unary", s.SessionType)
			}
			if s.State != "complete" {
				t.Errorf("state = %q, want complete", s.State)
			}
		}
	}
	if !found {
		t.Error("sess-1 not found in results")
	}
}

func TestQuery_Sessions_WithFilter(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "sess-get", "HTTPS", "GET", "https://example.com/api", 200)
	seedSession(t, store, "sess-post", "HTTPS", "POST", "https://example.com/api", 201)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Filter:   &queryFilter{Method: "POST"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Sessions[0].ID != "sess-post" {
		t.Errorf("id = %q, want sess-post", out.Sessions[0].ID)
	}
}

func TestQuery_Sessions_Pagination(t *testing.T) {
	store := newTestStore(t)
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("sess-%d", i)
		seedSession(t, store, id, "HTTPS", "GET", "https://example.com/"+id, 200)
	}

	cs := setupQueryTestSession(t, store)

	// First page: limit 2, offset 0.
	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Limit:    2,
		Offset:   0,
	})
	if result.IsError {
		t.Fatalf("page 1: expected success, got error: %v", result.Content)
	}
	var page1 querySessionsResult
	unmarshalQueryResult(t, result, &page1)
	if page1.Count != 2 {
		t.Errorf("page 1 count = %d, want 2", page1.Count)
	}
	if page1.Total != 5 {
		t.Errorf("page 1 total = %d, want 5", page1.Total)
	}

	// Second page: limit 2, offset 2.
	result = callQuery(t, cs, queryInput{
		Resource: "sessions",
		Limit:    2,
		Offset:   2,
	})
	if result.IsError {
		t.Fatalf("page 2: expected success, got error: %v", result.Content)
	}
	var page2 querySessionsResult
	unmarshalQueryResult(t, result, &page2)
	if page2.Count != 2 {
		t.Errorf("page 2 count = %d, want 2", page2.Count)
	}
	if page2.Total != 5 {
		t.Errorf("page 2 total = %d, want 5", page2.Total)
	}
}

func TestQuery_Sessions_NegativeOffset(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Offset:   -1,
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for negative offset")
	}
}

func TestQuery_Sessions_NilStore(t *testing.T) {
	cs := setupQueryTestSession(t, nil)

	result := callQuery(t, cs, queryInput{Resource: "sessions"})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

// --- Test: session resource ---

func TestQuery_Session_Success(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "sess-detail", "HTTPS", "GET", "https://example.com/api/users", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "sess-detail",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionResult
	unmarshalQueryResult(t, result, &out)

	if out.ID != "sess-detail" {
		t.Errorf("id = %q, want sess-detail", out.ID)
	}
	if out.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want HTTPS", out.Protocol)
	}
	if out.Method != "GET" {
		t.Errorf("method = %q, want GET", out.Method)
	}
	if out.URL != "https://example.com/api/users" {
		t.Errorf("url = %q, want https://example.com/api/users", out.URL)
	}
	if out.ResponseStatusCode != 200 {
		t.Errorf("response_status_code = %d, want 200", out.ResponseStatusCode)
	}
	if out.RequestBodyEncoding != "text" {
		t.Errorf("request_body_encoding = %q, want text", out.RequestBodyEncoding)
	}
	if out.RequestBody != "request body" {
		t.Errorf("request_body = %q, want 'request body'", out.RequestBody)
	}
	if out.MessageCount != 2 {
		t.Errorf("message_count = %d, want 2", out.MessageCount)
	}
	if out.SessionType != "unary" {
		t.Errorf("session_type = %q, want unary", out.SessionType)
	}
}

func TestQuery_Session_MissingID(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "session"})
	if !result.IsError {
		t.Fatal("expected IsError=true for missing id")
	}
}

func TestQuery_Session_NotFound(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "nonexistent",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent session")
	}
}

func TestQuery_Session_NilStore(t *testing.T) {
	cs := setupQueryTestSession(t, nil)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "some-id",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

// --- Test: messages resource ---

func TestQuery_Messages_Success(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "sess-msgs", "HTTPS", "GET", "https://example.com/api", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "sess-msgs",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}

	// Verify message ordering by sequence.
	if len(out.Messages) != 2 {
		t.Fatalf("messages len = %d, want 2", len(out.Messages))
	}
	if out.Messages[0].Direction != "send" {
		t.Errorf("messages[0].direction = %q, want send", out.Messages[0].Direction)
	}
	if out.Messages[0].Method != "GET" {
		t.Errorf("messages[0].method = %q, want GET", out.Messages[0].Method)
	}
	if out.Messages[1].Direction != "receive" {
		t.Errorf("messages[1].direction = %q, want receive", out.Messages[1].Direction)
	}
	if out.Messages[1].StatusCode != 200 {
		t.Errorf("messages[1].status_code = %d, want 200", out.Messages[1].StatusCode)
	}
	if out.Messages[0].BodyEncoding != "text" {
		t.Errorf("messages[0].body_encoding = %q, want text", out.Messages[0].BodyEncoding)
	}
}

func TestQuery_Messages_Pagination(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &session.Session{
		ID:          "sess-many",
		Protocol:    "HTTPS",
		SessionType: "stream",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	// Create 5 messages.
	for i := 0; i < 5; i++ {
		msg := &session.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			SessionID: "sess-many",
			Sequence:  i,
			Direction: "send",
			Timestamp: time.Now().UTC(),
			Method:    "GET",
			Body:      []byte(fmt.Sprintf("body-%d", i)),
		}
		if err := store.AppendMessage(ctx, msg); err != nil {
			t.Fatalf("AppendMessage(%d): %v", i, err)
		}
	}

	cs := setupQueryTestSession(t, store)

	// Page 1: limit 2, offset 0.
	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "sess-many",
		Limit:    2,
		Offset:   0,
	})
	if result.IsError {
		t.Fatalf("page 1: expected success: %v", result.Content)
	}
	var page1 queryMessagesResult
	unmarshalQueryResult(t, result, &page1)
	if page1.Count != 2 {
		t.Errorf("page 1 count = %d, want 2", page1.Count)
	}
	if page1.Total != 5 {
		t.Errorf("page 1 total = %d, want 5", page1.Total)
	}

	// Page 2: limit 2, offset 2.
	result = callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "sess-many",
		Limit:    2,
		Offset:   2,
	})
	if result.IsError {
		t.Fatalf("page 2: expected success: %v", result.Content)
	}
	var page2 queryMessagesResult
	unmarshalQueryResult(t, result, &page2)
	if page2.Count != 2 {
		t.Errorf("page 2 count = %d, want 2", page2.Count)
	}

	// Page 3: offset beyond total.
	result = callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "sess-many",
		Limit:    2,
		Offset:   10,
	})
	if result.IsError {
		t.Fatalf("page 3: expected success: %v", result.Content)
	}
	var page3 queryMessagesResult
	unmarshalQueryResult(t, result, &page3)
	if page3.Count != 0 {
		t.Errorf("page 3 count = %d, want 0", page3.Count)
	}
	if page3.Total != 5 {
		t.Errorf("page 3 total = %d, want 5", page3.Total)
	}
}

func TestQuery_Messages_MissingID(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "messages"})
	if !result.IsError {
		t.Fatal("expected IsError=true for missing id")
	}
}

func TestQuery_Messages_SessionNotFound(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "nonexistent",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent session")
	}
}

func TestQuery_Messages_NegativeOffset(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "any",
		Offset:   -1,
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for negative offset")
	}
}

func TestQuery_Messages_NilStore(t *testing.T) {
	cs := setupQueryTestSession(t, nil)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "some-id",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

// --- Test: status resource ---

func TestQuery_Status_Basic(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "status"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryStatusResult
	unmarshalQueryResult(t, result, &out)

	// No manager configured, so proxy should not be running.
	if out.Running {
		t.Error("running = true, want false")
	}
	if out.TotalSessions != 0 {
		t.Errorf("total_sessions = %d, want 0", out.TotalSessions)
	}
	// CA is initialized in setupQueryTestSession.
	if !out.CAInitialized {
		t.Error("ca_initialized = false, want true")
	}
}

func TestQuery_Status_WithSessions(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "s1", "HTTPS", "GET", "https://example.com", 200)
	seedSession(t, store, "s2", "HTTPS", "POST", "https://example.com", 201)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "status"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryStatusResult
	unmarshalQueryResult(t, result, &out)

	if out.TotalSessions != 2 {
		t.Errorf("total_sessions = %d, want 2", out.TotalSessions)
	}
}

// --- Test: config resource ---

func TestQuery_Config_Default(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)

	// No scope/passthrough configured, should have empty defaults.
	if out.CaptureScope == nil {
		t.Fatal("capture_scope is nil")
	}
	if len(out.CaptureScope.Includes) != 0 {
		t.Errorf("includes len = %d, want 0", len(out.CaptureScope.Includes))
	}
	if len(out.CaptureScope.Excludes) != 0 {
		t.Errorf("excludes len = %d, want 0", len(out.CaptureScope.Excludes))
	}
	if out.TLSPassthrough == nil {
		t.Fatal("tls_passthrough is nil")
	}
	if out.TLSPassthrough.Count != 0 {
		t.Errorf("tls_passthrough.count = %d, want 0", out.TLSPassthrough.Count)
	}
}

func TestQuery_Config_WithScopeAndPassthrough(t *testing.T) {
	store := newTestStore(t)
	scope := proxy.NewCaptureScope()
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "target.com"}},
		[]proxy.ScopeRule{{Hostname: "excluded.com"}},
	)
	pl := proxy.NewPassthroughList()
	pl.Add("pinned.example.com")
	pl.Add("*.cdn.example.com")

	cs := setupQueryTestSession(t, store,
		WithCaptureScope(scope),
		WithPassthroughList(pl),
	)

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)

	if len(out.CaptureScope.Includes) != 1 {
		t.Errorf("includes len = %d, want 1", len(out.CaptureScope.Includes))
	}
	if out.CaptureScope.Includes[0].Hostname != "target.com" {
		t.Errorf("includes[0].hostname = %q, want target.com", out.CaptureScope.Includes[0].Hostname)
	}
	if len(out.CaptureScope.Excludes) != 1 {
		t.Errorf("excludes len = %d, want 1", len(out.CaptureScope.Excludes))
	}
	if out.TLSPassthrough.Count != 2 {
		t.Errorf("tls_passthrough.count = %d, want 2", out.TLSPassthrough.Count)
	}
	// Patterns should be sorted.
	if len(out.TLSPassthrough.Patterns) == 2 {
		if out.TLSPassthrough.Patterns[0] != "*.cdn.example.com" {
			t.Errorf("patterns[0] = %q, want *.cdn.example.com", out.TLSPassthrough.Patterns[0])
		}
		if out.TLSPassthrough.Patterns[1] != "pinned.example.com" {
			t.Errorf("patterns[1] = %q, want pinned.example.com", out.TLSPassthrough.Patterns[1])
		}
	}
}

// --- Test: ca_cert resource ---

func TestQuery_CACert_Success(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)

	// Build server with the CA directly.
	ctx := context.Background()
	s := NewServer(ctx, ca, store, nil)
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

	result := callQuery(t, cs, queryInput{Resource: "ca_cert"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryCACertResult
	unmarshalQueryResult(t, result, &out)

	if out.PEM == "" {
		t.Error("pem is empty")
	}
	if out.Subject == "" {
		t.Error("subject is empty")
	}
	if out.NotAfter == "" {
		t.Error("not_after is empty")
	}

	// Verify fingerprint.
	expectedFingerprint := sha256.Sum256(ca.Certificate().Raw)
	expectedFingerprintStr := formatFingerprint(expectedFingerprint[:])
	if out.Fingerprint != expectedFingerprintStr {
		t.Errorf("fingerprint = %q, want %q", out.Fingerprint, expectedFingerprintStr)
	}
}

func TestQuery_CACert_NilCA(t *testing.T) {
	// Build server without CA.
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

	result := callQuery(t, cs, queryInput{Resource: "ca_cert"})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil CA")
	}
}

// --- Test: sessions filter combinations ---

func TestQuery_Sessions_FilterByProtocol(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "https-1", "HTTPS", "GET", "https://example.com", 200)
	seedSession(t, store, "http-1", "HTTP/1.x", "GET", "http://example.com", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Filter:   &queryFilter{Protocol: "HTTPS"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Sessions[0].Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want HTTPS", out.Sessions[0].Protocol)
	}
}

func TestQuery_Sessions_FilterByURLPattern(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "api-1", "HTTPS", "GET", "https://example.com/api/users", 200)
	seedSession(t, store, "page-1", "HTTPS", "GET", "https://example.com/pages/home", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Filter:   &queryFilter{URLPattern: "/api/"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Sessions[0].ID != "api-1" {
		t.Errorf("id = %q, want api-1", out.Sessions[0].ID)
	}
}

func TestQuery_Sessions_FilterByStatusCode(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "ok-1", "HTTPS", "GET", "https://example.com/ok", 200)
	seedSession(t, store, "err-1", "HTTPS", "GET", "https://example.com/error", 500)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Filter:   &queryFilter{StatusCode: 500},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Sessions[0].ID != "err-1" {
		t.Errorf("id = %q, want err-1", out.Sessions[0].ID)
	}
}

// --- Test: ca_cert resource with persisted source ---

func TestQuery_CACert_PersistedFields(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	ca.SetSource(cert.CASource{
		Persisted: true,
		CertPath:  "/tmp/test/ca.crt",
		KeyPath:   "/tmp/test/ca.key",
	})

	ctx := context.Background()
	s := NewServer(ctx, ca, store, nil)
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

	result := callQuery(t, cs, queryInput{Resource: "ca_cert"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryCACertResult
	unmarshalQueryResult(t, result, &out)

	if !out.Persisted {
		t.Error("persisted = false, want true")
	}
	if out.CertPath != "/tmp/test/ca.crt" {
		t.Errorf("cert_path = %q, want /tmp/test/ca.crt", out.CertPath)
	}
	if out.InstallHint == "" {
		t.Error("install_hint should not be empty for persisted CA")
	}
	if !strings.Contains(out.InstallHint, "/tmp/test/ca.crt") {
		t.Errorf("install_hint = %q, should contain cert path", out.InstallHint)
	}
}

func TestQuery_CACert_EphemeralFields(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	// No SetSource — defaults to ephemeral (Persisted=false).

	ctx := context.Background()
	s := NewServer(ctx, ca, store, nil)
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

	result := callQuery(t, cs, queryInput{Resource: "ca_cert"})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryCACertResult
	unmarshalQueryResult(t, result, &out)

	if out.Persisted {
		t.Error("persisted = true, want false for ephemeral CA")
	}
	if out.CertPath != "" {
		t.Errorf("cert_path = %q, want empty for ephemeral CA", out.CertPath)
	}
	if out.InstallHint != "" {
		t.Errorf("install_hint = %q, want empty for ephemeral CA", out.InstallHint)
	}
}

// --- Test: blocked_by in sessions and session resources ---

// seedBlockedSession creates a blocked session with only a send message (no response).
func seedBlockedSession(t *testing.T, store session.Store, id, protocol, method, urlStr, blockedBy string) {
	t.Helper()
	ctx := context.Background()

	sess := &session.Session{
		ID:          id,
		ConnID:      "conn-" + id,
		Protocol:    protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    0,
		BlockedBy:   blockedBy,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)
	sendMsg := &session.Message{
		ID:        id + "-send",
		SessionID: id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    method,
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {"evil.com"}},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}
}

func TestQuery_Sessions_FilterByBlockedBy(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "normal-1", "HTTPS", "GET", "https://example.com/ok", 200)
	seedBlockedSession(t, store, "blocked-1", "HTTPS", "GET", "https://evil.com/admin", "target_scope")
	seedBlockedSession(t, store, "blocked-2", "HTTPS", "POST", "https://evil.com/api", "target_scope")

	cs := setupQueryTestSession(t, store)

	// Filter for blocked sessions only.
	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Filter:   &queryFilter{BlockedBy: "target_scope"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}
	for _, s := range out.Sessions {
		if s.BlockedBy != "target_scope" {
			t.Errorf("session %s blocked_by = %q, want %q", s.ID, s.BlockedBy, "target_scope")
		}
	}
}

func TestQuery_Sessions_BlockedByFieldInResponse(t *testing.T) {
	store := newTestStore(t)
	seedBlockedSession(t, store, "blocked-resp", "HTTPS", "GET", "https://evil.com/secret", "target_scope")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "sessions"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	if out.Sessions[0].BlockedBy != "target_scope" {
		t.Errorf("blocked_by = %q, want %q", out.Sessions[0].BlockedBy, "target_scope")
	}
}

func TestQuery_Sessions_NormalSessionHasEmptyBlockedBy(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "normal-check", "HTTPS", "GET", "https://example.com/page", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "sessions"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	if out.Sessions[0].BlockedBy != "" {
		t.Errorf("blocked_by = %q, want empty string", out.Sessions[0].BlockedBy)
	}
}

func TestQuery_Session_BlockedByInDetail(t *testing.T) {
	store := newTestStore(t)
	seedBlockedSession(t, store, "blocked-detail", "HTTPS", "GET", "https://evil.com/admin", "target_scope")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "blocked-detail",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionResult
	unmarshalQueryResult(t, result, &out)

	if out.ID != "blocked-detail" {
		t.Errorf("id = %q, want blocked-detail", out.ID)
	}
	if out.BlockedBy != "target_scope" {
		t.Errorf("blocked_by = %q, want %q", out.BlockedBy, "target_scope")
	}
	if out.Method != "GET" {
		t.Errorf("method = %q, want GET", out.Method)
	}
	if out.URL != "https://evil.com/admin" {
		t.Errorf("url = %q, want https://evil.com/admin", out.URL)
	}
	// Blocked session has no response.
	if out.ResponseStatusCode != 0 {
		t.Errorf("response_status_code = %d, want 0", out.ResponseStatusCode)
	}
	if out.MessageCount != 1 {
		t.Errorf("message_count = %d, want 1 (send only)", out.MessageCount)
	}
}

func TestQuery_Session_NormalHasNoBlockedBy(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "normal-detail", "HTTPS", "GET", "https://example.com/ok", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "normal-detail",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionResult
	unmarshalQueryResult(t, result, &out)

	if out.BlockedBy != "" {
		t.Errorf("blocked_by = %q, want empty string", out.BlockedBy)
	}
}

// --- Test: state filter ---

// seedSessionWithState creates a session with a specific state and messages.
func seedSessionWithState(t *testing.T, store session.Store, id, protocol, method, urlStr, state string, statusCode int) {
	t.Helper()
	ctx := context.Background()

	sess := &session.Session{
		ID:          id,
		ConnID:      "conn-" + id,
		Protocol:    protocol,
		SessionType: "unary",
		State:       state,
		Timestamp:   time.Now().UTC(),
		Duration:    100 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)
	sendMsg := &session.Message{
		ID:        id + "-send",
		SessionID: id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    method,
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      []byte("request body"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	if statusCode > 0 {
		recvMsg := &session.Message{
			ID:         id + "-recv",
			SessionID:  id,
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now().UTC(),
			StatusCode: statusCode,
			Headers:    map[string][]string{"Content-Type": {"text/plain"}},
			Body:       []byte("response body"),
		}
		if err := store.AppendMessage(ctx, recvMsg); err != nil {
			t.Fatalf("AppendMessage(recv): %v", err)
		}
	}
}

func TestQuery_Sessions_FilterByState(t *testing.T) {
	store := newTestStore(t)
	seedSessionWithState(t, store, "active-1", "HTTPS", "GET", "https://example.com/a", "active", 0)
	seedSessionWithState(t, store, "complete-1", "HTTPS", "GET", "https://example.com/b", "complete", 200)
	seedSessionWithState(t, store, "error-1", "HTTPS", "GET", "https://example.com/c", "error", 0)
	seedSessionWithState(t, store, "complete-2", "HTTPS", "POST", "https://example.com/d", "complete", 201)

	cs := setupQueryTestSession(t, store)

	tests := []struct {
		name      string
		state     string
		wantCount int
	}{
		{"active only", "active", 1},
		{"complete only", "complete", 2},
		{"error only", "error", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := callQuery(t, cs, queryInput{
				Resource: "sessions",
				Filter:   &queryFilter{State: tt.state},
			})
			if result.IsError {
				t.Fatalf("expected success, got error: %v", result.Content)
			}

			var out querySessionsResult
			unmarshalQueryResult(t, result, &out)

			if out.Count != tt.wantCount {
				t.Errorf("count = %d, want %d", out.Count, tt.wantCount)
			}
			if out.Total != tt.wantCount {
				t.Errorf("total = %d, want %d", out.Total, tt.wantCount)
			}
			for _, s := range out.Sessions {
				if s.State != tt.state {
					t.Errorf("session %s state = %q, want %q", s.ID, s.State, tt.state)
				}
			}
		})
	}
}

func TestQuery_Session_ErrorStateNoResponse(t *testing.T) {
	store := newTestStore(t)
	// Error session with send only (no receive)
	seedSessionWithState(t, store, "err-sess", "HTTPS", "POST", "https://example.com/fail", "error", 0)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "err-sess",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionResult
	unmarshalQueryResult(t, result, &out)

	if out.State != "error" {
		t.Errorf("state = %q, want %q", out.State, "error")
	}
	if out.ResponseStatusCode != 0 {
		t.Errorf("response_status_code = %d, want 0", out.ResponseStatusCode)
	}
	if out.MessageCount != 1 {
		t.Errorf("message_count = %d, want 1", out.MessageCount)
	}
}

// --- Test: variant messages ---

// seedVariantSession creates a session with original and modified variant send messages.
func seedVariantSession(t *testing.T, store session.Store, id string) {
	t.Helper()
	ctx := context.Background()

	sess := &session.Session{
		ID:          id,
		ConnID:      "conn-" + id,
		Protocol:    "HTTPS",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    200 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession(%s): %v", id, err)
	}

	origURL, _ := url.Parse("https://example.com/original")
	originalSend := &session.Message{
		ID:        id + "-send-orig",
		SessionID: id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       origURL,
		Headers:   map[string][]string{"Host": {"example.com"}, "X-Original": {"true"}},
		Body:      []byte("original body"),
		Metadata:  map[string]string{"variant": "original"},
	}
	if err := store.AppendMessage(ctx, originalSend); err != nil {
		t.Fatalf("AppendMessage(original send): %v", err)
	}

	modURL, _ := url.Parse("https://example.com/modified")
	modifiedSend := &session.Message{
		ID:        id + "-send-mod",
		SessionID: id,
		Sequence:  1,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       modURL,
		Headers:   map[string][]string{"Host": {"example.com"}, "X-Modified": {"true"}},
		Body:      []byte("modified body"),
		Metadata:  map[string]string{"variant": "modified"},
	}
	if err := store.AppendMessage(ctx, modifiedSend); err != nil {
		t.Fatalf("AppendMessage(modified send): %v", err)
	}

	recvMsg := &session.Message{
		ID:         id + "-recv",
		SessionID:  id,
		Sequence:   2,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"ok":true}`),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}
}

func TestQuery_Session_VariantMessages(t *testing.T) {
	store := newTestStore(t)
	seedVariantSession(t, store, "variant-sess")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "variant-sess",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionResult
	unmarshalQueryResult(t, result, &out)

	// The effective request should be the modified version.
	if out.Method != "POST" {
		t.Errorf("method = %q, want POST (modified)", out.Method)
	}
	if out.URL != "https://example.com/modified" {
		t.Errorf("url = %q, want https://example.com/modified", out.URL)
	}
	if out.RequestBody != "modified body" {
		t.Errorf("request_body = %q, want 'modified body'", out.RequestBody)
	}

	// Original request should be populated.
	if out.OriginalRequest == nil {
		t.Fatal("original_request is nil, expected original variant data")
	}
	if out.OriginalRequest.Method != "GET" {
		t.Errorf("original_request.method = %q, want GET", out.OriginalRequest.Method)
	}
	if out.OriginalRequest.URL != "https://example.com/original" {
		t.Errorf("original_request.url = %q, want https://example.com/original", out.OriginalRequest.URL)
	}
	if out.OriginalRequest.Body != "original body" {
		t.Errorf("original_request.body = %q, want 'original body'", out.OriginalRequest.Body)
	}

	// Response should still be present.
	if out.ResponseStatusCode != 200 {
		t.Errorf("response_status_code = %d, want 200", out.ResponseStatusCode)
	}
	if out.MessageCount != 3 {
		t.Errorf("message_count = %d, want 3", out.MessageCount)
	}
}

func TestQuery_Session_NoVariantMessages(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "normal-sess", "HTTPS", "GET", "https://example.com/normal", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "session",
		ID:       "normal-sess",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionResult
	unmarshalQueryResult(t, result, &out)

	// No variant, so original_request should be nil.
	if out.OriginalRequest != nil {
		t.Errorf("original_request should be nil for non-variant session, got %+v", out.OriginalRequest)
	}
}

func TestQuery_Sessions_VariantUsesModifiedMethod(t *testing.T) {
	store := newTestStore(t)
	seedVariantSession(t, store, "variant-list")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}

	// The sessions list should use the modified method/URL.
	if out.Sessions[0].Method != "POST" {
		t.Errorf("method = %q, want POST (modified)", out.Sessions[0].Method)
	}
	if out.Sessions[0].URL != "https://example.com/modified" {
		t.Errorf("url = %q, want https://example.com/modified", out.Sessions[0].URL)
	}
}

// --- Test: intercept_drop blocked_by filter ---

func TestQuery_Sessions_FilterByInterceptDrop(t *testing.T) {
	store := newTestStore(t)
	seedSession(t, store, "normal", "HTTPS", "GET", "https://example.com/ok", 200)
	seedBlockedSession(t, store, "dropped", "HTTPS", "GET", "https://example.com/drop", "intercept_drop")
	seedBlockedSession(t, store, "scoped", "HTTPS", "GET", "https://evil.com/admin", "target_scope")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "sessions",
		Filter:   &queryFilter{BlockedBy: "intercept_drop"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out querySessionsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Sessions[0].ID != "dropped" {
		t.Errorf("id = %q, want dropped", out.Sessions[0].ID)
	}
	if out.Sessions[0].BlockedBy != "intercept_drop" {
		t.Errorf("blocked_by = %q, want intercept_drop", out.Sessions[0].BlockedBy)
	}
}

