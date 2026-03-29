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
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// setupQueryTestSession creates an MCP client session for query tool tests.
// It accepts optional ServerOption values for configuring scope, passthrough, etc.
func setupQueryTestSession(t *testing.T, store flow.Store, opts ...ServerOption) *gomcp.ClientSession {
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

// seedSession creates a flow and its messages in the store for testing.
func seedSession(t *testing.T, store flow.Store, id, protocol, method, urlStr string, statusCode int) {
	t.Helper()
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  150 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)

	sendMsg := &flow.Message{
		ID:        id + "-send",
		FlowID:    id,
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

	recvMsg := &flow.Message{
		ID:         id + "-recv",
		FlowID:     id,
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
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{})
	if !result.IsError {
		t.Fatal("expected IsError=true for empty resource")
	}
}

func TestQuery_UnknownResource(t *testing.T) {
	t.Parallel()
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
	if !strings.Contains(text.Text, "flows") || !strings.Contains(text.Text, "ca_cert") {
		t.Errorf("error message should list available resources, got: %s", text.Text)
	}
}

// --- Test: sessions resource ---

func TestQuery_Sessions_Empty(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 0 {
		t.Errorf("count = %d, want 0", out.Count)
	}
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
	if len(out.Flows) != 0 {
		t.Errorf("sessions len = %d, want 0", len(out.Flows))
	}
}

func TestQuery_Sessions_WithData(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "sess-1", "HTTPS", "GET", "https://example.com/api", 200)
	seedSession(t, store, "sess-2", "HTTP/1.x", "POST", "http://example.com/form", 302)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}

	// Verify fields are populated (sessions returned newest first).
	found := false
	for _, s := range out.Flows {
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
			if s.FlowType != "unary" {
				t.Errorf("flow_type = %q, want unary", s.FlowType)
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
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "sess-get", "HTTPS", "GET", "https://example.com/api", 200)
	seedSession(t, store, "sess-post", "HTTPS", "POST", "https://example.com/api", 201)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Method: "POST"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Flows[0].ID != "sess-post" {
		t.Errorf("id = %q, want sess-post", out.Flows[0].ID)
	}
}

func TestQuery_Sessions_Pagination(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("sess-%d", i)
		seedSession(t, store, id, "HTTPS", "GET", "https://example.com/"+id, 200)
	}

	cs := setupQueryTestSession(t, store)

	// First page: limit 2, offset 0.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Limit:    2,
		Offset:   0,
	})
	if result.IsError {
		t.Fatalf("page 1: expected success, got error: %v", result.Content)
	}
	var page1 queryFlowsResult
	unmarshalQueryResult(t, result, &page1)
	if page1.Count != 2 {
		t.Errorf("page 1 count = %d, want 2", page1.Count)
	}
	if page1.Total != 5 {
		t.Errorf("page 1 total = %d, want 5", page1.Total)
	}

	// Second page: limit 2, offset 2.
	result = callQuery(t, cs, queryInput{
		Resource: "flows",
		Limit:    2,
		Offset:   2,
	})
	if result.IsError {
		t.Fatalf("page 2: expected success, got error: %v", result.Content)
	}
	var page2 queryFlowsResult
	unmarshalQueryResult(t, result, &page2)
	if page2.Count != 2 {
		t.Errorf("page 2 count = %d, want 2", page2.Count)
	}
	if page2.Total != 5 {
		t.Errorf("page 2 total = %d, want 5", page2.Total)
	}
}

func TestQuery_Sessions_NegativeOffset(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Offset:   -1,
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for negative offset")
	}
}

func TestQuery_Sessions_NilStore(t *testing.T) {
	t.Parallel()
	cs := setupQueryTestSession(t, nil)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

// --- Test: flow resource ---

func TestQuery_Session_Success(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "sess-detail", "HTTPS", "GET", "https://example.com/api/users", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "sess-detail",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
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
	if out.FlowType != "unary" {
		t.Errorf("flow_type = %q, want unary", out.FlowType)
	}
}

func TestQuery_Session_MissingID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flow"})
	if !result.IsError {
		t.Fatal("expected IsError=true for missing id")
	}
}

func TestQuery_Session_NotFound(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "nonexistent",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent session")
	}
}

func TestQuery_Session_NilStore(t *testing.T) {
	t.Parallel()
	cs := setupQueryTestSession(t, nil)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "some-id",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil store")
	}
}

func TestQuery_Session_NilHeaders_ReturnsEmptyMap(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow with only a send message (no receive message),
	// simulating a gRPC flow interrupted before receiving a response.
	fl := &flow.Flow{
		ID:        "nil-headers",
		ConnID:    "conn-nil-headers",
		Protocol:  "gRPC",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	parsedURL, _ := url.Parse("https://example.com/grpc.Service/Method")
	sendMsg := &flow.Message{
		ID:        "nil-headers-send",
		FlowID:    "nil-headers",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       parsedURL,
		Headers:   map[string][]string{"Content-Type": {"application/grpc"}},
		Body:      []byte("request"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	cs := setupQueryTestSession(t, store)
	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "nil-headers",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	// response_headers must be an empty map, not null.
	if out.ResponseHeaders == nil {
		t.Error("response_headers is nil, want empty map")
	}
	if len(out.ResponseHeaders) != 0 {
		t.Errorf("response_headers has %d entries, want 0", len(out.ResponseHeaders))
	}
	// request_headers should be populated from the send message.
	if out.RequestHeaders == nil {
		t.Error("request_headers is nil, want non-nil map")
	}
}

func TestQuery_Session_NoMessages_ReturnsEmptyHeaders(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow with no messages at all.
	fl := &flow.Flow{
		ID:        "no-msgs",
		ConnID:    "conn-no-msgs",
		Protocol:  "HTTP",
		FlowType:  "unary",
		State:     "active",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	cs := setupQueryTestSession(t, store)
	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "no-msgs",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	// Both headers must be empty maps, not null.
	if out.RequestHeaders == nil {
		t.Error("request_headers is nil, want empty map")
	}
	if out.ResponseHeaders == nil {
		t.Error("response_headers is nil, want empty map")
	}
}

// --- Test: messages resource ---

func TestQuery_Messages_Success(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        "sess-many",
		Protocol:  "HTTPS",
		FlowType:  "stream",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Create 5 messages.
	for i := 0; i < 5; i++ {
		msg := &flow.Message{
			ID:        fmt.Sprintf("msg-%d", i),
			FlowID:    "sess-many",
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
	t.Parallel()
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "messages"})
	if !result.IsError {
		t.Fatal("expected IsError=true for missing id")
	}
}

func TestQuery_Messages_SessionNotFound(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	if out.TotalFlows != 0 {
		t.Errorf("total_flows = %d, want 0", out.TotalFlows)
	}
	// CA is initialized in setupQueryTestSession.
	if !out.CAInitialized {
		t.Error("ca_initialized = false, want true")
	}
}

func TestQuery_Status_WithSessions(t *testing.T) {
	t.Parallel()
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

	if out.TotalFlows != 2 {
		t.Errorf("total_flows = %d, want 2", out.TotalFlows)
	}
}

// --- Test: config resource ---

func TestQuery_Config_Default(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestQuery_Config_WithManagerFields(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { manager.Stop(context.Background()) })

	// Set non-default values so we can verify them.
	manager.SetMaxConnections(512)
	manager.SetPeekTimeout(5 * time.Second)

	ca := newTestCA(t)
	s := NewServer(ctx, ca, store, manager)
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

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)

	if out.MaxConnections != 512 {
		t.Errorf("max_connections = %d, want 512", out.MaxConnections)
	}
	if out.PeekTimeoutMs != 5000 {
		t.Errorf("peek_timeout_ms = %d, want 5000", out.PeekTimeoutMs)
	}
	// request_timeout_ms should have the default value (60000) when no handler is registered.
	if out.RequestTimeoutMs != 60000 {
		t.Errorf("request_timeout_ms = %d, want 60000", out.RequestTimeoutMs)
	}
	if out.TLSFingerprint != "chrome" {
		t.Errorf("tls_fingerprint = %q, want %q", out.TLSFingerprint, "chrome")
	}
}

func TestQuery_Config_DefaultManagerValues(t *testing.T) {
	t.Parallel()
	// When manager is nil, max_connections and peek_timeout_ms should be zero.
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)

	if out.MaxConnections != 0 {
		t.Errorf("max_connections = %d, want 0 (no manager)", out.MaxConnections)
	}
	if out.PeekTimeoutMs != 0 {
		t.Errorf("peek_timeout_ms = %d, want 0 (no manager)", out.PeekTimeoutMs)
	}
	// request_timeout_ms should still have the default.
	if out.RequestTimeoutMs != 60000 {
		t.Errorf("request_timeout_ms = %d, want 60000", out.RequestTimeoutMs)
	}
	if out.TLSFingerprint != "chrome" {
		t.Errorf("tls_fingerprint = %q, want %q", out.TLSFingerprint, "chrome")
	}
}

// --- Test: ca_cert resource ---

func TestQuery_CACert_Success(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "https-1", "HTTPS", "GET", "https://example.com", 200)
	seedSession(t, store, "http-1", "HTTP/1.x", "GET", "http://example.com", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Protocol: "HTTPS"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want HTTPS", out.Flows[0].Protocol)
	}
}

func TestQuery_Sessions_FilterByURLPattern(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "api-1", "HTTPS", "GET", "https://example.com/api/users", 200)
	seedSession(t, store, "page-1", "HTTPS", "GET", "https://example.com/pages/home", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{URLPattern: "/api/"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].ID != "api-1" {
		t.Errorf("id = %q, want api-1", out.Flows[0].ID)
	}
}

func TestQuery_Sessions_FilterByStatusCode(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "ok-1", "HTTPS", "GET", "https://example.com/ok", 200)
	seedSession(t, store, "err-1", "HTTPS", "GET", "https://example.com/error", 500)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{StatusCode: 500},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].ID != "err-1" {
		t.Errorf("id = %q, want err-1", out.Flows[0].ID)
	}
}

// --- Test: ca_cert resource with persisted source ---

func TestQuery_CACert_PersistedFields(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// --- Test: blocked_by in sessions and flow resources ---

// seedBlockedSession creates a blocked flow with only a send message (no response).
func seedBlockedSession(t *testing.T, store flow.Store, id, protocol, method, urlStr, blockedBy string) {
	t.Helper()
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  0,
		BlockedBy: blockedBy,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)
	sendMsg := &flow.Message{
		ID:        id + "-send",
		FlowID:    id,
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
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "normal-1", "HTTPS", "GET", "https://example.com/ok", 200)
	seedBlockedSession(t, store, "blocked-1", "HTTPS", "GET", "https://evil.com/admin", "target_scope")
	seedBlockedSession(t, store, "blocked-2", "HTTPS", "POST", "https://evil.com/api", "target_scope")

	cs := setupQueryTestSession(t, store)

	// Filter for blocked sessions only.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{BlockedBy: "target_scope"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}
	for _, s := range out.Flows {
		if s.BlockedBy != "target_scope" {
			t.Errorf("flow %s blocked_by = %q, want %q", s.ID, s.BlockedBy, "target_scope")
		}
	}
}

func TestQuery_Sessions_BlockedByFieldInResponse(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedBlockedSession(t, store, "blocked-resp", "HTTPS", "GET", "https://evil.com/secret", "target_scope")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].BlockedBy != "target_scope" {
		t.Errorf("blocked_by = %q, want %q", out.Flows[0].BlockedBy, "target_scope")
	}
}

func TestQuery_Sessions_NormalSessionHasEmptyBlockedBy(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "normal-check", "HTTPS", "GET", "https://example.com/page", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].BlockedBy != "" {
		t.Errorf("blocked_by = %q, want empty string", out.Flows[0].BlockedBy)
	}
}

func TestQuery_Session_BlockedByInDetail(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedBlockedSession(t, store, "blocked-detail", "HTTPS", "GET", "https://evil.com/admin", "target_scope")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "blocked-detail",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
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
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "normal-detail", "HTTPS", "GET", "https://example.com/ok", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "normal-detail",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	if out.BlockedBy != "" {
		t.Errorf("blocked_by = %q, want empty string", out.BlockedBy)
	}
}

// --- Test: state filter ---

// seedSessionWithState creates a session with a specific state and messages.
func seedSessionWithState(t *testing.T, store flow.Store, id, protocol, method, urlStr, state string, statusCode int) {
	t.Helper()
	ctx := context.Background()

	sess := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		FlowType:  "unary",
		State:     state,
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, sess); err != nil {
		t.Fatalf("SaveSession(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)
	sendMsg := &flow.Message{
		ID:        id + "-send",
		FlowID:    id,
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
		recvMsg := &flow.Message{
			ID:         id + "-recv",
			FlowID:     id,
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
	t.Parallel()
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
				Resource: "flows",
				Filter:   &queryFilter{State: tt.state},
			})
			if result.IsError {
				t.Fatalf("expected success, got error: %v", result.Content)
			}

			var out queryFlowsResult
			unmarshalQueryResult(t, result, &out)

			if out.Count != tt.wantCount {
				t.Errorf("count = %d, want %d", out.Count, tt.wantCount)
			}
			if out.Total != tt.wantCount {
				t.Errorf("total = %d, want %d", out.Total, tt.wantCount)
			}
			for _, s := range out.Flows {
				if s.State != tt.state {
					t.Errorf("session %s state = %q, want %q", s.ID, s.State, tt.state)
				}
			}
		})
	}
}

func TestQuery_Session_ErrorStateNoResponse(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	// Error session with send only (no receive)
	seedSessionWithState(t, store, "err-sess", "HTTPS", "POST", "https://example.com/fail", "error", 0)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "err-sess",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
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
func seedVariantSession(t *testing.T, store flow.Store, id string) {
	t.Helper()
	ctx := context.Background()

	sess := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  200 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, sess); err != nil {
		t.Fatalf("SaveSession(%s): %v", id, err)
	}

	origURL, _ := url.Parse("https://example.com/original")
	originalSend := &flow.Message{
		ID:        id + "-send-orig",
		FlowID:    id,
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
	modifiedSend := &flow.Message{
		ID:        id + "-send-mod",
		FlowID:    id,
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

	recvMsg := &flow.Message{
		ID:         id + "-recv",
		FlowID:     id,
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
	t.Parallel()
	store := newTestStore(t)
	seedVariantSession(t, store, "variant-sess")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "variant-sess",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
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
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "normal-sess", "HTTPS", "GET", "https://example.com/normal", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "normal-sess",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	// No variant, so original_request should be nil.
	if out.OriginalRequest != nil {
		t.Errorf("original_request should be nil for non-variant session, got %+v", out.OriginalRequest)
	}
}

func TestQuery_Sessions_VariantUsesModifiedMethod(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedVariantSession(t, store, "variant-list")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}

	// The sessions list should use the modified method/URL.
	if out.Flows[0].Method != "POST" {
		t.Errorf("method = %q, want POST (modified)", out.Flows[0].Method)
	}
	if out.Flows[0].URL != "https://example.com/modified" {
		t.Errorf("url = %q, want https://example.com/modified", out.Flows[0].URL)
	}
}

// --- Test: intercept_drop blocked_by filter ---

func TestQuery_Sessions_FilterByInterceptDrop(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "normal", "HTTPS", "GET", "https://example.com/ok", 200)
	seedBlockedSession(t, store, "dropped", "HTTPS", "GET", "https://example.com/drop", "intercept_drop")
	seedBlockedSession(t, store, "scoped", "HTTPS", "GET", "https://evil.com/admin", "target_scope")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{BlockedBy: "intercept_drop"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Flows[0].ID != "dropped" {
		t.Errorf("id = %q, want dropped", out.Flows[0].ID)
	}
	if out.Flows[0].BlockedBy != "intercept_drop" {
		t.Errorf("blocked_by = %q, want intercept_drop", out.Flows[0].BlockedBy)
	}
}

// --- Test: response variant messages ---

// seedResponseVariantSession creates a session with original and modified
// variant receive messages (simulating response intercept modification).
func seedResponseVariantSession(t *testing.T, store flow.Store, id string) {
	t.Helper()
	ctx := context.Background()

	sess := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  200 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, sess); err != nil {
		t.Fatalf("SaveFlow(%s): %v", id, err)
	}

	reqURL, _ := url.Parse("https://example.com/api")
	sendMsg := &flow.Message{
		ID:        id + "-send",
		FlowID:    id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       reqURL,
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      []byte("request body"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	originalRecv := &flow.Message{
		ID:         id + "-recv-orig",
		FlowID:     id,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}, "X-Original": {"true"}},
		Body:       []byte(`{"status":"original"}`),
		Metadata:   map[string]string{"variant": "original"},
	}
	if err := store.AppendMessage(ctx, originalRecv); err != nil {
		t.Fatalf("AppendMessage(original recv): %v", err)
	}

	modifiedRecv := &flow.Message{
		ID:         id + "-recv-mod",
		FlowID:     id,
		Sequence:   2,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 403,
		Headers:    map[string][]string{"Content-Type": {"application/json"}, "X-Modified": {"true"}},
		Body:       []byte(`{"status":"modified"}`),
		Metadata:   map[string]string{"variant": "modified"},
	}
	if err := store.AppendMessage(ctx, modifiedRecv); err != nil {
		t.Fatalf("AppendMessage(modified recv): %v", err)
	}
}

func TestQuery_Session_ResponseVariantMessages(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedResponseVariantSession(t, store, "resp-variant-sess")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "resp-variant-sess",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	// The effective response should be the modified version.
	if out.ResponseStatusCode != 403 {
		t.Errorf("response_status_code = %d, want 403 (modified)", out.ResponseStatusCode)
	}
	if out.ResponseBody != `{"status":"modified"}` {
		t.Errorf("response_body = %q, want '{\"status\":\"modified\"}'", out.ResponseBody)
	}

	// Original response should be populated.
	if out.OriginalResponse == nil {
		t.Fatal("original_response is nil, expected original variant data")
	}
	if out.OriginalResponse.StatusCode != 200 {
		t.Errorf("original_response.status_code = %d, want 200", out.OriginalResponse.StatusCode)
	}
	if out.OriginalResponse.Body != `{"status":"original"}` {
		t.Errorf("original_response.body = %q, want '{\"status\":\"original\"}'", out.OriginalResponse.Body)
	}

	// Original request should be nil (no request variant in this test).
	if out.OriginalRequest != nil {
		t.Errorf("original_request should be nil, got %+v", out.OriginalRequest)
	}
}

func TestQuery_Session_NoResponseVariant(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	// Use a regular session (no response variant).
	seedVariantSession(t, store, "no-resp-variant")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "no-resp-variant",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	// No response variant, so original_response should be nil.
	if out.OriginalResponse != nil {
		t.Errorf("original_response should be nil for non-variant response, got %+v", out.OriginalResponse)
	}
}

func TestQuery_Flows_ResponseVariantUsesModifiedStatus(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedResponseVariantSession(t, store, "resp-variant-flows")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	// The flows list should show the modified status code.
	if out.Flows[0].StatusCode != 403 {
		t.Errorf("status_code = %d, want 403 (modified variant)", out.Flows[0].StatusCode)
	}
}

// seedBothVariantsSession creates a session with both request and response variants.
func seedBothVariantsSession(t *testing.T, store flow.Store, id string) {
	t.Helper()
	ctx := context.Background()

	sess := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  200 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, sess); err != nil {
		t.Fatalf("SaveFlow(%s): %v", id, err)
	}

	reqURL, _ := url.Parse("https://example.com/api")

	// Original send (variant=original)
	if err := store.AppendMessage(ctx, &flow.Message{
		ID: id + "-send-orig", FlowID: id, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: reqURL,
		Headers:  map[string][]string{"Host": {"example.com"}},
		Body:     []byte("orig-req-body"),
		Metadata: map[string]string{"variant": "original"},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Modified send (variant=modified)
	modURL, _ := url.Parse("https://example.com/api-mod")
	if err := store.AppendMessage(ctx, &flow.Message{
		ID: id + "-send-mod", FlowID: id, Sequence: 1, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: modURL,
		Headers:  map[string][]string{"Host": {"example.com"}},
		Body:     []byte("mod-req-body"),
		Metadata: map[string]string{"variant": "modified"},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Original receive (variant=original)
	if err := store.AppendMessage(ctx, &flow.Message{
		ID: id + "-recv-orig", FlowID: id, Sequence: 2, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200,
		Headers:  map[string][]string{"Content-Type": {"application/json"}},
		Body:     []byte(`{"r":"orig"}`),
		Metadata: map[string]string{"variant": "original"},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Modified receive (variant=modified)
	if err := store.AppendMessage(ctx, &flow.Message{
		ID: id + "-recv-mod", FlowID: id, Sequence: 3, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 401,
		Headers:  map[string][]string{"Content-Type": {"text/plain"}},
		Body:     []byte("Unauthorized"),
		Metadata: map[string]string{"variant": "modified"},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
}

func TestQuery_Session_BothRequestAndResponseVariants(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedBothVariantsSession(t, store, "both-variants")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "both-variants",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	// Request: effective should be modified.
	if out.Method != "POST" {
		t.Errorf("method = %q, want POST", out.Method)
	}
	if out.RequestBody != "mod-req-body" {
		t.Errorf("request_body = %q, want 'mod-req-body'", out.RequestBody)
	}

	// Original request populated.
	if out.OriginalRequest == nil {
		t.Fatal("original_request is nil")
	}
	if out.OriginalRequest.Method != "GET" {
		t.Errorf("original_request.method = %q, want GET", out.OriginalRequest.Method)
	}

	// Response: effective should be modified.
	if out.ResponseStatusCode != 401 {
		t.Errorf("response_status_code = %d, want 401", out.ResponseStatusCode)
	}
	if out.ResponseBody != "Unauthorized" {
		t.Errorf("response_body = %q, want 'Unauthorized'", out.ResponseBody)
	}

	// Original response populated.
	if out.OriginalResponse == nil {
		t.Fatal("original_response is nil")
	}
	if out.OriginalResponse.StatusCode != 200 {
		t.Errorf("original_response.status_code = %d, want 200", out.OriginalResponse.StatusCode)
	}
	if out.OriginalResponse.Body != `{"r":"orig"}` {
		t.Errorf("original_response.body = %q, want '{\"r\":\"orig\"}'", out.OriginalResponse.Body)
	}
}

// --- Test: conn_id filter ---

func TestQuery_Sessions_FilterByConnID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create two flows with different conn_ids.
	for _, tc := range []struct {
		id, connID string
	}{
		{"flow-a1", "conn-alpha"},
		{"flow-a2", "conn-alpha"},
		{"flow-b1", "conn-beta"},
	} {
		fl := &flow.Flow{
			ID:        tc.id,
			ConnID:    tc.connID,
			Protocol:  "HTTPS",
			FlowType:  "unary",
			State:     "complete",
			Timestamp: time.Now().UTC(),
			Duration:  100 * time.Millisecond,
		}
		if err := store.SaveFlow(ctx, fl); err != nil {
			t.Fatalf("SaveFlow(%s): %v", tc.id, err)
		}
		parsedURL, _ := url.Parse("https://example.com/api")
		if err := store.AppendMessage(ctx, &flow.Message{
			ID: tc.id + "-send", FlowID: tc.id, Sequence: 0, Direction: "send",
			Timestamp: time.Now().UTC(), Method: "GET", URL: parsedURL,
		}); err != nil {
			t.Fatalf("AppendMessage: %v", err)
		}
	}

	cs := setupQueryTestSession(t, store)

	// Filter by conn_id = conn-alpha should return 2 flows.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{ConnID: "conn-alpha"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}
	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}

	// Filter by conn_id = conn-beta should return 1 flow.
	result = callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{ConnID: "conn-beta"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	unmarshalQueryResult(t, result, &out)
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Flows[0].ID != "flow-b1" {
		t.Errorf("id = %q, want flow-b1", out.Flows[0].ID)
	}

	// Filter by non-existent conn_id should return 0 flows.
	result = callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{ConnID: "conn-nonexistent"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	unmarshalQueryResult(t, result, &out)
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
}

// --- Test: host filter ---

// seedFlowWithHost creates a flow with optional server_addr and a send message with the given URL.
func seedFlowWithHost(t *testing.T, store flow.Store, id, serverAddr, urlStr string) {
	t.Helper()
	ctx := context.Background()

	fl := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if serverAddr != "" {
		fl.ConnInfo = &flow.ConnectionInfo{
			ServerAddr: serverAddr,
		}
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)
	if err := store.AppendMessage(ctx, &flow.Message{
		ID: id + "-send", FlowID: id, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: parsedURL,
		Headers: map[string][]string{"Host": {parsedURL.Hostname()}},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		ID: id + "-recv", FlowID: id, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200,
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
}

func TestQuery_Sessions_FilterByHost(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Flow with server_addr matching host exactly (no port).
	seedFlowWithHost(t, store, "flow-h1", "example.com", "https://example.com/page1")
	// Flow with server_addr including port.
	seedFlowWithHost(t, store, "flow-h2", "example.com:443", "https://example.com/page2")
	// Flow with different host.
	seedFlowWithHost(t, store, "flow-h3", "other.com:443", "https://other.com/page3")
	// Flow with no server_addr but URL matches host.
	seedFlowWithHost(t, store, "flow-h4", "", "https://example.com/page4")

	cs := setupQueryTestSession(t, store)

	// Filter by host = example.com should match flow-h1, flow-h2, flow-h4.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Host: "example.com"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}

	// Filter by host = other.com should match flow-h3 only.
	result = callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Host: "other.com"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	unmarshalQueryResult(t, result, &out)
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Flows[0].ID != "flow-h3" {
		t.Errorf("id = %q, want flow-h3", out.Flows[0].ID)
	}
}

func TestQuery_Sessions_FilterByConnIDAndHost(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create flows sharing same conn_id but different hosts.
	for _, tc := range []struct {
		id, connID, serverAddr, urlStr string
	}{
		{"flow-c1", "conn-shared", "example.com:443", "https://example.com/a"},
		{"flow-c2", "conn-shared", "other.com:443", "https://other.com/b"},
		{"flow-c3", "conn-other", "example.com:443", "https://example.com/c"},
	} {
		fl := &flow.Flow{
			ID:        tc.id,
			ConnID:    tc.connID,
			Protocol:  "HTTPS",
			FlowType:  "unary",
			State:     "complete",
			Timestamp: time.Now().UTC(),
			Duration:  100 * time.Millisecond,
			ConnInfo:  &flow.ConnectionInfo{ServerAddr: tc.serverAddr},
		}
		if err := store.SaveFlow(ctx, fl); err != nil {
			t.Fatalf("SaveFlow(%s): %v", tc.id, err)
		}
		parsedURL, _ := url.Parse(tc.urlStr)
		if err := store.AppendMessage(ctx, &flow.Message{
			ID: tc.id + "-send", FlowID: tc.id, Sequence: 0, Direction: "send",
			Timestamp: time.Now().UTC(), Method: "GET", URL: parsedURL,
		}); err != nil {
			t.Fatalf("AppendMessage: %v", err)
		}
	}

	cs := setupQueryTestSession(t, store)

	// Combine conn_id + host filters: conn-shared AND example.com.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{ConnID: "conn-shared", Host: "example.com"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)
	if out.Total != 1 {
		t.Errorf("total = %d, want 1", out.Total)
	}
	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if len(out.Flows) > 0 && out.Flows[0].ID != "flow-c1" {
		t.Errorf("id = %q, want flow-c1", out.Flows[0].ID)
	}
}

// --- Test: extractAnomalies ---

func TestExtractAnomalies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tags      map[string]string
		wantLen   int
		wantNil   bool
		wantTypes []string // expected types in sorted order (nil to skip check)
	}{
		{
			name:    "nil tags",
			tags:    nil,
			wantNil: true,
		},
		{
			name:    "empty tags",
			tags:    map[string]string{},
			wantNil: true,
		},
		{
			name:    "no smuggling tags",
			tags:    map[string]string{"error": "timeout"},
			wantNil: true,
		},
		{
			name: "single anomaly",
			tags: map[string]string{
				"smuggling:cl_te_conflict": "true",
				"smuggling:warnings":       "CL/TE conflict detected",
			},
			wantLen:   1,
			wantTypes: []string{"CLTE"},
		},
		{
			name: "multiple anomalies",
			tags: map[string]string{
				"smuggling:cl_te_conflict":   "true",
				"smuggling:header_injection": "true",
				"smuggling:warnings":         "multiple issues",
			},
			wantLen:   2,
			wantTypes: []string{"CLTE", "HeaderInjection"},
		},
		{
			name: "all types",
			tags: map[string]string{
				"smuggling:cl_te_conflict":   "true",
				"smuggling:duplicate_cl":     "true",
				"smuggling:ambiguous_te":     "true",
				"smuggling:invalid_te":       "true",
				"smuggling:header_injection": "true",
				"smuggling:obs_fold":         "true",
			},
			wantLen: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := extractAnomalies(tt.tags)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if len(result) != tt.wantLen {
				t.Fatalf("len = %d, want %d", len(result), tt.wantLen)
			}
			if tt.wantTypes != nil {
				for i, wantType := range tt.wantTypes {
					if result[i].Type != wantType {
						t.Errorf("result[%d].Type = %q, want %q", i, result[i].Type, wantType)
					}
				}
			}
		})
	}
}

// --- Test: anomalies in flow detail response ---

func TestQuery_FlowDetail_Anomalies(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow with smuggling tags.
	fl := &flow.Flow{
		ID:        "flow-anomaly-1",
		ConnID:    "conn-anomaly",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
		Tags: map[string]string{
			"smuggling:cl_te_conflict": "true",
			"smuggling:warnings":       "CL and TE both present",
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	parsedURL, _ := url.Parse("http://example.com/test")
	sendMsg := &flow.Message{
		FlowID:    "flow-anomaly-1",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {"example.com"}},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	recvMsg := &flow.Message{
		FlowID:     "flow-anomaly-1",
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"text/plain"}},
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupQueryTestSession(t, store)

	// Test flow detail.
	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "flow-anomaly-1"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var detail queryFlowResult
	unmarshalQueryResult(t, result, &detail)

	// Verify anomalies are present.
	if len(detail.Anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(detail.Anomalies))
	}
	if detail.Anomalies[0].Type != "CLTE" {
		t.Errorf("anomaly type = %q, want CLTE", detail.Anomalies[0].Type)
	}
	if detail.Anomalies[0].Detail != "CL and TE both present" {
		t.Errorf("anomaly detail = %q, want warning text", detail.Anomalies[0].Detail)
	}

	// Verify tags are still present for backward compatibility.
	if detail.Tags["smuggling:cl_te_conflict"] != "true" {
		t.Error("expected smuggling:cl_te_conflict tag to be preserved")
	}
}

func TestQuery_FlowsList_Anomalies(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow with smuggling tags.
	fl := &flow.Flow{
		ID:        "flow-anomaly-list",
		ConnID:    "conn-anomaly-list",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
		Tags: map[string]string{
			"smuggling:duplicate_cl": "true",
			"smuggling:invalid_te":   "true",
			"smuggling:warnings":     "multiple anomalies",
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	parsedURL, _ := url.Parse("http://example.com/list")
	sendMsg := &flow.Message{
		FlowID:    "flow-anomaly-list",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {"example.com"}},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	if len(out.Flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(out.Flows))
	}
	if len(out.Flows[0].Anomalies) != 2 {
		t.Fatalf("expected 2 anomalies, got %d", len(out.Flows[0].Anomalies))
	}
	// Sorted alphabetically: DuplicateCL, InvalidTE
	if out.Flows[0].Anomalies[0].Type != "DuplicateCL" {
		t.Errorf("anomaly[0].Type = %q, want DuplicateCL", out.Flows[0].Anomalies[0].Type)
	}
	if out.Flows[0].Anomalies[1].Type != "InvalidTE" {
		t.Errorf("anomaly[1].Type = %q, want InvalidTE", out.Flows[0].Anomalies[1].Type)
	}
}

func TestQuery_FlowDetail_NoAnomalies(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "flow-no-anomaly", "HTTP/1.x", "GET", "http://example.com/ok", 200)

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: "flow-no-anomaly"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var detail queryFlowResult
	unmarshalQueryResult(t, result, &detail)

	if detail.Anomalies != nil {
		t.Errorf("expected nil anomalies for normal flow, got %v", detail.Anomalies)
	}
}
