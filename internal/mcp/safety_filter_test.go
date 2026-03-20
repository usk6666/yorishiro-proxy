package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// newBlockingSafetyEngine creates a safety engine that blocks DROP TABLE patterns.
func newBlockingSafetyEngine(t *testing.T) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "destructive-sql:drop-table",
				Name:    "DROP TABLE pattern",
				Pattern: `(?i)\bDROP\s+TABLE\b`,
				Targets: []string{"body", "url", "headers"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("create safety engine: %v", err)
	}
	return engine
}

// setupTestSessionWithSafety creates an MCP client session with a safety engine
// and a custom HTTP doer for testing safety filter integration.
func setupTestSessionWithSafety(t *testing.T, store flow.Store, doer httpDoer, engine *safety.Engine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, store, nil, WithSafetyEngine(engine))
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

func TestSafetyFilter_Resend_BlocksDestructiveBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	safetyEngine := newBlockingSafetyEngine(t)

	u, _ := url.Parse("http://example.com/api")
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
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"query":"SELECT 1"}`),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	// Get the flow ID from the store.
	flows, err := store.ListFlows(context.Background(), flow.ListOptions{Limit: 1})
	if err != nil {
		t.Fatalf("list flows: %v", err)
	}
	if len(flows) == 0 {
		t.Fatal("no flows saved")
	}
	flowID := flows[0].ID

	cs := setupTestSessionWithSafety(t, store, newPermissiveClient(), safetyEngine)

	// Resend with destructive body override should be blocked.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":       flowID,
			"override_body": "DROP TABLE users;",
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for destructive payload")
	}
	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "SafetyFilter blocked") {
		t.Errorf("error text = %q, want containing 'SafetyFilter blocked'", textContent.Text)
	}
	// Rule internals should not be exposed to the MCP client.
	if strings.Contains(textContent.Text, "destructive-sql:drop-table") {
		t.Errorf("error text should not contain rule ID: %q", textContent.Text)
	}
}

func TestSafetyFilter_Resend_AllowsSafeBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	safetyEngine := newBlockingSafetyEngine(t)

	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(echoServer.Close)

	u, _ := url.Parse(echoServer.URL + "/api")
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
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"query":"SELECT * FROM users"}`),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	flows, _ := store.ListFlows(context.Background(), flow.ListOptions{Limit: 1})
	flowID := flows[0].ID

	cs := setupTestSessionWithSafety(t, store, newPermissiveClient(), safetyEngine)

	// Resend with safe body should succeed.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": flowID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
}

func TestSafetyFilter_Resend_BlocksDestructiveHeaders(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	safetyEngine := newBlockingSafetyEngine(t)

	u, _ := url.Parse("http://example.com/api")
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
			Body:      nil,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	flows, _ := store.ListFlows(context.Background(), flow.ListOptions{Limit: 1})
	flowID := flows[0].ID

	cs := setupTestSessionWithSafety(t, store, newPermissiveClient(), safetyEngine)

	// Override headers with destructive payload.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": flowID,
			"override_headers": []any{
				map[string]any{"key": "X-Custom", "value": "DROP TABLE users"},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for destructive headers")
	}
	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "SafetyFilter blocked") {
		t.Errorf("error text = %q, want containing 'SafetyFilter blocked'", textContent.Text)
	}
}

func TestSafetyFilter_Intercept_ModifyAndForward_BlocksDestructiveBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	safetyEngine := newBlockingSafetyEngine(t)

	ctx := context.Background()
	queue := intercept.NewQueue()
	s := NewServer(ctx, nil, store, nil,
		WithSafetyEngine(safetyEngine),
		WithInterceptQueue(queue),
	)
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

	destructiveBody := "DROP TABLE orders;"
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "intercept",
		Arguments: map[string]any{
			"action": "modify_and_forward",
			"params": map[string]any{
				"intercept_id":  "test-id",
				"override_body": destructiveBody,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for destructive body in modify_and_forward")
	}
	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "SafetyFilter blocked") {
		t.Errorf("error text = %q, want containing 'SafetyFilter blocked'", textContent.Text)
	}
}

func TestSafetyFilter_Intercept_ModifyAndForward_AllowsSafe(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	safetyEngine := newBlockingSafetyEngine(t)

	ctx := context.Background()
	queue := intercept.NewQueue()
	s := NewServer(ctx, nil, store, nil,
		WithSafetyEngine(safetyEngine),
		WithInterceptQueue(queue),
	)
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

	// Safe body should pass safety check (will fail at intercept queue, not safety).
	safeBody := "SELECT * FROM users WHERE id = 1"
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "intercept",
		Arguments: map[string]any{
			"action": "modify_and_forward",
			"params": map[string]any{
				"intercept_id":  "test-id",
				"override_body": safeBody,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// The result should NOT be a safety error (it may fail for other reasons like
	// "intercept queue is not initialized", but not safety).
	if result.IsError {
		textContent := result.Content[0].(*gomcp.TextContent)
		if strings.Contains(textContent.Text, "SafetyFilter blocked") {
			t.Fatalf("safe body was incorrectly blocked: %s", textContent.Text)
		}
	}
}

func TestSafetyFilter_ErrorFormat(t *testing.T) {
	t.Parallel()
	v := &safety.InputViolation{
		RuleID:    "destructive-sql:drop-table",
		RuleName:  "DROP TABLE pattern",
		Target:    safety.TargetBody,
		MatchedOn: "DROP TABLE",
	}
	msg := safetyViolationError(v)

	// The client-facing message should contain a generic blocking notice
	// without leaking rule details (rule ID, pattern, target).
	if !strings.Contains(msg, "SafetyFilter blocked this operation") {
		t.Errorf("message missing 'SafetyFilter blocked this operation': %s", msg)
	}
	if !strings.Contains(msg, "blocked by safety policy") {
		t.Errorf("message missing 'blocked by safety policy': %s", msg)
	}
	// Rule internals must NOT be exposed to the MCP client.
	if strings.Contains(msg, "destructive-sql:drop-table") {
		t.Errorf("message should not contain rule ID: %s", msg)
	}
	if strings.Contains(msg, "DROP TABLE pattern") {
		t.Errorf("message should not contain rule name/pattern: %s", msg)
	}
}

func TestSafetyFilter_FuzzTemplate_BlocksDestructiveBody(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	safetyEngine := newBlockingSafetyEngine(t)

	u, _ := url.Parse("http://example.com/api")
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
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"text/plain"}},
			Body:      []byte("DROP TABLE users;"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	flows, _ := store.ListFlows(context.Background(), flow.ListOptions{Limit: 1})
	flowID := flows[0].ID

	ctx := context.Background()
	s := NewServer(ctx, nil, store, nil, WithSafetyEngine(safetyEngine))
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

	// Fuzz with destructive template body should be blocked.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "fuzz",
		Arguments: map[string]any{
			"action": "fuzz",
			"params": map[string]any{
				"flow_id":     flowID,
				"attack_type": "sequential",
				"positions": []any{
					map[string]any{
						"id":          "pos-1",
						"location":    "body",
						"mode":        "replace",
						"payload_set": "test",
					},
				},
				"payload_sets": map[string]any{
					"test": map[string]any{
						"type":   "wordlist",
						"values": []any{"a", "b"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		// Decode and check it was blocked.
		var raw json.RawMessage
		textContent := result.Content[0].(*gomcp.TextContent)
		_ = json.Unmarshal([]byte(textContent.Text), &raw)
		t.Fatalf("expected IsError=true for destructive fuzz template body, got: %s", textContent.Text)
	}
	textContent := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(textContent.Text, "SafetyFilter blocked") {
		t.Errorf("error text = %q, want containing 'SafetyFilter blocked'", textContent.Text)
	}
}

func TestSafetyFilter_NoEngine_PassesThrough(t *testing.T) {
	t.Parallel()
	// When no safety engine is configured, all operations should pass through.
	store := newTestStore(t)

	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(echoServer.Close)

	u, _ := url.Parse(echoServer.URL + "/api")
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
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"text/plain"}},
			Body:      []byte("DROP TABLE users;"),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Body:       []byte("ok"),
		},
	)

	flows, _ := store.ListFlows(context.Background(), flow.ListOptions{Limit: 1})
	flowID := flows[0].ID

	// No safety engine = should allow destructive payloads.
	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": flowID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success without safety engine, got error: %v", result.Content)
	}
}
