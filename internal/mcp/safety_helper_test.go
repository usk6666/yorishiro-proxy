package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// newOutputMaskingSafetyEngine creates a safety engine with output rules that mask
// email addresses and a specific API key pattern.
func newOutputMaskingSafetyEngine(t *testing.T) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				ID:          "mask-email",
				Name:        "Email address",
				Pattern:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
				Targets:     []string{"body", "headers"},
				Action:      "mask",
				Replacement: "[EMAIL_REDACTED]",
			},
			{
				ID:          "mask-api-key",
				Name:        "API Key",
				Pattern:     `sk-[a-zA-Z0-9]{16,}`,
				Targets:     []string{"body", "headers"},
				Action:      "mask",
				Replacement: "[API_KEY_REDACTED]",
			},
		},
	})
	if err != nil {
		t.Fatalf("create output masking safety engine: %v", err)
	}
	return engine
}

// setupTestSessionWithOutputFilter creates an MCP client session with an output-masking
// safety engine and a custom HTTP doer.
func setupTestSessionWithOutputFilter(t *testing.T, store flow.Store, doer httpDoer, engine *safety.Engine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := newServer(context.Background(), nil, store, nil, WithSafetyEngine(engine))
	s.jobRunner.replayDoer = doer
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

// outputTextContent extracts the text content from a CallToolResult.
func outputTextContent(result *gomcp.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

// outputMustMarshalArgs marshals v to JSON RawMessage for MCP tool arguments.
func outputMustMarshalArgs(t *testing.T, v any) map[string]any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return m
}

func TestOutputFilter_QueryMessages_MasksBody(t *testing.T) {
	store := newTestStore(t)
	engine := newOutputMaskingSafetyEngine(t)

	u, _ := url.Parse("http://example.com/api")
	entry := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Method:    "GET",
			URL:       u,
			Timestamp: time.Now(),
			Body:      []byte("request body"),
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			StatusCode: 200,
			Headers: map[string][]string{
				"Content-Type": {"application/json"},
				"X-User-Email": {"user@example.com"},
			},
			Timestamp: time.Now(),
			Body:      []byte(`{"email":"admin@secret.com","key":"sk-abcdefghijklmnop"}`),
		},
	)

	cs := setupTestSessionWithOutputFilter(t, store, nil, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: outputMustMarshalArgs(t, queryInput{Resource: "messages", ID: entry.Session.ID}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", outputTextContent(result))
	}

	text := outputTextContent(result)

	// Body should be masked.
	if strings.Contains(text, "admin@secret.com") {
		t.Error("response body should not contain unmasked email admin@secret.com")
	}
	if !strings.Contains(text, "[EMAIL_REDACTED]") {
		t.Error("response body should contain [EMAIL_REDACTED] mask")
	}
	if strings.Contains(text, "sk-abcdefghijklmnop") {
		t.Error("response body should not contain unmasked API key")
	}
	if !strings.Contains(text, "[API_KEY_REDACTED]") {
		t.Error("response body should contain [API_KEY_REDACTED] mask")
	}

	// Headers should be masked.
	if strings.Contains(text, "user@example.com") {
		t.Error("response headers should not contain unmasked email user@example.com")
	}
}

func TestOutputFilter_QueryMessages_RawDataPreserved(t *testing.T) {
	store := newTestStore(t)
	engine := newOutputMaskingSafetyEngine(t)

	u, _ := url.Parse("http://example.com/api")
	originalBody := `{"email":"admin@secret.com"}`
	entry := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Method:    "GET",
			URL:       u,
			Timestamp: time.Now(),
			Body:      []byte("request body"),
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			StatusCode: 200,
			Timestamp:  time.Now(),
			Body:       []byte(originalBody),
		},
	)

	// Set up session with output filter.
	_ = setupTestSessionWithOutputFilter(t, store, nil, engine)

	// Verify raw data in store is unchanged.
	msgs, err := store.GetFlows(context.Background(), entry.Session.ID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("expected at least one receive message")
	}
	if string(msgs[0].Body) != originalBody {
		t.Errorf("raw store body = %q, want %q", string(msgs[0].Body), originalBody)
	}
}

func TestOutputFilter_InterceptQueue_MasksBody(t *testing.T) {
	store := newTestStore(t)
	engine := newOutputMaskingSafetyEngine(t)

	hold := common.NewHoldQueue()
	env := &envelope.Envelope{
		Direction: envelope.Send,
		FlowID:    "flow-1",
		StreamID:  "stream-1",
		Message: &envelope.HTTPMessage{
			Method:    "POST",
			Scheme:    "http",
			Authority: "example.com",
			Path:      "/api",
			Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "application/json"},
				{Name: "X-Api-Key", Value: "sk-interceptedkey12345"},
			},
			Body: []byte(`{"contact":"intercepted@email.com"}`),
		},
	}

	holdDone := make(chan struct{})
	go func() {
		defer close(holdDone)
		_, _ = hold.Hold(context.Background(), env, []string{"rule-1"})
	}()
	t.Cleanup(func() {
		// Drain any held entry so the goroutine exits cleanly.
		for _, entry := range hold.List() {
			_ = hold.Release(entry.ID, &common.HoldAction{Type: common.ActionRelease})
		}
		<-holdDone
	})
	if !waitForHeldEntryReady(t, hold, 2*time.Second) {
		t.Fatal("hold queue did not receive entry")
	}

	ctx := context.Background()
	s := newServer(ctx, nil, store, nil, WithSafetyEngine(engine), WithHoldQueue(hold))

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

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "query",
		Arguments: outputMustMarshalArgs(t, queryInput{Resource: "intercept_queue"}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", outputTextContent(result))
	}

	text := outputTextContent(result)

	if strings.Contains(text, "intercepted@email.com") {
		t.Error("intercept queue body should not contain unmasked email")
	}
	if !strings.Contains(text, "[EMAIL_REDACTED]") {
		t.Error("intercept queue body should contain [EMAIL_REDACTED] mask")
	}
	if strings.Contains(text, "sk-interceptedkey12345") {
		t.Error("intercept queue headers should not contain unmasked API key")
	}
	if !strings.Contains(text, "[API_KEY_REDACTED]") {
		t.Error("intercept queue headers should contain [API_KEY_REDACTED] mask")
	}
}

// waitForHeldEntryReady polls the hold queue for at least one entry. Used
// by safety-helper tests that hold an envelope from a goroutine.
func waitForHeldEntryReady(t *testing.T, queue *common.HoldQueue, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if queue.Len() > 0 {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

func TestOutputFilter_NoEngine_PassesThrough(t *testing.T) {
	store := newTestStore(t)

	u, _ := url.Parse("http://example.com/api")
	entry := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Method:    "GET",
			URL:       u,
			Timestamp: time.Now(),
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			StatusCode: 200,
			Timestamp:  time.Now(),
			Body:       []byte(`{"email":"visible@example.com"}`),
		},
	)

	// No safety engine - should pass through unchanged.
	cs := setupTestSessionWithStore(t, nil, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: outputMustMarshalArgs(t, queryInput{Resource: "messages", ID: entry.Session.ID}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", outputTextContent(result))
	}

	text := outputTextContent(result)
	if !strings.Contains(text, "visible@example.com") {
		t.Error("without safety engine, email should be visible in output")
	}
}

func TestFilterOutputBody_NilEngine(t *testing.T) {
	s := newServer(context.Background(), nil, nil, nil)
	input := []byte("test@example.com sk-abcdefghijklmnop")
	got := s.filterOutputBody(input)
	if string(got) != string(input) {
		t.Errorf("filterOutputBody with nil engine should return input unchanged, got %q", string(got))
	}
}

func TestFilterOutputHeaders_NilEngine(t *testing.T) {
	s := newServer(context.Background(), nil, nil, nil)
	headers := http.Header{"X-Key": {"sk-abcdefghijklmnop"}}
	got := s.filterOutputHeaders(headers)
	if got.Get("X-Key") != "sk-abcdefghijklmnop" {
		t.Errorf("filterOutputHeaders with nil engine should return headers unchanged")
	}
}

func TestDecodeEntryBody_Base64(t *testing.T) {
	// "hello world" in base64
	got := decodeEntryBody("aGVsbG8gd29ybGQ=", "base64")
	if string(got) != "hello world" {
		t.Errorf("decodeEntryBody(base64) = %q, want %q", string(got), "hello world")
	}
}
