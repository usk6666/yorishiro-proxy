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
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// httpHeaderToKV converts net/http.Header to []exchange.KeyValue for test convenience.
func httpHeaderToKV(h http.Header) []exchange.KeyValue {
	if h == nil {
		return nil
	}
	var kv []exchange.KeyValue
	for name, vals := range h {
		for _, v := range vals {
			kv = append(kv, exchange.KeyValue{Name: name, Value: v})
		}
	}
	return kv
}

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

func TestOutputFilter_Resend_MasksResponseBody(t *testing.T) {
	store := newTestStore(t)
	engine := newOutputMaskingSafetyEngine(t)

	// Create a server that returns PII in response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Token", "sk-testkey1234567890")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":"test@pii.com","token":"sk-abcdefghijklmnop"}`))
	}))
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL + "/api")
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
			Headers: map[string][]string{
				"Host": {u.Host},
			},
			Timestamp: time.Now(),
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			StatusCode: 200,
			Timestamp:  time.Now(),
			Body:       []byte("original"),
		},
	)

	cs := setupTestSessionWithOutputFilter(t, store, nil, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend",
		Arguments: outputMustMarshalArgs(t, resendInput{Action: "resend", Params: resendParams{StreamID: entry.Session.ID}}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", outputTextContent(result))
	}

	text := outputTextContent(result)

	// Response body should be masked.
	if strings.Contains(text, "test@pii.com") {
		t.Error("resend response should not contain unmasked email")
	}
	if !strings.Contains(text, "[EMAIL_REDACTED]") {
		t.Error("resend response should contain [EMAIL_REDACTED] mask")
	}
	if strings.Contains(text, "sk-abcdefghijklmnop") {
		t.Error("resend response should not contain unmasked API key in body")
	}

	// Response headers should be masked.
	if strings.Contains(text, "sk-testkey1234567890") {
		t.Error("resend response headers should not contain unmasked API key")
	}
}

func TestOutputFilter_Resend_RawDataPreservedInStore(t *testing.T) {
	store := newTestStore(t)
	engine := newOutputMaskingSafetyEngine(t)

	piiBody := `{"email":"store-check@pii.com"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(piiBody))
	}))
	t.Cleanup(srv.Close)

	u, _ := url.Parse(srv.URL + "/api")
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
			Headers: map[string][]string{
				"Host": {u.Host},
			},
			Timestamp: time.Now(),
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			StatusCode: 200,
			Timestamp:  time.Now(),
			Body:       []byte("original"),
		},
	)

	cs := setupTestSessionWithOutputFilter(t, store, nil, engine)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend",
		Arguments: outputMustMarshalArgs(t, resendInput{Action: "resend", Params: resendParams{StreamID: entry.Session.ID}}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", outputTextContent(result))
	}

	// Extract new flow ID from the resend result.
	text := outputTextContent(result)
	var resendResult resendActionResult
	if err := json.Unmarshal([]byte(text), &resendResult); err != nil {
		t.Fatalf("unmarshal resend result: %v", err)
	}

	// Verify the raw data in the store is unchanged.
	msgs, err := store.GetFlows(context.Background(), resendResult.NewFlowID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("expected at least one receive message in store")
	}
	if string(msgs[0].Body) != piiBody {
		t.Errorf("raw store body = %q, want %q", string(msgs[0].Body), piiBody)
	}
}

func TestOutputFilter_InterceptQueue_MasksBody(t *testing.T) {
	store := newTestStore(t)
	engine := newOutputMaskingSafetyEngine(t)

	// Set up intercept queue with a test item.
	queue := intercept.NewQueue()
	u, _ := url.Parse("http://example.com/api")

	queue.Enqueue(
		"POST",
		u,
		httpHeaderToKV(http.Header{
			"Content-Type": {"application/json"},
			"X-Api-Key":    {"sk-interceptedkey12345"},
		}),
		[]byte(`{"contact":"intercepted@email.com"}`),
		[]string{"rule-1"},
	)

	ctx := context.Background()
	s := NewServer(ctx, nil, store, nil, WithSafetyEngine(engine))
	s.deps.interceptQueue = queue

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

	// Body should be masked.
	if strings.Contains(text, "intercepted@email.com") {
		t.Error("intercept queue body should not contain unmasked email")
	}
	if !strings.Contains(text, "[EMAIL_REDACTED]") {
		t.Error("intercept queue body should contain [EMAIL_REDACTED] mask")
	}

	// Headers should be masked.
	if strings.Contains(text, "sk-interceptedkey12345") {
		t.Error("intercept queue headers should not contain unmasked API key")
	}

	// Verify original data in queue is unchanged.
	queueItems := queue.List()
	if len(queueItems) != 1 {
		t.Fatalf("expected 1 queue item, got %d", len(queueItems))
	}
	if string(queueItems[0].Body) != `{"contact":"intercepted@email.com"}` {
		t.Errorf("queue item body was modified: %s", string(queueItems[0].Body))
	}
}

// setupTestSessionWithInterceptAndSafety creates an MCP client session with both
// an intercept queue and an output-masking safety engine.
func setupTestSessionWithInterceptAndSafety(t *testing.T, queue *intercept.Queue, engine *safety.Engine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(ctx, nil, nil, nil, WithInterceptQueue(queue), WithSafetyEngine(engine))
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

func TestOutputFilter_InterceptRelease_MasksBody(t *testing.T) {
	engine := newOutputMaskingSafetyEngine(t)
	queue := intercept.NewQueue()
	u, _ := url.Parse("http://example.com/api")

	id, actionCh := queue.Enqueue(
		"POST",
		u,
		httpHeaderToKV(http.Header{
			"Content-Type": {"application/json"},
			"X-Api-Key":    {"sk-interceptedkey12345"},
		}),
		[]byte(`{"contact":"intercepted@email.com"}`),
		[]string{"rule-1"},
	)

	cs := setupTestSessionWithInterceptAndSafety(t, queue, engine)

	done := make(chan struct{})
	var resultText string
	go func() {
		defer close(done)
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name:      "intercept",
			Arguments: outputMustMarshalArgs(t, interceptInput{Action: "release", Params: interceptParams{InterceptID: id}}),
		})
		if err != nil {
			t.Errorf("CallTool error: %v", err)
			return
		}
		if result.IsError {
			t.Errorf("unexpected error: %v", result.Content)
			return
		}
		resultText = outputTextContent(result)
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

	// Body should be masked.
	if strings.Contains(resultText, "intercepted@email.com") {
		t.Error("intercept release body should not contain unmasked email")
	}
	if !strings.Contains(resultText, "[EMAIL_REDACTED]") {
		t.Error("intercept release body should contain [EMAIL_REDACTED] mask")
	}

	// Headers should be masked.
	if strings.Contains(resultText, "sk-interceptedkey12345") {
		t.Error("intercept release headers should not contain unmasked API key")
	}
	if !strings.Contains(resultText, "[API_KEY_REDACTED]") {
		t.Error("intercept release headers should contain [API_KEY_REDACTED] mask")
	}

	// Verify phase and method are returned.
	if !strings.Contains(resultText, `"phase":"request"`) {
		t.Error("intercept release should include phase field")
	}
	if !strings.Contains(resultText, `"method":"POST"`) {
		t.Error("intercept release should include method field")
	}
}

func TestOutputFilter_InterceptDrop_MasksBody(t *testing.T) {
	engine := newOutputMaskingSafetyEngine(t)
	queue := intercept.NewQueue()

	id, actionCh := queue.EnqueueResponse(
		"GET",
		nil,
		200,
		httpHeaderToKV(http.Header{
			"Content-Type": {"application/json"},
			"X-Token":      {"sk-responseapikey12345"},
		}),
		[]byte(`{"email":"victim@secret.com","data":"ok"}`),
		[]string{"rule-pii"},
	)

	cs := setupTestSessionWithInterceptAndSafety(t, queue, engine)

	done := make(chan struct{})
	var resultText string
	go func() {
		defer close(done)
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name:      "intercept",
			Arguments: outputMustMarshalArgs(t, interceptInput{Action: "drop", Params: interceptParams{InterceptID: id}}),
		})
		if err != nil {
			t.Errorf("CallTool error: %v", err)
			return
		}
		if result.IsError {
			t.Errorf("unexpected error: %v", result.Content)
			return
		}
		resultText = outputTextContent(result)
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

	// Body should be masked.
	if strings.Contains(resultText, "victim@secret.com") {
		t.Error("intercept drop body should not contain unmasked email")
	}
	if !strings.Contains(resultText, "[EMAIL_REDACTED]") {
		t.Error("intercept drop body should contain [EMAIL_REDACTED] mask")
	}

	// Headers should be masked.
	if strings.Contains(resultText, "sk-responseapikey12345") {
		t.Error("intercept drop headers should not contain unmasked API key")
	}

	// Verify response phase fields.
	if !strings.Contains(resultText, `"phase":"response"`) {
		t.Error("intercept drop should include response phase")
	}
	if !strings.Contains(resultText, `"status_code":200`) {
		t.Error("intercept drop should include status_code for response phase")
	}
}

func TestOutputFilter_InterceptModifyAndForward_MasksBody(t *testing.T) {
	engine := newOutputMaskingSafetyEngine(t)
	queue := intercept.NewQueue()
	u, _ := url.Parse("http://example.com/api/data")

	id, actionCh := queue.Enqueue(
		"POST",
		u,
		httpHeaderToKV(http.Header{
			"Content-Type":  {"application/json"},
			"Authorization": {"Bearer sk-secretapikey123456"},
		}),
		[]byte(`{"user":"agent@internal.com"}`),
		[]string{"rule-auth"},
	)

	cs := setupTestSessionWithInterceptAndSafety(t, queue, engine)

	done := make(chan struct{})
	var resultText string
	go func() {
		defer close(done)
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "intercept",
			Arguments: outputMustMarshalArgs(t, interceptInput{
				Action: "modify_and_forward",
				Params: interceptParams{
					InterceptID:    id,
					OverrideMethod: "PUT",
				},
			}),
		})
		if err != nil {
			t.Errorf("CallTool error: %v", err)
			return
		}
		if result.IsError {
			t.Errorf("unexpected error: %v", result.Content)
			return
		}
		resultText = outputTextContent(result)
	}()

	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionModifyAndForward {
			t.Errorf("expected ActionModifyAndForward, got %v", action.Type)
		}
		if action.OverrideMethod != "PUT" {
			t.Errorf("expected method PUT, got %q", action.OverrideMethod)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for action")
	}

	<-done

	// Body should be masked.
	if strings.Contains(resultText, "agent@internal.com") {
		t.Error("intercept modify_and_forward body should not contain unmasked email")
	}
	if !strings.Contains(resultText, "[EMAIL_REDACTED]") {
		t.Error("intercept modify_and_forward body should contain [EMAIL_REDACTED] mask")
	}

	// Headers should be masked.
	if strings.Contains(resultText, "sk-secretapikey123456") {
		t.Error("intercept modify_and_forward headers should not contain unmasked API key")
	}
	if !strings.Contains(resultText, "[API_KEY_REDACTED]") {
		t.Error("intercept modify_and_forward headers should contain [API_KEY_REDACTED] mask")
	}
}

func TestOutputFilter_InterceptRelease_NoEngine_PassesThrough(t *testing.T) {
	queue := intercept.NewQueue()

	id, actionCh := queue.Enqueue(
		"GET",
		nil,
		nil,
		[]byte(`{"email":"visible@example.com"}`),
		nil,
	)

	cs := setupTestSessionWithInterceptQueue(t, queue)

	done := make(chan struct{})
	var resultText string
	go func() {
		defer close(done)
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name:      "intercept",
			Arguments: outputMustMarshalArgs(t, interceptInput{Action: "release", Params: interceptParams{InterceptID: id}}),
		})
		if err != nil {
			t.Errorf("CallTool error: %v", err)
			return
		}
		if result.IsError {
			t.Errorf("unexpected error: %v", result.Content)
			return
		}
		resultText = outputTextContent(result)
	}()

	select {
	case <-actionCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for action")
	}

	<-done

	// Without safety engine, email should be visible.
	if !strings.Contains(resultText, "visible@example.com") {
		t.Error("without safety engine, email should be visible in intercept release output")
	}
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
	s := NewServer(context.Background(), nil, nil, nil)
	input := []byte("test@example.com sk-abcdefghijklmnop")
	got := s.filterOutputBody(input)
	if string(got) != string(input) {
		t.Errorf("filterOutputBody with nil engine should return input unchanged, got %q", string(got))
	}
}

func TestFilterOutputHeaders_NilEngine(t *testing.T) {
	s := NewServer(context.Background(), nil, nil, nil)
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
