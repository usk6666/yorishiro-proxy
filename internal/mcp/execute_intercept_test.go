package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// setupTestSessionWithInterceptQueue creates an MCP client flow with an intercept queue.
func setupTestSessionWithInterceptQueue(t *testing.T, queue *intercept.Queue) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, nil, nil, WithInterceptQueue(queue))
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

// interceptCallTool is a helper that calls the intercept tool with the given arguments.
func interceptCallTool(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "intercept",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

func TestExecuteRelease(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Enqueue a request.
	id, actionCh := queue.Enqueue("GET", nil, nil, nil, nil)

	// Call release in a goroutine since the handler on the other end is blocking.
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
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
			return
		}
		if result.IsError {
			t.Errorf("unexpected error: %v", result.Content)
			return
		}
	}()

	// Wait for the action on the channel.
	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionRelease {
			t.Errorf("expected ActionRelease, got %v", action.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for action")
	}

	<-done
}

func TestExecuteDrop(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	id, actionCh := queue.Enqueue("GET", nil, nil, nil, nil)

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

func TestExecuteModifyAndForward(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	id, actionCh := queue.Enqueue("GET", nil, nil, nil, nil)

	newBody := "modified body"
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "intercept",
			Arguments: mustMarshal(t, interceptInput{
				Action: "modify_and_forward",
				Params: interceptParams{
					InterceptID:     id,
					OverrideMethod:  "POST",
					OverrideURL:     "http://other.com/api",
					OverrideHeaders: map[string]string{"X-Modified": "true"},
					OverrideBody:    &newBody,
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
		if action.Type != intercept.ActionModifyAndForward {
			t.Errorf("expected ActionModifyAndForward, got %v", action.Type)
		}
		if action.OverrideMethod != "POST" {
			t.Errorf("expected method POST, got %q", action.OverrideMethod)
		}
		if action.OverrideURL != "http://other.com/api" {
			t.Errorf("expected URL override, got %q", action.OverrideURL)
		}
		if action.OverrideHeaders["X-Modified"] != "true" {
			t.Errorf("expected header override, got %v", action.OverrideHeaders)
		}
		if action.OverrideBody == nil || *action.OverrideBody != "modified body" {
			t.Errorf("expected body override")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for action")
	}

	<-done
}

func TestExecuteRelease_MissingInterceptID(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	result := interceptCallTool(t, cs, map[string]any{
		"action": "release",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error for missing intercept_id")
	}
}

func TestExecuteRelease_NotFound(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	result := interceptCallTool(t, cs, map[string]any{
		"action": "release",
		"params": map[string]any{
			"intercept_id": "nonexistent",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent intercept_id")
	}
}

func TestExecuteRelease_NoQueue(t *testing.T) {
	t.Parallel()
	// Server without intercept queue.
	cs := setupTestSession(t, nil)

	result := interceptCallTool(t, cs, map[string]any{
		"action": "release",
		"params": map[string]any{
			"intercept_id": "test-id",
		},
	})
	if !result.IsError {
		t.Fatal("expected error when queue is not initialized")
	}
}

func TestQueryInterceptQueue_Empty(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

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
	if queueResult.Count != 0 {
		t.Errorf("expected 0 items, got %d", queueResult.Count)
	}
}

func TestQueryInterceptQueue_WithItems(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Enqueue some requests.
	queue.Enqueue("GET", nil, nil, nil, []string{"rule-1"})
	queue.Enqueue("POST", nil, nil, []byte("test body"), []string{"rule-2"})

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
		t.Errorf("expected 2 items, got %d", queueResult.Count)
	}
}

func TestQueryInterceptQueue_NoQueue(t *testing.T) {
	t.Parallel()
	cs := setupTestSession(t, nil)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: mustMarshal(t, queryInput{
			Resource: "intercept_queue",
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error when queue is not initialized")
	}
}

func TestQueryInterceptQueue_WithLimit(t *testing.T) {
	t.Parallel()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Add 5 items.
	for i := 0; i < 5; i++ {
		queue.Enqueue("GET", nil, nil, nil, nil)
	}

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: mustMarshal(t, queryInput{
			Resource: "intercept_queue",
			Limit:    3,
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
	if queueResult.Count != 3 {
		t.Errorf("expected 3 items with limit, got %d", queueResult.Count)
	}
}

// mustMarshal marshals v to JSON as a map for MCP tool arguments.
func mustMarshal(t *testing.T, v any) map[string]any {
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

// extractResult extracts the structured result from a CallToolResult.
func extractResult(t *testing.T, result *gomcp.CallToolResult, v any) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty result content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(text.Text), v); err != nil {
		t.Fatalf("json.Unmarshal result: %v (text: %s)", err, text.Text)
	}
}
