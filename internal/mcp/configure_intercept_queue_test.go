package mcp

import (
	"context"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy/intercept"
)

// setupTestSessionWithInterceptAll creates an MCP client session with
// both intercept engine and queue for testing configure tool.
func setupTestSessionWithInterceptAll(t *testing.T, engine *intercept.Engine, queue *intercept.Queue) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, nil, nil,
		WithInterceptEngine(engine),
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

	return cs
}

func TestConfigureInterceptQueue_SetTimeout(t *testing.T) {
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptAll(t, engine, queue)

	timeoutMs := 60000
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: mustMarshal(t, configureInput{
			InterceptQueue: &configureInterceptQueue{
				TimeoutMs: &timeoutMs,
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	var cfgResult configureResult
	extractResult(t, result, &cfgResult)
	if cfgResult.InterceptQueue == nil {
		t.Fatal("expected intercept_queue in result")
	}
	if cfgResult.InterceptQueue.TimeoutMs != 60000 {
		t.Errorf("expected timeout 60000ms, got %d", cfgResult.InterceptQueue.TimeoutMs)
	}
}

func TestConfigureInterceptQueue_SetTimeoutBehavior(t *testing.T) {
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptAll(t, engine, queue)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: mustMarshal(t, configureInput{
			InterceptQueue: &configureInterceptQueue{
				TimeoutBehavior: "auto_drop",
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	var cfgResult configureResult
	extractResult(t, result, &cfgResult)
	if cfgResult.InterceptQueue == nil {
		t.Fatal("expected intercept_queue in result")
	}
	if cfgResult.InterceptQueue.TimeoutBehavior != "auto_drop" {
		t.Errorf("expected auto_drop, got %q", cfgResult.InterceptQueue.TimeoutBehavior)
	}
}

func TestConfigureInterceptQueue_InvalidTimeoutBehavior(t *testing.T) {
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptAll(t, engine, queue)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: mustMarshal(t, configureInput{
			InterceptQueue: &configureInterceptQueue{
				TimeoutBehavior: "invalid",
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for invalid timeout behavior")
	}
}

func TestConfigureInterceptQueue_TimeoutTooSmall(t *testing.T) {
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptAll(t, engine, queue)

	timeoutMs := 500 // too small (< 1000)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: mustMarshal(t, configureInput{
			InterceptQueue: &configureInterceptQueue{
				TimeoutMs: &timeoutMs,
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error for timeout < 1000ms")
	}
}

func TestConfigureInterceptQueue_NoQueue(t *testing.T) {
	cs := setupTestSession(t, nil)

	timeoutMs := 60000
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: mustMarshal(t, configureInput{
			InterceptQueue: &configureInterceptQueue{
				TimeoutMs: &timeoutMs,
			},
		}),
	})
	if err != nil {
		return // Go-level error is acceptable.
	}
	if !result.IsError {
		t.Fatal("expected error when queue not initialized")
	}
}

func TestConfigureInterceptQueue_Replace(t *testing.T) {
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptAll(t, engine, queue)

	timeoutMs := 120000
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: mustMarshal(t, configureInput{
			Operation: "replace",
			InterceptQueue: &configureInterceptQueue{
				TimeoutMs:       &timeoutMs,
				TimeoutBehavior: "auto_release",
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	var cfgResult configureResult
	extractResult(t, result, &cfgResult)
	if cfgResult.InterceptQueue == nil {
		t.Fatal("expected intercept_queue in result")
	}
	if cfgResult.InterceptQueue.TimeoutMs != 120000 {
		t.Errorf("expected 120000, got %d", cfgResult.InterceptQueue.TimeoutMs)
	}
	if cfgResult.InterceptQueue.TimeoutBehavior != "auto_release" {
		t.Errorf("expected auto_release, got %q", cfgResult.InterceptQueue.TimeoutBehavior)
	}
}
