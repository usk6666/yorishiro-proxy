package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// setupMacroTestSession creates an MCP client session for macro action tests.
// It uses a permissive HTTP client to allow localhost connections.
func setupMacroTestSession(t *testing.T, store flow.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := newServer(context.Background(), nil, store, nil)
	s.jobRunner.replayDoer = newPermissiveClient()
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

// callMacro invokes the macro tool and returns the raw result.
func callMacro(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "macro",
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

// unmarshalExecuteResult extracts the JSON result from CallToolResult content.
func unmarshalExecuteResult(t *testing.T, result *gomcp.CallToolResult, dest any) {
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

func TestExecute_DefineMacro_Success(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":        "auth-flow",
			"description": "Login and get CSRF token",
			"steps": []any{
				map[string]any{
					"id":      "login",
					"flow_id": "recorded-login",
				},
				map[string]any{
					"id":      "get-csrf",
					"flow_id": "recorded-csrf",
				},
			},
			"initial_vars":     map[string]any{"password": "admin123"},
			"macro_timeout_ms": 60000,
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out macroDefineMacroResult
	unmarshalExecuteResult(t, result, &out)

	if out.Name != "auth-flow" {
		t.Errorf("Name = %q, want %q", out.Name, "auth-flow")
	}
	if out.StepCount != 2 {
		t.Errorf("StepCount = %d, want 2", out.StepCount)
	}
	if !out.Created {
		t.Error("Created should be true for new macro")
	}
}

func TestExecute_DefineMacro_Upsert(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	steps := []any{
		map[string]any{
			"id":      "step1",
			"flow_id": "s1",
		},
	}

	// First define.
	result1 := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":  "test-macro",
			"steps": steps,
		},
	})
	if result1.IsError {
		t.Fatalf("first define failed: %v", result1.Content)
	}

	var out1 macroDefineMacroResult
	unmarshalExecuteResult(t, result1, &out1)
	if !out1.Created {
		t.Error("first define should report Created=true")
	}

	// Second define (update).
	result2 := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":        "test-macro",
			"description": "updated",
			"steps":       steps,
		},
	})
	if result2.IsError {
		t.Fatalf("second define failed: %v", result2.Content)
	}

	var out2 macroDefineMacroResult
	unmarshalExecuteResult(t, result2, &out2)
	if out2.Created {
		t.Error("second define should report Created=false (update)")
	}
}

func TestExecute_DefineMacro_MissingName(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"steps": []any{
				map[string]any{"id": "s1", "flow_id": "sess"},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error for missing name")
	}
}

func TestExecute_DefineMacro_MissingSteps(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "no-steps",
		},
	})

	if !result.IsError {
		t.Fatal("expected error for missing steps")
	}
}

func TestExecute_DefineMacro_InvalidStep_MissingID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// The MCP SDK may validate the schema and reject the request before
	// it reaches our handler. Either the SDK error or our validation error
	// is acceptable.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "macro",
		Arguments: map[string]any{
			"action": "define_macro",
			"params": map[string]any{
				"name": "bad-step",
				"steps": []any{
					map[string]any{"flow_id": "sess"},
				},
			},
		},
	})
	if err != nil {
		// SDK schema validation error — this is expected.
		return
	}
	if !result.IsError {
		t.Fatal("expected error for step without ID")
	}
}

func TestExecute_DefineMacro_InvalidStep_MissingFlowID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// The MCP SDK may validate the schema and reject the request before
	// it reaches our handler. Either the SDK error or our validation error
	// is acceptable.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "macro",
		Arguments: map[string]any{
			"action": "define_macro",
			"params": map[string]any{
				"name": "bad-step",
				"steps": []any{
					map[string]any{"id": "s1"},
				},
			},
		},
	})
	if err != nil {
		// SDK schema validation error — this is expected.
		return
	}
	if !result.IsError {
		t.Fatal("expected error for step without flow_id")
	}
}

func TestExecute_DefineMacro_DuplicateStepID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "dup-steps",
			"steps": []any{
				map[string]any{"id": "s1", "flow_id": "sess"},
				map[string]any{"id": "s1", "flow_id": "sess2"},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error for duplicate step IDs")
	}
}

func TestExecute_DefineMacro_InvalidExtractSource(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// "response" is a valid "from" value but invalid as "source".
	// This is the exact mistake from the bug report (swapped source/from).
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "macro",
		Arguments: map[string]any{
			"action": "define_macro",
			"params": map[string]any{
				"name": "bad-source",
				"steps": []any{
					map[string]any{
						"id":      "s1",
						"flow_id": "sess1",
						"extract": []any{
							map[string]any{
								"name":   "token",
								"source": "response",
								"from":   "body",
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		// SDK schema validation may reject the invalid enum value before
		// it reaches the handler. Verify the error mentions the field.
		if !strings.Contains(err.Error(), "source") {
			t.Fatalf("expected SDK error about 'source', got: %v", err)
		}
		return
	}
	if !result.IsError {
		t.Fatal("expected error for invalid source value 'response'")
	}
	errText := extractTextContent(result)
	if !strings.Contains(errText, "invalid source") {
		t.Errorf("error should mention 'invalid source', got: %s", errText)
	}
}

func TestExecute_DefineMacro_InvalidExtractFrom(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "macro",
		Arguments: map[string]any{
			"action": "define_macro",
			"params": map[string]any{
				"name": "bad-from",
				"steps": []any{
					map[string]any{
						"id":      "s1",
						"flow_id": "sess1",
						"extract": []any{
							map[string]any{
								"name":   "token",
								"source": "body",
								"from":   "body",
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		// SDK schema validation may reject the invalid enum value before
		// it reaches the handler. Verify the error mentions the field.
		if !strings.Contains(err.Error(), "from") {
			t.Fatalf("expected SDK error about 'from', got: %v", err)
		}
		return
	}
	if !result.IsError {
		t.Fatal("expected error for invalid from value 'body'")
	}
	errText := extractTextContent(result)
	if !strings.Contains(errText, "invalid from") {
		t.Errorf("error should mention 'invalid from', got: %s", errText)
	}
}

func TestExecute_RunMacro_Success(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Create an echo server that returns a response with a token.
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Token", "test-token-value")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer echoServer.Close()

	u, _ := url.Parse(echoServer.URL + "/api/login")
	ctx := context.Background()

	// Save a flow that the macro step will reference.
	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"user":"admin"}`),
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define a macro that references the flow.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "test-macro",
			"steps": []any{
				map[string]any{
					"id":      "login",
					"flow_id": fl.ID,
					"extract": []any{
						map[string]any{
							"name":        "token",
							"from":        "response",
							"source":      "header",
							"header_name": "X-Token",
						},
					},
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Run the macro.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "test-macro",
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var out macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &out)

	if out.MacroName != "test-macro" {
		t.Errorf("MacroName = %q, want %q", out.MacroName, "test-macro")
	}
	if out.Status != "completed" {
		t.Errorf("Status = %q, want %q", out.Status, "completed")
	}
	if out.StepsExecuted != 1 {
		t.Errorf("StepsExecuted = %d, want 1", out.StepsExecuted)
	}
	if len(out.StepResults) != 1 {
		t.Fatalf("StepResults count = %d, want 1", len(out.StepResults))
	}
	if out.StepResults[0].ID != "login" {
		t.Errorf("StepResults[0].ID = %q, want %q", out.StepResults[0].ID, "login")
	}
	if out.StepResults[0].StatusCode != 200 {
		t.Errorf("StepResults[0].StatusCode = %d, want 200", out.StepResults[0].StatusCode)
	}
	if out.KVStore["token"] != "test-token-value" {
		t.Errorf("KVStore[token] = %q, want %q", out.KVStore["token"], "test-token-value")
	}
}

func TestExecute_RunMacro_WithVarsOverride(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write(body) // Echo back the body.
	}))
	defer echoServer.Close()

	u, _ := url.Parse(echoServer.URL + "/api/test")
	ctx := context.Background()

	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		Body:      []byte("hello"),
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define macro with initial_vars.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "vars-macro",
			"steps": []any{
				map[string]any{
					"id":      "step1",
					"flow_id": fl.ID,
				},
			},
			"initial_vars": map[string]any{"key1": "default-value"},
		},
	})

	// Run with vars override.
	result := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "vars-macro",
			"vars": map[string]any{"key1": "overridden"},
		},
	})
	if result.IsError {
		t.Fatalf("run_macro failed: %v", result.Content)
	}

	var out macroRunMacroResult
	unmarshalExecuteResult(t, result, &out)

	if out.KVStore["key1"] != "overridden" {
		t.Errorf("KVStore[key1] = %q, want %q", out.KVStore["key1"], "overridden")
	}
}

func TestExecute_RunMacro_TimeoutOverride(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Create a slow server that takes 500ms to respond.
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer slowServer.Close()

	u, _ := url.Parse(slowServer.URL + "/api/slow")
	ctx := context.Background()

	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       u,
		Headers:   map[string][]string{},
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define a macro with a generous timeout (10s).
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":             "timeout-macro",
			"macro_timeout_ms": 10000,
			"steps": []any{
				map[string]any{
					"id":      "slow-step",
					"flow_id": fl.ID,
				},
			},
		},
	})

	// Run without timeout override — should succeed (10s timeout, 500ms response).
	result := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "timeout-macro",
		},
	})
	if result.IsError {
		t.Fatalf("run_macro without override should succeed, got error: %v", result.Content)
	}
	var out macroRunMacroResult
	unmarshalExecuteResult(t, result, &out)
	if out.Status != "completed" {
		t.Errorf("without override: Status = %q, want %q", out.Status, "completed")
	}

	// Run with a very short timeout override (50ms) — should timeout
	// because the server takes 500ms to respond.
	result2 := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name":             "timeout-macro",
			"macro_timeout_ms": 50,
		},
	})
	// The engine returns a result with Status="timeout" (not an MCP error).
	if result2.IsError {
		t.Fatalf("run_macro returned MCP error: %v", result2.Content)
	}
	var out2 macroRunMacroResult
	unmarshalExecuteResult(t, result2, &out2)
	if out2.Status != "timeout" {
		t.Errorf("with 50ms override: Status = %q, want %q", out2.Status, "timeout")
	}
}

func TestExecute_RunMacro_TimeoutOverrideZeroUsesDefinition(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Create a slow server that takes 200ms to respond.
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer slowServer.Close()

	u, _ := url.Parse(slowServer.URL + "/api/test")
	ctx := context.Background()

	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       u,
		Headers:   map[string][]string{},
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define macro with a very short timeout (50ms) — shorter than the
	// server's 200ms response time, so it will timeout if this value is used.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":             "zero-timeout-macro",
			"macro_timeout_ms": 50,
			"steps": []any{
				map[string]any{
					"id":      "step1",
					"flow_id": fl.ID,
				},
			},
		},
	})

	// Run with macro_timeout_ms=0 — should fall back to definition timeout (50ms),
	// which is shorter than the server's 200ms delay, causing a timeout.
	result := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name":             "zero-timeout-macro",
			"macro_timeout_ms": 0,
		},
	})
	if result.IsError {
		t.Fatalf("run_macro returned MCP error: %v", result.Content)
	}
	var out macroRunMacroResult
	unmarshalExecuteResult(t, result, &out)
	if out.Status != "timeout" {
		t.Errorf("with macro_timeout_ms=0 (fallback to 50ms definition): Status = %q, want %q", out.Status, "timeout")
	}
}

func TestExecute_RunMacro_NotFound(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "nonexistent",
		},
	})

	if !result.IsError {
		t.Fatal("expected error for nonexistent macro")
	}
}

func TestExecute_RunMacro_MissingName(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{},
	})

	if !result.IsError {
		t.Fatal("expected error for missing name")
	}
}

func TestExecute_DeleteMacro_Success(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// Create a macro first.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "to-delete",
			"steps": []any{
				map[string]any{"id": "s1", "flow_id": "sess"},
			},
		},
	})

	// Delete it.
	result := callMacro(t, cs, map[string]any{
		"action": "delete_macro",
		"params": map[string]any{
			"name": "to-delete",
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out macroDeleteMacroResult
	unmarshalExecuteResult(t, result, &out)

	if out.Name != "to-delete" {
		t.Errorf("Name = %q, want %q", out.Name, "to-delete")
	}
	if !out.Deleted {
		t.Error("Deleted should be true")
	}

	// Verify macro is gone.
	queryResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "to-delete",
		},
	})
	if !queryResult.IsError {
		t.Error("expected error when running deleted macro")
	}
}

func TestExecute_DeleteMacro_NotFound(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "delete_macro",
		"params": map[string]any{
			"name": "nonexistent",
		},
	})

	if !result.IsError {
		t.Fatal("expected error for nonexistent macro")
	}
}

func TestExecute_DeleteMacro_MissingName(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "delete_macro",
		"params": map[string]any{},
	})

	if !result.IsError {
		t.Fatal("expected error for missing name")
	}
}

func TestExecute_DefineMacro_WithExtractAndGuard(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "complex-macro",
			"steps": []any{
				map[string]any{
					"id":      "login",
					"flow_id": "sess-1",
					"extract": []any{
						map[string]any{
							"name":        "cookie",
							"from":        "response",
							"source":      "header",
							"header_name": "Set-Cookie",
							"regex":       "sid=([^;]+)",
							"group":       1,
						},
					},
				},
				map[string]any{
					"id":      "mfa",
					"flow_id": "sess-2",
					"when": map[string]any{
						"step":        "login",
						"status_code": 302,
					},
					"override_headers": map[string]any{
						"Cookie": "sid=§cookie§",
					},
				},
			},
			"initial_vars": map[string]any{"password": "secret"},
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out macroDefineMacroResult
	unmarshalExecuteResult(t, result, &out)

	if out.StepCount != 2 {
		t.Errorf("StepCount = %d, want 2", out.StepCount)
	}
}

func TestExecute_DefineMacro_NoStore(t *testing.T) {
	t.Parallel()
	// Test with nil store.
	ctx := context.Background()
	s := newServer(context.Background(), nil, nil, nil)
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

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "test",
			"steps": []any{
				map[string]any{"id": "s1", "flow_id": "sess"},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error when store is nil")
	}
}

func TestExecute_RunMacro_RecordsSessions(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Create an echo server that returns a predictable response.
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Step", r.Header.Get("X-Step"))
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer echoServer.Close()

	ctx := context.Background()

	// Save a template flow for step1.
	u1, _ := url.Parse(echoServer.URL + "/api/step1")
	sess1 := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, sess1); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  sess1.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       u1,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save a template flow for step2.
	u2, _ := url.Parse(echoServer.URL + "/api/step2")
	sess2 := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, sess2); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  sess2.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u2,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"data":"test"}`),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define a 2-step macro.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "record-test",
			"steps": []any{
				map[string]any{
					"id":      "step1",
					"flow_id": sess1.ID,
				},
				map[string]any{
					"id":      "step2",
					"flow_id": sess2.ID,
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Count sessions before running the macro.
	beforeSessions, err := store.ListStreams(ctx, flow.StreamListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows before: %v", err)
	}
	beforeCount := len(beforeSessions)

	// Run the macro.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "record-test",
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var out macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &out)

	if out.Status != "completed" {
		t.Fatalf("Status = %q, want completed", out.Status)
	}
	if out.StepsExecuted != 2 {
		t.Fatalf("StepsExecuted = %d, want 2", out.StepsExecuted)
	}

	// After running, there should be 2 new flows (one per step).
	afterFlows, err := store.ListStreams(ctx, flow.StreamListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows after: %v", err)
	}
	newCount := len(afterFlows) - beforeCount
	if newCount != 2 {
		t.Errorf("new flows = %d, want 2 (one per macro step)", newCount)
	}

	// Find the macro-recorded flows by checking tags.
	var macroFlows []*flow.Stream
	for _, s := range afterFlows {
		if s.Tags != nil && s.Tags["macro"] == "record-test" {
			macroFlows = append(macroFlows, s)
		}
	}
	if len(macroFlows) != 2 {
		t.Fatalf("macro-tagged sessions = %d, want 2", len(macroFlows))
	}

	// Verify each macro session has the correct tags and messages.
	stepIDs := map[string]bool{}
	for _, ms := range macroFlows {
		if ms.Protocol != "HTTP/1.x" {
			t.Errorf("flow %s: Protocol = %q, want HTTP/1.x", ms.ID, ms.Protocol)
		}
		if ms.State != "complete" {
			t.Errorf("flow %s: State = %q, want complete", ms.ID, ms.State)
		}
		if ms.Tags["macro"] != "record-test" {
			t.Errorf("flow %s: Tags[macro] = %q, want record-test", ms.ID, ms.Tags["macro"])
		}
		stepID := ms.Tags["macro_step"]
		if stepID == "" {
			t.Errorf("flow %s: Tags[macro_step] is empty", ms.ID)
		}
		stepIDs[stepID] = true

		// Check send message exists.
		sendMsgs, err := store.GetFlows(ctx, ms.ID, flow.FlowListOptions{Direction: "send"})
		if err != nil {
			t.Errorf("GetMessages(send) for flow %s: %v", ms.ID, err)
			continue
		}
		if len(sendMsgs) != 1 {
			t.Errorf("flow %s: send messages = %d, want 1", ms.ID, len(sendMsgs))
			continue
		}
		if sendMsgs[0].Method == "" {
			t.Errorf("flow %s: send message has empty method", ms.ID)
		}
		if sendMsgs[0].URL == nil {
			t.Errorf("flow %s: send message has nil URL", ms.ID)
		}

		// Check receive message exists.
		recvMsgs, err := store.GetFlows(ctx, ms.ID, flow.FlowListOptions{Direction: "receive"})
		if err != nil {
			t.Errorf("GetMessages(receive) for flow %s: %v", ms.ID, err)
			continue
		}
		if len(recvMsgs) != 1 {
			t.Errorf("flow %s: receive messages = %d, want 1", ms.ID, len(recvMsgs))
			continue
		}
		if recvMsgs[0].StatusCode != 200 {
			t.Errorf("flow %s: receive StatusCode = %d, want 200", ms.ID, recvMsgs[0].StatusCode)
		}
	}

	// Verify both step IDs are recorded.
	if !stepIDs["step1"] {
		t.Error("missing macro session for step1")
	}
	if !stepIDs["step2"] {
		t.Error("missing macro session for step2")
	}
}

func TestExecute_RunMacro_SkippedStepNotRecorded(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Login server returns 200 (not 302), so the guarded step should be skipped.
	loginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer loginServer.Close()

	mfaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"mfa":"done"}`))
	}))
	defer mfaServer.Close()

	ctx := context.Background()

	loginURL, _ := url.Parse(loginServer.URL + "/login")
	loginSess := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, loginSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: loginSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: loginURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	mfaURL, _ := url.Parse(mfaServer.URL + "/mfa")
	mfaSess := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, mfaSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: mfaSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: mfaURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define macro with guarded step.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "skip-test",
			"steps": []any{
				map[string]any{
					"id":      "login",
					"flow_id": loginSess.ID,
				},
				map[string]any{
					"id":      "mfa",
					"flow_id": mfaSess.ID,
					"when": map[string]any{
						"step":        "login",
						"status_code": 302, // Login returns 200, so MFA is skipped.
					},
				},
			},
		},
	})

	// Run the macro.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{"name": "skip-test"},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var out macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &out)

	if out.StepsExecuted != 1 {
		t.Fatalf("StepsExecuted = %d, want 1", out.StepsExecuted)
	}

	// Only the executed step should create a macro session (not the skipped one).
	allFlows, err := store.ListStreams(ctx, flow.StreamListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	var macroFlows []*flow.Stream
	for _, s := range allFlows {
		if s.Tags != nil && s.Tags["macro"] == "skip-test" {
			macroFlows = append(macroFlows, s)
		}
	}
	if len(macroFlows) != 1 {
		t.Errorf("macro-tagged sessions = %d, want 1 (only executed step)", len(macroFlows))
	}
	if len(macroFlows) > 0 && macroFlows[0].Tags["macro_step"] != "login" {
		t.Errorf("macro_step = %q, want login", macroFlows[0].Tags["macro_step"])
	}
}
