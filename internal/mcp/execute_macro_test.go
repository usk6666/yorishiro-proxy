package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// setupMacroTestSession creates an MCP client session for macro action tests.
// It uses a permissive HTTP client to allow localhost connections.
func setupMacroTestSession(t *testing.T, store session.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, store, nil)
	s.replayDoer = newPermissiveClient()
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

// callExecute invokes the execute tool and returns the raw result.
func callExecute(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
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
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":        "auth-flow",
			"description": "Login and get CSRF token",
			"steps": []any{
				map[string]any{
					"id":         "login",
					"session_id": "recorded-login",
				},
				map[string]any{
					"id":         "get-csrf",
					"session_id": "recorded-csrf",
				},
			},
			"initial_vars":    map[string]any{"password": "admin123"},
			"macro_timeout_ms": 60000,
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDefineMacroResult
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
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	steps := []any{
		map[string]any{
			"id":         "step1",
			"session_id": "s1",
		},
	}

	// First define.
	result1 := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":  "test-macro",
			"steps": steps,
		},
	})
	if result1.IsError {
		t.Fatalf("first define failed: %v", result1.Content)
	}

	var out1 executeDefineMacroResult
	unmarshalExecuteResult(t, result1, &out1)
	if !out1.Created {
		t.Error("first define should report Created=true")
	}

	// Second define (update).
	result2 := callExecute(t, cs, map[string]any{
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

	var out2 executeDefineMacroResult
	unmarshalExecuteResult(t, result2, &out2)
	if out2.Created {
		t.Error("second define should report Created=false (update)")
	}
}

func TestExecute_DefineMacro_MissingName(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"steps": []any{
				map[string]any{"id": "s1", "session_id": "sess"},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error for missing name")
	}
}

func TestExecute_DefineMacro_MissingSteps(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
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
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// The MCP SDK may validate the schema and reject the request before
	// it reaches our handler. Either the SDK error or our validation error
	// is acceptable.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "execute",
		Arguments: map[string]any{
			"action": "define_macro",
			"params": map[string]any{
				"name": "bad-step",
				"steps": []any{
					map[string]any{"session_id": "sess"},
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

func TestExecute_DefineMacro_InvalidStep_MissingSessionID(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// The MCP SDK may validate the schema and reject the request before
	// it reaches our handler. Either the SDK error or our validation error
	// is acceptable.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "execute",
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
		t.Fatal("expected error for step without session_id")
	}
}

func TestExecute_DefineMacro_DuplicateStepID(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "dup-steps",
			"steps": []any{
				map[string]any{"id": "s1", "session_id": "sess"},
				map[string]any{"id": "s1", "session_id": "sess2"},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error for duplicate step IDs")
	}
}

func TestExecute_RunMacro_Success(t *testing.T) {
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

	// Save a session that the macro step will reference.
	sess := &session.Session{
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    100 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	sendMsg := &session.Message{
		SessionID: sess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"user":"admin"}`),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define a macro that references the session.
	defineResult := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "test-macro",
			"steps": []any{
				map[string]any{
					"id":         "login",
					"session_id": sess.ID,
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
	runResult := callExecute(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "test-macro",
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var out executeRunMacroResult
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

	sess := &session.Session{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	sendMsg := &session.Message{
		SessionID: sess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		Body:      []byte("hello"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define macro with initial_vars.
	callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "vars-macro",
			"steps": []any{
				map[string]any{
					"id":         "step1",
					"session_id": sess.ID,
				},
			},
			"initial_vars": map[string]any{"key1": "default-value"},
		},
	})

	// Run with vars override.
	result := callExecute(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "vars-macro",
			"vars": map[string]any{"key1": "overridden"},
		},
	})
	if result.IsError {
		t.Fatalf("run_macro failed: %v", result.Content)
	}

	var out executeRunMacroResult
	unmarshalExecuteResult(t, result, &out)

	if out.KVStore["key1"] != "overridden" {
		t.Errorf("KVStore[key1] = %q, want %q", out.KVStore["key1"], "overridden")
	}
}

func TestExecute_RunMacro_NotFound(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
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
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{},
	})

	if !result.IsError {
		t.Fatal("expected error for missing name")
	}
}

func TestExecute_DeleteMacro_Success(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// Create a macro first.
	callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "to-delete",
			"steps": []any{
				map[string]any{"id": "s1", "session_id": "sess"},
			},
		},
	})

	// Delete it.
	result := callExecute(t, cs, map[string]any{
		"action": "delete_macro",
		"params": map[string]any{
			"name": "to-delete",
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDeleteMacroResult
	unmarshalExecuteResult(t, result, &out)

	if out.Name != "to-delete" {
		t.Errorf("Name = %q, want %q", out.Name, "to-delete")
	}
	if !out.Deleted {
		t.Error("Deleted should be true")
	}

	// Verify macro is gone.
	queryResult := callExecute(t, cs, map[string]any{
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
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
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
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
		"action": "delete_macro",
		"params": map[string]any{},
	})

	if !result.IsError {
		t.Fatal("expected error for missing name")
	}
}

func TestExecute_DefineMacro_WithExtractAndGuard(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "complex-macro",
			"steps": []any{
				map[string]any{
					"id":         "login",
					"session_id": "sess-1",
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
					"id":         "mfa",
					"session_id": "sess-2",
					"when": map[string]any{
						"step":        "login",
						"status_code": 302,
					},
					"override_headers": map[string]any{
						"Cookie": "sid={{cookie}}",
					},
				},
			},
			"initial_vars": map[string]any{"password": "secret"},
		},
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDefineMacroResult
	unmarshalExecuteResult(t, result, &out)

	if out.StepCount != 2 {
		t.Errorf("StepCount = %d, want 2", out.StepCount)
	}
}

func TestExecute_DefineMacro_NoStore(t *testing.T) {
	// Test with nil store.
	ctx := context.Background()
	s := NewServer(context.Background(), nil, nil, nil)
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

	result := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "test",
			"steps": []any{
				map[string]any{"id": "s1", "session_id": "sess"},
			},
		},
	})

	if !result.IsError {
		t.Fatal("expected error when store is nil")
	}
}
