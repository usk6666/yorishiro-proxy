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
	"github.com/usk6666/yorishiro-proxy/internal/session"
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

func TestExecute_RunMacro_RecordsSessions(t *testing.T) {
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

	// Save a template session for step1.
	u1, _ := url.Parse(echoServer.URL + "/api/step1")
	sess1 := &session.Session{
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    50 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess1); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: sess1.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       u1,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save a template session for step2.
	u2, _ := url.Parse(echoServer.URL + "/api/step2")
	sess2 := &session.Session{
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    50 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess2); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: sess2.ID,
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
	defineResult := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "record-test",
			"steps": []any{
				map[string]any{
					"id":         "step1",
					"session_id": sess1.ID,
				},
				map[string]any{
					"id":         "step2",
					"session_id": sess2.ID,
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Count sessions before running the macro.
	beforeSessions, err := store.ListSessions(ctx, session.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions before: %v", err)
	}
	beforeCount := len(beforeSessions)

	// Run the macro.
	runResult := callExecute(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "record-test",
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var out executeRunMacroResult
	unmarshalExecuteResult(t, runResult, &out)

	if out.Status != "completed" {
		t.Fatalf("Status = %q, want completed", out.Status)
	}
	if out.StepsExecuted != 2 {
		t.Fatalf("StepsExecuted = %d, want 2", out.StepsExecuted)
	}

	// After running, there should be 2 new sessions (one per step).
	afterSessions, err := store.ListSessions(ctx, session.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions after: %v", err)
	}
	newCount := len(afterSessions) - beforeCount
	if newCount != 2 {
		t.Errorf("new sessions = %d, want 2 (one per macro step)", newCount)
	}

	// Find the macro-recorded sessions by checking tags.
	var macroSessions []*session.Session
	for _, s := range afterSessions {
		if s.Tags != nil && s.Tags["macro"] == "record-test" {
			macroSessions = append(macroSessions, s)
		}
	}
	if len(macroSessions) != 2 {
		t.Fatalf("macro-tagged sessions = %d, want 2", len(macroSessions))
	}

	// Verify each macro session has the correct tags and messages.
	stepIDs := map[string]bool{}
	for _, ms := range macroSessions {
		if ms.Protocol != "HTTP/1.x" {
			t.Errorf("session %s: Protocol = %q, want HTTP/1.x", ms.ID, ms.Protocol)
		}
		if ms.SessionType != "unary" {
			t.Errorf("session %s: SessionType = %q, want unary", ms.ID, ms.SessionType)
		}
		if ms.State != "complete" {
			t.Errorf("session %s: State = %q, want complete", ms.ID, ms.State)
		}
		if ms.Tags["macro"] != "record-test" {
			t.Errorf("session %s: Tags[macro] = %q, want record-test", ms.ID, ms.Tags["macro"])
		}
		stepID := ms.Tags["macro_step"]
		if stepID == "" {
			t.Errorf("session %s: Tags[macro_step] is empty", ms.ID)
		}
		stepIDs[stepID] = true

		// Check send message exists.
		sendMsgs, err := store.GetMessages(ctx, ms.ID, session.MessageListOptions{Direction: "send"})
		if err != nil {
			t.Errorf("GetMessages(send) for session %s: %v", ms.ID, err)
			continue
		}
		if len(sendMsgs) != 1 {
			t.Errorf("session %s: send messages = %d, want 1", ms.ID, len(sendMsgs))
			continue
		}
		if sendMsgs[0].Method == "" {
			t.Errorf("session %s: send message has empty method", ms.ID)
		}
		if sendMsgs[0].URL == nil {
			t.Errorf("session %s: send message has nil URL", ms.ID)
		}

		// Check receive message exists.
		recvMsgs, err := store.GetMessages(ctx, ms.ID, session.MessageListOptions{Direction: "receive"})
		if err != nil {
			t.Errorf("GetMessages(receive) for session %s: %v", ms.ID, err)
			continue
		}
		if len(recvMsgs) != 1 {
			t.Errorf("session %s: receive messages = %d, want 1", ms.ID, len(recvMsgs))
			continue
		}
		if recvMsgs[0].StatusCode != 200 {
			t.Errorf("session %s: receive StatusCode = %d, want 200", ms.ID, recvMsgs[0].StatusCode)
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
	loginSess := &session.Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveSession(ctx, loginSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: loginSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: loginURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	mfaURL, _ := url.Parse(mfaServer.URL + "/mfa")
	mfaSess := &session.Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveSession(ctx, mfaSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: mfaSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: mfaURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define macro with guarded step.
	callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "skip-test",
			"steps": []any{
				map[string]any{
					"id":         "login",
					"session_id": loginSess.ID,
				},
				map[string]any{
					"id":         "mfa",
					"session_id": mfaSess.ID,
					"when": map[string]any{
						"step":        "login",
						"status_code": 302, // Login returns 200, so MFA is skipped.
					},
				},
			},
		},
	})

	// Run the macro.
	runResult := callExecute(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{"name": "skip-test"},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var out executeRunMacroResult
	unmarshalExecuteResult(t, runResult, &out)

	if out.StepsExecuted != 1 {
		t.Fatalf("StepsExecuted = %d, want 1", out.StepsExecuted)
	}

	// Only the executed step should create a macro session (not the skipped one).
	allSessions, err := store.ListSessions(ctx, session.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	var macroSessions []*session.Session
	for _, s := range allSessions {
		if s.Tags != nil && s.Tags["macro"] == "skip-test" {
			macroSessions = append(macroSessions, s)
		}
	}
	if len(macroSessions) != 1 {
		t.Errorf("macro-tagged sessions = %d, want 1 (only executed step)", len(macroSessions))
	}
	if len(macroSessions) > 0 && macroSessions[0].Tags["macro_step"] != "login" {
		t.Errorf("macro_step = %q, want login", macroSessions[0].Tags["macro_step"])
	}
}

func TestExecute_RunMacro_HookAlsoRecordsSessions(t *testing.T) {
	store := newTestStore(t)

	// Token server for the hook macro step.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Token", "hook-token")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer tokenServer.Close()

	// Target server for the main resend.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("target-ok"))
	}))
	defer targetServer.Close()

	ctx := context.Background()

	// Save token session.
	tokenURL, _ := url.Parse(tokenServer.URL + "/token")
	tokenSess := &session.Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveSession(ctx, tokenSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: tokenSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: tokenURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save target session.
	targetURL, _ := url.Parse(targetServer.URL + "/api/data")
	targetSess := &session.Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveSession(ctx, targetSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: targetSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: targetURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define the hook macro.
	callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "hook-macro",
			"steps": []any{
				map[string]any{
					"id":         "get-token",
					"session_id": tokenSess.ID,
					"extract": []any{
						map[string]any{
							"name":        "auth_token",
							"from":        "response",
							"source":      "header",
							"header_name": "X-Auth-Token",
						},
					},
				},
			},
		},
	})

	// Count sessions before resend.
	beforeSessions, err := store.ListSessions(ctx, session.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	beforeCount := len(beforeSessions)

	// Resend with pre_send hook.
	resendResult := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": targetSess.ID,
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro":        "hook-macro",
					"run_interval": "always",
				},
			},
		},
	})
	if resendResult.IsError {
		t.Fatalf("resend with hook failed: %v", resendResult.Content)
	}

	// Check that the hook macro step was recorded as a session.
	afterSessions, err := store.ListSessions(ctx, session.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}

	var hookSessions []*session.Session
	for _, s := range afterSessions {
		if s.Tags != nil && s.Tags["macro"] == "hook-macro" {
			hookSessions = append(hookSessions, s)
		}
	}

	if len(hookSessions) != 1 {
		t.Errorf("hook macro sessions = %d, want 1", len(hookSessions))
	}
	if len(hookSessions) > 0 {
		if hookSessions[0].Tags["macro_step"] != "get-token" {
			t.Errorf("macro_step = %q, want get-token", hookSessions[0].Tags["macro_step"])
		}
	}

	// The total new sessions should be at least 2: 1 for the hook macro step + 1 for the resend itself.
	newCount := len(afterSessions) - beforeCount
	if newCount < 2 {
		t.Errorf("new sessions = %d, want >= 2 (hook macro + resend)", newCount)
	}
}
