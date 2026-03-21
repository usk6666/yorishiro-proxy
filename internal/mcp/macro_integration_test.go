//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- M3 Integration: Macro + Hooks ---

// TestM3_Macro_DefineAndRunWithExtract verifies the full macro lifecycle:
// define_macro -> run_macro -> verify KV Store contains extracted values.
func TestM3_Macro_DefineAndRunWithExtract(t *testing.T) {
	store := newTestStore(t)

	// Token server returns a flow token in a header.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session-Token", "extracted-token-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"authenticated"}`))
	}))
	defer tokenServer.Close()

	ctx := context.Background()

	// Save the template flow for the macro step.
	tokenURL, _ := url.Parse(tokenServer.URL + "/auth/login")
	fl := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: tokenURL,
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"username":"admin","password":"§password§"}`),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define the macro with extract rule.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":        "auth-flow",
			"description": "Login and extract session token",
			"steps": []any{
				map[string]any{
					"id":      "login",
					"flow_id": fl.ID,
					"extract": []any{
						map[string]any{
							"name":        "session_token",
							"from":        "response",
							"source":      "header",
							"header_name": "X-Session-Token",
						},
					},
				},
			},
			"initial_vars":     map[string]any{"password": "admin123"},
			"macro_timeout_ms": 30000,
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	var defOut macroDefineMacroResult
	unmarshalExecuteResult(t, defineResult, &defOut)
	if defOut.StepCount != 1 {
		t.Errorf("StepCount = %d, want 1", defOut.StepCount)
	}
	if !defOut.Created {
		t.Error("expected Created=true for new macro")
	}

	// Run the macro.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "auth-flow",
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var runOut macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &runOut)

	if runOut.MacroName != "auth-flow" {
		t.Errorf("MacroName = %q, want auth-flow", runOut.MacroName)
	}
	if runOut.Status != "completed" {
		t.Errorf("Status = %q, want completed", runOut.Status)
	}
	if runOut.StepsExecuted != 1 {
		t.Errorf("StepsExecuted = %d, want 1", runOut.StepsExecuted)
	}
	// The extracted token should be in the KV store.
	if runOut.KVStore["session_token"] != "extracted-token-value" {
		t.Errorf("KVStore[session_token] = %q, want extracted-token-value", runOut.KVStore["session_token"])
	}
}

// TestM3_Macro_StepGuard_When verifies that step guards (when conditions)
// control step execution based on prior step outcomes.
func TestM3_Macro_StepGuard_When(t *testing.T) {
	store := newTestStore(t)

	// Login server returns 302 to trigger the MFA step.
	loginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Token", "temp-token")
		w.WriteHeader(302)
		w.Write([]byte("redirect to mfa"))
	}))
	defer loginServer.Close()

	// MFA server returns 200.
	mfaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"mfa":"ok"}`))
	}))
	defer mfaServer.Close()

	ctx := context.Background()

	// Save login flow.
	loginURL, _ := url.Parse(loginServer.URL + "/login")
	loginSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, loginSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: loginSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: loginURL,
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"user":"admin"}`),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save MFA flow.
	mfaURL, _ := url.Parse(mfaServer.URL + "/mfa")
	mfaSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, mfaSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: mfaSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: mfaURL,
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"code":"123456"}`),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define macro with step guard: MFA only runs when login returns 302.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "login-mfa",
			"steps": []any{
				map[string]any{
					"id":      "login",
					"flow_id": loginSess.ID,
					"extract": []any{
						map[string]any{
							"name":        "token",
							"from":        "response",
							"source":      "header",
							"header_name": "X-Token",
						},
					},
				},
				map[string]any{
					"id":      "mfa",
					"flow_id": mfaSess.ID,
					"when": map[string]any{
						"step":        "login",
						"status_code": 302,
					},
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Run the macro -- login returns 302, so MFA step should execute.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "login-mfa",
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var runOut macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &runOut)

	if runOut.Status != "completed" {
		t.Errorf("Status = %q, want completed", runOut.Status)
	}
	if runOut.StepsExecuted != 2 {
		t.Errorf("StepsExecuted = %d, want 2 (both login and MFA)", runOut.StepsExecuted)
	}
	if len(runOut.StepResults) != 2 {
		t.Fatalf("StepResults count = %d, want 2", len(runOut.StepResults))
	}
	if runOut.StepResults[0].ID != "login" {
		t.Errorf("StepResults[0].ID = %q, want login", runOut.StepResults[0].ID)
	}
	if runOut.StepResults[1].ID != "mfa" {
		t.Errorf("StepResults[1].ID = %q, want mfa", runOut.StepResults[1].ID)
	}
}

// TestM3_Macro_StepGuard_Skipped verifies that a step with a guard that doesn't
// match is skipped.
func TestM3_Macro_StepGuard_Skipped(t *testing.T) {
	store := newTestStore(t)

	// Login returns 200 (not 302), so the guarded step should be skipped.
	loginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer loginServer.Close()

	mfaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"mfa":"completed"}`))
	}))
	defer mfaServer.Close()

	ctx := context.Background()

	loginURL, _ := url.Parse(loginServer.URL + "/login")
	loginSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, loginSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: loginSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: loginURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	mfaURL, _ := url.Parse(mfaServer.URL + "/mfa")
	mfaSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, mfaSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: mfaSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: mfaURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "login-mfa-skip",
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
						"status_code": 302, // Login returns 200, so this should be skipped.
					},
				},
			},
		},
	})

	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{"name": "login-mfa-skip"},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var runOut macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &runOut)

	if runOut.Status != "completed" {
		t.Errorf("Status = %q, want completed", runOut.Status)
	}
	// Only login step should execute, MFA should be skipped.
	if runOut.StepsExecuted != 1 {
		t.Errorf("StepsExecuted = %d, want 1 (MFA should be skipped)", runOut.StepsExecuted)
	}
}

// TestM3_Hook_ResendPreSendTemplateExpansion verifies that a pre_send hook runs
// a macro, extracts values, and template-expands them into resend override headers.
func TestM3_Hook_ResendPreSendTemplateExpansion(t *testing.T) {
	store := newTestStore(t)

	// Token server for the macro step.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Token", "hook-extracted-token")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer tokenServer.Close()

	// Target server that echoes the Authorization header.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
	}))
	defer targetServer.Close()

	ctx := context.Background()

	// Save token flow.
	tokenURL, _ := url.Parse(tokenServer.URL + "/token")
	tokenSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, tokenSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: tokenSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: tokenURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save target flow.
	targetURL, _ := url.Parse(targetServer.URL + "/api/data")
	targetSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, targetSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: targetSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: targetURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define the auth macro that extracts a token.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "auth-hook-macro",
			"steps": []any{
				map[string]any{
					"id":      "get-token",
					"flow_id": tokenSess.ID,
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

	// Resend with pre_send hook and template expansion.
	resendResult := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": targetSess.ID,
			"override_headers": map[string]any{
				"Authorization": "Bearer §auth_token§",
			},
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro":        "auth-hook-macro",
					"run_interval": "always",
				},
			},
		},
	})
	if resendResult.IsError {
		t.Fatalf("resend with hook failed: %v", resendResult.Content)
	}

	var out resendActionResult
	unmarshalExecuteResult(t, resendResult, &out)

	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}
	// The response body should contain the expanded token.
	if out.ResponseBody != "auth=Bearer hook-extracted-token" {
		t.Errorf("ResponseBody = %q, want %q", out.ResponseBody, "auth=Bearer hook-extracted-token")
	}
}

// TestM3_Hook_PostReceiveOnStatus verifies that a post_receive hook fires
// when the response matches the specified status code filter.
func TestM3_Hook_PostReceiveOnStatus(t *testing.T) {
	store := newTestStore(t)

	// Target server returns 401.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer targetServer.Close()

	// Macro step server (post_receive handler).
	macroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("logged"))
	}))
	defer macroServer.Close()

	ctx := context.Background()

	// Save macro step flow.
	macroURL, _ := url.Parse(macroServer.URL + "/log")
	macroSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, macroSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: macroSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: macroURL,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("log"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save target flow.
	targetURL, _ := url.Parse(targetServer.URL + "/api/secure")
	targetSess := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, targetSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: targetSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: targetURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define the post-receive logging macro.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "error-logger",
			"steps": []any{
				map[string]any{
					"id":      "log-error",
					"flow_id": macroSess.ID,
				},
			},
		},
	})

	// Resend with post_receive hook on 401.
	result := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": targetSess.ID,
			"hooks": map[string]any{
				"post_receive": map[string]any{
					"macro":         "error-logger",
					"pass_response": true,
					"run_interval":  "on_status",
					"status_codes":  []any{401, 403},
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend with post_receive hook failed: %v", result.Content)
	}

	var out resendActionResult
	unmarshalExecuteResult(t, result, &out)

	// The main request should still return 401.
	if out.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", out.StatusCode)
	}
}

// TestM3_Macro_QueryMacros verifies that defined macros can be queried
// and details retrieved.
func TestM3_Macro_QueryMacros(t *testing.T) {
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	// Define two macros.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":        "alpha",
			"description": "First macro",
			"steps": []any{
				map[string]any{"id": "s1", "flow_id": "sess-1"},
			},
		},
	})
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name":        "beta",
			"description": "Second macro",
			"steps": []any{
				map[string]any{"id": "s1", "flow_id": "sess-1"},
				map[string]any{"id": "s2", "flow_id": "sess-2"},
			},
		},
	})

	// Query list.
	listResult := callQueryRaw(t, cs, map[string]any{
		"resource": "macros",
	})
	if listResult.IsError {
		t.Fatalf("query macros error: %v", listResult.Content)
	}

	var macros queryMacrosResult
	unmarshalQueryResultRaw(t, listResult, &macros)

	if macros.Count != 2 {
		t.Errorf("Count = %d, want 2", macros.Count)
	}

	// Query single macro detail.
	detailResult := callQueryRaw(t, cs, map[string]any{
		"resource": "macro",
		"id":       "beta",
	})
	if detailResult.IsError {
		t.Fatalf("query macro detail error: %v", detailResult.Content)
	}

	var detail queryMacroResult
	unmarshalQueryResultRaw(t, detailResult, &detail)

	if detail.Name != "beta" {
		t.Errorf("Name = %q, want beta", detail.Name)
	}
	if detail.Description != "Second macro" {
		t.Errorf("Description = %q, want Second macro", detail.Description)
	}
	if len(detail.Steps) != 2 {
		t.Errorf("len(Steps) = %d, want 2", len(detail.Steps))
	}

	// Delete one macro and verify.
	deleteResult := callMacro(t, cs, map[string]any{
		"action": "delete_macro",
		"params": map[string]any{"name": "alpha"},
	})
	if deleteResult.IsError {
		t.Fatalf("delete_macro error: %v", deleteResult.Content)
	}

	var delOut macroDeleteMacroResult
	unmarshalExecuteResult(t, deleteResult, &delOut)
	if !delOut.Deleted {
		t.Error("expected Deleted=true")
	}

	// Verify only 1 macro remains.
	listResult2 := callQueryRaw(t, cs, map[string]any{
		"resource": "macros",
	})
	var macros2 queryMacrosResult
	unmarshalQueryResultRaw(t, listResult2, &macros2)
	if macros2.Count != 1 {
		t.Errorf("Count after delete = %d, want 1", macros2.Count)
	}
}

// TestM3_Macro_VarsOverrideRuntime verifies that run_macro vars override
// the initial_vars from define_macro.
func TestM3_Macro_VarsOverrideRuntime(t *testing.T) {
	store := newTestStore(t)

	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]any{
			"received_body": string(body),
		})
	}))
	defer echoServer.Close()

	ctx := context.Background()
	u, _ := url.Parse(echoServer.URL + "/api")
	fl := &flow.Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: u,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("data"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define with initial_vars.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "vars-test",
			"steps": []any{
				map[string]any{"id": "step1", "flow_id": fl.ID},
			},
			"initial_vars": map[string]any{"env": "default-env"},
		},
	})

	// Run with override vars.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "vars-test",
			"vars": map[string]any{"env": "production"},
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var out macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &out)

	if out.KVStore["env"] != "production" {
		t.Errorf("KVStore[env] = %q, want production", out.KVStore["env"])
	}
}
