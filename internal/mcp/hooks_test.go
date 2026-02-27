package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/session"
)

// --- validateHooks tests ---

func TestValidateHooks_Nil(t *testing.T) {
	if err := validateHooks(nil); err != nil {
		t.Fatalf("validateHooks(nil) = %v, want nil", err)
	}
}

func TestValidateHooks_EmptyPreSendMacro(t *testing.T) {
	hooks := &hooksInput{
		PreSend: &hookConfig{},
	}
	err := validateHooks(hooks)
	if err == nil {
		t.Fatal("expected error for empty pre_send macro name")
	}
}

func TestValidateHooks_EmptyPostReceiveMacro(t *testing.T) {
	hooks := &hooksInput{
		PostReceive: &hookConfig{},
	}
	err := validateHooks(hooks)
	if err == nil {
		t.Fatal("expected error for empty post_receive macro name")
	}
}

func TestValidateHooks_ValidPreSendIntervals(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		n        int
		wantErr  bool
	}{
		{name: "always", interval: "always", wantErr: false},
		{name: "once", interval: "once", wantErr: false},
		{name: "every_n_valid", interval: "every_n", n: 5, wantErr: false},
		{name: "every_n_zero", interval: "every_n", n: 0, wantErr: true},
		{name: "every_n_negative", interval: "every_n", n: -1, wantErr: true},
		{name: "on_error", interval: "on_error", wantErr: false},
		{name: "invalid", interval: "invalid", wantErr: true},
		{name: "empty_defaults_to_always", interval: "", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hooks := &hooksInput{
				PreSend: &hookConfig{
					Macro:       "test-macro",
					RunInterval: tt.interval,
					N:           tt.n,
				},
			}
			err := validateHooks(hooks)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHooks() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHooks_ValidPostReceiveIntervals(t *testing.T) {
	tests := []struct {
		name         string
		interval     string
		statusCodes  []int
		matchPattern string
		wantErr      bool
	}{
		{name: "always", interval: "always", wantErr: false},
		{name: "on_status_valid", interval: "on_status", statusCodes: []int{401, 403}, wantErr: false},
		{name: "on_status_empty_codes", interval: "on_status", wantErr: true},
		{name: "on_match_valid", interval: "on_match", matchPattern: "error.*", wantErr: false},
		{name: "on_match_empty_pattern", interval: "on_match", wantErr: true},
		{name: "on_match_invalid_regex", interval: "on_match", matchPattern: "[invalid", wantErr: true},
		{name: "invalid", interval: "invalid", wantErr: true},
		{name: "empty_defaults_to_always", interval: "", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hooks := &hooksInput{
				PostReceive: &hookConfig{
					Macro:        "test-macro",
					RunInterval:  tt.interval,
					StatusCodes:  tt.statusCodes,
					MatchPattern: tt.matchPattern,
				},
			}
			err := validateHooks(hooks)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHooks() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- shouldRunPreSend tests ---

func TestShouldRunPreSend_Always(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "always"}
	for i := 0; i < 5; i++ {
		if !he.shouldRunPreSend(h) {
			t.Errorf("iteration %d: shouldRunPreSend(always) = false, want true", i)
		}
		he.state.requestCount++
	}
}

func TestShouldRunPreSend_Once(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "once"}

	// First call should return true.
	if !he.shouldRunPreSend(h) {
		t.Error("first call: shouldRunPreSend(once) = false, want true")
	}
	he.state.requestCount++

	// Subsequent calls should return false.
	for i := 0; i < 5; i++ {
		if he.shouldRunPreSend(h) {
			t.Errorf("call %d: shouldRunPreSend(once) = true, want false", i+2)
		}
		he.state.requestCount++
	}
}

func TestShouldRunPreSend_EveryN(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "every_n", N: 3}

	expected := []bool{true, false, false, true, false, false, true}
	for i, want := range expected {
		got := he.shouldRunPreSend(h)
		if got != want {
			t.Errorf("iteration %d: shouldRunPreSend(every_3) = %v, want %v", i, got, want)
		}
		he.state.requestCount++
	}
}

func TestShouldRunPreSend_OnError(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "on_error"}

	// First request: always run (no previous error to check).
	if !he.shouldRunPreSend(h) {
		t.Error("first request: shouldRunPreSend(on_error) = false, want true")
	}
	he.state.requestCount++
	he.state.lastStatusCode = 200

	// After 200: should not run.
	if he.shouldRunPreSend(h) {
		t.Error("after 200: shouldRunPreSend(on_error) = true, want false")
	}
	he.state.requestCount++
	he.state.lastStatusCode = 401

	// After 401: should run.
	if !he.shouldRunPreSend(h) {
		t.Error("after 401: shouldRunPreSend(on_error) = false, want true")
	}
	he.state.requestCount++
	he.state.lastError = true
	he.state.lastStatusCode = 0

	// After transport error: should run.
	if !he.shouldRunPreSend(h) {
		t.Error("after error: shouldRunPreSend(on_error) = false, want true")
	}
}

// --- shouldRunPostReceive tests ---

func TestShouldRunPostReceive_Always(t *testing.T) {
	he := &hookExecutor{state: &hookState{}}
	h := &hookConfig{Macro: "m", RunInterval: "always"}
	if !he.shouldRunPostReceive(h, 200, nil) {
		t.Error("shouldRunPostReceive(always) = false, want true")
	}
}

func TestShouldRunPostReceive_OnStatus(t *testing.T) {
	he := &hookExecutor{state: &hookState{}}
	h := &hookConfig{Macro: "m", RunInterval: "on_status", StatusCodes: []int{401, 403}}

	if he.shouldRunPostReceive(h, 200, nil) {
		t.Error("shouldRunPostReceive(on_status, 200) = true, want false")
	}
	if !he.shouldRunPostReceive(h, 401, nil) {
		t.Error("shouldRunPostReceive(on_status, 401) = false, want true")
	}
	if !he.shouldRunPostReceive(h, 403, nil) {
		t.Error("shouldRunPostReceive(on_status, 403) = false, want true")
	}
}

func TestShouldRunPostReceive_OnMatch(t *testing.T) {
	he := &hookExecutor{state: &hookState{}}
	h := &hookConfig{
		Macro:           "m",
		RunInterval:     "on_match",
		MatchPattern:    `"error":\s*true`,
		compiledPattern: regexp.MustCompile(`"error":\s*true`),
	}

	if he.shouldRunPostReceive(h, 200, []byte(`{"ok":true}`)) {
		t.Error("shouldRunPostReceive(on_match, no match) = true, want false")
	}
	if !he.shouldRunPostReceive(h, 200, []byte(`{"error": true}`)) {
		t.Error("shouldRunPostReceive(on_match, match) = false, want true")
	}
}

// --- expandParamsWithKVStore tests ---

func TestExpandParamsWithKVStore_URL(t *testing.T) {
	params := executeParams{
		OverrideURL: "https://{{host}}/api/{{path}}",
	}
	kvStore := map[string]string{
		"host": "example.com",
		"path": "users",
	}
	if err := expandParamsWithKVStore(&params, kvStore); err != nil {
		t.Fatalf("expandParamsWithKVStore: %v", err)
	}
	want := "https://example.com/api/users"
	if params.OverrideURL != want {
		t.Errorf("OverrideURL = %q, want %q", params.OverrideURL, want)
	}
}

func TestExpandParamsWithKVStore_Headers(t *testing.T) {
	params := executeParams{
		OverrideHeaders: map[string]string{
			"Cookie":       "sid={{session_cookie}}",
			"X-CSRF-Token": "{{csrf_token}}",
		},
		AddHeaders: map[string]string{
			"Authorization": "Bearer {{token}}",
		},
	}
	kvStore := map[string]string{
		"session_cookie": "abc123",
		"csrf_token":     "x9f2k",
		"token":          "jwt-token",
	}
	if err := expandParamsWithKVStore(&params, kvStore); err != nil {
		t.Fatalf("expandParamsWithKVStore: %v", err)
	}
	if params.OverrideHeaders["Cookie"] != "sid=abc123" {
		t.Errorf("Cookie = %q, want %q", params.OverrideHeaders["Cookie"], "sid=abc123")
	}
	if params.OverrideHeaders["X-CSRF-Token"] != "x9f2k" {
		t.Errorf("X-CSRF-Token = %q, want %q", params.OverrideHeaders["X-CSRF-Token"], "x9f2k")
	}
	if params.AddHeaders["Authorization"] != "Bearer jwt-token" {
		t.Errorf("Authorization = %q, want %q", params.AddHeaders["Authorization"], "Bearer jwt-token")
	}
}

func TestExpandParamsWithKVStore_Body(t *testing.T) {
	body := `{"username":"admin","password":"{{password}}"}`
	params := executeParams{
		OverrideBody: &body,
	}
	kvStore := map[string]string{
		"password": "secret123",
	}
	if err := expandParamsWithKVStore(&params, kvStore); err != nil {
		t.Fatalf("expandParamsWithKVStore: %v", err)
	}
	want := `{"username":"admin","password":"secret123"}`
	if *params.OverrideBody != want {
		t.Errorf("OverrideBody = %q, want %q", *params.OverrideBody, want)
	}
}

func TestExpandParamsWithKVStore_EmptyKVStore(t *testing.T) {
	params := executeParams{
		OverrideURL: "https://{{host}}/api",
	}
	if err := expandParamsWithKVStore(&params, nil); err != nil {
		t.Fatalf("expandParamsWithKVStore: %v", err)
	}
	// URL should remain unchanged.
	if params.OverrideURL != "https://{{host}}/api" {
		t.Errorf("OverrideURL changed despite empty KV store")
	}
}

// --- parseHooksFromJSON tests ---

func TestParseHooksFromJSON_Nil(t *testing.T) {
	hooks, err := parseHooksFromJSON(nil)
	if err != nil {
		t.Fatalf("parseHooksFromJSON(nil) = %v", err)
	}
	if hooks != nil {
		t.Error("expected nil hooks")
	}
}

func TestParseHooksFromJSON_Null(t *testing.T) {
	hooks, err := parseHooksFromJSON(json.RawMessage("null"))
	if err != nil {
		t.Fatalf("parseHooksFromJSON(null) = %v", err)
	}
	if hooks != nil {
		t.Error("expected nil hooks")
	}
}

func TestParseHooksFromJSON_Valid(t *testing.T) {
	raw := json.RawMessage(`{
		"pre_send": {
			"macro": "auth-flow",
			"vars": {"password": "admin123"},
			"run_interval": "always"
		},
		"post_receive": {
			"macro": "log-response",
			"pass_response": true,
			"run_interval": "on_status",
			"status_codes": [401]
		}
	}`)
	hooks, err := parseHooksFromJSON(raw)
	if err != nil {
		t.Fatalf("parseHooksFromJSON: %v", err)
	}
	if hooks == nil {
		t.Fatal("expected non-nil hooks")
	}
	if hooks.PreSend == nil || hooks.PreSend.Macro != "auth-flow" {
		t.Errorf("PreSend.Macro = %v, want auth-flow", hooks.PreSend)
	}
	if hooks.PostReceive == nil || hooks.PostReceive.Macro != "log-response" {
		t.Errorf("PostReceive.Macro = %v, want log-response", hooks.PostReceive)
	}
	if !hooks.PostReceive.PassResponse {
		t.Error("PostReceive.PassResponse should be true")
	}
}

// --- Integration tests: resend with hooks ---

func TestExecute_Resend_WithPreSendHook(t *testing.T) {
	store := newTestStore(t)

	// Create a token server that returns a token value.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Token", "fresh-token-value")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer tokenServer.Close()

	// Create a target server that echoes back the received headers.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		resp := map[string]any{
			"received_token": r.Header.Get("X-Token"),
			"received_csrf":  r.Header.Get("X-Csrf-Token"),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer targetServer.Close()

	ctx := context.Background()

	// Save the token session (referenced by macro step).
	tokenURL, _ := url.Parse(tokenServer.URL + "/token")
	tokenSess := &session.Session{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveSession(ctx, tokenSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	tokenSendMsg := &session.Message{
		SessionID: tokenSess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       tokenURL,
		Headers:   map[string][]string{},
	}
	if err := store.AppendMessage(ctx, tokenSendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save the target session (referenced by resend).
	targetURL, _ := url.Parse(targetServer.URL + "/api/data")
	targetSess := &session.Session{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveSession(ctx, targetSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	targetSendMsg := &session.Message{
		SessionID: targetSess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       targetURL,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
	}
	if err := store.AppendMessage(ctx, targetSendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define the auth macro.
	defineResult := callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "auth-flow",
			"steps": []any{
				map[string]any{
					"id":         "get-token",
					"session_id": tokenSess.ID,
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

	// Resend with pre_send hook.
	resendResult := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": targetSess.ID,
			"override_headers": map[string]any{
				"X-Token": "{{token}}",
			},
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro": "auth-flow",
				},
			},
		},
	})
	if resendResult.IsError {
		t.Fatalf("resend with hooks failed: %v", resendResult.Content)
	}

	var out executeResendResult
	unmarshalExecuteResult(t, resendResult, &out)

	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}

	// Parse the response body to check if the token was injected.
	var responseData map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &responseData); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}

	receivedToken, _ := responseData["received_token"].(string)
	if receivedToken != "fresh-token-value" {
		t.Errorf("received_token = %q, want %q", receivedToken, "fresh-token-value")
	}
}

func TestExecute_Resend_WithPostReceiveHook(t *testing.T) {
	store := newTestStore(t)

	// Create a target server.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer targetServer.Close()

	// Create a macro step server.
	macroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(200)
		// The macro step will receive __response_body and __response_status as vars.
		w.Write(body)
	}))
	defer macroServer.Close()

	ctx := context.Background()

	// Save macro step session.
	macroURL, _ := url.Parse(macroServer.URL + "/log")
	macroSess := &session.Session{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveSession(ctx, macroSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: macroSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: macroURL,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("log entry"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save target session.
	targetURL, _ := url.Parse(targetServer.URL + "/api")
	targetSess := &session.Session{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
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

	// Define post-receive macro.
	callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "log-response",
			"steps": []any{
				map[string]any{
					"id":         "log",
					"session_id": macroSess.ID,
				},
			},
		},
	})

	// Resend with post_receive hook that fires on 401.
	result := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": targetSess.ID,
			"hooks": map[string]any{
				"post_receive": map[string]any{
					"macro":         "log-response",
					"pass_response": true,
					"run_interval":  "on_status",
					"status_codes":  []any{401},
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend with post_receive hook failed: %v", result.Content)
	}

	var out executeResendResult
	unmarshalExecuteResult(t, result, &out)
	if out.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", out.StatusCode)
	}
}

func TestExecute_Resend_WithInvalidHooks(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Save a minimal target session.
	targetURL, _ := url.Parse("https://example.com/api")
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

	// Invalid hooks: pre_send with invalid run_interval.
	result := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": targetSess.ID,
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro":        "some-macro",
					"run_interval": "invalid_interval",
				},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid run_interval")
	}
}

func TestExecute_Resend_WithHookEncoder(t *testing.T) {
	store := newTestStore(t)

	// Create a token server.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Token", "hello world")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer tokenServer.Close()

	// Create a target server that echoes back the Authorization header.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		fmt.Fprintf(w, "auth=%s", r.Header.Get("Authorization"))
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
	targetURL, _ := url.Parse(targetServer.URL + "/api")
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

	// Define macro that extracts a token.
	callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "token-macro",
			"steps": []any{
				map[string]any{
					"id":         "get-token",
					"session_id": tokenSess.ID,
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

	// Resend with hook, using {{token | base64}} encoder in header.
	result := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": targetSess.ID,
			"override_headers": map[string]any{
				"Authorization": "Bearer {{token | base64}}",
			},
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro": "token-macro",
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend with encoder hook failed: %v", result.Content)
	}

	var out executeResendResult
	unmarshalExecuteResult(t, result, &out)

	// The token "hello world" base64-encoded is "aGVsbG8gd29ybGQ=".
	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}
	wantAuth := "auth=Bearer aGVsbG8gd29ybGQ="
	if out.ResponseBody != wantAuth {
		t.Errorf("ResponseBody = %q, want %q", out.ResponseBody, wantAuth)
	}
}

// --- hookState tests ---

func TestHookState_UpdateState(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	he.updateState(200, false)
	if he.state.requestCount != 1 {
		t.Errorf("requestCount = %d, want 1", he.state.requestCount)
	}
	if he.state.lastStatusCode != 200 {
		t.Errorf("lastStatusCode = %d, want 200", he.state.lastStatusCode)
	}
	if he.state.lastError {
		t.Error("lastError should be false")
	}

	he.updateState(500, true)
	if he.state.requestCount != 2 {
		t.Errorf("requestCount = %d, want 2", he.state.requestCount)
	}
	if he.state.lastStatusCode != 500 {
		t.Errorf("lastStatusCode = %d, want 500", he.state.lastStatusCode)
	}
	if !he.state.lastError {
		t.Error("lastError should be true")
	}
}

// --- Resend with nonexistent hook macro ---

func TestExecute_Resend_WithNonexistentHookMacro(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	targetURL, _ := url.Parse("https://example.com/api")
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

	result := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": targetSess.ID,
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro": "nonexistent-macro",
				},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for nonexistent hook macro")
	}
}

// --- hookExecutor with pre_send + vars ---

func TestExecute_Resend_WithPreSendHookVars(t *testing.T) {
	store := newTestStore(t)

	// Server that returns a value based on the password var.
	macroStepServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Session", "session-for-"+string(body))
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer macroStepServer.Close()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "cookie=%s", r.Header.Get("Cookie"))
	}))
	defer targetServer.Close()

	ctx := context.Background()

	// Save macro step session.
	macroURL, _ := url.Parse(macroStepServer.URL + "/login")
	macroSess := &session.Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveSession(ctx, macroSess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.AppendMessage(ctx, &session.Message{
		SessionID: macroSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: macroURL,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("password={{password}}"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save target session.
	targetURL, _ := url.Parse(targetServer.URL + "/api")
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

	// Define macro with initial_vars.
	callExecute(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "auth-with-vars",
			"steps": []any{
				map[string]any{
					"id":            "login",
					"session_id":    macroSess.ID,
					"override_body": stringPtr("password={{password}}"),
					"extract": []any{
						map[string]any{
							"name":        "session_id",
							"from":        "response",
							"source":      "header",
							"header_name": "X-Session",
						},
					},
				},
			},
			"initial_vars": map[string]any{"password": "default-pwd"},
		},
	})

	// Resend with hook vars override.
	result := callExecute(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"session_id": targetSess.ID,
			"override_headers": map[string]any{
				"Cookie": "sid={{session_id}}",
			},
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro": "auth-with-vars",
					"vars":  map[string]any{"password": "overridden-pwd"},
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend with hook vars failed: %v", result.Content)
	}

	var out executeResendResult
	unmarshalExecuteResult(t, result, &out)
	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}
}

// stringPtr returns a pointer to a string value.
func stringPtr(s string) *string {
	return &s
}
