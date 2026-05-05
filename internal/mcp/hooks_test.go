package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
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

func TestValidatePostReceiveHook_MatchPatternLength(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "at max length accepted",
			pattern: strings.Repeat("a", maxRegexPatternLen),
			wantErr: false,
		},
		{
			name:    "exceeds max length rejected",
			pattern: strings.Repeat("a", maxRegexPatternLen+1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &hookConfig{
				Macro:        "test-macro",
				RunInterval:  "on_match",
				MatchPattern: tt.pattern,
			}
			err := validatePostReceiveHook(h)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePostReceiveHook() error = %v, wantErr %v", err, tt.wantErr)
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

// --- executePostReceive KV Store merge tests ---

func TestExecutePostReceive_KVStoreMerge(t *testing.T) {
	// Create a macro step server that echoes back received headers.
	macroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Echo back the Cookie header value to verify template expansion.
		fmt.Fprintf(w, "cookie=%s", r.Header.Get("Cookie"))
	}))
	defer macroServer.Close()

	store := newTestStore(t)
	ctx := context.Background()

	// Save macro step flow.
	macroURL, _ := url.Parse(macroServer.URL + "/logout")
	macroSess := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, macroSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: macroSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: macroURL,
		Headers: map[string][]string{"Cookie": {"§auth_session§"}},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	// Define logout macro that uses §auth_session§ from its vars.
	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "logout-macro",
			"steps": []any{
				map[string]any{
					"id":      "logout",
					"flow_id": macroSess.ID,
				},
			},
		},
	})

	// Create the hook executor with post_receive hook that has its own vars.
	s := newServer(context.Background(), nil, store, nil)
	hooks := &hooksInput{
		PostReceive: &hookConfig{
			Macro:       "logout-macro",
			RunInterval: "always",
			Vars:        map[string]string{"auth_session": "config-session-value"},
		},
	}
	state := &hookState{}
	executor := newHookExecutor(s, hooks, state)

	// Call executePostReceive with KV Store from pre_send that has the same key.
	// pre_send KV Store should take precedence over hook config vars.
	kvStore := map[string]string{"auth_session": "pre-send-session-value"}
	err := executor.executePostReceive(ctx, 200, []byte("ok"), kvStore)
	if err != nil {
		t.Fatalf("executePostReceive: %v", err)
	}
}

func TestExecutePostReceive_NilKVStore(t *testing.T) {
	// When kvStore is nil, only hook config vars should be used.
	macroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer macroServer.Close()

	store := newTestStore(t)
	ctx := context.Background()

	macroURL, _ := url.Parse(macroServer.URL + "/cleanup")
	macroSess := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, macroSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: macroSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: macroURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "cleanup-macro",
			"steps": []any{
				map[string]any{
					"id":      "cleanup",
					"flow_id": macroSess.ID,
				},
			},
		},
	})

	s := newServer(context.Background(), nil, store, nil)
	hooks := &hooksInput{
		PostReceive: &hookConfig{
			Macro:       "cleanup-macro",
			RunInterval: "always",
			Vars:        map[string]string{"key": "value"},
		},
	}
	state := &hookState{}
	executor := newHookExecutor(s, hooks, state)

	// Call with nil kvStore — should not panic or error.
	err := executor.executePostReceive(ctx, 200, []byte("ok"), nil)
	if err != nil {
		t.Fatalf("executePostReceive with nil kvStore: %v", err)
	}
}

func TestExecutePostReceive_EmptyKVStore(t *testing.T) {
	// When kvStore is empty, only hook config vars should be used.
	macroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer macroServer.Close()

	store := newTestStore(t)
	ctx := context.Background()

	macroURL, _ := url.Parse(macroServer.URL + "/cleanup")
	macroSess := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, macroSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: macroSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: macroURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "cleanup-macro-2",
			"steps": []any{
				map[string]any{
					"id":      "cleanup",
					"flow_id": macroSess.ID,
				},
			},
		},
	})

	s := newServer(context.Background(), nil, store, nil)
	hooks := &hooksInput{
		PostReceive: &hookConfig{
			Macro:       "cleanup-macro-2",
			RunInterval: "always",
			Vars:        map[string]string{"key": "value"},
		},
	}
	state := &hookState{}
	executor := newHookExecutor(s, hooks, state)

	// Call with empty kvStore — should not modify behavior.
	err := executor.executePostReceive(ctx, 200, []byte("ok"), map[string]string{})
	if err != nil {
		t.Fatalf("executePostReceive with empty kvStore: %v", err)
	}
}
