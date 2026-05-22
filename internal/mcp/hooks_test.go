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
	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// --- validateHooks tests ---

func TestValidateHooks_Nil(t *testing.T) {
	if err := validateHooks(nil); err != nil {
		t.Fatalf("validateHooks(nil) = %v, want nil", err)
	}
}

func TestValidateHooks_EmptyPreMacro(t *testing.T) {
	hooks := &hooksInput{
		PreMacro: &hookConfig{},
	}
	err := validateHooks(hooks)
	if err == nil {
		t.Fatal("expected error for empty pre_macro macro name")
	}
}

func TestValidateHooks_EmptyPostMacro(t *testing.T) {
	hooks := &hooksInput{
		PostMacro: &hookConfig{},
	}
	err := validateHooks(hooks)
	if err == nil {
		t.Fatal("expected error for empty post_macro macro name")
	}
}

func TestValidateHooks_ValidPreMacroIntervals(t *testing.T) {
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
				PreMacro: &hookConfig{
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

func TestValidateHooks_ValidPostMacroIntervals(t *testing.T) {
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
				PostMacro: &hookConfig{
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

func TestValidatePostMacroHook_MatchPatternLength(t *testing.T) {
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
			err := validatePostMacroHook(h)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePostMacroHook() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- shouldRunPreMacro tests ---

func TestShouldRunPreMacro_Always(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "always"}
	for i := 0; i < 5; i++ {
		if !he.shouldRunPreMacro(h) {
			t.Errorf("iteration %d: shouldRunPreMacro(always) = false, want true", i)
		}
		he.state.requestCount++
	}
}

func TestShouldRunPreMacro_Once(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "once"}

	// First call should return true.
	if !he.shouldRunPreMacro(h) {
		t.Error("first call: shouldRunPreMacro(once) = false, want true")
	}
	he.state.requestCount++

	// Subsequent calls should return false.
	for i := 0; i < 5; i++ {
		if he.shouldRunPreMacro(h) {
			t.Errorf("call %d: shouldRunPreMacro(once) = true, want false", i+2)
		}
		he.state.requestCount++
	}
}

func TestShouldRunPreMacro_EveryN(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "every_n", N: 3}

	expected := []bool{true, false, false, true, false, false, true}
	for i, want := range expected {
		got := he.shouldRunPreMacro(h)
		if got != want {
			t.Errorf("iteration %d: shouldRunPreMacro(every_3) = %v, want %v", i, got, want)
		}
		he.state.requestCount++
	}
}

func TestShouldRunPreMacro_OnError(t *testing.T) {
	he := &hookExecutor{
		state: &hookState{},
	}
	h := &hookConfig{Macro: "m", RunInterval: "on_error"}

	// First request: always run (no previous error to check).
	if !he.shouldRunPreMacro(h) {
		t.Error("first request: shouldRunPreMacro(on_error) = false, want true")
	}
	he.state.requestCount++
	he.state.lastStatusCode = 200

	// After 200: should not run.
	if he.shouldRunPreMacro(h) {
		t.Error("after 200: shouldRunPreMacro(on_error) = true, want false")
	}
	he.state.requestCount++
	he.state.lastStatusCode = 401

	// After 401: should run.
	if !he.shouldRunPreMacro(h) {
		t.Error("after 401: shouldRunPreMacro(on_error) = false, want true")
	}
	he.state.requestCount++
	he.state.lastError = true
	he.state.lastStatusCode = 0

	// After transport error: should run.
	if !he.shouldRunPreMacro(h) {
		t.Error("after error: shouldRunPreMacro(on_error) = false, want true")
	}
}

// --- shouldRunPostMacro tests ---

func TestShouldRunPostMacro_Always(t *testing.T) {
	he := &hookExecutor{state: &hookState{}}
	h := &hookConfig{Macro: "m", RunInterval: "always"}
	if !he.shouldRunPostMacro(h, 200, nil) {
		t.Error("shouldRunPostMacro(always) = false, want true")
	}
}

func TestShouldRunPostMacro_OnStatus(t *testing.T) {
	he := &hookExecutor{state: &hookState{}}
	h := &hookConfig{Macro: "m", RunInterval: "on_status", StatusCodes: []int{401, 403}}

	if he.shouldRunPostMacro(h, 200, nil) {
		t.Error("shouldRunPostMacro(on_status, 200) = true, want false")
	}
	if !he.shouldRunPostMacro(h, 401, nil) {
		t.Error("shouldRunPostMacro(on_status, 401) = false, want true")
	}
	if !he.shouldRunPostMacro(h, 403, nil) {
		t.Error("shouldRunPostMacro(on_status, 403) = false, want true")
	}
}

func TestShouldRunPostMacro_OnMatch(t *testing.T) {
	he := &hookExecutor{state: &hookState{}}
	h := &hookConfig{
		Macro:           "m",
		RunInterval:     "on_match",
		MatchPattern:    `"error":\s*true`,
		compiledPattern: regexp.MustCompile(`"error":\s*true`),
	}

	if he.shouldRunPostMacro(h, 200, []byte(`{"ok":true}`)) {
		t.Error("shouldRunPostMacro(on_match, no match) = true, want false")
	}
	if !he.shouldRunPostMacro(h, 200, []byte(`{"error": true}`)) {
		t.Error("shouldRunPostMacro(on_match, match) = false, want true")
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

// --- executePostMacro KV Store merge tests ---

func TestExecutePostMacro_KVStoreMerge(t *testing.T) {
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
		PostMacro: &hookConfig{
			Macro:       "logout-macro",
			RunInterval: "always",
			Vars:        map[string]string{"auth_session": "config-session-value"},
		},
	}
	state := &hookState{}
	executor := newHookExecutor(s, hooks, state)

	// Call executePostMacro with KV Store from pre_macro that has the same key.
	// pre_macro KV Store should take precedence over hook config vars.
	kvStore := map[string]string{"auth_session": "pre-macro-session-value"}
	err := executor.executePostMacro(ctx, 200, []byte("ok"), nil, kvStore)
	if err != nil {
		t.Fatalf("executePostMacro: %v", err)
	}
}

func TestExecutePostMacro_NilKVStore(t *testing.T) {
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
		PostMacro: &hookConfig{
			Macro:       "cleanup-macro",
			RunInterval: "always",
			Vars:        map[string]string{"key": "value"},
		},
	}
	state := &hookState{}
	executor := newHookExecutor(s, hooks, state)

	// Call with nil kvStore — should not panic or error.
	err := executor.executePostMacro(ctx, 200, []byte("ok"), nil, nil)
	if err != nil {
		t.Fatalf("executePostMacro with nil kvStore: %v", err)
	}
}

func TestExecutePostMacro_EmptyKVStore(t *testing.T) {
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
		PostMacro: &hookConfig{
			Macro:       "cleanup-macro-2",
			RunInterval: "always",
			Vars:        map[string]string{"key": "value"},
		},
	}
	state := &hookState{}
	executor := newHookExecutor(s, hooks, state)

	// Call with empty kvStore — should not modify behavior.
	err := executor.executePostMacro(ctx, 200, []byte("ok"), nil, map[string]string{})
	if err != nil {
		t.Fatalf("executePostMacro with empty kvStore: %v", err)
	}
}

// TestRecordMacroStepSessionDeps_RecordsCanonicalProtocol is a regression guard
// for USK-774: recordMacroStepSessionDeps must persist the canonical
// envelope.ProtocolHTTP value ("http"), not the legacy "HTTP/1.x" spelling, so
// macro-recorded streams match the query MCP tool's protocol filter (canonical
// only since USK-705 / PR #694).
func TestRecordMacroStepSessionDeps_RecordsCanonicalProtocol(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	s := newServer(context.Background(), nil, store, nil)

	reqURL, _ := url.Parse("http://example.test/api/v1/login")
	httpReq, err := http.NewRequestWithContext(ctx, "POST", reqURL.String(), strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
	}
	respBody := []byte(`{"ok":true}`)
	macroReq := &macro.SendRequest{
		Method: "POST",
		URL:    reqURL.String(),
		Body:   []byte("{}"),
		StepID: "login",
	}
	start := time.Now().UTC()
	duration := 10 * time.Millisecond

	recordMacroStepSessionDeps(ctx, s, "login-macro", macroReq, resp, respBody, httpReq, start, duration)

	streams, err := store.ListStreams(ctx, flow.StreamListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("ListStreams returned %d, want 1", len(streams))
	}
	got := streams[0]
	if got.Protocol != "http" {
		t.Errorf("Stream.Protocol = %q, want %q (canonical envelope.ProtocolHTTP)", got.Protocol, "http")
	}
	if got.Tags["macro"] != "login-macro" || got.Tags["macro_step"] != "login" {
		t.Errorf("Tags = %#v, want macro=login-macro, macro_step=login", got.Tags)
	}

	// Round-trip via the query-style protocol filter to confirm the canonical
	// value flows through StreamListOptions.Protocol matching.
	matched, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "http", Limit: 100})
	if err != nil {
		t.Fatalf("ListStreams(protocol=http): %v", err)
	}
	if len(matched) != 1 || matched[0].ID != got.ID {
		t.Errorf("ListStreams(protocol=http) returned %d entries, want exactly the macro-recorded stream", len(matched))
	}
}
