package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/macro"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// hooksInput holds the hook configuration for resend/fuzz actions.
type hooksInput struct {
	// PreSend is the hook executed before the main request is sent.
	PreSend *hookConfig `json:"pre_send,omitempty"`
	// PostReceive is the hook executed after the main response is received.
	PostReceive *hookConfig `json:"post_receive,omitempty"`
}

// hookConfig defines a single hook's configuration.
type hookConfig struct {
	// Macro is the name of the stored macro to execute.
	Macro string `json:"macro"`
	// Vars are runtime variable overrides for the macro.
	Vars map[string]string `json:"vars,omitempty"`
	// RunInterval controls when the hook fires.
	// For pre_send: "always" (default), "once", "every_n", "on_error".
	// For post_receive: "always" (default), "on_status", "on_match".
	RunInterval string `json:"run_interval,omitempty"`
	// N is the interval count for "every_n" run_interval.
	N int `json:"n,omitempty"`
	// StatusCodes is the list of status codes for "on_status" run_interval.
	StatusCodes []int `json:"status_codes,omitempty"`
	// MatchPattern is the regex pattern for "on_match" run_interval.
	MatchPattern string `json:"match_pattern,omitempty"`
	// compiledPattern is the pre-compiled regexp for MatchPattern.
	// Set during validation to avoid recompilation on every invocation.
	compiledPattern *regexp.Regexp
	// PassResponse passes the main request's response to the macro when true.
	// Only applicable to post_receive hooks.
	PassResponse bool `json:"pass_response,omitempty"`
}

// validPreSendIntervals are the allowed run_interval values for pre_send hooks.
var validPreSendIntervals = map[string]bool{
	"always":   true,
	"once":     true,
	"every_n":  true,
	"on_error": true,
}

// validPostReceiveIntervals are the allowed run_interval values for post_receive hooks.
var validPostReceiveIntervals = map[string]bool{
	"always":    true,
	"on_status": true,
	"on_match":  true,
}

// validateHooks validates the hooks configuration.
func validateHooks(hooks *hooksInput) error {
	if hooks == nil {
		return nil
	}
	if hooks.PreSend != nil {
		if err := validatePreSendHook(hooks.PreSend); err != nil {
			return fmt.Errorf("pre_send: %w", err)
		}
	}
	if hooks.PostReceive != nil {
		if err := validatePostReceiveHook(hooks.PostReceive); err != nil {
			return fmt.Errorf("post_receive: %w", err)
		}
	}
	return nil
}

// validatePreSendHook validates a pre_send hook configuration.
func validatePreSendHook(h *hookConfig) error {
	if h.Macro == "" {
		return fmt.Errorf("macro name is required")
	}
	interval := h.RunInterval
	if interval == "" {
		interval = "always"
	}
	if !validPreSendIntervals[interval] {
		return fmt.Errorf("invalid run_interval %q: must be one of always, once, every_n, on_error", interval)
	}
	if interval == "every_n" && h.N <= 0 {
		return fmt.Errorf("n must be > 0 for every_n run_interval")
	}
	return nil
}

// validatePostReceiveHook validates a post_receive hook configuration.
func validatePostReceiveHook(h *hookConfig) error {
	if h.Macro == "" {
		return fmt.Errorf("macro name is required")
	}
	interval := h.RunInterval
	if interval == "" {
		interval = "always"
	}
	if !validPostReceiveIntervals[interval] {
		return fmt.Errorf("invalid run_interval %q: must be one of always, on_status, on_match", interval)
	}
	if interval == "on_status" && len(h.StatusCodes) == 0 {
		return fmt.Errorf("status_codes is required for on_status run_interval")
	}
	if interval == "on_match" && h.MatchPattern == "" {
		return fmt.Errorf("match_pattern is required for on_match run_interval")
	}
	if h.MatchPattern != "" {
		re, err := regexp.Compile(h.MatchPattern)
		if err != nil {
			return fmt.Errorf("invalid match_pattern: %w", err)
		}
		h.compiledPattern = re
	}
	return nil
}

// hookState tracks the execution state of hooks across multiple iterations
// (used by fuzzer). For single resend calls, a fresh hookState is created each time.
type hookState struct {
	// preSendExecuted tracks whether the pre_send hook has been executed (for "once").
	preSendExecuted bool
	// requestCount tracks the total number of main requests sent (for "every_n").
	requestCount int
	// lastStatusCode is the status code from the previous main request (for "on_error").
	lastStatusCode int
	// lastError indicates whether the previous main request had an error (for "on_error").
	lastError bool
}

// hookExecutor provides methods to execute pre_send and post_receive hooks
// using the macro engine. It is created per resend call or per fuzz iteration batch.
type hookExecutor struct {
	server *Server
	hooks  *hooksInput
	state  *hookState
}

// newHookExecutor creates a new hook executor.
func newHookExecutor(server *Server, hooks *hooksInput, state *hookState) *hookExecutor {
	return &hookExecutor{
		server: server,
		hooks:  hooks,
		state:  state,
	}
}

// executePreSend runs the pre_send hook if configured and the run_interval condition is met.
// Returns the KV Store from the macro execution (for template expansion), or nil if not executed.
func (he *hookExecutor) executePreSend(ctx context.Context) (map[string]string, error) {
	if he.hooks == nil || he.hooks.PreSend == nil {
		return nil, nil
	}

	h := he.hooks.PreSend
	if !he.shouldRunPreSend(h) {
		return nil, nil
	}

	result, err := he.runMacro(ctx, h.Macro, h.Vars)
	if err != nil {
		return nil, fmt.Errorf("pre_send hook: %w", err)
	}

	if result.Status != "completed" {
		return nil, fmt.Errorf("pre_send hook macro %q failed: %s", h.Macro, result.Error)
	}

	return result.KVStore, nil
}

// executePostReceive runs the post_receive hook if configured and the run_interval condition is met.
// The statusCode and responseBody are from the main request's response.
// The kvStore parameter carries KV Store values from the preceding pre_send hook execution.
// When merging vars, the priority order is:
//  1. pre_send KV Store (highest priority)
//  2. hook config vars (lowest priority)
//
// This ensures that values produced by pre_send (e.g., auth_session) take precedence
// over static hook config vars when the same key exists in both.
func (he *hookExecutor) executePostReceive(ctx context.Context, statusCode int, responseBody []byte, kvStore map[string]string) error {
	if he.hooks == nil || he.hooks.PostReceive == nil {
		return nil
	}

	h := he.hooks.PostReceive
	if !he.shouldRunPostReceive(h, statusCode, responseBody) {
		return nil
	}

	// Start with hook config vars as the base.
	vars := make(map[string]string)
	for k, v := range h.Vars {
		vars[k] = v
	}

	// Merge pre_send KV Store values. These take precedence over hook config vars.
	for k, v := range kvStore {
		vars[k] = v
	}

	// If pass_response is true, pass the response status code and body as variables.
	if h.PassResponse {
		vars["__response_status"] = fmt.Sprintf("%d", statusCode)
		vars["__response_body"] = string(responseBody)
	}

	result, err := he.runMacro(ctx, h.Macro, vars)
	if err != nil {
		return fmt.Errorf("post_receive hook: %w", err)
	}

	if result.Status != "completed" {
		return fmt.Errorf("post_receive hook macro %q failed: %s", h.Macro, result.Error)
	}

	return nil
}

// updateState updates the hook state after a main request completes.
// This should be called after each main request to track state for run_interval evaluation.
func (he *hookExecutor) updateState(statusCode int, hadError bool) {
	he.state.requestCount++
	he.state.lastStatusCode = statusCode
	he.state.lastError = hadError
}

// shouldRunPreSend evaluates whether the pre_send hook should fire based on run_interval.
func (he *hookExecutor) shouldRunPreSend(h *hookConfig) bool {
	interval := h.RunInterval
	if interval == "" {
		interval = "always"
	}

	switch interval {
	case "always":
		return true
	case "once":
		if he.state.preSendExecuted {
			return false
		}
		he.state.preSendExecuted = true
		return true
	case "every_n":
		// Run on 0th, nth, 2nth, ... request.
		// requestCount is the count before this request, so we check
		// if the current request index (requestCount) is divisible by n.
		if h.N <= 0 {
			return false
		}
		return he.state.requestCount%h.N == 0
	case "on_error":
		// Run if the previous request had an error (4xx/5xx or transport error).
		// Always run on the first request (no previous error to check).
		if he.state.requestCount == 0 {
			return true
		}
		return he.state.lastError || he.state.lastStatusCode >= 400
	default:
		return false
	}
}

// shouldRunPostReceive evaluates whether the post_receive hook should fire.
func (he *hookExecutor) shouldRunPostReceive(h *hookConfig, statusCode int, responseBody []byte) bool {
	interval := h.RunInterval
	if interval == "" {
		interval = "always"
	}

	switch interval {
	case "always":
		return true
	case "on_status":
		for _, code := range h.StatusCodes {
			if statusCode == code {
				return true
			}
		}
		return false
	case "on_match":
		if h.compiledPattern == nil {
			return false
		}
		// Limit the body size for regex matching to prevent ReDoS.
		body := responseBody
		if len(body) > macro.MaxRegexInputSize {
			body = body[:macro.MaxRegexInputSize]
		}
		return h.compiledPattern.Match(body)
	default:
		return false
	}
}

// runMacro loads a macro from the DB and runs it with the given vars.
func (he *hookExecutor) runMacro(ctx context.Context, macroName string, vars map[string]string) (*macro.Result, error) {
	s := he.server
	if s.store == nil {
		return nil, fmt.Errorf("session store is not initialized")
	}

	// Load macro from DB.
	rec, err := s.store.GetMacro(ctx, macroName)
	if err != nil {
		return nil, fmt.Errorf("load macro %q: %w", macroName, err)
	}

	// Parse config JSON.
	var cfg macroConfig
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
		return nil, fmt.Errorf("parse macro config: %w", err)
	}

	// Build macro.Macro from stored config.
	m, err := configToMacro(rec.Name, rec.Description, cfg)
	if err != nil {
		return nil, fmt.Errorf("build macro from config: %w", err)
	}

	// Target scope enforcement: check each step's target URL before running.
	// This mirrors the same check in handleExecuteRunMacro to prevent hooks
	// from bypassing target scope restrictions via macro execution.
	if s.targetScope != nil && s.targetScope.HasRules() {
		for _, step := range cfg.Steps {
			// Check override_url if specified.
			if step.OverrideURL != "" {
				u, parseErr := url.Parse(step.OverrideURL)
				if parseErr == nil && u.Host != "" {
					if scopeErr := s.checkTargetScopeURL(u); scopeErr != nil {
						return nil, fmt.Errorf("macro step %q: %w", step.ID, scopeErr)
					}
				}
			}
			// Check the session's URL for this step.
			sendMsgs, msgErr := s.store.GetMessages(ctx, step.SessionID, session.MessageListOptions{Direction: "send"})
			if msgErr == nil && len(sendMsgs) > 0 && sendMsgs[0].URL != nil {
				// Only check session URL if no override_url (override takes precedence).
				if step.OverrideURL == "" {
					if scopeErr := s.checkTargetScopeURL(sendMsgs[0].URL); scopeErr != nil {
						return nil, fmt.Errorf("macro step %q: %w", step.ID, scopeErr)
					}
				}
			}
		}
	}

	// Create engine with HTTP client and session fetcher.
	sendFunc := s.macroSendFunc()
	fetcher := &storeSessionFetcher{store: s.store}

	engine, err := macro.NewEngine(sendFunc, fetcher)
	if err != nil {
		return nil, fmt.Errorf("create macro engine: %w", err)
	}

	result, err := engine.Run(ctx, m, vars)
	if err != nil {
		return nil, fmt.Errorf("run macro: %w", err)
	}

	return result, nil
}

// expandParamsWithKVStore applies template expansion to the resend/fuzz override
// parameters using the KV Store values from a pre_send hook execution.
func expandParamsWithKVStore(params *executeParams, kvStore map[string]string) error {
	if len(kvStore) == 0 {
		return nil
	}

	// Expand override_url.
	if params.OverrideURL != "" {
		expanded, err := macro.ExpandTemplate(params.OverrideURL, kvStore)
		if err != nil {
			return fmt.Errorf("expand override_url: %w", err)
		}
		params.OverrideURL = expanded
	}

	// Expand override_headers values.
	if len(params.OverrideHeaders) > 0 {
		expanded, err := macro.ExpandHeaders(params.OverrideHeaders, kvStore)
		if err != nil {
			return fmt.Errorf("expand override_headers: %w", err)
		}
		params.OverrideHeaders = expanded
	}

	// Expand add_headers values.
	if len(params.AddHeaders) > 0 {
		expanded, err := macro.ExpandHeaders(params.AddHeaders, kvStore)
		if err != nil {
			return fmt.Errorf("expand add_headers: %w", err)
		}
		params.AddHeaders = expanded
	}

	// Expand override_body.
	if params.OverrideBody != nil {
		expanded, err := macro.ExpandTemplate(*params.OverrideBody, kvStore)
		if err != nil {
			return fmt.Errorf("expand override_body: %w", err)
		}
		params.OverrideBody = &expanded
	}

	return nil
}

// parseHooksFromJSON parses hooks from a raw JSON map extracted from the params.
// This is needed because the hooks field is not part of the typed executeParams struct
// but is passed as a nested JSON object.
func parseHooksFromJSON(raw json.RawMessage) (*hooksInput, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	// Check if the raw message is a valid JSON object (not null).
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" || trimmed == "" {
		return nil, nil
	}

	var hooks hooksInput
	if err := json.Unmarshal(raw, &hooks); err != nil {
		return nil, fmt.Errorf("parse hooks: %w", err)
	}

	return &hooks, nil
}
