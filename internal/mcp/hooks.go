package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// Reserved KV Store keys used by pass_response injection. See
// internal/macro/reserved.go for the broader reserved-key contract;
// the "__" prefix prevents user-controlled macros from shadowing these
// runtime-populated values via the macro.IsReservedKey filter applied
// at every KV-store merge site.
const (
	// macroResponseStatusKey is the kvStore key receiving the HTTP
	// response status code as a base-10 decimal string.
	macroResponseStatusKey = macro.ReservedKeyPrefix + "response_status"

	// macroResponseBodyKey is the kvStore key receiving the HTTP response
	// body verbatim, capped at maxResponseBodyKVBytes.
	//
	// USK-985: also reused by fuzz_grpc post_macro for the concatenated
	// gRPC DATA payload (capped at maxFuzzGRPCResponseBodyCapture / 64
	// KiB at capture time). The byte cap is enforced at capture inside
	// runFuzzGRPCSingleVariant rather than at injection — see the doc
	// comment there for the streaming-response rationale.
	macroResponseBodyKey = macro.ReservedKeyPrefix + "response_body"

	// macroResponseHeaderKeyPrefix / macroResponseHeaderKeySuffix bracket the
	// per-header kvStore keys: __response_headers__<lower(name)>__. Header
	// names are lowercased on insert so the key stays stable regardless of
	// wire casing — the recorded flow's header list keeps original casing.
	macroResponseHeaderKeyPrefix = macro.ReservedKeyPrefix + "response_headers" + macro.ReservedKeyPrefix
	macroResponseHeaderKeySuffix = macro.ReservedKeyPrefix

	// macroResponseChunksKey is the kvStore key receiving the count of
	// receive-loop envelopes / chunks that materialised the variant's
	// response. Used by fuzz_raw (USK-986); raw has no L7 status concept
	// but the chunk count is a useful shape diagnostic for post_macro
	// templates. Value is the base-10 decimal string of the chunk count.
	macroResponseChunksKey = macro.ReservedKeyPrefix + "response_chunks"

	// macroResponseTruncatedKey is the kvStore key receiving "true" or
	// "false" depending on whether the variant's receive loop hit the
	// response cap (maxResendRawResponse, 16 MiB) before EOF. Used by
	// fuzz_raw (USK-986).
	macroResponseTruncatedKey = macro.ReservedKeyPrefix + "response_truncated"

	// USK-985: gRPC-specific __response_* reserved keys for fuzz_grpc
	// post_macro. The status domain differs from HTTP — gRPC status is
	// 0-16 per google.golang.org/grpc/codes (0 = OK, 1..16 = canonical
	// error codes), while __response_status under fuzz_http carries an
	// HTTP status (200-599). The shared key NAME __response_status is
	// reused for cross-protocol macro portability; the value-DOMAIN is
	// protocol-specific and operators specifying run_interval=on_status
	// must supply codes appropriate to the fuzz tool they invoke. See
	// help_fuzz_grpc.md for the canonical gRPC status mapping.

	// macroResponseStatusMessageKey is the kvStore key receiving the
	// gRPC end trailer's status_message field as a verbatim string. Empty
	// on a clean OK trailer; non-empty on canonical error codes (e.g.
	// "deadline exceeded" for status=4). fuzz_grpc only — fuzz_http does
	// not populate this key.
	macroResponseStatusMessageKey = macro.ReservedKeyPrefix + "response_status_message"

	// macroResponseMessageCountKey is the kvStore key receiving the
	// per-variant gRPC DATA-envelope count (decimal int). fuzz_grpc only.
	macroResponseMessageCountKey = macro.ReservedKeyPrefix + "response_message_count"

	// macroResponseTotalBytesKey is the kvStore key receiving the
	// per-variant gRPC DATA-payload byte sum (decimal int). This is the
	// pre-truncation total of every receive-side DATA payload (so it
	// matches fuzz_results.response_length); __response_body is the
	// concatenated payload bytes after the 64 KiB capture cap. fuzz_grpc
	// only.
	macroResponseTotalBytesKey = macro.ReservedKeyPrefix + "response_total_bytes"
)

// maxResponseBodyKVBytes caps the body bytes copied into the kvStore via
// __response_body. Templates substituting the entire body into a follow-up
// macro step's URL or header would otherwise OOM on attacker-controlled
// large responses (CWE-770). 64 KiB matches the order of magnitude used by
// the macro engine's MaxStepBodySize (1 MiB) downsized for the kvStore-
// versus-state distinction: state captures the whole body for guard
// evaluation; kvStore values feed into template expansion at every
// downstream invocation.
const maxResponseBodyKVBytes = 64 * 1024

// maxResponseHeaderValueKVBytes caps the bytes copied into a single
// __response_headers__<lower(name)>__ kvStore entry. A malicious upstream
// could return a very long single-header value (Set-Cookie payloads,
// Server-Timing dumps, X-Debug-* leakage) and amplify memory by having
// templates substitute the full value into multiple downstream macro
// invocations. 8 KiB matches the order of magnitude of typical HTTP
// header value caps and is generous for legitimate cases (Bearer tokens,
// CSRF tokens) while bounding attacker-controlled growth (CWE-770).
const maxResponseHeaderValueKVBytes = 8 * 1024

// maxResponseHeaderKVCount caps the number of distinct response headers
// injected into the kvStore as __response_headers__<lower(name)>__
// entries. The recorded flow keeps the full header list untouched; this
// only bounds the kvStore-side projection consumed by post_macro template
// expansion (CWE-770). 256 covers any reasonable response while
// preventing a malicious upstream emitting a Set-Cookie storm from
// inflating the per-iteration kvStore.
const maxResponseHeaderKVCount = 256

// hooksInput holds the hook configuration for fuzz/resend actions. The
// JSON keys are pre_macro / post_macro (USK-960 nomenclature) — older
// pre_send / post_receive spellings are not accepted. The dormant
// scaffold that originated this file (PR #78, orphaned by PR #688's
// legacy-tool retirement) is re-attached to fuzz_http as the engine
// for per-iteration pre/post macro dispatch.
type hooksInput struct {
	// PreMacro is the hook executed before the main request is sent.
	PreMacro *hookConfig `json:"pre_macro,omitempty"`
	// PostMacro is the hook executed after the main response is received.
	PostMacro *hookConfig `json:"post_macro,omitempty"`
}

// hookConfig defines a single hook's configuration.
type hookConfig struct {
	// Macro is the name of the stored macro to execute.
	Macro string `json:"macro"`
	// Vars are runtime variable overrides for the macro.
	Vars map[string]string `json:"vars,omitempty"`
	// RunInterval controls when the hook fires.
	// For pre_macro: "always" (default), "once", "every_n", "on_error".
	// For post_macro: "always" (default), "on_status", "on_match".
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
	// Only applicable to post_macro hooks.
	PassResponse bool `json:"pass_response,omitempty"`
}

// validPreMacroIntervals are the allowed run_interval values for pre_macro hooks.
var validPreMacroIntervals = map[string]bool{
	"always":   true,
	"once":     true,
	"every_n":  true,
	"on_error": true,
}

// validPostMacroIntervals are the allowed run_interval values for post_macro hooks.
var validPostMacroIntervals = map[string]bool{
	"always":    true,
	"on_status": true,
	"on_match":  true,
}

// validateHooks validates the hooks configuration.
func validateHooks(hooks *hooksInput) error {
	if hooks == nil {
		return nil
	}
	if hooks.PreMacro != nil {
		if err := validatePreMacroHook(hooks.PreMacro); err != nil {
			return fmt.Errorf("pre_macro: %w", err)
		}
	}
	if hooks.PostMacro != nil {
		if err := validatePostMacroHook(hooks.PostMacro); err != nil {
			return fmt.Errorf("post_macro: %w", err)
		}
	}
	return nil
}

// validatePreMacroHook validates a pre_macro hook configuration.
func validatePreMacroHook(h *hookConfig) error {
	if h.Macro == "" {
		return fmt.Errorf("macro name is required")
	}
	interval := h.RunInterval
	if interval == "" {
		interval = "always"
	}
	if !validPreMacroIntervals[interval] {
		return fmt.Errorf("invalid run_interval %q: must be one of always, once, every_n, on_error", interval)
	}
	if interval == "every_n" && h.N <= 0 {
		return fmt.Errorf("n must be > 0 for every_n run_interval")
	}
	return nil
}

// validatePostMacroHook validates a post_macro hook configuration.
func validatePostMacroHook(h *hookConfig) error {
	if h.Macro == "" {
		return fmt.Errorf("macro name is required")
	}
	interval := h.RunInterval
	if interval == "" {
		interval = "always"
	}
	if !validPostMacroIntervals[interval] {
		return fmt.Errorf("invalid run_interval %q: must be one of always, on_status, on_match", interval)
	}
	if interval == "on_status" && len(h.StatusCodes) == 0 {
		return fmt.Errorf("status_codes is required for on_status run_interval")
	}
	if interval == "on_match" && h.MatchPattern == "" {
		return fmt.Errorf("match_pattern is required for on_match run_interval")
	}
	if h.MatchPattern != "" {
		if len(h.MatchPattern) > maxRegexPatternLen {
			return fmt.Errorf("match_pattern too long: %d > %d", len(h.MatchPattern), maxRegexPatternLen)
		}
		re, err := regexp.Compile(h.MatchPattern)
		if err != nil {
			return fmt.Errorf("invalid match_pattern: %w", err)
		}
		h.compiledPattern = re
	}
	return nil
}

// hookState tracks the execution state of hooks across multiple iterations
// (used by fuzzer). For single-shot resend calls, a fresh hookState is
// created each time.
type hookState struct {
	// preMacroExecuted tracks whether the pre_macro hook has been executed (for "once").
	preMacroExecuted bool
	// requestCount tracks the total number of main requests sent (for "every_n").
	requestCount int
	// lastStatusCode is the status code from the previous main request (for "on_error").
	lastStatusCode int
	// lastError indicates whether the previous main request had an error (for "on_error").
	lastError bool
}

// hookExecutor provides methods to execute pre_macro and post_macro hooks
// using the macro engine. It is created per resend call or per fuzz iteration batch.
//
// It holds a *Server reference because hooks need to read from three components
// (FlowStore for macro persistence, Connector for target scope, JobRunner for
// the legacy replayDoer). Passing the parent Server is simpler than threading
// three component pointers through every call site.
type hookExecutor struct {
	s     *Server
	hooks *hooksInput
	state *hookState
}

// newHookExecutor creates a new hook executor.
func newHookExecutor(s *Server, hooks *hooksInput, state *hookState) *hookExecutor {
	return &hookExecutor{
		s:     s,
		hooks: hooks,
		state: state,
	}
}

// executePreMacro runs the pre_macro hook if configured and the run_interval
// condition is met. Returns the KV Store from the macro execution (for
// template expansion downstream), or nil if not executed.
//
// kvStore, when non-nil, is shared with the engine via RunWithKV — extracted
// values land directly in the caller-owned map so subsequent hooks (post_macro)
// see them without an explicit re-merge.
func (he *hookExecutor) executePreMacro(ctx context.Context, kvStore map[string]string) (map[string]string, error) {
	if he.hooks == nil || he.hooks.PreMacro == nil {
		return nil, nil
	}

	h := he.hooks.PreMacro
	if !he.shouldRunPreMacro(h) {
		return nil, nil
	}

	// Seed the caller-supplied store with hook.Vars (non-destructive — existing
	// caller-owned reserved keys win) so the macro sees both per-iteration
	// state and the operator's static hook overrides.
	for k, v := range h.Vars {
		if _, ok := kvStore[k]; !ok {
			kvStore[k] = v
		}
	}

	result, err := he.runMacroWithKV(ctx, h.Macro, kvStore)
	if err != nil {
		return nil, fmt.Errorf("pre_macro hook: %w", err)
	}

	if result.Status != "completed" {
		return nil, fmt.Errorf("pre_macro hook macro %q failed: %s", h.Macro, result.Error)
	}

	return result.KVStore, nil
}

// executePostMacro runs the post_macro hook if configured and the
// run_interval condition is met. The statusCode and responseBody are from
// the main request's response.
//
// kvStore carries the shared per-iteration KV Store. When non-nil it is
// shared with the engine via RunWithKV so pre_macro extracts AND
// PassResponse-injected variables are visible to the post macro's template
// expansions without an explicit re-merge. The legacy nil-kvStore path is
// retained for callers that do not own a long-lived store.
//
// The priority order for variable resolution remains:
//  1. caller-owned KV Store entries (highest priority — covers reserved
//     keys, pre_macro extracts, response injection)
//  2. post_macro hook config vars (filled in only for keys the caller did
//     not already populate)
func (he *hookExecutor) executePostMacro(ctx context.Context, statusCode int, responseBody []byte, responseHeaders map[string][]string, kvStore map[string]string) error {
	if he.hooks == nil || he.hooks.PostMacro == nil {
		return nil
	}

	h := he.hooks.PostMacro
	if !he.shouldRunPostMacro(h, statusCode, responseBody) {
		return nil
	}

	// When the caller did not supply a kvStore we mint a fresh one — the
	// macro engine accepts nil but for the Vars-merge dance below we want a
	// concrete map.
	if kvStore == nil {
		kvStore = make(map[string]string)
	}

	// Hook config vars fill in only for keys the caller's store does not
	// already define. Caller wins on conflict (matches the pre-USK-960
	// "pre_send KV Store wins over hook config vars" rule).
	for k, v := range h.Vars {
		if _, ok := kvStore[k]; !ok {
			kvStore[k] = v
		}
	}

	// If pass_response is true, inject the response status / body / per-
	// header values as reserved variables. These overwrite any prior writes
	// from the same iteration so a re-invocation of post_macro sees the
	// latest response, not a stale snapshot.
	if h.PassResponse {
		injectResponseVars(kvStore, statusCode, responseBody, responseHeaders)
	}

	result, err := he.runMacroWithKV(ctx, h.Macro, kvStore)
	if err != nil {
		return fmt.Errorf("post_macro hook: %w", err)
	}

	if result.Status != "completed" {
		return fmt.Errorf("post_macro hook macro %q failed: %s", h.Macro, result.Error)
	}

	return nil
}

// injectResponseVars writes the canonical __response_* reserved keys
// (status, body, per-header) into kvStore for consumption by post_macro
// template expansion. Header names are lowercased so the kvStore key is
// stable regardless of wire casing — the recorded wire flow keeps its
// original casing untouched (per project MITM principle: lossless
// representations live on the wire path).
//
// Existing reserved-key writes for the same iteration are overwritten so
// a re-run of post_macro within the same kvStore sees the latest response
// rather than a stale snapshot.
//
// CWE-770 caps:
//   - __response_body is truncated to maxResponseBodyKVBytes (64 KiB).
//   - Per-header values are truncated to maxResponseHeaderValueKVBytes
//     (8 KiB); the cap protects template substitution from amplifying
//     an attacker-controlled X-Debug / Set-Cookie payload across multiple
//     downstream macro invocations.
//   - At most maxResponseHeaderKVCount (256) distinct headers are
//     injected; remaining headers are silently dropped from the kvStore
//     projection. The recorded wire flow keeps every header — the cap
//     only bounds the control-plane kvStore convenience view.
func injectResponseVars(kvStore map[string]string, statusCode int, responseBody []byte, responseHeaders map[string][]string) {
	kvStore[macroResponseStatusKey] = fmt.Sprintf("%d", statusCode)

	body := responseBody
	if len(body) > maxResponseBodyKVBytes {
		body = body[:maxResponseBodyKVBytes]
	}
	kvStore[macroResponseBodyKey] = string(body)

	injected := 0
	for name, values := range responseHeaders {
		if len(values) == 0 {
			continue
		}
		if injected >= maxResponseHeaderKVCount {
			// Stop injecting once the per-iteration kvStore header cap is
			// reached. The wire-recorded flow already holds every header;
			// the kvStore projection is a control-plane convenience.
			break
		}
		// Last value wins for duplicate-name headers. The wire-recorded
		// flow keeps every occurrence; the kvStore is a control-plane
		// convenience and intentionally collapses duplicates so template
		// expansion gets a single string per key.
		v := values[len(values)-1]
		if len(v) > maxResponseHeaderValueKVBytes {
			v = v[:maxResponseHeaderValueKVBytes]
		}
		kvStore[macroResponseHeaderKeyPrefix+strings.ToLower(name)+macroResponseHeaderKeySuffix] = v
		injected++
	}
}

// injectRawResponseVars writes the raw-specific __response_* reserved
// keys (__response_body / __response_chunks / __response_truncated)
// into kvStore for consumption by fuzz_raw post_macro template
// expansion (USK-986). Raw has NO L7 status concept — __response_status
// and __response_headers* are intentionally NOT injected, matching the
// MITM principle "do not invent hypothetical surface" (CLAUDE.md). The
// chunk count and truncated flag are the shape diagnostics raw can
// honestly surface.
//
// Existing reserved-key writes for the same iteration are overwritten
// so a re-run of post_macro within the same kvStore sees the latest
// response rather than a stale snapshot — matches injectResponseVars's
// semantics.
//
// CWE-770 caps:
//   - __response_body is truncated to maxResponseBodyKVBytes (64 KiB).
//     The variant's wire-recorded response (capped at maxResendRawResponse,
//     16 MiB, by the receive loop) is independent of this kvStore-side
//     truncation — the row's row.Truncated flag reflects the 16 MiB cap,
//     not the 64 KiB kvStore cap.
func injectRawResponseVars(kvStore map[string]string, responseBody []byte, chunks int, truncated bool) {
	body := responseBody
	if len(body) > maxResponseBodyKVBytes {
		body = body[:maxResponseBodyKVBytes]
	}
	kvStore[macroResponseBodyKey] = string(body)
	kvStore[macroResponseChunksKey] = strconv.Itoa(chunks)
	if truncated {
		kvStore[macroResponseTruncatedKey] = "true"
	} else {
		kvStore[macroResponseTruncatedKey] = "false"
	}
}

// updateState updates the hook state after a main request completes.
// This should be called after each main request to track state for run_interval evaluation.
func (he *hookExecutor) updateState(statusCode int, hadError bool) {
	he.state.requestCount++
	he.state.lastStatusCode = statusCode
	he.state.lastError = hadError
}

// shouldRunPreMacro evaluates whether the pre_macro hook should fire based on run_interval.
func (he *hookExecutor) shouldRunPreMacro(h *hookConfig) bool {
	interval := h.RunInterval
	if interval == "" {
		interval = "always"
	}

	switch interval {
	case "always":
		return true
	case "once":
		if he.state.preMacroExecuted {
			return false
		}
		he.state.preMacroExecuted = true
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
		// Fires when the previous main request had an error (transport
		// error or HTTP status >= 400). Returns false on the first
		// iteration — there is no previous request to react to (USK-982).
		// This makes "fires only after a real error" match the operator
		// mental model and avoids a vacuous iter-0 fire when no error has
		// been observed yet.
		if he.state.requestCount == 0 {
			return false
		}
		return he.state.lastError || he.state.lastStatusCode >= 400
	default:
		return false
	}
}

// shouldRunPostMacro evaluates whether the post_macro hook should fire.
func (he *hookExecutor) shouldRunPostMacro(h *hookConfig, statusCode int, responseBody []byte) bool {
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

// runMacroWithKV loads a macro from the DB and runs it via Engine.RunWithKV
// against the caller-supplied kvStore. Extracted values land directly in
// kvStore in place, so the caller can thread a single per-iteration store
// across multiple hook invocations (pre then post in fuzz_http) without
// re-merging.
//
// Pass nil for kvStore to run the macro against a fresh empty store; this
// path is equivalent to a vars=nil call into Engine.Run.
func (he *hookExecutor) runMacroWithKV(ctx context.Context, macroName string, kvStore map[string]string) (*macro.Result, error) {
	s := he.s
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}

	m, cfg, err := loadAndBuildMacroDeps(ctx, s, macroName)
	if err != nil {
		return nil, err
	}

	// Protocol gate: reject non-HTTP flow_ids before running. Mirrors
	// the same check in handleDefineMacro / handleRunMacro so hook-
	// invoked macros cannot bypass the gate via a stored macro that
	// was defined before the gate landed. See USK-877.
	if err := checkMacroStepsProtocolWithStore(ctx, s.flowStore.store, cfg.Steps); err != nil {
		return nil, err
	}

	// Target scope enforcement: check each step's target URL before running.
	// This mirrors the same check in handleRunMacro to prevent hooks
	// from bypassing target scope restrictions via macro execution.
	if err := checkMacroStepsTargetScopeDeps(ctx, s, cfg.Steps); err != nil {
		return nil, err
	}

	// Create engine with HTTP client and session fetcher.
	sendFunc := hookMacroSendFunc(s, macroName)
	fetcher := &storeFlowFetcher{store: s.flowStore.store}

	engine, err := macro.NewEngine(sendFunc, fetcher)
	if err != nil {
		return nil, fmt.Errorf("create macro engine: %w", err)
	}

	result, err := engine.RunWithKV(ctx, m, kvStore)
	if err != nil {
		return nil, fmt.Errorf("run macro: %w", err)
	}

	return result, nil
}

// loadAndBuildMacroDeps loads a macro record from DB using the Server's
// FlowStore component. Despite the legacy "Deps" suffix, this helper now
// reads through *Server; renaming would touch many sites for no benefit.
func loadAndBuildMacroDeps(ctx context.Context, s *Server, macroName string) (*macro.Macro, macroConfig, error) {
	rec, err := s.flowStore.store.GetMacro(ctx, macroName)
	if err != nil {
		return nil, macroConfig{}, fmt.Errorf("load macro %q: %w", macroName, err)
	}

	var cfg macroConfig
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
		return nil, macroConfig{}, fmt.Errorf("parse macro config: %w", err)
	}

	m, err := configToMacro(rec.Name, rec.Description, cfg)
	if err != nil {
		return nil, macroConfig{}, fmt.Errorf("build macro from config: %w", err)
	}

	return m, cfg, nil
}

// checkMacroStepsTargetScopeDeps checks each macro step's target URL against
// the target scope rules using the Server's Connector + FlowStore components.
// Despite the legacy "Deps" suffix, this helper now reads through *Server;
// renaming would touch many sites for no benefit.
func checkMacroStepsTargetScopeDeps(ctx context.Context, s *Server, steps []macroStepInput) error {
	if s.connector.targetScope == nil || !s.connector.targetScope.HasRules() {
		return nil
	}
	for _, step := range steps {
		if step.OverrideURL != "" {
			u, parseErr := url.Parse(step.OverrideURL)
			if parseErr == nil && u.Host != "" {
				if scopeErr := checkTargetScopeURLHelper(s.connector.targetScope, u); scopeErr != nil {
					return fmt.Errorf("macro step %q: %w", step.ID, scopeErr)
				}
			}
		}
		sendMsgs, msgErr := s.flowStore.store.GetFlows(ctx, step.StreamID, flow.FlowListOptions{Direction: "send"})
		if msgErr == nil && len(sendMsgs) > 0 && sendMsgs[0].URL != nil {
			if step.OverrideURL == "" {
				if scopeErr := checkTargetScopeURLHelper(s.connector.targetScope, sendMsgs[0].URL); scopeErr != nil {
					return fmt.Errorf("macro step %q: %w", step.ID, scopeErr)
				}
			}
		}
	}
	return nil
}

// hookMacroSendFunc creates a macro.SendFunc that reads from the Server's
// JobRunner (replayDoer), Connector (targetScope), and FlowStore (store).
func hookMacroSendFunc(s *Server, macroName string) macro.SendFunc {
	return func(ctx context.Context, req *macro.SendRequest) (*macro.SendResponse, error) {
		var client httpDoer
		if s.jobRunner.replayDoer != nil {
			client = s.jobRunner.replayDoer
		} else {
			dialer := &net.Dialer{
				Timeout: defaultReplayTimeout,
			}
			transport := &http.Transport{
				DialContext: dialer.DialContext,
			}
			client = &http.Client{
				Timeout:   defaultReplayTimeout,
				Transport: transport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}

		var body io.Reader
		if len(req.Body) > 0 {
			body = bytes.NewReader(req.Body)
		}

		httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		for key, values := range req.Headers {
			for i, v := range values {
				if i == 0 {
					httpReq.Header.Set(key, v)
				} else {
					httpReq.Header.Add(key, v)
				}
			}
		}

		// Target scope enforcement after template expansion: the pre-run check
		// validates static URLs, but templates like §target_url§ produce the
		// final URL only at send time. Check httpReq.URL to close the TOCTOU gap.
		if err := checkTargetScopeURLHelper(s.connector.targetScope, httpReq.URL); err != nil {
			return nil, fmt.Errorf("hook macro step target scope check: %w", err)
		}

		start := time.Now()
		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("send request: %w", err)
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, config.ResolveMaxReplayResponseSize(s.connector.proxyDefaults)))
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
		duration := time.Since(start)

		// Record the macro step as a flow so it appears in session history.
		if s.flowStore.store != nil {
			recordMacroStepSessionDeps(ctx, s, macroName, req, resp, respBody, httpReq, start, duration)
		}

		return &macro.SendResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       respBody,
			URL:        resp.Request.URL.String(),
		}, nil
	}
}

// recordMacroStepSessionDeps saves a macro step's HTTP exchange as a flow with
// send and receive messages. It is the single recorder shared by both the hook
// executor path (hooks.go) and the direct macro handler path (macro_handlers.go);
// having one helper prevents the lockstep-edit drift class that produced USK-774,
// where two duplicate sites had to be patched together to canonicalise Protocol.
// Reads through *Server's FlowStore component. Errors are logged but not
// propagated to avoid disrupting macro execution when flow recording fails.
func recordMacroStepSessionDeps(
	ctx context.Context,
	s *Server,
	macroName string,
	req *macro.SendRequest,
	resp *http.Response,
	respBody []byte,
	httpReq *http.Request,
	start time.Time,
	duration time.Duration,
) {
	tags := map[string]string{
		"macro":      macroName,
		"macro_step": req.StepID,
	}

	scheme := "http"
	if httpReq.URL != nil && httpReq.URL.Scheme == "https" {
		scheme = "https"
	}
	fl := &flow.Stream{
		Protocol:  string(envelope.ProtocolHTTP),
		Scheme:    scheme,
		State:     "complete",
		Timestamp: start,
		Duration:  duration,
		Tags:      tags,
	}
	if err := s.flowStore.store.SaveStream(ctx, fl); err != nil {
		slog.WarnContext(ctx, "failed to save macro step session",
			"macro", macroName, "step", req.StepID, "error", err)
		return
	}

	recordedHeaders := make(map[string][]string)
	for key, values := range httpReq.Header {
		recordedHeaders[key] = values
	}

	parsedURL := httpReq.URL

	sendMsg := &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Method:    req.Method,
		URL:       parsedURL,
		Headers:   recordedHeaders,
		Body:      req.Body,
	}
	if err := s.flowStore.store.SaveFlow(ctx, sendMsg); err != nil {
		slog.WarnContext(ctx, "failed to save macro step send message",
			"macro", macroName, "step", req.StepID, "error", err)
		return
	}

	respHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		respHeaders[key] = values
	}

	recvMsg := &flow.Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  start.Add(duration),
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       respBody,
	}
	if err := s.flowStore.store.SaveFlow(ctx, recvMsg); err != nil {
		slog.WarnContext(ctx, "failed to save macro step receive message",
			"macro", macroName, "step", req.StepID, "error", err)
	}
}
