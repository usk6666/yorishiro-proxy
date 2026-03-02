package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// executeInput is the typed input for the execute tool.
type executeInput struct {
	// Action specifies the action to execute.
	// Available actions: resend, resend_raw, tcp_replay, delete_sessions, define_macro, run_macro, delete_macro
	// (replay is a deprecated alias for resend; replay_raw is a deprecated alias for resend_raw).
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params executeParams `json:"params"`
}

// executeParams holds the union of all action-specific parameters.
// Only the fields relevant to the specified action are used.
type executeParams struct {
	// SessionID is used by resend, resend_raw, and delete_sessions (single deletion).
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID for resend/resend_raw/delete"`

	// MessageSequence specifies a specific message within a session for WebSocket/streaming resend.
	MessageSequence *int `json:"message_sequence,omitempty" jsonschema:"message sequence number for WebSocket/streaming resend"`

	// resend overrides
	OverrideMethod  string            `json:"override_method,omitempty" jsonschema:"HTTP method override for resend"`
	OverrideURL     string            `json:"override_url,omitempty" jsonschema:"URL override for resend"`
	OverrideHeaders map[string]string `json:"override_headers,omitempty" jsonschema:"header overrides for resend"`
	OverrideBody    *string           `json:"override_body,omitempty" jsonschema:"body override for resend"`

	// resend extended mutation options
	AddHeaders         map[string]string `json:"add_headers,omitempty" jsonschema:"headers to add (appended to existing)"`
	RemoveHeaders      []string          `json:"remove_headers,omitempty" jsonschema:"headers to remove"`
	OverrideBodyBase64 *string           `json:"override_body_base64,omitempty" jsonschema:"body override as Base64-encoded binary"`
	BodyPatches        []BodyPatch       `json:"body_patches,omitempty" jsonschema:"body partial modification rules"`
	OverrideHost       string            `json:"override_host,omitempty" jsonschema:"TCP connection target host:port (independent of URL host)"`
	FollowRedirects    *bool             `json:"follow_redirects,omitempty" jsonschema:"follow HTTP redirects (default: false)"`
	TimeoutMs          *int              `json:"timeout_ms,omitempty" jsonschema:"request timeout in milliseconds (default: 30000)"`
	DryRun             bool              `json:"dry_run,omitempty" jsonschema:"preview modified request without sending"`
	Tag                string            `json:"tag,omitempty" jsonschema:"tag to attach to the result session"`

	// resend_raw parameters
	TargetAddr        string     `json:"target_addr,omitempty" jsonschema:"target address (host:port) for resend_raw"`
	UseTLS            *bool      `json:"use_tls,omitempty" jsonschema:"use TLS for resend_raw connection"`
	OverrideRawBase64 string     `json:"override_raw_base64,omitempty" jsonschema:"Base64-encoded raw bytes to replace entire payload (patches ignored)"`
	Patches           []RawPatch `json:"patches,omitempty" jsonschema:"byte-level patches for resend_raw (offset, binary find/replace, text find/replace)"`

	// delete_sessions parameters
	OlderThanDays *int   `json:"older_than_days,omitempty" jsonschema:"delete sessions older than this many days"`
	Confirm       bool   `json:"confirm,omitempty" jsonschema:"confirm bulk deletion"`
	Protocol      string `json:"protocol,omitempty" jsonschema:"protocol filter for delete_sessions (e.g. HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP)"`

	// intercept queue parameters (release, modify_and_forward, drop)
	InterceptID string `json:"intercept_id,omitempty" jsonschema:"intercepted request ID for release/modify_and_forward/drop"`

	// fuzz parameters
	AttackType  string                       `json:"attack_type,omitempty" jsonschema:"fuzz attack type: sequential or parallel"`
	Positions   []fuzzer.Position            `json:"positions,omitempty" jsonschema:"payload positions for fuzzing"`
	PayloadSets map[string]fuzzer.PayloadSet `json:"payload_sets,omitempty" jsonschema:"named payload sets for fuzzing"`

	// fuzz execution control parameters
	Concurrency  *int     `json:"concurrency,omitempty" jsonschema:"number of concurrent workers (default: 1)"`
	RateLimitRPS *float64 `json:"rate_limit_rps,omitempty" jsonschema:"requests per second limit (0 = unlimited)"`
	DelayMs      *int     `json:"delay_ms,omitempty" jsonschema:"fixed delay between requests in ms"`
	MaxRetries   *int     `json:"max_retries,omitempty" jsonschema:"retry count per failed request"`

	// fuzz stop conditions
	StopOn *fuzzer.StopCondition `json:"stop_on,omitempty" jsonschema:"automatic stop conditions for fuzz jobs"`

	// fuzz job control (fuzz_pause, fuzz_resume, fuzz_cancel)
	FuzzID string `json:"fuzz_id,omitempty" jsonschema:"fuzz job ID for pause/resume/cancel"`

	// hooks parameters (resend, fuzz)
	Hooks *hooksInput `json:"hooks,omitempty" jsonschema:"pre_send/post_receive hooks for macro integration"`

	// macro parameters (define_macro, run_macro, delete_macro)
	Name         string            `json:"name,omitempty" jsonschema:"macro name"`
	Description  string            `json:"description,omitempty" jsonschema:"macro description"`
	Steps        []macroStepInput  `json:"steps,omitempty" jsonschema:"macro steps for define_macro"`
	InitialVars  map[string]string `json:"initial_vars,omitempty" jsonschema:"initial KV Store entries for define_macro"`
	MacroTimeout int               `json:"macro_timeout_ms,omitempty" jsonschema:"macro timeout in milliseconds"`
	Vars         map[string]string `json:"vars,omitempty" jsonschema:"runtime variable overrides for run_macro"`

	// export_sessions parameters
	Format       string        `json:"format,omitempty" jsonschema:"export format (jsonl)"`
	Filter       *exportFilter `json:"filter,omitempty" jsonschema:"session filter for export"`
	IncludeBodies *bool        `json:"include_bodies,omitempty" jsonschema:"include message bodies in export (default: true)"`
	OutputPath   string        `json:"output_path,omitempty" jsonschema:"file path to write export data"`

	// import_sessions parameters
	InputPath  string `json:"input_path,omitempty" jsonschema:"file path to read import data"`
	OnConflict string `json:"on_conflict,omitempty" jsonschema:"conflict policy: skip or replace (default: skip)"`

	// SSRF protection override
	AllowPrivateNetworks bool `json:"allow_private_networks,omitempty" jsonschema:"disable SSRF protection to allow connections to private/loopback networks (default: false)"`
}

// exportFilter holds filter parameters for the export_sessions action.
type exportFilter struct {
	Protocol   string `json:"protocol,omitempty"`
	URLPattern string `json:"url_pattern,omitempty"`
	TimeAfter  string `json:"time_after,omitempty"`
	TimeBefore string `json:"time_before,omitempty"`
}

// availableActions lists the valid action names for error messages.
var availableActions = []string{"resend", "resend_raw", "tcp_replay", "delete_sessions", "release", "modify_and_forward", "drop", "fuzz", "fuzz_pause", "fuzz_resume", "fuzz_cancel", "define_macro", "run_macro", "delete_macro", "regenerate_ca_cert", "export_sessions", "import_sessions"}

// registerExecute registers the execute MCP tool.
func (s *Server) registerExecute() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "execute",
		Description: "Execute an action on recorded proxy data. " +
			"Available actions: " +
			"'resend' resends a recorded HTTP/HTTP2/WebSocket request with optional mutation (method/URL/header/body overrides, body patches, dry-run). " +
			"For WebSocket sessions, use message_sequence to specify which message to resend as a raw TCP frame; " +
			"'resend_raw' resends raw bytes from a recorded session over TCP/TLS with optional byte-level patches (offset overwrite, binary/text find-replace, override_raw_base64 full replacement, dry-run); " +
			"'tcp_replay' replays a Raw TCP session by sending all 'send' messages sequentially to the target; " +
			"'delete_sessions' deletes sessions by ID, by age (older_than_days), by protocol, or all (confirm required); " +
			"'release' forwards an intercepted request as-is (requires intercept_id); " +
			"'modify_and_forward' forwards an intercepted request with mutations (same override params as resend, requires intercept_id); " +
			"'drop' discards an intercepted request returning 502 to the client (requires intercept_id); " +
			"'fuzz' starts an async fuzz campaign (returns fuzz_id immediately, query fuzz_results for progress); " +
			"'fuzz_pause' pauses a running fuzz job (requires fuzz_id); " +
			"'fuzz_resume' resumes a paused fuzz job (requires fuzz_id); " +
			"'fuzz_cancel' cancels a running or paused fuzz job (requires fuzz_id); " +
			"'define_macro' saves a macro definition (upsert) with steps, extraction rules, and guards; " +
			"'run_macro' executes a stored macro for testing; " +
			"'delete_macro' removes a stored macro definition; " +
			"'regenerate_ca_cert' regenerates the CA certificate (auto-persist mode: saves to disk; ephemeral mode: in-memory only; explicit mode: error); " +
			"'export_sessions' exports sessions to JSONL format (optionally filtered, with or without bodies, to file or inline); " +
			"'import_sessions' imports sessions from a JSONL file (supports skip/replace on ID conflict). " +
			"('replay' is a deprecated alias for 'resend'; 'replay_raw' is a deprecated alias for 'resend_raw'.)",
	}, s.handleExecute)
}

// handleExecute routes the execute tool invocation to the appropriate action handler.
func (s *Server) handleExecute(ctx context.Context, req *gomcp.CallToolRequest, input executeInput) (*gomcp.CallToolResult, any, error) {
	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableActions, ", "))
	case "resend", "replay": // "replay" is a deprecated alias
		return s.handleExecuteResend(ctx, input.Params)
	case "resend_raw", "replay_raw": // "replay_raw" is a deprecated alias
		return s.handleExecuteResendRaw(ctx, input.Params)
	case "tcp_replay":
		return s.handleExecuteReplayRaw(ctx, input.Params)
	case "delete_sessions":
		return s.handleExecuteDeleteSessions(ctx, input.Params)
	case "release":
		return s.handleExecuteRelease(ctx, input.Params)
	case "modify_and_forward":
		return s.handleExecuteModifyAndForward(ctx, input.Params)
	case "drop":
		return s.handleExecuteDrop(ctx, input.Params)
	case "fuzz":
		return s.handleExecuteFuzz(ctx, input.Params)
	case "fuzz_pause":
		return s.handleExecuteFuzzPause(input.Params)
	case "fuzz_resume":
		return s.handleExecuteFuzzResume(input.Params)
	case "fuzz_cancel":
		return s.handleExecuteFuzzCancel(input.Params)
	case "define_macro":
		mp := paramsToMacroParams(input.Params)
		result, err := s.handleExecuteDefineMacro(ctx, mp)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "run_macro":
		mp := paramsToMacroParams(input.Params)
		allowPrivate := input.Params.AllowPrivateNetworks || s.allowPrivateNetworks
		if allowPrivate {
			slog.Warn("SSRF protection disabled: allow_private_networks is enabled for run_macro")
		}
		result, err := s.handleExecuteRunMacro(ctx, mp, allowPrivate)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "delete_macro":
		mp := paramsToMacroParams(input.Params)
		result, err := s.handleExecuteDeleteMacro(ctx, mp)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "regenerate_ca_cert":
		return s.handleExecuteRegenerateCA()
	case "export_sessions":
		result, err := s.handleExecuteExportSessions(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "import_sessions":
		result, err := s.handleExecuteImportSessions(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %v", input.Action, availableActions)
	}
}

// paramsToMacroParams extracts macro-specific parameters from the union executeParams.
func paramsToMacroParams(p executeParams) macroParams {
	return macroParams{
		Name:        p.Name,
		Description: p.Description,
		Steps:       p.Steps,
		InitialVars: p.InitialVars,
		TimeoutMs:   p.MacroTimeout,
		Vars:        p.Vars,
	}
}

// executeResendResult is the structured output of the resend action.
type executeResendResult struct {
	// NewSessionID is the session ID of the resent request.
	NewSessionID string `json:"new_session_id"`
	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`
	// ResponseHeaders is the response headers.
	ResponseHeaders map[string][]string `json:"response_headers"`
	// ResponseBody is the response body as text or Base64-encoded string.
	ResponseBody string `json:"response_body"`
	// ResponseBodyEncoding indicates the encoding of the response body ("text" or "base64").
	ResponseBodyEncoding string `json:"response_body_encoding"`
	// DurationMs is the request duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
	// Tag is the tag attached to the result session (if specified).
	Tag string `json:"tag,omitempty"`
}

// executeDryRunResult is the structured output of a dry-run resend.
type executeDryRunResult struct {
	// DryRun is always true for dry-run results.
	DryRun bool `json:"dry_run"`
	// RequestPreview contains the modified request details.
	RequestPreview *requestPreview `json:"request_preview"`
}

// requestPreview is the preview of a modified request for dry-run mode.
type requestPreview struct {
	// Method is the HTTP method.
	Method string `json:"method"`
	// URL is the request URL.
	URL string `json:"url"`
	// Headers is the request headers.
	Headers map[string][]string `json:"headers"`
	// Body is the request body as text or Base64-encoded string.
	Body string `json:"body"`
	// BodyEncoding indicates the encoding of the body ("text" or "base64").
	BodyEncoding string `json:"body_encoding"`
}

// handleExecuteResend handles the resend action within the execute tool.
// It retrieves the original session, applies all mutations, and either sends the request
// or returns a dry-run preview. The result is recorded as a new session.
// When hooks are configured, pre_send hooks execute before mutation application
// (providing KV Store values for template expansion), and post_receive hooks
// execute after the response is received.
func (s *Server) handleExecuteResend(ctx context.Context, params executeParams) (*gomcp.CallToolResult, any, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for resend action")
	}

	// Validate hooks if present.
	if err := validateHooks(params.Hooks); err != nil {
		return nil, nil, fmt.Errorf("invalid hooks: %w", err)
	}

	// Execute pre_send hook if configured.
	var kvStore map[string]string
	if params.Hooks != nil && params.Hooks.PreSend != nil {
		state := &hookState{}
		executor := newHookExecutor(s, params.Hooks, state)
		executor.allowPrivateNetworks = params.AllowPrivateNetworks || s.allowPrivateNetworks
		var err error
		kvStore, err = executor.executePreSend(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	// Apply template expansion from hook KV Store to override parameters.
	if len(kvStore) > 0 {
		if err := expandParamsWithKVStore(&params, kvStore); err != nil {
			return nil, nil, fmt.Errorf("template expansion: %w", err)
		}
	}

	// Retrieve the original session and its send message.
	sess, err := s.store.GetSession(ctx, params.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	// WebSocket sessions use a different resend path.
	if sess.Protocol == "WebSocket" {
		return s.handleWebSocketResend(ctx, sess, params)
	}

	sendMsgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("session %s has no send messages", params.SessionID)
	}
	sendMsg := sendMsgs[0]

	// Build the resend request with mutations applied.
	method := sendMsg.Method
	if params.OverrideMethod != "" {
		method = params.OverrideMethod
	}

	targetURL := sendMsg.URL
	if params.OverrideURL != "" {
		parsed, err := url.Parse(params.OverrideURL)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid override_url %q: %w", params.OverrideURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, nil, fmt.Errorf("invalid override_url %q: must include scheme and host", params.OverrideURL)
		}
		if err := validateURLScheme(parsed); err != nil {
			return nil, nil, fmt.Errorf("invalid override_url %q: %w", params.OverrideURL, err)
		}
		targetURL = parsed
	}

	if targetURL == nil {
		return nil, nil, fmt.Errorf("original session has no URL and no override_url was provided")
	}

	// Validate the final target URL scheme.
	if err := validateURLScheme(targetURL); err != nil {
		return nil, nil, err
	}

	// Validate override_host if specified (SSRF protection).
	if params.OverrideHost != "" {
		if err := validateOverrideHost(params.OverrideHost); err != nil {
			return nil, nil, fmt.Errorf("invalid override_host %q: %w", params.OverrideHost, err)
		}
	}

	// Target scope enforcement: check the final target URL.
	if err := s.checkTargetScopeURL(targetURL); err != nil {
		return nil, nil, err
	}
	// Also check override_host if specified (actual TCP connection target).
	if params.OverrideHost != "" {
		if err := s.checkTargetScopeAddr(targetURL.Scheme, params.OverrideHost); err != nil {
			return nil, nil, err
		}
	}

	// Validate header overrides for CRLF injection (CWE-113).
	if err := validateResendHeaders(params); err != nil {
		return nil, nil, err
	}

	// Apply body mutations.
	reqBody, err := buildResendBody(sendMsg.Body, params)
	if err != nil {
		return nil, nil, err
	}

	// Build headers: start from original, then apply mutations in order.
	headers := buildResendHeaders(sendMsg.Headers, params)

	// Dry-run mode: return preview without sending.
	if params.DryRun {
		bodyStr, bodyEncoding := encodeBody(reqBody)
		// Filter out empty-slice headers (removed headers) from the preview
		// since they represent suppressed headers that won't be sent.
		previewHeaders := make(map[string][]string)
		for k, v := range headers {
			if len(v) > 0 {
				previewHeaders[k] = v
			}
		}
		preview := &executeDryRunResult{
			DryRun: true,
			RequestPreview: &requestPreview{
				Method:       method,
				URL:          targetURL.String(),
				Headers:      previewHeaders,
				Body:         bodyStr,
				BodyEncoding: bodyEncoding,
			},
		}
		return nil, preview, nil
	}

	var body io.Reader
	if len(reqBody) > 0 {
		body = bytes.NewReader(reqBody)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL.String(), body)
	if err != nil {
		return nil, nil, fmt.Errorf("create resend request: %w", err)
	}

	// Set headers on the request.
	for key, values := range headers {
		if len(values) == 0 {
			// Empty slice suppresses Go's net/http default header auto-addition
			// (e.g., User-Agent: Go-http-client/1.1).
			httpReq.Header[key] = values
			continue
		}
		for i, v := range values {
			if i == 0 {
				httpReq.Header.Set(key, v)
			} else {
				httpReq.Header.Add(key, v)
			}
		}
	}

	// Build the HTTP client with appropriate configuration.
	client := s.resendHTTPClient(params)
	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("resend request: %w", err)
	}
	defer resp.Body.Close()

	// Limit response body read to prevent OOM from unbounded responses.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxReplayResponseSize))
	if err != nil {
		return nil, nil, fmt.Errorf("read resend response body: %w", err)
	}
	duration := time.Since(start)

	// Build response headers snapshot.
	respHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		respHeaders[key] = values
	}

	// Build the final request headers snapshot for recording.
	recordedHeaders := make(map[string][]string)
	for key, values := range httpReq.Header {
		recordedHeaders[key] = values
	}

	// Record the resend as a new session.
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newSess := &session.Session{
		Protocol:    sess.Protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   start,
		Duration:    duration,
		Tags:        tags,
	}

	if err := s.store.SaveSession(ctx, newSess); err != nil {
		return nil, nil, fmt.Errorf("save resend session: %w", err)
	}

	// Save send message.
	newSendMsg := &session.Message{
		SessionID: newSess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Method:    method,
		URL:       targetURL,
		Headers:   recordedHeaders,
		Body:      reqBody,
	}
	if err := s.store.AppendMessage(ctx, newSendMsg); err != nil {
		return nil, nil, fmt.Errorf("save resend send message: %w", err)
	}

	// Save receive message.
	newRecvMsg := &session.Message{
		SessionID:  newSess.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  start.Add(duration),
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       respBody,
	}
	if err := s.store.AppendMessage(ctx, newRecvMsg); err != nil {
		return nil, nil, fmt.Errorf("save resend receive message: %w", err)
	}

	// Execute post_receive hook if configured.
	// Pass the kvStore from pre_send so that post_receive hooks can access
	// values produced by pre_send (e.g., auth_session for logout).
	if params.Hooks != nil && params.Hooks.PostReceive != nil {
		state := &hookState{}
		executor := newHookExecutor(s, params.Hooks, state)
		executor.allowPrivateNetworks = params.AllowPrivateNetworks || s.allowPrivateNetworks
		if err := executor.executePostReceive(ctx, resp.StatusCode, respBody, kvStore); err != nil {
			return nil, nil, err
		}
	}

	respBodyStr, respBodyEncoding := encodeBody(respBody)

	result := &executeResendResult{
		NewSessionID:         newSess.ID,
		StatusCode:           resp.StatusCode,
		ResponseHeaders:      respHeaders,
		ResponseBody:         respBodyStr,
		ResponseBodyEncoding: respBodyEncoding,
		DurationMs:           duration.Milliseconds(),
		Tag:                  params.Tag,
	}

	return nil, result, nil
}

// buildResendBody builds the request body after applying mutations.
// Priority: override_body/override_body_base64 > body_patches > original body.
func buildResendBody(originalBody []byte, params executeParams) ([]byte, error) {
	// Full body replacement takes priority.
	if params.OverrideBody != nil {
		return []byte(*params.OverrideBody), nil
	}
	if params.OverrideBodyBase64 != nil {
		decoded, err := base64.StdEncoding.DecodeString(*params.OverrideBodyBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid override_body_base64: %w", err)
		}
		return decoded, nil
	}

	// Apply body patches to the original body.
	body := originalBody
	if len(params.BodyPatches) > 0 {
		var err error
		body, err = applyBodyPatches(body, params.BodyPatches)
		if err != nil {
			return nil, err
		}
	}

	return body, nil
}

// validateResendHeaders checks override_headers, add_headers, and remove_headers
// for CRLF injection (CWE-113). This must be called before buildResendHeaders.
func validateResendHeaders(params executeParams) error {
	if err := validateHeaderValues(params.OverrideHeaders); err != nil {
		return fmt.Errorf("override_headers: %w", err)
	}
	if err := validateHeaderValues(params.AddHeaders); err != nil {
		return fmt.Errorf("add_headers: %w", err)
	}
	if err := validateHeaderKeys(params.RemoveHeaders); err != nil {
		return fmt.Errorf("remove_headers: %w", err)
	}
	return nil
}

// buildResendHeaders builds the final request headers by applying mutations
// in the specified order: remove -> override -> add.
func buildResendHeaders(originalHeaders map[string][]string, params executeParams) map[string][]string {
	// Start with a copy of the original headers.
	headers := make(map[string][]string)
	for key, values := range originalHeaders {
		cp := make([]string, len(values))
		copy(cp, values)
		headers[key] = cp
	}

	// Step 1: Remove headers.
	// Use empty slice (not delete) to suppress Go's net/http default headers
	// (e.g., User-Agent: Go-http-client/1.1) that are auto-added when the key is absent.
	for _, key := range params.RemoveHeaders {
		// Case-insensitive removal: normalize to canonical form.
		headers[http.CanonicalHeaderKey(key)] = []string{}
	}

	// Step 2: Override headers (replace entire value for a key).
	for key, value := range params.OverrideHeaders {
		headers[http.CanonicalHeaderKey(key)] = []string{value}
	}

	// Step 3: Add headers (append to existing values).
	for key, value := range params.AddHeaders {
		canonical := http.CanonicalHeaderKey(key)
		headers[canonical] = append(headers[canonical], value)
	}

	return headers
}

// validateOverrideHost validates the override_host parameter format.
// It must be a valid host:port pair.
func validateOverrideHost(host string) error {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return fmt.Errorf("must be host:port format: %w", err)
	}
	if h == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if p == "" {
		return fmt.Errorf("port cannot be empty")
	}
	return nil
}

// resendHTTPClient returns an HTTP client configured for the resend action.
// It respects follow_redirects, timeout_ms, override_host, and allow_private_networks parameters.
func (s *Server) resendHTTPClient(params executeParams) httpDoer {
	if s.replayDoer != nil {
		return s.replayDoer
	}

	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil {
		if *params.TimeoutMs > 0 {
			timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
		}
	}

	allowPrivate := params.AllowPrivateNetworks || s.allowPrivateNetworks
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	if !allowPrivate {
		dialer.Control = denyPrivateNetwork
	} else {
		slog.Warn("SSRF protection disabled: allow_private_networks is enabled for resend")
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if params.OverrideHost != "" {
				addr = params.OverrideHost
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if params.FollowRedirects != nil && *params.FollowRedirects {
		checkRedirect = targetScopeCheckRedirect(s.targetScope)
	}

	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: checkRedirect,
	}
}

// executeResendRawResult is the structured output of the resend_raw action.
type executeResendRawResult struct {
	// NewSessionID is the session ID of the resent raw request (if recorded).
	NewSessionID string `json:"new_session_id,omitempty"`
	// ResponseData is the raw response bytes, Base64-encoded.
	ResponseData string `json:"response_data"`
	// ResponseSize is the number of response bytes received.
	ResponseSize int `json:"response_size"`
	// DurationMs is the round-trip duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
	// Tag is the tag attached to the result session (if specified).
	Tag string `json:"tag,omitempty"`
}

// executeRawDryRunResult is the structured output of a dry-run resend_raw.
type executeRawDryRunResult struct {
	// DryRun is always true for dry-run results.
	DryRun bool `json:"dry_run"`
	// RawPreview contains the patched raw bytes preview.
	RawPreview *rawPreview `json:"raw_preview"`
}

// rawPreview is the preview of patched raw bytes for dry-run mode.
type rawPreview struct {
	// DataBase64 is the patched raw bytes, Base64-encoded.
	DataBase64 string `json:"data_base64"`
	// DataSize is the size of the patched raw bytes in bytes.
	DataSize int `json:"data_size"`
	// PatchesApplied is the number of patches that were applied.
	PatchesApplied int `json:"patches_applied"`
}

// handleExecuteResendRaw handles the resend_raw action within the execute tool.
// It retrieves the session's raw request bytes, applies byte-level patches,
// and sends them directly over TCP/TLS. Supports dry-run mode, override_raw_base64,
// and byte-level patches (offset, binary find/replace, text find/replace).
func (s *Server) handleExecuteResendRaw(ctx context.Context, params executeParams) (*gomcp.CallToolResult, any, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for resend_raw action")
	}

	// Retrieve the original session and its send message.
	sess, err := s.store.GetSession(ctx, params.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	sendMsgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("session %s has no send messages", params.SessionID)
	}
	sendMsg := sendMsgs[0]

	// Verify raw request bytes are available.
	if len(sendMsg.RawBytes) == 0 {
		return nil, nil, fmt.Errorf("session %s has no raw request bytes", params.SessionID)
	}

	// Target scope enforcement: check the session's URL before any processing.
	// This ensures dry-run mode cannot bypass scope checks.
	if sendMsg.URL != nil {
		if err := s.checkTargetScopeURL(sendMsg.URL); err != nil {
			return nil, nil, err
		}
	}

	// Build the raw bytes to send, applying patches or override.
	rawBytes, patchCount, err := buildResendRawBytes(sendMsg.RawBytes, params)
	if err != nil {
		return nil, nil, err
	}

	// Dry-run mode: return preview without sending.
	if params.DryRun {
		preview := &executeRawDryRunResult{
			DryRun: true,
			RawPreview: &rawPreview{
				DataBase64:     base64.StdEncoding.EncodeToString(rawBytes),
				DataSize:       len(rawBytes),
				PatchesApplied: patchCount,
			},
		}
		return nil, preview, nil
	}

	// Determine the target address.
	targetAddr := params.TargetAddr
	if targetAddr == "" {
		if sendMsg.URL == nil {
			return nil, nil, fmt.Errorf("session has no URL and no target_addr was provided")
		}
		host := sendMsg.URL.Hostname()
		port := sendMsg.URL.Port()
		if port == "" {
			if sendMsg.URL.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		targetAddr = net.JoinHostPort(host, port)
	}

	// Target scope enforcement: check the target address.
	// For resend_raw we only have hostname + port (no scheme/path).
	scheme := ""
	if sess.Protocol == "HTTPS" {
		scheme = "https"
	}
	if err := s.checkTargetScopeAddr(scheme, targetAddr); err != nil {
		return nil, nil, err
	}

	// Determine whether to use TLS.
	useTLS := sess.Protocol == "HTTPS"
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	}

	// Determine timeout.
	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}

	// Establish the connection.
	allowPrivate := params.AllowPrivateNetworks || s.allowPrivateNetworks
	if allowPrivate {
		slog.Warn("SSRF protection disabled: allow_private_networks is enabled for resend_raw")
	}
	dialer := s.rawDialerFuncWithOpts(allowPrivate)
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	// Upgrade to TLS if needed.
	if useTLS {
		host, _, _ := net.SplitHostPort(targetAddr)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // resend_raw intentionally uses raw bytes for security testing
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("TLS handshake with %s: %w", targetAddr, err)
		}
		conn = tlsConn
	}

	// Set a deadline for the entire operation.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, fmt.Errorf("set connection deadline: %w", err)
	}

	// Send the (potentially patched) raw bytes.
	if _, err := conn.Write(rawBytes); err != nil {
		return nil, nil, fmt.Errorf("send raw request: %w", err)
	}

	// Read the raw response (limited to maxReplayResponseSize).
	respData, err := io.ReadAll(io.LimitReader(conn, maxReplayResponseSize))
	if err != nil {
		// Connection may be closed by the server after sending the response.
		// If we already have some data, that's fine.
		if len(respData) == 0 {
			return nil, nil, fmt.Errorf("read raw response: %w", err)
		}
	}
	duration := time.Since(start)

	// Record the resend_raw as a new session.
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newSess := &session.Session{
		Protocol:    sess.Protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   start,
		Duration:    duration,
		Tags:        tags,
	}

	if err := s.store.SaveSession(ctx, newSess); err != nil {
		return nil, nil, fmt.Errorf("save resend_raw session: %w", err)
	}

	// Save send message with the patched raw bytes.
	newSendMsg := &session.Message{
		SessionID: newSess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		RawBytes:  rawBytes,
	}
	if err := s.store.AppendMessage(ctx, newSendMsg); err != nil {
		return nil, nil, fmt.Errorf("save resend_raw send message: %w", err)
	}

	// Save receive message with the raw response.
	newRecvMsg := &session.Message{
		SessionID: newSess.ID,
		Sequence:  1,
		Direction: "receive",
		Timestamp: start.Add(duration),
		RawBytes:  respData,
	}
	if err := s.store.AppendMessage(ctx, newRecvMsg); err != nil {
		return nil, nil, fmt.Errorf("save resend_raw receive message: %w", err)
	}

	result := &executeResendRawResult{
		NewSessionID: newSess.ID,
		ResponseData: base64.StdEncoding.EncodeToString(respData),
		ResponseSize: len(respData),
		DurationMs:   duration.Milliseconds(),
		Tag:          params.Tag,
	}

	return nil, result, nil
}

// buildResendRawBytes builds the raw bytes to send after applying mutations.
// Priority: override_raw_base64 > patches > original raw bytes.
// Returns the final bytes and the number of patches applied.
func buildResendRawBytes(originalRaw []byte, params executeParams) ([]byte, int, error) {
	// Full replacement takes priority.
	if params.OverrideRawBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(params.OverrideRawBase64)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid override_raw_base64: %w", err)
		}
		if len(decoded) == 0 {
			return nil, 0, fmt.Errorf("override_raw_base64 decodes to empty bytes")
		}
		return decoded, 0, nil
	}

	// Apply byte-level patches to the original raw bytes.
	if len(params.Patches) > 0 {
		patched, err := applyRawPatches(originalRaw, params.Patches)
		if err != nil {
			return nil, 0, err
		}
		return patched, len(params.Patches), nil
	}

	return originalRaw, 0, nil
}

// executeDeleteSessionsResult is the structured output of the delete_sessions action.
type executeDeleteSessionsResult struct {
	// DeletedCount is the number of sessions that were deleted.
	DeletedCount int64 `json:"deleted_count"`
	// CutoffTime is the cutoff timestamp in RFC 3339 format (only set for older_than_days).
	CutoffTime string `json:"cutoff_time,omitempty"`
}

// handleExecuteDeleteSessions handles the delete_sessions action within the execute tool.
// It supports single ID deletion, protocol-based deletion, all-session deletion (with confirm),
// and age-based deletion.
func (s *Server) handleExecuteDeleteSessions(ctx context.Context, params executeParams) (*gomcp.CallToolResult, *executeDeleteSessionsResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	// Age-based deletion (older_than_days).
	if params.OlderThanDays != nil {
		days := *params.OlderThanDays
		if days < 1 {
			return nil, nil, fmt.Errorf("older_than_days must be >= 1, got %d", days)
		}
		if !params.Confirm {
			return nil, nil, fmt.Errorf("confirm must be true to proceed with age-based deletion")
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		n, err := s.store.DeleteSessionsOlderThan(ctx, cutoff)
		if err != nil {
			return nil, nil, fmt.Errorf("delete old sessions: %w", err)
		}
		return nil, &executeDeleteSessionsResult{
			DeletedCount: n,
			CutoffTime:   cutoff.Format(time.RFC3339),
		}, nil
	}

	// Single ID deletion.
	if params.SessionID != "" {
		// Verify the session exists before deleting.
		if _, err := s.store.GetSession(ctx, params.SessionID); err != nil {
			return nil, nil, fmt.Errorf("session not found: %s", params.SessionID)
		}
		if err := s.store.DeleteSession(ctx, params.SessionID); err != nil {
			return nil, nil, fmt.Errorf("delete session: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: 1}, nil
	}

	// Protocol-based deletion (requires confirm).
	if params.Protocol != "" {
		if !params.Confirm {
			return nil, nil, fmt.Errorf("confirm must be true to proceed with protocol-based deletion")
		}
		n, err := s.store.DeleteSessionsByProtocol(ctx, params.Protocol)
		if err != nil {
			return nil, nil, fmt.Errorf("delete sessions by protocol: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: n}, nil
	}

	// All-session deletion (requires confirm).
	if params.Confirm {
		n, err := s.store.DeleteAllSessions(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("delete all sessions: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: n}, nil
	}

	return nil, nil, fmt.Errorf("delete_sessions requires one of: session_id, older_than_days, protocol (with confirm), or confirm=true for all deletion")
}

// --- Intercept queue actions ---

// executeInterceptResult is the structured output of intercept queue actions.
type executeInterceptResult struct {
	// InterceptID is the ID of the intercepted request that was acted upon.
	InterceptID string `json:"intercept_id"`
	// Action is the action that was performed.
	Action string `json:"action"`
	// Status indicates the result.
	Status string `json:"status"`
}

// handleExecuteRelease handles the release action for an intercepted request.
// It forwards the request as-is to the upstream server.
func (s *Server) handleExecuteRelease(_ context.Context, params executeParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for release action")
	}

	action := intercept.InterceptAction{
		Type: intercept.ActionRelease,
	}
	if err := s.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("release: %w", err)
	}

	return nil, &executeInterceptResult{
		InterceptID: params.InterceptID,
		Action:      "release",
		Status:      "released",
	}, nil
}

// handleExecuteModifyAndForward handles the modify_and_forward action for an intercepted request.
// It applies modifications (same override parameters as resend) and forwards the request.
func (s *Server) handleExecuteModifyAndForward(_ context.Context, params executeParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for modify_and_forward action")
	}

	// Validate header overrides for CRLF injection (CWE-113).
	if err := validateHeaderValues(params.OverrideHeaders); err != nil {
		return nil, nil, fmt.Errorf("override_headers: %w", err)
	}
	if err := validateHeaderValues(params.AddHeaders); err != nil {
		return nil, nil, fmt.Errorf("add_headers: %w", err)
	}
	if err := validateHeaderKeys(params.RemoveHeaders); err != nil {
		return nil, nil, fmt.Errorf("remove_headers: %w", err)
	}

	action := intercept.InterceptAction{
		Type:            intercept.ActionModifyAndForward,
		OverrideMethod:  params.OverrideMethod,
		OverrideURL:     params.OverrideURL,
		OverrideHeaders: params.OverrideHeaders,
		AddHeaders:      params.AddHeaders,
		RemoveHeaders:   params.RemoveHeaders,
		OverrideBody:    params.OverrideBody,
	}

	if err := s.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	return nil, &executeInterceptResult{
		InterceptID: params.InterceptID,
		Action:      "modify_and_forward",
		Status:      "forwarded",
	}, nil
}

// handleExecuteDrop handles the drop action for an intercepted request.
// It discards the request and returns a 502 to the client.
func (s *Server) handleExecuteDrop(_ context.Context, params executeParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for drop action")
	}

	action := intercept.InterceptAction{
		Type: intercept.ActionDrop,
	}
	if err := s.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("drop: %w", err)
	}

	return nil, &executeInterceptResult{
		InterceptID: params.InterceptID,
		Action:      "drop",
		Status:      "dropped",
	}, nil
}

// handleExecuteFuzz handles the fuzz action within the execute tool.
// It starts an asynchronous fuzz job and returns the fuzz_id immediately.
// When hooks are configured, they are passed to the fuzzer as callbacks
// that execute at each iteration.
func (s *Server) handleExecuteFuzz(ctx context.Context, params executeParams) (*gomcp.CallToolResult, *fuzzer.AsyncResult, error) {
	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for fuzz action")
	}
	if params.AttackType == "" {
		return nil, nil, fmt.Errorf("attack_type is required for fuzz action")
	}
	if len(params.Positions) == 0 {
		return nil, nil, fmt.Errorf("at least one position is required for fuzz action")
	}

	// Validate hooks if present.
	if err := validateHooks(params.Hooks); err != nil {
		return nil, nil, fmt.Errorf("invalid hooks: %w", err)
	}

	// Target scope enforcement: check the template session's URL before starting fuzz.
	// This check runs before the fuzz runner initialization check to enforce
	// security boundaries early (deny-first).
	if s.targetScope != nil && s.targetScope.HasRules() {
		if s.store == nil {
			return nil, nil, fmt.Errorf("session store is not initialized")
		}
		templateSess, err := s.store.GetSession(ctx, params.SessionID)
		if err != nil {
			return nil, nil, fmt.Errorf("get template session for target scope check: %w", err)
		}
		sendMsgs, err := s.store.GetMessages(ctx, templateSess.ID, session.MessageListOptions{Direction: "send"})
		if err != nil {
			return nil, nil, fmt.Errorf("get send messages for target scope check: %w", err)
		}
		if len(sendMsgs) > 0 && sendMsgs[0].URL != nil {
			if err := s.checkTargetScopeURL(sendMsgs[0].URL); err != nil {
				return nil, nil, err
			}
		}
	}

	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}

	cfg := fuzzer.RunConfig{
		Config: fuzzer.Config{
			SessionID:   params.SessionID,
			AttackType:  params.AttackType,
			Positions:   params.Positions,
			PayloadSets: params.PayloadSets,
			Tag:         params.Tag,
		},
		StopOn: params.StopOn,
	}
	if params.TimeoutMs != nil {
		cfg.TimeoutMs = *params.TimeoutMs
	}
	if params.Concurrency != nil {
		cfg.Concurrency = *params.Concurrency
	}
	if params.RateLimitRPS != nil {
		cfg.RateLimitRPS = *params.RateLimitRPS
	}
	if params.DelayMs != nil {
		cfg.DelayMs = *params.DelayMs
	}
	if params.MaxRetries != nil {
		cfg.MaxRetries = *params.MaxRetries
	}

	allowPrivate := params.AllowPrivateNetworks || s.allowPrivateNetworks

	// Set up hooks callbacks if configured.
	if params.Hooks != nil {
		hooks := newFuzzHookCallbacks(s, params.Hooks)
		hooks.allowPrivateNetworks = allowPrivate
		cfg.Hooks = hooks
	}

	// When allow_private_networks is enabled, provide a permissive HTTP client
	// that bypasses SSRF protection for the fuzz job.
	if allowPrivate {
		slog.Warn("SSRF protection disabled: allow_private_networks is enabled for fuzz")
		cfg.HTTPDoer = newPermissiveHTTPClient()
	}

	// Use the application-level context so the job survives beyond the MCP request.
	result, err := s.fuzzRunner.Start(s.appCtx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzz execution: %w", err)
	}

	return nil, result, nil
}

// executeFuzzControlResult is the structured output of fuzz control actions.
type executeFuzzControlResult struct {
	// FuzzID is the ID of the fuzz job.
	FuzzID string `json:"fuzz_id"`
	// Action is the control action performed.
	Action string `json:"action"`
	// Status is the resulting job status.
	Status string `json:"status"`
}

// handleExecuteFuzzPause handles the fuzz_pause action.
func (s *Server) handleExecuteFuzzPause(params executeParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_pause action")
	}

	ctrl := s.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Pause(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_pause: %w", err)
	}

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_pause",
		Status: string(ctrl.Status()),
	}, nil
}

// handleExecuteFuzzResume handles the fuzz_resume action.
func (s *Server) handleExecuteFuzzResume(params executeParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_resume action")
	}

	ctrl := s.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Resume(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_resume: %w", err)
	}

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_resume",
		Status: string(ctrl.Status()),
	}, nil
}

// handleExecuteFuzzCancel handles the fuzz_cancel action.
func (s *Server) handleExecuteFuzzCancel(params executeParams) (*gomcp.CallToolResult, *executeFuzzControlResult, error) {
	if s.fuzzRunner == nil {
		return nil, nil, fmt.Errorf("fuzz runner is not initialized")
	}
	if params.FuzzID == "" {
		return nil, nil, fmt.Errorf("fuzz_id is required for fuzz_cancel action")
	}

	ctrl := s.fuzzRunner.Registry().Get(params.FuzzID)
	if ctrl == nil {
		return nil, nil, fmt.Errorf("fuzz job %q not found or already completed", params.FuzzID)
	}

	if err := ctrl.Cancel(); err != nil {
		return nil, nil, fmt.Errorf("fuzz_cancel: %w", err)
	}

	return nil, &executeFuzzControlResult{
		FuzzID: params.FuzzID,
		Action: "fuzz_cancel",
		Status: string(ctrl.Status()),
	}, nil
}

// --- regenerate_ca_cert action ---

// executeRegenerateCACertResult is the structured output of the regenerate_ca_cert action.
type executeRegenerateCACertResult struct {
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
	Persisted   bool   `json:"persisted"`
	CertPath    string `json:"cert_path,omitempty"`
	InstallHint string `json:"install_hint,omitempty"`
}

// handleExecuteRegenerateCA regenerates the CA certificate.
// In auto-persist mode, the new CA is saved to the default path.
// In ephemeral mode, the new CA exists only in memory.
// In explicit mode (user-provided paths), regeneration is rejected.
func (s *Server) handleExecuteRegenerateCA() (*gomcp.CallToolResult, *executeRegenerateCACertResult, error) {
	if s.ca == nil {
		return nil, nil, fmt.Errorf("CA is not initialized")
	}

	source := s.ca.Source()

	// Reject regeneration in explicit mode (user-provided CA via -ca-cert/-ca-key).
	if source.Explicit {
		return nil, nil, fmt.Errorf("cannot regenerate user-provided CA (loaded from %s); provide new files via -ca-cert/-ca-key flags instead", source.CertPath)
	}

	// Generate a new CA.
	if err := s.ca.Generate(); err != nil {
		return nil, nil, fmt.Errorf("regenerate CA: %w", err)
	}

	// Clear the issuer cache so new TLS handshakes use the new CA.
	if s.issuer != nil {
		s.issuer.ClearCache()
	}

	// If the CA was persisted, save the new CA to the same paths.
	if source.Persisted && source.CertPath != "" {
		if err := s.ca.Save(source.CertPath, source.KeyPath); err != nil {
			// Save failed but the CA has already been regenerated in memory.
			// Clear source metadata so the CA is treated as ephemeral.
			slog.Warn("failed to save regenerated CA, continuing with ephemeral CA",
				"cert_path", source.CertPath, "error", err)
			s.ca.SetSource(cert.CASource{})
		} else {
			s.ca.SetSource(source) // preserve source metadata
		}
	}

	newCert := s.ca.Certificate()
	fingerprint := sha256.Sum256(newCert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	newSource := s.ca.Source()
	result := &executeRegenerateCACertResult{
		Fingerprint: fingerprintHex,
		Subject:     newCert.Subject.String(),
		NotAfter:    newCert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		Persisted:   newSource.Persisted,
		CertPath:    newSource.CertPath,
	}

	if newSource.Persisted && newSource.CertPath != "" {
		result.InstallHint = "CA certificate has been regenerated. Please re-install the CA from " + newSource.CertPath + " into your trust store"
	} else {
		result.InstallHint = "CA certificate has been regenerated in memory. It will be lost on restart"
	}

	return nil, result, nil
}

// maxInlineExportSessions is the maximum number of sessions returned inline
// (without output_path) to prevent unbounded memory usage (S-4: CWE-400).
const maxInlineExportSessions = 100

// maxImportScannerBuffer is the maximum per-line buffer size for the import
// scanner. 4 MB is generous for JSONL session records while preventing
// excessive memory allocation (S-6: CWE-400).
const maxImportScannerBuffer = 4 * 1024 * 1024

// validateFilePath sanitises and validates a user-supplied file path.
// It rejects empty paths, normalises via filepath.Abs + filepath.Clean,
// and checks that existing targets are not symbolic links (S-3: CWE-61).
func validateFilePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path must not be empty")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}
	cleaned := filepath.Clean(abs)

	// If the path already exists, reject symbolic links.
	info, err := os.Lstat(cleaned)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("file path must not be a symbolic link: %s", cleaned)
		}
	}
	// If the path does not exist, that is fine -- the caller may create it.

	return cleaned, nil
}

// executeExportSessionsResult is the structured output of the export_sessions action.
type executeExportSessionsResult struct {
	ExportedCount int    `json:"exported_count"`
	Format        string `json:"format"`
	OutputPath    string `json:"output_path,omitempty"`
	Data          string `json:"data,omitempty"`
}

// handleExecuteExportSessions handles the export_sessions action within the execute tool.
func (s *Server) handleExecuteExportSessions(ctx context.Context, params executeParams) (*executeExportSessionsResult, error) {
	if s.store == nil {
		return nil, fmt.Errorf("session store is not initialized")
	}

	format := params.Format
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" {
		return nil, fmt.Errorf("unsupported export format %q: only \"jsonl\" is supported", format)
	}

	includeBodies := true
	if params.IncludeBodies != nil {
		includeBodies = *params.IncludeBodies
	}

	opts := session.ExportOptions{
		IncludeBodies: includeBodies,
	}

	if params.Filter != nil {
		opts.Filter.Protocol = params.Filter.Protocol
		opts.Filter.URLPattern = params.Filter.URLPattern

		if params.Filter.TimeAfter != "" {
			t, err := time.Parse(time.RFC3339, params.Filter.TimeAfter)
			if err != nil {
				return nil, fmt.Errorf("invalid time_after format (expected RFC3339): %w", err)
			}
			opts.Filter.TimeAfter = &t
		}
		if params.Filter.TimeBefore != "" {
			t, err := time.Parse(time.RFC3339, params.Filter.TimeBefore)
			if err != nil {
				return nil, fmt.Errorf("invalid time_before format (expected RFC3339): %w", err)
			}
			opts.Filter.TimeBefore = &t
		}
	}

	if params.OutputPath != "" {
		// S-1/S-2: validate and normalise file path.
		cleanPath, err := validateFilePath(params.OutputPath)
		if err != nil {
			return nil, fmt.Errorf("invalid output_path: %w", err)
		}

		// M-1: write to a temp file in the same directory, then rename
		// for atomic writes. This prevents partial files on failure.
		dir := filepath.Dir(cleanPath)
		// S-8: create temp file with 0600 permissions.
		tmpFile, err := os.CreateTemp(dir, ".yorishiro-export-*.tmp")
		if err != nil {
			return nil, fmt.Errorf("create temp file for export: %w", err)
		}
		tmpPath := tmpFile.Name()
		// Ensure temp file is cleaned up on any error path.
		success := false
		defer func() {
			tmpFile.Close()
			if !success {
				os.Remove(tmpPath)
			}
		}()

		// S-8: restrict permissions to owner-only.
		if err := tmpFile.Chmod(0600); err != nil {
			return nil, fmt.Errorf("set file permissions: %w", err)
		}

		n, err := session.ExportSessions(ctx, s.store, tmpFile, opts)
		if err != nil {
			return nil, fmt.Errorf("export sessions: %w", err)
		}

		if err := tmpFile.Close(); err != nil {
			return nil, fmt.Errorf("close temp file: %w", err)
		}

		// S-3: reject if the final destination is now a symlink
		// (TOCTOU mitigation -- re-check after write completes).
		if info, statErr := os.Lstat(cleanPath); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("output_path must not be a symbolic link: %s", cleanPath)
			}
		}

		if err := os.Rename(tmpPath, cleanPath); err != nil {
			return nil, fmt.Errorf("rename temp file to output: %w", err)
		}
		success = true

		return &executeExportSessionsResult{
			ExportedCount: n,
			Format:        format,
			OutputPath:    cleanPath,
		}, nil
	}

	// No output_path: return data inline in the MCP response.
	// S-4: limit inline export to prevent unbounded memory usage.
	opts.MaxSessions = maxInlineExportSessions
	var buf bytes.Buffer
	n, err := session.ExportSessions(ctx, s.store, &buf, opts)
	if err != nil {
		return nil, fmt.Errorf("export sessions: %w", err)
	}

	return &executeExportSessionsResult{
		ExportedCount: n,
		Format:        format,
		Data:          buf.String(),
	}, nil
}

// executeImportSessionsResult is the structured output of the import_sessions action.
type executeImportSessionsResult struct {
	Imported int    `json:"imported"`
	Skipped  int    `json:"skipped"`
	Errors   int    `json:"errors"`
	Source   string `json:"source"`
}

// handleExecuteImportSessions handles the import_sessions action within the execute tool.
func (s *Server) handleExecuteImportSessions(ctx context.Context, params executeParams) (*executeImportSessionsResult, error) {
	if s.store == nil {
		return nil, fmt.Errorf("session store is not initialized")
	}

	if params.InputPath == "" {
		return nil, fmt.Errorf("input_path is required for import_sessions action")
	}

	// S-2: validate and normalise file path.
	cleanPath, err := validateFilePath(params.InputPath)
	if err != nil {
		return nil, fmt.Errorf("invalid input_path: %w", err)
	}

	conflict := session.ConflictSkip
	if params.OnConflict != "" {
		switch params.OnConflict {
		case "skip":
			conflict = session.ConflictSkip
		case "replace":
			conflict = session.ConflictReplace
		default:
			return nil, fmt.Errorf("invalid on_conflict value %q: must be \"skip\" or \"replace\"", params.OnConflict)
		}
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()

	result, err := session.ImportSessions(ctx, s.store, f, session.ImportOptions{
		OnConflict:       conflict,
		MaxScannerBuffer: maxImportScannerBuffer,
		ValidateIDs:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("import sessions: %w", err)
	}

	return &executeImportSessionsResult{
		Imported: result.Imported,
		Skipped:  result.Skipped,
		Errors:   result.Errors,
		Source:   cleanPath,
	}, nil
}
