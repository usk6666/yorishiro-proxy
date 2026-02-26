package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/fuzzer"
	"github.com/usk6666/katashiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// executeInput is the typed input for the execute tool.
type executeInput struct {
	// Action specifies the action to execute.
	// Available actions: resend, resend_raw, delete_sessions, define_macro, run_macro, delete_macro
	// (replay, replay_raw are deprecated aliases).
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params executeParams `json:"params"`
}

// executeParams holds the union of all action-specific parameters.
// Only the fields relevant to the specified action are used.
type executeParams struct {
	// SessionID is used by resend, resend_raw, and delete_sessions (single deletion).
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID for resend/resend_raw/delete"`

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
	TargetAddr string `json:"target_addr,omitempty" jsonschema:"target address (host:port) for resend_raw"`
	UseTLS     *bool  `json:"use_tls,omitempty" jsonschema:"use TLS for resend_raw connection"`

	// delete_sessions parameters
	OlderThanDays *int `json:"older_than_days,omitempty" jsonschema:"delete sessions older than this many days"`
	Confirm       bool `json:"confirm,omitempty" jsonschema:"confirm bulk deletion"`

	// intercept queue parameters (release, modify_and_forward, drop)
	InterceptID string `json:"intercept_id,omitempty" jsonschema:"intercepted request ID for release/modify_and_forward/drop"`

	// fuzz parameters
	AttackType  string                       `json:"attack_type,omitempty" jsonschema:"fuzz attack type: sequential or parallel"`
	Positions   []fuzzer.Position            `json:"positions,omitempty" jsonschema:"payload positions for fuzzing"`
	PayloadSets map[string]fuzzer.PayloadSet `json:"payload_sets,omitempty" jsonschema:"named payload sets for fuzzing"`

	// macro parameters (define_macro, run_macro, delete_macro)
	Name         string            `json:"name,omitempty" jsonschema:"macro name"`
	Description  string            `json:"description,omitempty" jsonschema:"macro description"`
	Steps        []macroStepInput  `json:"steps,omitempty" jsonschema:"macro steps for define_macro"`
	InitialVars  map[string]string `json:"initial_vars,omitempty" jsonschema:"initial KV Store entries for define_macro"`
	MacroTimeout int               `json:"macro_timeout_ms,omitempty" jsonschema:"macro timeout in milliseconds"`
	Vars         map[string]string `json:"vars,omitempty" jsonschema:"runtime variable overrides for run_macro"`
}

// availableActions lists the valid action names for error messages.
var availableActions = []string{"resend", "resend_raw", "delete_sessions", "release", "modify_and_forward", "drop", "fuzz", "define_macro", "run_macro", "delete_macro"}

// registerExecute registers the execute MCP tool.
func (s *Server) registerExecute() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "execute",
		Description: "Execute an action on recorded proxy data. " +
			"Available actions: " +
			"'resend' resends a recorded HTTP request with optional mutation (method/URL/header/body overrides, body patches, dry-run); " +
			"'resend_raw' resends raw bytes from a recorded session over TCP/TLS; " +
			"'delete_sessions' deletes sessions by ID, by age (older_than_days), or all (confirm required); " +
			"'release' forwards an intercepted request as-is (requires intercept_id); " +
			"'modify_and_forward' forwards an intercepted request with mutations (same override params as resend, requires intercept_id); " +
			"'drop' discards an intercepted request returning 502 to the client (requires intercept_id); " +
			"'fuzz' runs a fuzz campaign against a recorded session with configurable positions, payload sets, and attack types (sequential/parallel); " +
			"'define_macro' saves a macro definition (upsert) with steps, extraction rules, and guards; " +
			"'run_macro' executes a stored macro for testing; " +
			"'delete_macro' removes a stored macro definition. " +
			"('replay' and 'replay_raw' are accepted as deprecated aliases for 'resend' and 'resend_raw'.)",
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
	case "define_macro":
		mp := paramsToMacroParams(input.Params)
		result, err := s.handleExecuteDefineMacro(ctx, mp)
		if err != nil {
			return nil, nil, err
		}
		return nil, result, nil
	case "run_macro":
		mp := paramsToMacroParams(input.Params)
		result, err := s.handleExecuteRunMacro(ctx, mp)
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
func (s *Server) handleExecuteResend(ctx context.Context, params executeParams) (*gomcp.CallToolResult, any, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for resend action")
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
		preview := &executeDryRunResult{
			DryRun: true,
			RequestPreview: &requestPreview{
				Method:       method,
				URL:          targetURL.String(),
				Headers:      headers,
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
	for _, key := range params.RemoveHeaders {
		// Case-insensitive removal: normalize to canonical form.
		delete(headers, http.CanonicalHeaderKey(key))
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
// It respects follow_redirects, timeout_ms, and override_host parameters.
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

	dialer := &net.Dialer{
		Timeout: timeout,
		Control: denyPrivateNetwork,
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
		checkRedirect = safeCheckRedirect
	}

	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: checkRedirect,
	}
}

// executeResendRawResult is the structured output of the resend_raw action.
type executeResendRawResult struct {
	// ResponseData is the raw response bytes, Base64-encoded.
	ResponseData string `json:"response_data"`
	// ResponseSize is the number of response bytes received.
	ResponseSize int `json:"response_size"`
	// DurationMs is the round-trip duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
}

// handleExecuteResendRaw handles the resend_raw action within the execute tool.
// It retrieves the session's raw request bytes and sends them directly over TCP/TLS.
func (s *Server) handleExecuteResendRaw(ctx context.Context, params executeParams) (*gomcp.CallToolResult, *executeResendRawResult, error) {
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
	dialer := s.rawDialerFunc()
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
			InsecureSkipVerify: true,
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

	// Send the raw request bytes exactly as captured.
	if _, err := conn.Write(sendMsg.RawBytes); err != nil {
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

	result := &executeResendRawResult{
		ResponseData: base64.StdEncoding.EncodeToString(respData),
		ResponseSize: len(respData),
		DurationMs:   duration.Milliseconds(),
	}

	return nil, result, nil
}

// executeDeleteSessionsResult is the structured output of the delete_sessions action.
type executeDeleteSessionsResult struct {
	// DeletedCount is the number of sessions that were deleted.
	DeletedCount int64 `json:"deleted_count"`
	// CutoffTime is the cutoff timestamp in RFC 3339 format (only set for older_than_days).
	CutoffTime string `json:"cutoff_time,omitempty"`
}

// handleExecuteDeleteSessions handles the delete_sessions action within the execute tool.
// It supports single ID deletion, all-session deletion (with confirm), and age-based deletion.
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

	// All-session deletion (requires confirm).
	if params.Confirm {
		n, err := s.store.DeleteAllSessions(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("delete all sessions: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: n}, nil
	}

	return nil, nil, fmt.Errorf("delete_sessions requires one of: session_id, older_than_days, or confirm=true for all deletion")
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

// executeFuzzResult is the structured output of the fuzz action.
type executeFuzzResult struct {
	// FuzzID is the unique identifier of the fuzz job.
	FuzzID string `json:"fuzz_id"`
	// Status is the final job status.
	Status string `json:"status"`
	// Total is the total number of iterations.
	Total int `json:"total"`
	// Completed is the number of completed iterations.
	Completed int `json:"completed"`
	// Errors is the number of failed iterations.
	Errors int `json:"errors"`
	// Tag is the job tag (if set).
	Tag string `json:"tag,omitempty"`
	// Message is a human-readable summary.
	Message string `json:"message"`
}

// handleExecuteFuzz handles the fuzz action within the execute tool.
// It creates a fuzz engine, executes the job synchronously, and returns a summary.
func (s *Server) handleExecuteFuzz(ctx context.Context, params executeParams) (*gomcp.CallToolResult, *executeFuzzResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	fuzzStore, ok := s.store.(session.FuzzStore)
	if !ok {
		return nil, nil, fmt.Errorf("session store does not support fuzz operations")
	}

	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for fuzz action")
	}
	if params.AttackType == "" {
		return nil, nil, fmt.Errorf("attack_type is required for fuzz action")
	}
	if len(params.Positions) == 0 {
		return nil, nil, fmt.Errorf("at least one position is required for fuzz action")
	}

	cfg := fuzzer.Config{
		SessionID:   params.SessionID,
		AttackType:  params.AttackType,
		Positions:   params.Positions,
		PayloadSets: params.PayloadSets,
		Tag:         params.Tag,
	}
	if params.TimeoutMs != nil {
		cfg.TimeoutMs = *params.TimeoutMs
	}

	// Build the HTTP client with SSRF protection.
	httpClient := s.resendHTTPClient(params)

	engine := fuzzer.NewEngine(s.store, s.store, fuzzStore, httpClient, fuzzer.DefaultWordlistBaseDir())
	result, err := engine.Run(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzz execution: %w", err)
	}

	return nil, &executeFuzzResult{
		FuzzID:    result.FuzzID,
		Status:    result.Status,
		Total:     result.Total,
		Completed: result.Completed,
		Errors:    result.Errors,
		Tag:       result.Tag,
		Message:   fmt.Sprintf("Fuzz completed: %d/%d requests sent, %d errors", result.Completed, result.Total, result.Errors),
	}, nil
}
