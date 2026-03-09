package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// resendInput is the typed input for the resend tool.
type resendInput struct {
	// Action specifies the action to perform.
	// Available actions: resend, resend_raw, tcp_replay
	// (replay is a deprecated alias for resend; replay_raw is a deprecated alias for resend_raw).
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params resendParams `json:"params"`
}

// HeaderEntry represents a single header key-value pair, allowing duplicate keys.
type HeaderEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// HeaderEntries is a slice of HeaderEntry that supports unmarshaling from both
// the new array format ([]HeaderEntry) and the legacy map format (map[string]string)
// for backward compatibility.
type HeaderEntries []HeaderEntry

// UnmarshalJSON implements json.Unmarshaler.
// It accepts both the new array format and the legacy map[string]string format.
func (h *HeaderEntries) UnmarshalJSON(data []byte) error {
	// Try array format first: [{"key":"k","value":"v"}, ...]
	var entries []HeaderEntry
	if err := json.Unmarshal(data, &entries); err == nil {
		*h = entries
		return nil
	}

	// Fall back to legacy map format: {"key": "value", ...}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("header entries must be an array of {key,value} objects or a map of key-value pairs")
	}
	result := make([]HeaderEntry, 0, len(m))
	for k, v := range m {
		result = append(result, HeaderEntry{Key: k, Value: v})
	}
	*h = result
	return nil
}

// resendParams holds parameters for the resend tool actions (resend, resend_raw, tcp_replay).
type resendParams struct {
	// FlowID identifies the flow to resend/replay.
	FlowID string `json:"flow_id,omitempty"`

	// MessageSequence specifies a specific message within a flow for WebSocket/streaming resend.
	MessageSequence *int `json:"message_sequence,omitempty"`

	// resend overrides
	OverrideMethod     string        `json:"override_method,omitempty"`
	OverrideURL        string        `json:"override_url,omitempty"`
	OverrideHeadersRaw any           `json:"override_headers,omitempty"`
	OverrideHeaders    HeaderEntries `json:"-"` // parsed from OverrideHeadersRaw
	OverrideBody       *string       `json:"override_body,omitempty"`

	// resend extended mutation options
	AddHeadersRaw      any           `json:"add_headers,omitempty"`
	AddHeaders         HeaderEntries `json:"-"` // parsed from AddHeadersRaw
	RemoveHeaders      []string      `json:"remove_headers,omitempty"`
	OverrideBodyBase64 *string       `json:"override_body_base64,omitempty"`
	BodyPatches        []BodyPatch   `json:"body_patches,omitempty"`
	OverrideHost       string        `json:"override_host,omitempty"`
	FollowRedirects    *bool         `json:"follow_redirects,omitempty"`
	TimeoutMs          *int          `json:"timeout_ms,omitempty"`
	DryRun             bool          `json:"dry_run,omitempty"`
	Tag                string        `json:"tag,omitempty"`

	// resend_raw parameters
	TargetAddr        string     `json:"target_addr,omitempty"`
	UseTLS            *bool      `json:"use_tls,omitempty"`
	OverrideRawBase64 string     `json:"override_raw_base64,omitempty"`
	Patches           []RawPatch `json:"patches,omitempty"`

	// hooks parameters (resend)
	Hooks *hooksInput `json:"hooks,omitempty"`
}

// parseRawHeaders parses the raw JSON header fields (OverrideHeadersRaw, AddHeadersRaw)
// into their typed HeaderEntries fields. This must be called before accessing
// OverrideHeaders or AddHeaders.
func (p *resendParams) parseRawHeaders() error {
	if p.OverrideHeadersRaw != nil {
		entries, err := parseHeaderEntriesFromAny(p.OverrideHeadersRaw)
		if err != nil {
			return fmt.Errorf("override_headers: %w", err)
		}
		p.OverrideHeaders = entries
	}
	if p.AddHeadersRaw != nil {
		entries, err := parseHeaderEntriesFromAny(p.AddHeadersRaw)
		if err != nil {
			return fmt.Errorf("add_headers: %w", err)
		}
		p.AddHeaders = entries
	}
	return nil
}

// parseHeaderEntriesFromAny converts an any value (from JSON deserialization)
// into HeaderEntries. It accepts:
//   - []any where each element is map[string]any with "key" and "value" fields (array format)
//   - map[string]any where each key-value pair is a header (legacy map format)
func parseHeaderEntriesFromAny(v any) (HeaderEntries, error) {
	switch val := v.(type) {
	case []any:
		entries := make(HeaderEntries, 0, len(val))
		for i, item := range val {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("entry %d: expected object with key and value fields", i)
			}
			key, _ := m["key"].(string)
			value, _ := m["value"].(string)
			if key == "" {
				return nil, fmt.Errorf("entry %d: key is required", i)
			}
			entries = append(entries, HeaderEntry{Key: key, Value: value})
		}
		return entries, nil
	case map[string]any:
		entries := make(HeaderEntries, 0, len(val))
		for k, v := range val {
			value, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("header %q: value must be a string", k)
			}
			entries = append(entries, HeaderEntry{Key: k, Value: value})
		}
		return entries, nil
	default:
		return nil, fmt.Errorf("must be an array of {key,value} objects or a map of key-value pairs")
	}
}

// availableResendActions lists the valid action names for the resend tool.
var availableResendActions = []string{"resend", "resend_raw", "tcp_replay"}

// registerResend registers the resend MCP tool.
func (s *Server) registerResend() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "resend",
		Description: "Resend and replay recorded proxy requests with optional mutations. " +
			"Available actions: " +
			"'resend' resends a recorded HTTP/HTTP2/WebSocket request with optional mutation (method/URL/header/body overrides, body patches, dry-run). " +
			"For WebSocket flows, use message_sequence to specify which message to resend as a raw TCP frame; " +
			"'resend_raw' resends raw bytes from a recorded flow over TCP/TLS with optional byte-level patches (offset overwrite, binary/text find-replace, override_raw_base64 full replacement, dry-run); " +
			"'tcp_replay' replays a Raw TCP flow by sending all 'send' messages sequentially to the target. " +
			"('replay' is a deprecated alias for 'resend'; 'replay_raw' is a deprecated alias for 'resend_raw'). " +
			"For flow management (delete/export/import), use the 'manage' tool. " +
			"For fuzzing, use the 'fuzz' tool. " +
			"For macro operations, use the 'macro' tool. " +
			"For intercept queue actions, use the 'intercept' tool.",
	}, s.handleResend)
}

// handleResend routes the resend tool invocation to the appropriate action handler.
func (s *Server) handleResend(ctx context.Context, _ *gomcp.CallToolRequest, input resendInput) (*gomcp.CallToolResult, any, error) {
	// Parse raw header JSON fields into typed HeaderEntries.
	if err := input.Params.parseRawHeaders(); err != nil {
		return nil, nil, err
	}

	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableResendActions, ", "))
	case "resend", "replay": // "replay" is a deprecated alias
		return s.handleResendAction(ctx, input.Params)
	case "resend_raw", "replay_raw": // "replay_raw" is a deprecated alias
		return s.handleResendActionRaw(ctx, input.Params)
	case "tcp_replay":
		return s.handleResendReplayRaw(ctx, input.Params)
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %v", input.Action, availableResendActions)
	}
}

// --- Resend result types ---

// resendActionResult is the structured output of the resend action.
type resendActionResult struct {
	NewFlowID            string              `json:"new_flow_id"`
	StatusCode           int                 `json:"status_code"`
	ResponseHeaders      map[string][]string `json:"response_headers"`
	ResponseBody         string              `json:"response_body"`
	ResponseBodyEncoding string              `json:"response_body_encoding"`
	DurationMs           int64               `json:"duration_ms"`
	Tag                  string              `json:"tag,omitempty"`
}

// resendDryRunResult is the structured output of a dry-run resend.
type resendDryRunResult struct {
	DryRun         bool            `json:"dry_run"`
	RequestPreview *requestPreview `json:"request_preview"`
}

// requestPreview is the preview of a modified request for dry-run mode.
type requestPreview struct {
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
}

// resendPrepared holds the validated and prepared state for a resend action,
// produced by validateResendParams before execution.
type resendPrepared struct {
	flow    *flow.Flow
	sendMsg *flow.Message
	method  string
	url     *url.URL
	body    []byte
	headers map[string][]string
	kvStore map[string]string
}

// handleResendAction handles the resend action within the resend tool.
func (s *Server) handleResendAction(ctx context.Context, params resendParams) (*gomcp.CallToolResult, any, error) {
	prep, wsResult, wsStructured, err := s.validateResendParams(ctx, &params)
	if err != nil {
		return nil, nil, err
	}
	if wsResult != nil || wsStructured != nil {
		return wsResult, wsStructured, nil
	}

	if params.DryRun {
		return nil, buildDryRunResult(prep.method, prep.url, prep.headers, prep.body), nil
	}

	return s.executeResend(ctx, prep, params)
}

// validateResendParams validates all resend parameters, executes hooks, retrieves the flow
// and send message, and prepares the method/URL/body/headers for the resend.
// If the flow is WebSocket, it delegates to handleWebSocketResend and returns the result.
func (s *Server) validateResendParams(ctx context.Context, params *resendParams) (*resendPrepared, *gomcp.CallToolResult, any, error) {
	if s.deps.store == nil {
		return nil, nil, nil, fmt.Errorf("flow store is not initialized")
	}
	if params.FlowID == "" {
		return nil, nil, nil, fmt.Errorf("flow_id is required for resend action")
	}

	if err := validateHooks(params.Hooks); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hooks: %w", err)
	}

	kvStore, err := s.executePreSendHook(ctx, params)
	if err != nil {
		return nil, nil, nil, err
	}

	fl, err := s.deps.store.GetFlow(ctx, params.FlowID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get flow: %w", err)
	}

	if fl.Protocol == "WebSocket" {
		r1, r2, err := s.handleWebSocketResend(ctx, fl, *params)
		return nil, r1, r2, err
	}

	sendMsgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, nil, fmt.Errorf("flow %s has no send messages", params.FlowID)
	}
	sendMsg := sendMsgs[0]

	method := sendMsg.Method
	if params.OverrideMethod != "" {
		method = params.OverrideMethod
	}

	targetURL, err := buildResendURL(sendMsg.URL, *params)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := s.validateResendScope(targetURL, *params); err != nil {
		return nil, nil, nil, err
	}

	if err := validateResendHeaders(*params); err != nil {
		return nil, nil, nil, err
	}

	reqBody, err := buildResendBody(sendMsg.Body, *params)
	if err != nil {
		return nil, nil, nil, err
	}

	headers := buildResendHeaders(sendMsg.Headers, *params)

	return &resendPrepared{
		flow: fl, sendMsg: sendMsg,
		method: method, url: targetURL,
		body: reqBody, headers: headers,
		kvStore: kvStore,
	}, nil, nil, nil
}

// executePreSendHook runs the pre-send hook if configured, returning the KV store
// and expanding template parameters.
func (s *Server) executePreSendHook(ctx context.Context, params *resendParams) (map[string]string, error) {
	var kvStore map[string]string
	if params.Hooks != nil && params.Hooks.PreSend != nil {
		state := &hookState{}
		executor := newHookExecutor(s.deps, params.Hooks, state)
		var err error
		kvStore, err = executor.executePreSend(ctx)
		if err != nil {
			return nil, err
		}
	}

	if len(kvStore) > 0 {
		if err := expandParamsWithKVStore(params, kvStore); err != nil {
			return nil, fmt.Errorf("template expansion: %w", err)
		}
	}
	return kvStore, nil
}

// buildResendURL resolves the target URL from the original message URL and any override.
func buildResendURL(originalURL *url.URL, params resendParams) (*url.URL, error) {
	targetURL := originalURL
	if params.OverrideURL != "" {
		parsed, err := url.Parse(params.OverrideURL)
		if err != nil {
			return nil, fmt.Errorf("invalid override_url %q: %w", params.OverrideURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("invalid override_url %q: must include scheme and host", params.OverrideURL)
		}
		if err := validateURLScheme(parsed); err != nil {
			return nil, fmt.Errorf("invalid override_url %q: %w", params.OverrideURL, err)
		}
		targetURL = parsed
	}

	if targetURL == nil {
		return nil, fmt.Errorf("original flow has no URL and no override_url was provided")
	}
	if err := validateURLScheme(targetURL); err != nil {
		return nil, err
	}
	return targetURL, nil
}

// validateResendScope validates override_host and checks target scope for the URL and host.
func (s *Server) validateResendScope(targetURL *url.URL, params resendParams) error {
	if params.OverrideHost != "" {
		if err := validateOverrideHost(params.OverrideHost); err != nil {
			return fmt.Errorf("invalid override_host %q: %w", params.OverrideHost, err)
		}
	}

	if err := s.checkTargetScopeURL(targetURL); err != nil {
		return err
	}
	if params.OverrideHost != "" {
		if err := s.checkTargetScopeAddr(targetURL.Scheme, params.OverrideHost); err != nil {
			return err
		}
	}
	return nil
}

// buildDryRunResult creates a dry-run result from the prepared request parameters.
func buildDryRunResult(method string, targetURL *url.URL, headers map[string][]string, reqBody []byte) *resendDryRunResult {
	bodyStr, bodyEncoding := encodeBody(reqBody)
	previewHeaders := make(map[string][]string)
	for k, v := range headers {
		if len(v) > 0 {
			previewHeaders[k] = v
		}
	}
	return &resendDryRunResult{
		DryRun: true,
		RequestPreview: &requestPreview{
			Method:       method,
			URL:          targetURL.String(),
			Headers:      previewHeaders,
			Body:         bodyStr,
			BodyEncoding: bodyEncoding,
		},
	}
}

// executeResend sends the HTTP request and records the flow and messages.
func (s *Server) executeResend(ctx context.Context, prep *resendPrepared, params resendParams) (*gomcp.CallToolResult, any, error) {
	httpReq, err := s.buildHTTPRequest(ctx, prep)
	if err != nil {
		return nil, nil, err
	}

	client := s.resendHTTPClient(params)
	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("resend request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxReplayResponseSize))
	if err != nil {
		return nil, nil, fmt.Errorf("read resend response body: %w", err)
	}
	duration := time.Since(start)

	if err := s.recordResendFlow(ctx, prep, params, httpReq, resp, respBody, start, duration); err != nil {
		return nil, nil, err
	}

	if params.Hooks != nil && params.Hooks.PostReceive != nil {
		state := &hookState{}
		executor := newHookExecutor(s.deps, params.Hooks, state)
		if err := executor.executePostReceive(ctx, resp.StatusCode, respBody, prep.kvStore); err != nil {
			return nil, nil, err
		}
	}

	respBodyStr, respBodyEncoding := encodeBody(respBody)
	return nil, &resendActionResult{
		NewFlowID: prep.flow.ID, StatusCode: resp.StatusCode,
		ResponseHeaders: copyHeaders(resp.Header), ResponseBody: respBodyStr,
		ResponseBodyEncoding: respBodyEncoding, DurationMs: duration.Milliseconds(),
		Tag: params.Tag,
	}, nil
}

// buildHTTPRequest creates an *http.Request from the prepared resend state.
func (s *Server) buildHTTPRequest(ctx context.Context, prep *resendPrepared) (*http.Request, error) {
	var body io.Reader
	if len(prep.body) > 0 {
		body = bytes.NewReader(prep.body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, prep.method, prep.url.String(), body)
	if err != nil {
		return nil, fmt.Errorf("create resend request: %w", err)
	}

	applyHeaders(httpReq, prep.headers)
	return httpReq, nil
}

// applyHeaders sets the headers on the HTTP request, preserving multi-value headers.
// When the Host header is set, it also updates req.Host because Go's net/http
// ignores the Host key in req.Header and uses req.Host exclusively.
func applyHeaders(req *http.Request, headers map[string][]string) {
	for key, values := range headers {
		if len(values) == 0 {
			req.Header[key] = values
			continue
		}
		for i, v := range values {
			if i == 0 {
				req.Header.Set(key, v)
			} else {
				req.Header.Add(key, v)
			}
		}
		// Go's net/http ignores the "Host" key in req.Header and uses
		// req.Host instead (mapped to :authority in HTTP/2).
		if http.CanonicalHeaderKey(key) == "Host" && len(values) > 0 {
			req.Host = values[0]
		}
	}
}

// copyHeaders creates a shallow copy of HTTP headers.
func copyHeaders(src http.Header) map[string][]string {
	result := make(map[string][]string)
	for key, values := range src {
		result[key] = values
	}
	return result
}

// recordResendFlow saves the resend flow and its send/receive messages to the store.
func (s *Server) recordResendFlow(ctx context.Context, prep *resendPrepared, params resendParams, httpReq *http.Request, resp *http.Response, respBody []byte, start time.Time, duration time.Duration) error {
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol: prep.flow.Protocol, FlowType: "unary", State: "complete",
		Timestamp: start, Duration: duration, Tags: tags,
	}
	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return fmt.Errorf("save resend flow: %w", err)
	}

	// Update prep.flow.ID to the new flow ID for the result.
	prep.flow = newFl

	recordedHeaders := make(map[string][]string)
	for key, values := range httpReq.Header {
		recordedHeaders[key] = values
	}

	newSendMsg := &flow.Message{
		FlowID: newFl.ID, Sequence: 0, Direction: "send",
		Timestamp: start, Method: prep.method, URL: prep.url,
		Headers: recordedHeaders, Body: prep.body,
	}
	if err := s.deps.store.AppendMessage(ctx, newSendMsg); err != nil {
		return fmt.Errorf("save resend send message: %w", err)
	}

	respHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		respHeaders[key] = values
	}

	newRecvMsg := &flow.Message{
		FlowID: newFl.ID, Sequence: 1, Direction: "receive",
		Timestamp: start.Add(duration), StatusCode: resp.StatusCode,
		Headers: respHeaders, Body: respBody,
	}
	if err := s.deps.store.AppendMessage(ctx, newRecvMsg); err != nil {
		return fmt.Errorf("save resend receive message: %w", err)
	}
	return nil
}

// --- Resend helper functions ---

func buildResendBody(originalBody []byte, params resendParams) ([]byte, error) {
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

func validateResendHeaders(params resendParams) error {
	if err := validateHeaderEntries(params.OverrideHeaders); err != nil {
		return fmt.Errorf("override_headers: %w", err)
	}
	if err := validateHeaderEntries(params.AddHeaders); err != nil {
		return fmt.Errorf("add_headers: %w", err)
	}
	if err := validateHeaderKeys(params.RemoveHeaders); err != nil {
		return fmt.Errorf("remove_headers: %w", err)
	}
	return nil
}

func buildResendHeaders(originalHeaders map[string][]string, params resendParams) map[string][]string {
	headers := make(map[string][]string)
	for key, values := range originalHeaders {
		cp := make([]string, len(values))
		copy(cp, values)
		headers[key] = cp
	}
	for _, key := range params.RemoveHeaders {
		headers[http.CanonicalHeaderKey(key)] = []string{}
	}
	// OverrideHeaders: collect all values per canonical key, replacing any original values.
	overrideGroups := groupHeaderEntries(params.OverrideHeaders)
	for canonical, values := range overrideGroups {
		headers[canonical] = values
	}
	for _, entry := range params.AddHeaders {
		canonical := http.CanonicalHeaderKey(entry.Key)
		headers[canonical] = append(headers[canonical], entry.Value)
	}
	return headers
}

// groupHeaderEntries groups HeaderEntries by canonical header key,
// preserving the order of values for each key.
func groupHeaderEntries(entries HeaderEntries) map[string][]string {
	if len(entries) == 0 {
		return nil
	}
	result := make(map[string][]string)
	for _, entry := range entries {
		canonical := http.CanonicalHeaderKey(entry.Key)
		result[canonical] = append(result[canonical], entry.Value)
	}
	return result
}

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

func (s *Server) resendHTTPClient(params resendParams) httpDoer {
	if s.deps.replayDoer != nil {
		return s.deps.replayDoer
	}
	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if params.OverrideHost != "" {
				addr = params.OverrideHost
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	// Use uTLS transport for HTTPS connections if configured.
	if s.deps.tlsTransport != nil {
		tlsT := s.deps.tlsTransport
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if params.OverrideHost != "" {
				addr = params.OverrideHost
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn, _, err := tlsT.TLSConnect(ctx, rawConn, host)
			if err != nil {
				rawConn.Close()
				return nil, err
			}
			// Wrap the connection so http.Transport can detect TLS and
			// populate resp.TLS via ConnectionState() tls.ConnectionState.
			return httputil.WrapTLSConn(tlsConn), nil
		}
	}
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if params.FollowRedirects != nil && *params.FollowRedirects {
		checkRedirect = targetScopeCheckRedirect(s.deps.targetScope)
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: checkRedirect}
}

// --- Resend raw ---

type resendRawResult struct {
	NewFlowID    string `json:"new_flow_id,omitempty"`
	ResponseData string `json:"response_data"`
	ResponseSize int    `json:"response_size"`
	DurationMs   int64  `json:"duration_ms"`
	Tag          string `json:"tag,omitempty"`
}

type resendRawDryRunResult struct {
	DryRun     bool        `json:"dry_run"`
	RawPreview *rawPreview `json:"raw_preview"`
}

type rawPreview struct {
	DataBase64     string `json:"data_base64"`
	DataSize       int    `json:"data_size"`
	PatchesApplied int    `json:"patches_applied"`
}

func (s *Server) handleResendActionRaw(ctx context.Context, params resendParams) (*gomcp.CallToolResult, any, error) {
	fl, sendMsg, err := s.loadRawResendFlow(ctx, params)
	if err != nil {
		return nil, nil, err
	}

	rawBytes, patchCount, err := buildResendRawBytes(sendMsg.RawBytes, params)
	if err != nil {
		return nil, nil, err
	}

	if params.DryRun {
		return nil, &resendRawDryRunResult{
			DryRun: true,
			RawPreview: &rawPreview{
				DataBase64: base64.StdEncoding.EncodeToString(rawBytes),
				DataSize:   len(rawBytes), PatchesApplied: patchCount,
			},
		}, nil
	}

	targetAddr, err := resolveTargetAddrRaw(sendMsg, params)
	if err != nil {
		return nil, nil, err
	}

	if err := s.checkRawTargetScope(fl, targetAddr); err != nil {
		return nil, nil, err
	}

	respData, start, duration, err := s.buildAndSendRaw(ctx, fl, params, targetAddr, rawBytes)
	if err != nil {
		return nil, nil, err
	}

	newFlowID, err := s.recordRawResend(ctx, fl, params, rawBytes, respData, start, duration)
	if err != nil {
		return nil, nil, err
	}

	return nil, &resendRawResult{
		NewFlowID:    newFlowID,
		ResponseData: base64.StdEncoding.EncodeToString(respData),
		ResponseSize: len(respData), DurationMs: duration.Milliseconds(),
		Tag: params.Tag,
	}, nil
}

// loadRawResendFlow validates parameters, loads the flow and its first send message,
// and checks the target scope for the URL.
func (s *Server) loadRawResendFlow(ctx context.Context, params resendParams) (*flow.Flow, *flow.Message, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}
	if params.FlowID == "" {
		return nil, nil, fmt.Errorf("flow_id is required for resend_raw action")
	}

	fl, err := s.deps.store.GetFlow(ctx, params.FlowID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	sendMsgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("flow %s has no send messages", params.FlowID)
	}
	sendMsg := sendMsgs[0]

	if len(sendMsg.RawBytes) == 0 && params.OverrideRawBase64 == "" {
		return nil, nil, fmt.Errorf("flow %s has no raw request bytes", params.FlowID)
	}

	if sendMsg.URL != nil {
		if err := s.checkTargetScopeURL(sendMsg.URL); err != nil {
			return nil, nil, err
		}
	}

	return fl, sendMsg, nil
}

// checkRawTargetScope checks target scope for a raw resend target address.
func (s *Server) checkRawTargetScope(fl *flow.Flow, targetAddr string) error {
	scheme := ""
	if fl.Protocol == "HTTPS" {
		scheme = "https"
	}
	return s.checkTargetScopeAddr(scheme, targetAddr)
}

// resolveTargetAddrRaw determines the target address for a raw resend from the
// send message URL or the explicit target_addr parameter.
func resolveTargetAddrRaw(sendMsg *flow.Message, params resendParams) (string, error) {
	if params.TargetAddr != "" {
		return params.TargetAddr, nil
	}
	if sendMsg.URL == nil {
		return "", fmt.Errorf("flow has no URL and no target_addr was provided")
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
	return net.JoinHostPort(host, port), nil
}

// buildAndSendRaw establishes a TCP/TLS connection, sends raw bytes, and reads the response.
func (s *Server) buildAndSendRaw(ctx context.Context, fl *flow.Flow, params resendParams, targetAddr string, rawBytes []byte) ([]byte, time.Time, time.Duration, error) {
	useTLS := fl.Protocol == "HTTPS"
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	}

	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}

	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, start, 0, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if useTLS {
		conn, err = upgradeTLS(ctx, conn, targetAddr, s.deps.tlsTransport)
		if err != nil {
			return nil, start, 0, err
		}
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, start, 0, fmt.Errorf("set connection deadline: %w", err)
	}
	if _, err := conn.Write(rawBytes); err != nil {
		return nil, start, 0, fmt.Errorf("send raw request: %w", err)
	}

	respData, err := io.ReadAll(io.LimitReader(conn, config.MaxReplayResponseSize))
	if err != nil && len(respData) == 0 {
		return nil, start, 0, fmt.Errorf("read raw response: %w", err)
	}
	duration := time.Since(start)

	return respData, start, duration, nil
}

// recordRawResend saves the raw resend flow and its send/receive messages.
func (s *Server) recordRawResend(ctx context.Context, fl *flow.Flow, params resendParams, rawBytes, respData []byte, start time.Time, duration time.Duration) (string, error) {
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol: fl.Protocol, FlowType: "unary", State: "complete",
		Timestamp: start, Duration: duration, Tags: tags,
	}
	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return "", fmt.Errorf("save resend_raw flow: %w", err)
	}

	if err := s.deps.store.AppendMessage(ctx, &flow.Message{
		FlowID: newFl.ID, Sequence: 0, Direction: "send",
		Timestamp: start, RawBytes: rawBytes,
	}); err != nil {
		return "", fmt.Errorf("save resend_raw send message: %w", err)
	}

	if err := s.deps.store.AppendMessage(ctx, &flow.Message{
		FlowID: newFl.ID, Sequence: 1, Direction: "receive",
		Timestamp: start.Add(duration), RawBytes: respData,
	}); err != nil {
		return "", fmt.Errorf("save resend_raw receive message: %w", err)
	}

	return newFl.ID, nil
}

func buildResendRawBytes(originalRaw []byte, params resendParams) ([]byte, int, error) {
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
	if len(params.Patches) > 0 {
		patched, err := applyRawPatches(originalRaw, params.Patches)
		if err != nil {
			return nil, 0, err
		}
		return patched, len(params.Patches), nil
	}
	return originalRaw, 0, nil
}
