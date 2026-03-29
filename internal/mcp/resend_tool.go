package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
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

// resendParams holds parameters for the resend tool actions (resend, resend_raw, tcp_replay, compare).
type resendParams struct {
	// FlowID identifies the flow to resend/replay.
	FlowID string `json:"flow_id,omitempty"`

	// FlowIDA identifies the first flow for the compare action.
	FlowIDA string `json:"flow_id_a,omitempty"`
	// FlowIDB identifies the second flow for the compare action.
	FlowIDB string `json:"flow_id_b,omitempty"`

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
var availableResendActions = []string{"resend", "resend_raw", "tcp_replay", "compare"}

// registerResend registers the resend MCP tool.
func (s *Server) registerResend() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "resend",
		Description: "Resend and replay recorded proxy requests with optional mutations, or compare two flows. " +
			"Available actions: " +
			"'resend' resends a recorded HTTP/HTTP2/WebSocket request with optional mutation (method/URL/header/body overrides, body patches, dry-run). " +
			"For WebSocket flows, use message_sequence to specify which message to resend as a raw TCP frame; " +
			"'resend_raw' resends raw bytes from a recorded flow over TCP/TLS with optional byte-level patches (offset overwrite, binary/text find-replace, override_raw_base64 full replacement, dry-run); " +
			"'tcp_replay' replays a Raw TCP flow by sending all 'send' messages sequentially to the target; " +
			"'compare' compares two flows structurally (status code, headers, body length, timing) for triage — use query tool for full details. " +
			"('replay' is a deprecated alias for 'resend'; 'replay_raw' is a deprecated alias for 'resend_raw'). " +
			"For flow management (delete/export/import), use the 'manage' tool. " +
			"For fuzzing, use the 'fuzz' tool. " +
			"For macro operations, use the 'macro' tool. " +
			"For intercept queue actions, use the 'intercept' tool.",
	}, s.handleResend)
}

// hasModifications reports whether any mutation field is set on the resend params.
func (p *resendParams) hasModifications() bool {
	return p.OverrideMethod != "" ||
		p.OverrideURL != "" ||
		p.OverrideHeadersRaw != nil ||
		p.AddHeadersRaw != nil ||
		p.OverrideBody != nil ||
		p.OverrideBodyBase64 != nil ||
		len(p.RemoveHeaders) > 0 ||
		len(p.BodyPatches) > 0 ||
		p.OverrideHost != "" ||
		p.OverrideRawBase64 != "" ||
		len(p.Patches) > 0
}

// handleResend routes the resend tool invocation to the appropriate action handler.
func (s *Server) handleResend(ctx context.Context, _ *gomcp.CallToolRequest, input resendInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "resend",
		"action", input.Action,
		"flow_id", input.Params.FlowID,
		"has_modifications", input.Params.hasModifications(),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "resend",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

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
	case "compare":
		return s.handleCompare(ctx, compareParams{
			FlowIDA: input.Params.FlowIDA,
			FlowIDB: input.Params.FlowIDB,
		})
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availableResendActions, ", "))
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
	headers parser.RawHeaders
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

	// SafetyFilter input check: block destructive payloads before sending.
	// Skipped for dry-run since no actual request is sent.
	if v := s.checkSafetyInput(prep.body, prep.url.String(), prep.headers); v != nil {
		return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
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

	// Reject follow_redirects: the UpstreamRouter does not support redirect
	// following (the old net/http.Client path was removed). Fail explicitly
	// rather than silently ignoring the parameter.
	if params.FollowRedirects != nil && *params.FollowRedirects {
		return nil, nil, nil, fmt.Errorf("follow_redirects is not supported: the resend transport does not implement redirect following")
	}

	if err := validateHooks(params.Hooks); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hooks: %w", err)
	}

	fl, err := s.deps.store.GetFlow(ctx, params.FlowID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get flow: %w", err)
	}

	if err := checkResendProtocolSupport(fl); err != nil {
		return nil, nil, nil, err
	}

	kvStore, err := s.executePreSendHook(ctx, params)
	if err != nil {
		return nil, nil, nil, err
	}

	if fl.Protocol == "WebSocket" {
		r1, r2, err := s.handleWebSocketResend(ctx, fl, *params)
		return nil, r1, r2, err
	}

	sendMsg, reqBody, err := s.loadResendSendData(ctx, fl, *params)
	if err != nil {
		return nil, nil, nil, err
	}

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

// loadResendSendData loads send messages from the store, validates gRPC-specific
// constraints, and builds the request body. For gRPC flows, the body is
// reconstructed from data frame messages (sequence 1+).
func (s *Server) loadResendSendData(ctx context.Context, fl *flow.Flow, params resendParams) (*flow.Message, []byte, error) {
	sendMsgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("flow %s has no send messages", params.FlowID)
	}
	sendMsg := sendMsgs[0]

	// Reject body_patches for gRPC flows: protobuf decode/re-encode is not yet supported.
	if isGRPCFlow(fl.Protocol) && len(params.BodyPatches) > 0 {
		return nil, nil, fmt.Errorf("body_patches is not yet supported for gRPC flows")
	}

	// For gRPC flows, reconstruct the request body from data frame messages
	// (sequence 1+), since sequence 0 is the header-only message.
	var originalBody []byte
	if isGRPCFlow(fl.Protocol) && len(sendMsgs) > 1 {
		originalBody = buildGRPCRequestBody(sendMsgs[1:])
	} else {
		originalBody = sendMsg.Body
	}

	reqBody, err := buildResendBody(originalBody, params)
	if err != nil {
		return nil, nil, err
	}

	return sendMsg, reqBody, nil
}

// checkResendProtocolSupport returns an error if the flow's protocol/type combination
// is not supported for resend. Currently gRPC streaming flows are unsupported.
func checkResendProtocolSupport(fl *flow.Flow) error {
	if isGRPCFlow(fl.Protocol) && fl.FlowType != "unary" {
		return fmt.Errorf("resending gRPC streaming flows (type: %s) is not yet supported; only unary gRPC flows can be resent", fl.FlowType)
	}
	return nil
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
func buildDryRunResult(method string, targetURL *url.URL, headers parser.RawHeaders, reqBody []byte) *resendDryRunResult {
	bodyStr, bodyEncoding := encodeBody(reqBody)
	previewHeaders := rawHeadersToMultiMap(headers)
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

// rawHeadersToMultiMap converts parser.RawHeaders to map[string][]string
// for JSON serialization in result types. Header names are canonicalized
// using http.CanonicalHeaderKey so that HTTP/2 lowercase names (e.g. "content-type")
// are normalized to the canonical form expected by consumers (e.g. "Content-Type").
func rawHeadersToMultiMap(headers parser.RawHeaders) map[string][]string {
	result := make(map[string][]string)
	for _, h := range headers {
		key := http.CanonicalHeaderKey(h.Name)
		result[key] = append(result[key], h.Value)
	}
	return result
}

// executeResend sends the HTTP request via UpstreamRouter and records the flow and messages.
func (s *Server) executeResend(ctx context.Context, prep *resendPrepared, params resendParams) (*gomcp.CallToolResult, any, error) {
	rawReq := s.buildRawRequest(prep)

	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}

	// Use a separate timeout context for the network round trip only.
	// The parent ctx is kept for flow recording and hooks so they do not fail
	// with "context deadline exceeded" if the upstream request consumes most
	// of the timeout budget.
	rtCtx, rtCancel := context.WithTimeout(ctx, timeout)
	defer rtCancel()

	// Determine target address and TLS settings from URL.
	addr, useTLS, hostname := resolveResendTarget(prep.url, params)

	router := s.resendUpstreamRouter(params)
	start := time.Now()
	rtResult, err := router.RoundTrip(rtCtx, rawReq, addr, useTLS, hostname)
	if err != nil {
		return nil, nil, fmt.Errorf("resend request: %w", err)
	}

	resp := rtResult.Response
	if resp == nil {
		return nil, nil, fmt.Errorf("resend request: upstream returned nil response")
	}

	// Defer body close to prevent connection leak if ReadAll fails.
	// The UpstreamRouter wraps the body with connClosingReader that closes the
	// underlying connection when the body is closed or fully read.
	if resp.Body != nil {
		if closer, ok := resp.Body.(io.Closer); ok {
			defer closer.Close()
		}
	}

	var respBody []byte
	if resp.Body != nil {
		respBody, err = io.ReadAll(io.LimitReader(resp.Body, config.MaxReplayResponseSize))
		if err != nil {
			return nil, nil, fmt.Errorf("read resend response body: %w", err)
		}
	}
	duration := time.Since(start)

	// Recording and hooks use the parent ctx, not the round-trip timeout context.
	if err := s.recordResendFlowRaw(ctx, prep, params, rawReq, resp, respBody, start, duration); err != nil {
		return nil, nil, err
	}

	if params.Hooks != nil && params.Hooks.PostReceive != nil {
		state := &hookState{}
		executor := newHookExecutor(s.deps, params.Hooks, state)
		if err := executor.executePostReceive(ctx, resp.StatusCode, respBody, prep.kvStore); err != nil {
			return nil, nil, err
		}
	}

	// Apply SafetyFilter output masking before returning to AI agent.
	// Raw data is already saved to the store above.
	maskedBody := s.filterOutputBody(respBody)
	maskedHeaders := s.filterOutputRawHeaders(resp.Headers)

	respBodyStr, respBodyEncoding := encodeBody(maskedBody)
	return nil, &resendActionResult{
		NewFlowID: prep.flow.ID, StatusCode: resp.StatusCode,
		ResponseHeaders: rawHeadersToMultiMap(maskedHeaders), ResponseBody: respBodyStr,
		ResponseBodyEncoding: respBodyEncoding, DurationMs: duration.Milliseconds(),
		Tag: params.Tag,
	}, nil
}

// buildRawRequest creates a *parser.RawRequest from the prepared resend state.
func (s *Server) buildRawRequest(prep *resendPrepared) *parser.RawRequest {
	var body io.Reader
	if len(prep.body) > 0 {
		body = bytes.NewReader(prep.body)
	}

	// Build the request URI in origin-form (path+query). url.URL.RequestURI()
	// returns the path?query portion, which is origin-form per RFC 7230 Section 5.3.1.
	requestURI := prep.url.RequestURI()

	headers := prep.headers.Clone()

	// Ensure Host header is present. HTTP/1.1 requires it, and the old
	// net/http.Client would set it automatically from the URL.
	if headers.Get("Host") == "" && prep.url.Host != "" {
		headers = append(parser.RawHeaders{{Name: "Host", Value: prep.url.Host}}, headers...)
	}

	// Structured resend always has the full body in memory, so Content-Length
	// is the correct framing mechanism. Remove Transfer-Encoding (the
	// H1Transport writes body bytes verbatim without chunked encoding, so
	// keeping TE: chunked would produce an invalid request — TE-1 fix).
	// Users who need chunked encoding or mismatched Content-Length (e.g. for
	// request smuggling tests) should use resend_raw.
	headers.Del("Transfer-Encoding")
	headers.Del("Content-Length")
	if len(prep.body) > 0 {
		headers.Set("Content-Length", fmt.Sprintf("%d", len(prep.body)))
	}

	return &parser.RawRequest{
		Method:     prep.method,
		RequestURI: requestURI,
		Proto:      "HTTP/1.1",
		Headers:    headers,
		Body:       body,
	}
}

// resolveResendTarget extracts the target address, TLS flag, and hostname
// from the URL and override_host parameter.
func resolveResendTarget(u *url.URL, params resendParams) (addr string, useTLS bool, hostname string) {
	useTLS = u.Scheme == "https"
	hostname = u.Hostname()
	port := u.Port()
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr = net.JoinHostPort(hostname, port)

	// Override host routes to a different address while preserving Host header.
	if params.OverrideHost != "" {
		addr = params.OverrideHost
		// Extract hostname from override for TLS SNI.
		if h, _, err := net.SplitHostPort(params.OverrideHost); err == nil {
			hostname = h
		}
	}

	return addr, useTLS, hostname
}

// recordResendFlowRaw saves the resend flow and its send/receive messages to the store.
// It works with parser.RawRequest/RawResponse from the UpstreamRouter.
func (s *Server) recordResendFlowRaw(ctx context.Context, prep *resendPrepared, params resendParams, rawReq *parser.RawRequest, resp *parser.RawResponse, respBody []byte, start time.Time, duration time.Duration) error {
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol: prep.flow.Protocol, Scheme: prep.flow.Scheme,
		FlowType: "unary", State: "complete",
		Timestamp: start, Duration: duration, Tags: tags,
	}
	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return fmt.Errorf("save resend flow: %w", err)
	}

	// Update prep.flow.ID to the new flow ID for the result.
	prep.flow = newFl

	newSendMsg := &flow.Message{
		FlowID: newFl.ID, Sequence: 0, Direction: "send",
		Timestamp: start, Method: prep.method, URL: prep.url,
		Headers: rawHeadersToMultiMap(rawReq.Headers), Body: prep.body,
	}
	if err := s.deps.store.AppendMessage(ctx, newSendMsg); err != nil {
		return fmt.Errorf("save resend send message: %w", err)
	}

	newRecvMsg := &flow.Message{
		FlowID: newFl.ID, Sequence: 1, Direction: "receive",
		Timestamp: start.Add(duration), StatusCode: resp.StatusCode,
		Headers: rawHeadersToMultiMap(resp.Headers), Body: respBody,
	}
	if err := s.deps.store.AppendMessage(ctx, newRecvMsg); err != nil {
		return fmt.Errorf("save resend receive message: %w", err)
	}

	// For gRPC flows, record trailers from the response headers.
	// Structured resend uses the H1 transport path, so gRPC trailers
	// (grpc-status, grpc-message) arrive as regular HTTP/1.x trailing headers
	// merged into the response headers. Detect them to build a separate
	// trailers message for format compatibility with native gRPC flows.
	if isGRPCFlow(prep.flow.Protocol) {
		grpcStatus := resp.Headers.Get("Grpc-Status")
		grpcMessage := resp.Headers.Get("Grpc-Message")
		if grpcStatus != "" {
			trailerMeta := map[string]string{
				"grpc_type": "trailers",
			}
			if prep.url != nil {
				parts := strings.SplitN(strings.TrimPrefix(prep.url.Path, "/"), "/", 2)
				if len(parts) == 2 {
					trailerMeta["service"] = parts[0]
					trailerMeta["method"] = parts[1]
				}
			}
			trailerMeta["grpc_status"] = grpcStatus
			if grpcMessage != "" {
				trailerMeta["grpc_message"] = grpcMessage
			}
			// Build trailer headers from response trailer fields.
			var trailerHeaders parser.RawHeaders
			for _, h := range resp.Headers {
				lower := strings.ToLower(h.Name)
				if lower == "grpc-status" || lower == "grpc-message" || lower == "grpc-status-details-bin" {
					trailerHeaders = append(trailerHeaders, h)
				}
			}
			trailerMsg := &flow.Message{
				FlowID:     newFl.ID,
				Sequence:   newRecvMsg.Sequence + 1,
				Direction:  "receive",
				Timestamp:  start.Add(duration),
				StatusCode: resp.StatusCode,
				Headers:    rawHeadersToMultiMap(trailerHeaders),
				Metadata:   trailerMeta,
			}
			if err := s.deps.store.AppendMessage(ctx, trailerMsg); err != nil {
				return fmt.Errorf("save resend gRPC trailers message: %w", err)
			}
		}
	}

	return nil
}

// isGRPCFlow reports whether the protocol string indicates a gRPC flow,
// including SOCKS5-tunneled gRPC flows.
func isGRPCFlow(protocol string) bool {
	return protocol == "gRPC" || protocol == "SOCKS5+gRPC"
}

// --- Resend helper functions ---

// buildGRPCRequestBody reconstructs the gRPC request body from data frame
// messages (sequence 1+). Each message's Body contains the raw protobuf
// payload, which is re-encoded into gRPC length-prefixed frames.
func buildGRPCRequestBody(dataMessages []*flow.Message) []byte {
	var buf bytes.Buffer
	for _, msg := range dataMessages {
		if len(msg.Body) == 0 {
			continue
		}
		compressed := msg.Metadata["compressed"] == "true"
		frame := protogrpc.EncodeFrame(compressed, msg.Body)
		buf.Write(frame)
	}
	return buf.Bytes()
}

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

func buildResendHeaders(originalHeaders map[string][]string, params resendParams) parser.RawHeaders {
	// Build a set of headers to remove (case-insensitive).
	removeSet := make(map[string]bool, len(params.RemoveHeaders))
	for _, key := range params.RemoveHeaders {
		removeSet[strings.ToLower(key)] = true
	}

	// Build a set of headers overridden by OverrideHeaders (case-insensitive).
	overrideSet := make(map[string]bool)
	for _, entry := range params.OverrideHeaders {
		overrideSet[strings.ToLower(entry.Key)] = true
	}

	// Copy original headers, skipping removed and overridden ones.
	var headers parser.RawHeaders
	for key, values := range originalHeaders {
		lower := strings.ToLower(key)
		if removeSet[lower] || overrideSet[lower] {
			continue
		}
		for _, v := range values {
			headers = append(headers, parser.RawHeader{Name: key, Value: v})
		}
	}

	// Add override headers.
	for _, entry := range params.OverrideHeaders {
		headers = append(headers, parser.RawHeader{Name: entry.Key, Value: entry.Value})
	}

	// Add additional headers.
	for _, entry := range params.AddHeaders {
		headers = append(headers, parser.RawHeader{Name: entry.Key, Value: entry.Value})
	}

	return headers
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

// resendRouter abstracts upstream round-trip for the resend tool, enabling
// test injection without net/http dependency.
type resendRouter interface {
	RoundTrip(ctx context.Context, req *parser.RawRequest, addr string, useTLS bool, hostname string) (*httputil.RoundTripResult, error)
}

// resendUpstreamRouter returns the upstream router for the resend tool.
// If a test-injected replayRouter is set, it is returned; otherwise a new
// UpstreamRouter is constructed using the configured TLS transport.
//
// A new ConnPool is created per call intentionally — resend is a low-frequency
// diagnostic operation and connection reuse across resends is not needed (YAGNI).
// AllowH2 is true so that the upstream can negotiate h2 when required (e.g. gRPC).
func (s *Server) resendUpstreamRouter(_ resendParams) resendRouter {
	if s.deps.replayRouter != nil {
		return s.deps.replayRouter
	}
	pool := &httputil.ConnPool{
		// Use the user's configured TLS transport as-is (including uTLS fingerprint
		// profiles). AllowH2 enables ALPN negotiation for both http/1.1 and h2,
		// allowing gRPC flows to be resent to h2-only upstreams.
		TLSTransport: s.deps.tlsTransport,
		AllowH2:      true,
	}
	return &protohttp.UpstreamRouter{
		H1:   &httputil.H1Transport{},
		H2:   &http2.Transport{},
		Pool: pool,
	}
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
	// Validate hooks before loading the flow.
	if err := validateHooks(params.Hooks); err != nil {
		return nil, nil, fmt.Errorf("invalid hooks: %w", err)
	}

	fl, sendMsg, err := s.loadRawResendFlow(ctx, params)
	if err != nil {
		return nil, nil, err
	}

	// Execute pre-send hook. Template expansion is not applied to raw bytes
	// (L4 operation — expanding templates would corrupt binary protocol framing).
	kvStore, err := s.executeRawPreSendHook(ctx, &params)
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

	// SafetyFilter input check: validate raw bytes before sending.
	if v := s.checkSafetyInput(rawBytes, "", nil); v != nil {
		return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
	}

	respData, newFlowID, duration, err := s.sendAndRecordRaw(ctx, fl, params, sendMsg, rawBytes)
	if err != nil {
		return nil, nil, err
	}

	// Execute post-receive hook if configured.
	if params.Hooks != nil && params.Hooks.PostReceive != nil {
		state := &hookState{}
		executor := newHookExecutor(s.deps, params.Hooks, state)
		// Raw mode does not have a structured status code; pass 0.
		if err := executor.executePostReceive(ctx, 0, respData, kvStore); err != nil {
			return nil, nil, err
		}
	}

	// Apply SafetyFilter output masking before returning to AI agent.
	// Raw data is already saved to the store above.
	maskedResp := s.filterOutputBody(respData)

	return nil, &resendRawResult{
		NewFlowID:    newFlowID,
		ResponseData: base64.StdEncoding.EncodeToString(maskedResp),
		ResponseSize: len(respData), DurationMs: duration.Milliseconds(),
		Tag: params.Tag,
	}, nil
}

// executeRawPreSendHook runs the pre-send hook for raw resend.
// Unlike the structured mode, template expansion is NOT applied to raw bytes.
// Raw mode operates at L4 (wire bytes) and expanding templates would corrupt
// binary protocol framing (HTTP/2, WebSocket, etc.). The KV Store is still
// returned so it can be passed to the post-receive hook.
func (s *Server) executeRawPreSendHook(ctx context.Context, params *resendParams) (map[string]string, error) {
	if params.Hooks == nil || params.Hooks.PreSend == nil {
		return nil, nil
	}

	state := &hookState{}
	executor := newHookExecutor(s.deps, params.Hooks, state)
	kvStore, err := executor.executePreSend(ctx)
	if err != nil {
		return nil, err
	}

	return kvStore, nil
}

// sendAndRecordRaw handles target resolution, scope checking, sending raw bytes,
// and recording the flow. It returns the response data, new flow ID, and duration.
func (s *Server) sendAndRecordRaw(ctx context.Context, fl *flow.Flow, params resendParams, sendMsg *flow.Message, rawBytes []byte) ([]byte, string, time.Duration, error) {
	targetAddr, err := resolveTargetAddrRaw(sendMsg, params)
	if err != nil {
		return nil, "", 0, err
	}

	// Determine useTLS for scope checking and connection establishment.
	// For HTTP/2 flows, infer from flow TLS metadata; for others, use protocol name.
	useTLS := fl.Protocol == "HTTPS"
	if isHTTP2Protocol(fl.Protocol) {
		useTLS = inferFlowUseTLS(fl)
	}
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	}

	if err := s.checkRawTargetScope(fl, targetAddr, useTLS); err != nil {
		return nil, "", 0, err
	}

	// Route to the appropriate raw send implementation based on protocol.
	var respData []byte
	var start time.Time
	var duration time.Duration
	if isHTTP2Protocol(fl.Protocol) {
		respData, start, duration, err = s.buildAndSendRawH2(ctx, fl, params, targetAddr, rawBytes)
	} else {
		respData, start, duration, err = s.buildAndSendRaw(ctx, fl, params, targetAddr, rawBytes)
	}
	if err != nil {
		return nil, "", 0, err
	}

	newFlowID, err := s.recordRawResend(ctx, fl, params, rawBytes, respData, start, duration)
	if err != nil {
		return nil, "", 0, err
	}

	return respData, newFlowID, duration, nil
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
// useTLS indicates whether the connection will use TLS, which determines the
// scheme used for scope matching. For HTTP/2 flows this may be false (h2c).
func (s *Server) checkRawTargetScope(fl *flow.Flow, targetAddr string, useTLS bool) error {
	scheme := ""
	if fl.Protocol == "HTTPS" || useTLS {
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

// isHTTP1Protocol reports whether the protocol string indicates an HTTP/1.x flow.
// It handles the SOCKS5+ prefix (e.g., "SOCKS5+HTTP", "SOCKS5+HTTPS") used for
// flows captured through the SOCKS5 proxy listener.
func isHTTP1Protocol(protocol string) bool {
	protocol = strings.TrimPrefix(protocol, "SOCKS5+")
	return protocol == "HTTP" || protocol == "HTTPS" || strings.HasPrefix(protocol, "HTTP/1")
}

// buildAndSendRaw establishes a TCP/TLS connection, sends raw bytes, and reads the response.
// For HTTP/1.x flows, it uses http.ReadResponse to correctly detect the end of the response,
// avoiding indefinite blocking when the server uses keep-alive connections.
// For other protocols (Raw TCP, WebSocket), it falls back to io.ReadAll.
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

	var respData []byte
	if isHTTP1Protocol(fl.Protocol) {
		respData, err = readHTTP1RawResponse(conn, rawBytes)
	} else {
		respData, err = io.ReadAll(io.LimitReader(conn, config.MaxReplayResponseSize))
	}
	if err != nil && len(respData) == 0 {
		return nil, start, 0, fmt.Errorf("read raw response: %w", err)
	}
	duration := time.Since(start)

	return respData, start, duration, nil
}

// readHTTP1RawResponse reads an HTTP/1.x response from conn using http.ReadResponse
// to correctly detect message boundaries (Content-Length, chunked transfer encoding,
// Connection: close). A TeeReader captures the wire-observed raw bytes for L4-capable
// recording. The request method is inferred from rawBytes to handle HEAD responses
// (which have no body despite Content-Length).
func readHTTP1RawResponse(conn net.Conn, rawBytes []byte) ([]byte, error) {
	// Parse the request method from raw bytes so http.ReadResponse can handle
	// HEAD responses correctly (no body even if Content-Length is present).
	req, _ := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawBytes)))

	// If ReadRequest failed but the raw bytes contain a HEAD request,
	// construct a minimal request so ReadResponse skips the body.
	if req == nil {
		if method := extractHTTPMethod(rawBytes); strings.EqualFold(method, "HEAD") {
			req = &http.Request{Method: "HEAD"}
		}
	}

	var rawBuf bytes.Buffer
	br := bufio.NewReader(io.TeeReader(
		io.LimitReader(conn, config.MaxReplayResponseSize),
		&rawBuf,
	))

	// Loop to skip 1xx informational responses (except 101 Switching Protocols).
	// The TeeReader accumulates all raw bytes including 1xx responses in rawBuf.
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			// If parsing fails, return whatever raw bytes were captured so far.
			if rawBuf.Len() > 0 {
				return rawBuf.Bytes(), fmt.Errorf("parse HTTP response: %w", err)
			}
			return nil, fmt.Errorf("parse HTTP response: %w", err)
		}

		// 101 Switching Protocols is a final response (e.g. WebSocket upgrade).
		if resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			defer resp.Body.Close()
			// Drain the body to ensure TeeReader captures all bytes.
			_, err = io.Copy(io.Discard, resp.Body)
			if err != nil {
				return rawBuf.Bytes(), fmt.Errorf("read HTTP response body: %w", err)
			}
			return rawBuf.Bytes(), nil
		}

		// 1xx informational response: drain body and continue to next response.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// extractHTTPMethod extracts the HTTP method from the first line of raw request bytes.
func extractHTTPMethod(rawBytes []byte) string {
	// Find the first space to extract the method from "METHOD /path HTTP/1.1\r\n".
	if idx := bytes.IndexByte(rawBytes, ' '); idx > 0 {
		return string(rawBytes[:idx])
	}
	return ""
}

// recordRawResend saves the raw resend flow and its send/receive messages.
func (s *Server) recordRawResend(ctx context.Context, fl *flow.Flow, params resendParams, rawBytes, respData []byte, start time.Time, duration time.Duration) (string, error) {
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol: fl.Protocol, Scheme: fl.Scheme,
		FlowType: "unary", State: "complete",
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
