package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// interceptInput is the typed input for the intercept tool.
type interceptInput struct {
	// Action specifies the intercept action to execute.
	// Available actions: release, modify_and_forward, drop.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params interceptParams `json:"params"`
}

// interceptParams holds the union of all intercept action-specific parameters.
// Only the fields relevant to the specified action are used.
type interceptParams struct {
	// InterceptID is the intercepted request/response ID (required for all actions).
	InterceptID string `json:"intercept_id,omitempty" jsonschema:"intercepted request/response ID for release/modify_and_forward/drop"`

	// Mode selects the forwarding mode: "structured" (default, L7 modifications)
	// or "raw" (send raw bytes directly, bypassing L7 serialization).
	// When mode is "raw", all L7 override fields are ignored and
	// raw_override_base64 is used instead.
	Mode string `json:"mode,omitempty" jsonschema:"forwarding mode: structured (default) or raw"`

	// RawOverrideBase64 is the Base64-encoded raw bytes to send when mode is "raw".
	// This replaces the entire request/response on the wire. Mutually exclusive
	// with L7 modification fields.
	RawOverrideBase64 *string `json:"raw_override_base64,omitempty" jsonschema:"Base64-encoded raw bytes for raw mode forwarding"`

	// --- Request modify_and_forward mutation parameters (mode=structured) ---
	OverrideMethod  string            `json:"override_method,omitempty" jsonschema:"HTTP method override (request phase, structured mode)"`
	OverrideURL     string            `json:"override_url,omitempty" jsonschema:"URL override (request phase, structured mode)"`
	OverrideHeaders map[string]string `json:"override_headers,omitempty" jsonschema:"header overrides (request phase, structured mode)"`
	AddHeaders      map[string]string `json:"add_headers,omitempty" jsonschema:"headers to add (request phase, structured mode)"`
	RemoveHeaders   []string          `json:"remove_headers,omitempty" jsonschema:"headers to remove (request phase, structured mode)"`
	OverrideBody    *string           `json:"override_body,omitempty" jsonschema:"body override (request phase, structured mode)"`

	// --- Response modify_and_forward mutation parameters (mode=structured) ---
	//
	// Note: Response mutation fields (OverrideStatus, OverrideResponse*, OverrideResponseBody)
	// are intentionally outside the SafetyFilter scope. SafetyFilter targets outbound
	// destructive requests (body/URL/headers sent to upstream servers). Response
	// modifications only affect data returned to the proxy client and do not pose
	// the same server-side risk.
	OverrideStatus          int               `json:"override_status,omitempty" jsonschema:"HTTP status code override (response phase, structured mode)"`
	OverrideResponseHeaders map[string]string `json:"override_response_headers,omitempty" jsonschema:"response header overrides (response phase, structured mode)"`
	AddResponseHeaders      map[string]string `json:"add_response_headers,omitempty" jsonschema:"response headers to add (response phase, structured mode)"`
	RemoveResponseHeaders   []string          `json:"remove_response_headers,omitempty" jsonschema:"response headers to remove (response phase, structured mode)"`
	OverrideResponseBody    *string           `json:"override_response_body,omitempty" jsonschema:"response body override (response phase, structured mode)"`
}

// availableInterceptActions lists the valid action names for the intercept tool.
var availableInterceptActions = []string{"release", "modify_and_forward", "drop"}

// registerIntercept registers the intercept MCP tool.
func (s *Server) registerIntercept() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "intercept",
		Description: "Act on intercepted requests, responses, or WebSocket frames in the intercept queue. " +
			"Items have a 'phase' field: 'request' (pre-send), 'response' (post-receive), or 'websocket_frame' (WebSocket frame). " +
			"Available actions: " +
			"'release' forwards the intercepted item as-is (requires intercept_id); " +
			"'modify_and_forward' forwards with mutations — use request params (override_method, override_url, override_headers, add_headers, remove_headers, override_body) for request phase, " +
			"response params (override_status, override_response_headers, add_response_headers, remove_response_headers, override_response_body) for response phase, " +
			"override_body for websocket_frame phase to modify the payload (requires intercept_id); " +
			"'drop' discards the item returning 502 to the client or dropping the WebSocket frame (requires intercept_id). " +
			"Mode: 'mode' selects forwarding mode — 'structured' (default, L7 modifications) or 'raw' (bypass L7, send raw_override_base64 directly). " +
			"Raw mode requires raw_override_base64 for modify_and_forward; release with raw mode forwards original raw bytes as-is.",
	}, s.handleInterceptTool)
}

// executeInterceptResult is the structured output of intercept queue actions.
// It includes the intercepted item's data (with output filter applied) so the AI
// can see what it acted upon without a separate query call.
type executeInterceptResult struct {
	InterceptID string `json:"intercept_id"`
	Action      string `json:"action"`
	Status      string `json:"status"`

	// Phase indicates whether this was a "request", "response", or "websocket_frame" intercept.
	Phase string `json:"phase"`
	// Protocol is the protocol type: "http" or "websocket".
	Protocol string `json:"protocol"`
	// Method is the HTTP method (HTTP only).
	Method string `json:"method,omitempty"`
	// URL is the request URL (HTTP only).
	URL string `json:"url,omitempty"`
	// StatusCode is the HTTP status code (only set for response phase).
	StatusCode int `json:"status_code,omitempty"`
	// Headers are the request/response headers (output-filtered, HTTP only).
	Headers map[string][]string `json:"headers,omitempty"`
	// BodyEncoding indicates the encoding of the body/payload ("text" or "base64").
	BodyEncoding string `json:"body_encoding"`
	// Body is the request/response body or WebSocket payload (output-filtered, as text or Base64).
	Body string `json:"body"`

	// RawBytesAvailable indicates whether raw bytes are available for this item.
	RawBytesAvailable bool `json:"raw_bytes_available"`
	// RawBytesSize is the size in bytes of the raw captured data (0 if unavailable).
	RawBytesSize int `json:"raw_bytes_size,omitempty"`
	// RawBytesEncoding indicates the encoding of raw_bytes ("text", "base64", or empty).
	RawBytesEncoding string `json:"raw_bytes_encoding,omitempty"`
	// RawBytes is the raw captured bytes (output-filtered, as text or Base64).
	// Only populated when raw bytes are available.
	RawBytes string `json:"raw_bytes,omitempty"`

	// --- WebSocket frame metadata (phase=websocket_frame only) ---

	// Opcode is the WebSocket frame opcode name (e.g. "Text", "Binary").
	Opcode string `json:"opcode,omitempty"`
	// Direction is the frame direction: "client_to_server" or "server_to_client".
	Direction string `json:"direction,omitempty"`
	// FlowID is the WebSocket flow ID this frame belongs to.
	FlowID string `json:"flow_id,omitempty"`
	// UpgradeURL is the URL from the original WebSocket upgrade request.
	UpgradeURL string `json:"upgrade_url,omitempty"`
	// Sequence is the frame sequence number within the WebSocket connection.
	Sequence int64 `json:"sequence,omitempty"`
}

// handleInterceptTool routes the intercept tool invocation to the appropriate action handler.
func (s *Server) handleInterceptTool(ctx context.Context, _ *gomcp.CallToolRequest, input interceptInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "intercept",
		"action", input.Action,
		"intercept_id", input.Params.InterceptID,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "intercept",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableInterceptActions, ", "))
	case "release":
		return s.handleInterceptRelease(ctx, input.Params)
	case "modify_and_forward":
		return s.handleInterceptModifyAndForward(ctx, input.Params)
	case "drop":
		return s.handleInterceptDrop(ctx, input.Params)
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availableInterceptActions, ", "))
	}
}

// buildInterceptResult creates an executeInterceptResult from an intercepted item,
// applying output filtering to the body and headers before returning to the AI.
func (s *Server) buildInterceptResult(item *intercept.InterceptedRequest, action, status string) *executeInterceptResult {
	// Apply output filter to body.
	filteredBody := s.filterOutputBody(item.Body)
	bodyStr, bodyEncoding := encodeBody(filteredBody)

	result := &executeInterceptResult{
		InterceptID:  item.ID,
		Action:       action,
		Status:       status,
		Phase:        string(item.Phase),
		BodyEncoding: bodyEncoding,
		Body:         bodyStr,
	}

	if item.Phase == intercept.PhaseWebSocketFrame {
		result.Protocol = "websocket"
		result.Opcode = wsOpcodeNameFromInt(item.WSOpcode)
		result.Direction = item.WSDirection
		result.FlowID = item.WSFlowID
		result.UpgradeURL = item.WSUpgradeURL
		result.Sequence = item.WSSequence
	} else {
		result.Protocol = "http"
		result.Method = item.Method
		result.StatusCode = item.StatusCode
		if item.URL != nil {
			result.URL = item.URL.String()
		}
		// Apply output filter to headers.
		filteredHeaders := s.filterOutputHeaders(item.Headers)
		headers := make(map[string][]string)
		for k, vs := range filteredHeaders {
			headers[k] = vs
		}
		result.Headers = headers
	}

	// Include raw bytes if available.
	if len(item.RawBytes) > 0 {
		result.RawBytesAvailable = true
		result.RawBytesSize = len(item.RawBytes)
		filteredRaw := s.filterOutputBody(item.RawBytes)
		result.RawBytes, result.RawBytesEncoding = encodeBody(filteredRaw)
	}

	return result
}

// handleInterceptRelease handles the release action.
func (s *Server) handleInterceptRelease(_ context.Context, params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.deps.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for release action")
	}

	// Validate mode.
	mode, err := resolveReleaseMode(params.Mode)
	if err != nil {
		return nil, nil, fmt.Errorf("release: %w", err)
	}

	// Fetch the intercepted item before responding (Respond removes it from the queue).
	item, err := s.deps.interceptQueue.Get(params.InterceptID)
	if err != nil {
		return nil, nil, fmt.Errorf("release: %w", err)
	}

	// In raw mode release, validate that raw bytes are available.
	if mode == intercept.ModeRaw && len(item.RawBytes) == 0 {
		return nil, nil, fmt.Errorf("release: raw mode requested but no raw bytes available for this item")
	}

	action := intercept.InterceptAction{
		Type: intercept.ActionRelease,
		Mode: mode,
	}
	if err := s.deps.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("release: %w", err)
	}

	return nil, s.buildInterceptResult(item, "release", "released"), nil
}

// handleInterceptModifyAndForward handles the modify_and_forward action.
func (s *Server) handleInterceptModifyAndForward(_ context.Context, params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.deps.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for modify_and_forward action")
	}

	// Validate mode.
	mode, err := resolveReleaseMode(params.Mode)
	if err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	// Branch on mode.
	if mode == intercept.ModeRaw {
		return s.handleInterceptModifyAndForwardRaw(params)
	}
	return s.handleInterceptModifyAndForwardStructured(params)
}

// handleInterceptModifyAndForwardStructured handles modify_and_forward in structured (L7) mode.
func (s *Server) handleInterceptModifyAndForwardStructured(params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	// Validate request header params.
	if err := validateHeaderValues(params.OverrideHeaders); err != nil {
		return nil, nil, fmt.Errorf("override_headers: %w", err)
	}
	if err := validateHeaderValues(params.AddHeaders); err != nil {
		return nil, nil, fmt.Errorf("add_headers: %w", err)
	}
	if err := validateHeaderKeys(params.RemoveHeaders); err != nil {
		return nil, nil, fmt.Errorf("remove_headers: %w", err)
	}
	// Validate response header params.
	if err := validateHeaderValues(params.OverrideResponseHeaders); err != nil {
		return nil, nil, fmt.Errorf("override_response_headers: %w", err)
	}
	if err := validateHeaderValues(params.AddResponseHeaders); err != nil {
		return nil, nil, fmt.Errorf("add_response_headers: %w", err)
	}
	if err := validateHeaderKeys(params.RemoveResponseHeaders); err != nil {
		return nil, nil, fmt.Errorf("remove_response_headers: %w", err)
	}

	// SafetyFilter input check: validate modified request data before forwarding.
	if err := s.checkInterceptSafety(params); err != nil {
		return nil, nil, err
	}

	action := intercept.InterceptAction{
		Type:            intercept.ActionModifyAndForward,
		Mode:            intercept.ModeStructured,
		OverrideMethod:  params.OverrideMethod,
		OverrideURL:     params.OverrideURL,
		OverrideHeaders: params.OverrideHeaders,
		AddHeaders:      params.AddHeaders,
		RemoveHeaders:   params.RemoveHeaders,
		OverrideBody:    params.OverrideBody,
		// Response modification fields.
		OverrideStatus:          params.OverrideStatus,
		OverrideResponseHeaders: params.OverrideResponseHeaders,
		AddResponseHeaders:      params.AddResponseHeaders,
		RemoveResponseHeaders:   params.RemoveResponseHeaders,
		OverrideResponseBody:    params.OverrideResponseBody,
	}

	// Fetch the intercepted item before responding (Respond removes it from the queue).
	item, err := s.deps.interceptQueue.Get(params.InterceptID)
	if err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	if err := s.deps.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	return nil, s.buildInterceptResult(item, "modify_and_forward", "forwarded"), nil
}

// handleInterceptModifyAndForwardRaw handles modify_and_forward in raw bytes mode.
func (s *Server) handleInterceptModifyAndForwardRaw(params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if params.RawOverrideBase64 == nil {
		return nil, nil, fmt.Errorf("modify_and_forward: raw_override_base64 is required when mode is \"raw\"")
	}

	rawBytes, err := decodeRawOverride(*params.RawOverrideBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	if err := intercept.ValidateRawOverride(rawBytes); err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	action := intercept.InterceptAction{
		Type:        intercept.ActionModifyAndForward,
		Mode:        intercept.ModeRaw,
		RawOverride: rawBytes,
	}

	// Fetch the intercepted item before responding (Respond removes it from the queue).
	item, err := s.deps.interceptQueue.Get(params.InterceptID)
	if err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	if err := s.deps.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	return nil, s.buildInterceptResult(item, "modify_and_forward", "forwarded_raw"), nil
}

// handleInterceptDrop handles the drop action.
func (s *Server) handleInterceptDrop(_ context.Context, params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.deps.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for drop action")
	}

	// Fetch the intercepted item before responding (Respond removes it from the queue).
	item, err := s.deps.interceptQueue.Get(params.InterceptID)
	if err != nil {
		return nil, nil, fmt.Errorf("drop: %w", err)
	}

	action := intercept.InterceptAction{
		Type: intercept.ActionDrop,
	}
	if err := s.deps.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("drop: %w", err)
	}

	return nil, s.buildInterceptResult(item, "drop", "dropped"), nil
}
