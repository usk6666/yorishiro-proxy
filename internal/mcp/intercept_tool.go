package mcp

import (
	"context"
	"fmt"
	"strings"

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

	// --- Request modify_and_forward mutation parameters ---
	OverrideMethod  string            `json:"override_method,omitempty" jsonschema:"HTTP method override (request phase)"`
	OverrideURL     string            `json:"override_url,omitempty" jsonschema:"URL override (request phase)"`
	OverrideHeaders map[string]string `json:"override_headers,omitempty" jsonschema:"header overrides (request phase)"`
	AddHeaders      map[string]string `json:"add_headers,omitempty" jsonschema:"headers to add (request phase)"`
	RemoveHeaders   []string          `json:"remove_headers,omitempty" jsonschema:"headers to remove (request phase)"`
	OverrideBody    *string           `json:"override_body,omitempty" jsonschema:"body override (request phase)"`

	// --- Response modify_and_forward mutation parameters ---
	OverrideStatus          int               `json:"override_status,omitempty" jsonschema:"HTTP status code override (response phase)"`
	OverrideResponseHeaders map[string]string `json:"override_response_headers,omitempty" jsonschema:"response header overrides (response phase)"`
	AddResponseHeaders      map[string]string `json:"add_response_headers,omitempty" jsonschema:"response headers to add (response phase)"`
	RemoveResponseHeaders   []string          `json:"remove_response_headers,omitempty" jsonschema:"response headers to remove (response phase)"`
	OverrideResponseBody    *string           `json:"override_response_body,omitempty" jsonschema:"response body override (response phase)"`
}

// availableInterceptActions lists the valid action names for the intercept tool.
var availableInterceptActions = []string{"release", "modify_and_forward", "drop"}

// registerIntercept registers the intercept MCP tool.
func (s *Server) registerIntercept() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "intercept",
		Description: "Act on intercepted requests or responses in the intercept queue. " +
			"Items have a 'phase' field: 'request' (pre-send) or 'response' (post-receive). " +
			"Available actions: " +
			"'release' forwards the intercepted item as-is (requires intercept_id); " +
			"'modify_and_forward' forwards with mutations — use request params (override_method, override_url, override_headers, add_headers, remove_headers, override_body) for request phase, " +
			"response params (override_status, override_response_headers, add_response_headers, remove_response_headers, override_response_body) for response phase (requires intercept_id); " +
			"'drop' discards the item returning 502 to the client (requires intercept_id).",
	}, s.handleInterceptTool)
}

// executeInterceptResult is the structured output of intercept queue actions.
type executeInterceptResult struct {
	InterceptID string `json:"intercept_id"`
	Action      string `json:"action"`
	Status      string `json:"status"`
}

// handleInterceptTool routes the intercept tool invocation to the appropriate action handler.
func (s *Server) handleInterceptTool(ctx context.Context, _ *gomcp.CallToolRequest, input interceptInput) (*gomcp.CallToolResult, any, error) {
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
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %v", input.Action, availableInterceptActions)
	}
}

// handleInterceptRelease handles the release action.
func (s *Server) handleInterceptRelease(_ context.Context, params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.deps.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for release action")
	}

	action := intercept.InterceptAction{
		Type: intercept.ActionRelease,
	}
	if err := s.deps.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("release: %w", err)
	}

	return nil, &executeInterceptResult{
		InterceptID: params.InterceptID,
		Action:      "release",
		Status:      "released",
	}, nil
}

// handleInterceptModifyAndForward handles the modify_and_forward action.
func (s *Server) handleInterceptModifyAndForward(_ context.Context, params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.deps.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for modify_and_forward action")
	}

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

	action := intercept.InterceptAction{
		Type:            intercept.ActionModifyAndForward,
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

	if err := s.deps.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("modify_and_forward: %w", err)
	}

	return nil, &executeInterceptResult{
		InterceptID: params.InterceptID,
		Action:      "modify_and_forward",
		Status:      "forwarded",
	}, nil
}

// handleInterceptDrop handles the drop action.
func (s *Server) handleInterceptDrop(_ context.Context, params interceptParams) (*gomcp.CallToolResult, *executeInterceptResult, error) {
	if s.deps.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}
	if params.InterceptID == "" {
		return nil, nil, fmt.Errorf("intercept_id is required for drop action")
	}

	action := intercept.InterceptAction{
		Type: intercept.ActionDrop,
	}
	if err := s.deps.interceptQueue.Respond(params.InterceptID, action); err != nil {
		return nil, nil, fmt.Errorf("drop: %w", err)
	}

	return nil, &executeInterceptResult{
		InterceptID: params.InterceptID,
		Action:      "drop",
		Status:      "dropped",
	}, nil
}
