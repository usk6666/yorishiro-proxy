package mcp

import (
	"context"
	"fmt"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// scopeRuleInput is the JSON representation of a scope rule for MCP tool input.
type scopeRuleInput struct {
	// Hostname matches the request's hostname (case-insensitive, exact match).
	// Supports wildcard prefix "*.example.com" to match all subdomains.
	Hostname string `json:"hostname,omitempty" jsonschema:"hostname pattern (e.g. example.com, *.example.com)"`

	// URLPrefix matches the beginning of the request URL path (case-sensitive).
	URLPrefix string `json:"url_prefix,omitempty" jsonschema:"URL path prefix (e.g. /api/)"`

	// Method matches the HTTP method (case-insensitive, exact match).
	Method string `json:"method,omitempty" jsonschema:"HTTP method (e.g. GET, POST)"`
}

// setCaptureInput is the input for the set_capture_scope tool.
type setCaptureInput struct {
	// Includes are rules for requests that should be captured.
	// If non-empty, only requests matching at least one include rule are captured.
	Includes []scopeRuleInput `json:"includes,omitempty" jsonschema:"include rules (capture only matching requests)"`

	// Excludes are rules for requests that should NOT be captured.
	// Exclude rules take precedence over include rules.
	Excludes []scopeRuleInput `json:"excludes,omitempty" jsonschema:"exclude rules (skip matching requests, takes precedence over includes)"`
}

// scopeRuleOutput is the JSON representation of a scope rule in MCP tool output.
type scopeRuleOutput struct {
	Hostname  string `json:"hostname,omitempty"`
	URLPrefix string `json:"url_prefix,omitempty"`
	Method    string `json:"method,omitempty"`
}

// getCaptureResult is the output of the get_capture_scope tool.
type getCaptureResult struct {
	// Includes are the current include rules.
	Includes []scopeRuleOutput `json:"includes"`
	// Excludes are the current exclude rules.
	Excludes []scopeRuleOutput `json:"excludes"`
}

// setCaptureResult is the output of the set_capture_scope tool.
type setCaptureResult struct {
	// Status indicates the result of the operation.
	Status string `json:"status"`
	// IncludeCount is the number of include rules set.
	IncludeCount int `json:"include_count"`
	// ExcludeCount is the number of exclude rules set.
	ExcludeCount int `json:"exclude_count"`
}

// clearCaptureResult is the output of the clear_capture_scope tool.
type clearCaptureResult struct {
	// Status indicates the result of the operation.
	Status string `json:"status"`
}

// registerSetCaptureScope registers the set_capture_scope MCP tool.
func (s *Server) registerSetCaptureScope() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "set_capture_scope",
		Description: "Set the capture scope to control which requests are recorded to the session store. " +
			"Include rules specify which requests to capture (if any include rules are set, only matching requests are captured). " +
			"Exclude rules specify which requests to skip (exclude takes precedence over include). " +
			"Each rule can match by hostname (supports *.example.com wildcard), URL path prefix, and/or HTTP method. " +
			"All non-empty fields in a rule must match (AND logic). Multiple rules use OR logic. " +
			"Calling this tool replaces all existing rules.",
	}, s.handleSetCaptureScope)
}

// registerGetCaptureScope registers the get_capture_scope MCP tool.
func (s *Server) registerGetCaptureScope() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "get_capture_scope",
		Description: "Get the current capture scope rules. Returns the include and exclude rules that control which requests are recorded to the session store. An empty scope means all requests are captured.",
	}, s.handleGetCaptureScope)
}

// registerClearCaptureScope registers the clear_capture_scope MCP tool.
func (s *Server) registerClearCaptureScope() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "clear_capture_scope",
		Description: "Clear all capture scope rules, returning to the default behavior of capturing all requests.",
	}, s.handleClearCaptureScope)
}

// handleSetCaptureScope handles the set_capture_scope tool invocation.
func (s *Server) handleSetCaptureScope(_ context.Context, _ *gomcp.CallToolRequest, input setCaptureInput) (*gomcp.CallToolResult, *setCaptureResult, error) {
	if s.scope == nil {
		return nil, nil, fmt.Errorf("capture scope is not initialized")
	}

	if len(input.Includes) == 0 && len(input.Excludes) == 0 {
		return nil, nil, fmt.Errorf("at least one include or exclude rule must be specified; use clear_capture_scope to remove all rules")
	}

	// Validate rules.
	for i, r := range input.Includes {
		if r.Hostname == "" && r.URLPrefix == "" && r.Method == "" {
			return nil, nil, fmt.Errorf("include rule %d has no fields set: at least one of hostname, url_prefix, or method must be specified", i)
		}
	}
	for i, r := range input.Excludes {
		if r.Hostname == "" && r.URLPrefix == "" && r.Method == "" {
			return nil, nil, fmt.Errorf("exclude rule %d has no fields set: at least one of hostname, url_prefix, or method must be specified", i)
		}
	}

	includes := toScopeRules(input.Includes)
	excludes := toScopeRules(input.Excludes)

	s.scope.SetRules(includes, excludes)

	return nil, &setCaptureResult{
		Status:       "scope_updated",
		IncludeCount: len(includes),
		ExcludeCount: len(excludes),
	}, nil
}

// handleGetCaptureScope handles the get_capture_scope tool invocation.
func (s *Server) handleGetCaptureScope(_ context.Context, _ *gomcp.CallToolRequest, _ any) (*gomcp.CallToolResult, *getCaptureResult, error) {
	if s.scope == nil {
		return nil, nil, fmt.Errorf("capture scope is not initialized")
	}

	includes, excludes := s.scope.Rules()

	return nil, &getCaptureResult{
		Includes: fromScopeRules(includes),
		Excludes: fromScopeRules(excludes),
	}, nil
}

// handleClearCaptureScope handles the clear_capture_scope tool invocation.
func (s *Server) handleClearCaptureScope(_ context.Context, _ *gomcp.CallToolRequest, _ any) (*gomcp.CallToolResult, *clearCaptureResult, error) {
	if s.scope == nil {
		return nil, nil, fmt.Errorf("capture scope is not initialized")
	}

	s.scope.Clear()

	return nil, &clearCaptureResult{
		Status: "scope_cleared",
	}, nil
}

// toScopeRules converts MCP input rules to proxy.ScopeRule slice.
func toScopeRules(inputs []scopeRuleInput) []proxy.ScopeRule {
	rules := make([]proxy.ScopeRule, len(inputs))
	for i, in := range inputs {
		rules[i] = proxy.ScopeRule{
			Hostname:  in.Hostname,
			URLPrefix: in.URLPrefix,
			Method:    in.Method,
		}
	}
	return rules
}

// fromScopeRules converts proxy.ScopeRule slice to MCP output rules.
func fromScopeRules(rules []proxy.ScopeRule) []scopeRuleOutput {
	out := make([]scopeRuleOutput, len(rules))
	for i, r := range rules {
		out[i] = scopeRuleOutput{
			Hostname:  r.Hostname,
			URLPrefix: r.URLPrefix,
			Method:    r.Method,
		}
	}
	return out
}
