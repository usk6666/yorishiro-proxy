package mcp

import (
	"context"
	"fmt"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// configureInput is the typed input for the configure tool.
type configureInput struct {
	// Operation specifies how the configuration should be applied.
	// "merge" (default) applies add/remove deltas to existing config.
	// "replace" replaces the specified fields entirely.
	Operation string `json:"operation,omitempty" jsonschema:"operation type: merge (default) or replace"`

	// CaptureScope configures request capture scope rules.
	// For merge: use add_includes/remove_includes/add_excludes/remove_excludes.
	// For replace: use includes/excludes to replace all rules.
	CaptureScope *configureCaptureScope `json:"capture_scope,omitempty" jsonschema:"capture scope configuration"`

	// TLSPassthrough configures TLS passthrough patterns.
	// For merge: use add/remove arrays.
	// For replace: use a string array to replace all patterns.
	TLSPassthrough *configureTLSPassthrough `json:"tls_passthrough,omitempty" jsonschema:"TLS passthrough configuration"`
}

// configureCaptureScope holds capture scope configuration for both merge and replace operations.
type configureCaptureScope struct {
	// Merge operation fields: delta add/remove.
	AddIncludes    []scopeRuleInput `json:"add_includes,omitempty" jsonschema:"(merge) rules to add to includes"`
	RemoveIncludes []scopeRuleInput `json:"remove_includes,omitempty" jsonschema:"(merge) rules to remove from includes"`
	AddExcludes    []scopeRuleInput `json:"add_excludes,omitempty" jsonschema:"(merge) rules to add to excludes"`
	RemoveExcludes []scopeRuleInput `json:"remove_excludes,omitempty" jsonschema:"(merge) rules to remove from excludes"`

	// Replace operation fields: full replacement.
	Includes []scopeRuleInput `json:"includes,omitempty" jsonschema:"(replace) full list of include rules"`
	Excludes []scopeRuleInput `json:"excludes,omitempty" jsonschema:"(replace) full list of exclude rules"`
}

// configureTLSPassthrough holds TLS passthrough configuration for both merge and replace operations.
type configureTLSPassthrough struct {
	// Merge operation fields: delta add/remove.
	Add    []string `json:"add,omitempty" jsonschema:"(merge) patterns to add"`
	Remove []string `json:"remove,omitempty" jsonschema:"(merge) patterns to remove"`

	// Replace operation fields: full replacement.
	// Patterns replaces the entire passthrough list when using replace operation.
	Patterns []string `json:"patterns,omitempty" jsonschema:"(replace) full list of passthrough patterns"`
}

// configureResult is the structured output of the configure tool.
type configureResult struct {
	// Status indicates the result of the operation.
	Status string `json:"status"`

	// CaptureScope summarizes the current capture scope state.
	CaptureScope *configureScopeResult `json:"capture_scope,omitempty"`

	// TLSPassthrough summarizes the current TLS passthrough state.
	TLSPassthrough *configurePassthroughResult `json:"tls_passthrough,omitempty"`
}

// configureScopeResult summarizes capture scope state in the configure response.
type configureScopeResult struct {
	IncludeCount int `json:"include_count"`
	ExcludeCount int `json:"exclude_count"`
}

// configurePassthroughResult summarizes TLS passthrough state in the configure response.
type configurePassthroughResult struct {
	TotalPatterns int `json:"total_patterns"`
}

// registerConfigure registers the configure MCP tool.
func (s *Server) registerConfigure() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "configure",
		Description: "Configure runtime proxy settings including capture scope and TLS passthrough. " +
			"Supports two operations: 'merge' (default) applies incremental add/remove changes, " +
			"'replace' replaces entire configuration sections. " +
			"Capture scope controls which requests are recorded (include/exclude rules with hostname, url_prefix, method). " +
			"TLS passthrough controls which CONNECT destinations bypass MITM interception. " +
			"Both sections are optional; only specified sections are modified.",
	}, s.handleConfigure)
}

// handleConfigure handles the configure tool invocation.
func (s *Server) handleConfigure(_ context.Context, _ *gomcp.CallToolRequest, input configureInput) (*gomcp.CallToolResult, *configureResult, error) {
	op := input.Operation
	if op == "" {
		op = "merge"
	}

	switch op {
	case "merge":
		return s.handleConfigureMerge(input)
	case "replace":
		return s.handleConfigureReplace(input)
	default:
		return nil, nil, fmt.Errorf("invalid operation %q: available operations are \"merge\" and \"replace\"", op)
	}
}

// handleConfigureMerge applies delta changes (add/remove) to existing configuration.
func (s *Server) handleConfigureMerge(input configureInput) (*gomcp.CallToolResult, *configureResult, error) {
	result := &configureResult{Status: "configured"}

	if input.CaptureScope != nil {
		if s.scope == nil {
			return nil, nil, fmt.Errorf("capture scope is not initialized: proxy may not be running")
		}
		if err := s.mergeScope(input.CaptureScope); err != nil {
			return nil, nil, fmt.Errorf("capture_scope merge: %w", err)
		}
		includes, excludes := s.scope.Rules()
		result.CaptureScope = &configureScopeResult{
			IncludeCount: len(includes),
			ExcludeCount: len(excludes),
		}
	}

	if input.TLSPassthrough != nil {
		if s.passthrough == nil {
			return nil, nil, fmt.Errorf("TLS passthrough list is not initialized: proxy may not be running")
		}
		s.mergePassthrough(input.TLSPassthrough)
		result.TLSPassthrough = &configurePassthroughResult{
			TotalPatterns: s.passthrough.Len(),
		}
	}

	return nil, result, nil
}

// handleConfigureReplace replaces entire configuration sections.
func (s *Server) handleConfigureReplace(input configureInput) (*gomcp.CallToolResult, *configureResult, error) {
	result := &configureResult{Status: "configured"}

	if input.CaptureScope != nil {
		if s.scope == nil {
			return nil, nil, fmt.Errorf("capture scope is not initialized: proxy may not be running")
		}
		includes := toScopeRules(input.CaptureScope.Includes)
		excludes := toScopeRules(input.CaptureScope.Excludes)
		s.scope.SetRules(includes, excludes)
		result.CaptureScope = &configureScopeResult{
			IncludeCount: len(includes),
			ExcludeCount: len(excludes),
		}
	}

	if input.TLSPassthrough != nil {
		if s.passthrough == nil {
			return nil, nil, fmt.Errorf("TLS passthrough list is not initialized: proxy may not be running")
		}
		s.replacePassthrough(input.TLSPassthrough)
		result.TLSPassthrough = &configurePassthroughResult{
			TotalPatterns: s.passthrough.Len(),
		}
	}

	return nil, result, nil
}

// mergeScope applies delta add/remove operations to the capture scope.
// Since CaptureScope only supports SetRules (full replace), we read current
// rules, apply deltas, and write back.
func (s *Server) mergeScope(cfg *configureCaptureScope) error {
	includes, excludes := s.scope.Rules()

	// Add new include rules.
	for _, r := range cfg.AddIncludes {
		rule := proxy.ScopeRule{Hostname: r.Hostname, URLPrefix: r.URLPrefix, Method: r.Method}
		if !containsScopeRule(includes, rule) {
			includes = append(includes, rule)
		}
	}

	// Remove include rules.
	for _, r := range cfg.RemoveIncludes {
		rule := proxy.ScopeRule{Hostname: r.Hostname, URLPrefix: r.URLPrefix, Method: r.Method}
		includes = removeScopeRule(includes, rule)
	}

	// Add new exclude rules.
	for _, r := range cfg.AddExcludes {
		rule := proxy.ScopeRule{Hostname: r.Hostname, URLPrefix: r.URLPrefix, Method: r.Method}
		if !containsScopeRule(excludes, rule) {
			excludes = append(excludes, rule)
		}
	}

	// Remove exclude rules.
	for _, r := range cfg.RemoveExcludes {
		rule := proxy.ScopeRule{Hostname: r.Hostname, URLPrefix: r.URLPrefix, Method: r.Method}
		excludes = removeScopeRule(excludes, rule)
	}

	s.scope.SetRules(includes, excludes)
	return nil
}

// mergePassthrough applies delta add/remove operations to the passthrough list.
func (s *Server) mergePassthrough(cfg *configureTLSPassthrough) {
	for _, p := range cfg.Add {
		s.passthrough.Add(p)
	}
	for _, p := range cfg.Remove {
		s.passthrough.Remove(p)
	}
}

// replacePassthrough replaces the entire passthrough list with new patterns.
func (s *Server) replacePassthrough(cfg *configureTLSPassthrough) {
	// Remove all existing patterns.
	for _, p := range s.passthrough.List() {
		s.passthrough.Remove(p)
	}
	// Add new patterns.
	for _, p := range cfg.Patterns {
		s.passthrough.Add(p)
	}
}

// containsScopeRule checks whether a rule exists in the slice (all fields must match).
func containsScopeRule(rules []proxy.ScopeRule, target proxy.ScopeRule) bool {
	for _, r := range rules {
		if scopeRulesEqual(r, target) {
			return true
		}
	}
	return false
}

// removeScopeRule removes all occurrences of target from rules.
func removeScopeRule(rules []proxy.ScopeRule, target proxy.ScopeRule) []proxy.ScopeRule {
	result := make([]proxy.ScopeRule, 0, len(rules))
	for _, r := range rules {
		if !scopeRulesEqual(r, target) {
			result = append(result, r)
		}
	}
	return result
}

// scopeRulesEqual reports whether two ScopeRules are equal (all fields match).
func scopeRulesEqual(a, b proxy.ScopeRule) bool {
	return a.Hostname == b.Hostname && a.URLPrefix == b.URLPrefix && a.Method == b.Method
}
