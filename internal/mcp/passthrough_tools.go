package mcp

import (
	"context"
	"fmt"
	"sort"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// addTLSPassthroughInput is the typed input for the add_tls_passthrough tool.
type addTLSPassthroughInput struct {
	// Pattern is a domain pattern to add. Supported formats:
	// - Exact match: "example.com"
	// - Wildcard: "*.example.com" (matches any subdomain)
	Pattern string `json:"pattern" jsonschema:"domain pattern to add (e.g. example.com or *.example.com)"`
}

// addTLSPassthroughResult is the structured output of the add_tls_passthrough tool.
type addTLSPassthroughResult struct {
	// Pattern is the normalized pattern that was added.
	Pattern string `json:"pattern"`
	// TotalPatterns is the total number of patterns after the operation.
	TotalPatterns int `json:"total_patterns"`
}

// registerAddTLSPassthrough registers the add_tls_passthrough MCP tool.
func (s *Server) registerAddTLSPassthrough() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "add_tls_passthrough",
		Description: "Add a domain pattern to the TLS passthrough list. Matching CONNECT destinations will bypass MITM interception and relay encrypted bytes directly. Use exact domains (e.g. \"example.com\") or wildcards (e.g. \"*.example.com\" for all subdomains). Useful for cert-pinned services, out-of-scope domains, or noisy CDN/analytics traffic.",
	}, s.handleAddTLSPassthrough)
}

// handleAddTLSPassthrough handles the add_tls_passthrough tool invocation.
func (s *Server) handleAddTLSPassthrough(_ context.Context, _ *gomcp.CallToolRequest, input addTLSPassthroughInput) (*gomcp.CallToolResult, *addTLSPassthroughResult, error) {
	if s.passthrough == nil {
		return nil, nil, fmt.Errorf("TLS passthrough list is not initialized")
	}

	if input.Pattern == "" {
		return nil, nil, fmt.Errorf("pattern is required")
	}

	if !s.passthrough.Add(input.Pattern) {
		return nil, nil, fmt.Errorf("invalid pattern: %q", input.Pattern)
	}

	result := &addTLSPassthroughResult{
		Pattern:       input.Pattern,
		TotalPatterns: s.passthrough.Len(),
	}
	return nil, result, nil
}

// removeTLSPassthroughInput is the typed input for the remove_tls_passthrough tool.
type removeTLSPassthroughInput struct {
	// Pattern is the domain pattern to remove.
	Pattern string `json:"pattern" jsonschema:"domain pattern to remove"`
}

// removeTLSPassthroughResult is the structured output of the remove_tls_passthrough tool.
type removeTLSPassthroughResult struct {
	// Removed indicates whether the pattern was found and removed.
	Removed bool `json:"removed"`
	// TotalPatterns is the total number of patterns after the operation.
	TotalPatterns int `json:"total_patterns"`
}

// registerRemoveTLSPassthrough registers the remove_tls_passthrough MCP tool.
func (s *Server) registerRemoveTLSPassthrough() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "remove_tls_passthrough",
		Description: "Remove a domain pattern from the TLS passthrough list. After removal, CONNECT requests to the matching domain will be intercepted (MITM) as usual.",
	}, s.handleRemoveTLSPassthrough)
}

// handleRemoveTLSPassthrough handles the remove_tls_passthrough tool invocation.
func (s *Server) handleRemoveTLSPassthrough(_ context.Context, _ *gomcp.CallToolRequest, input removeTLSPassthroughInput) (*gomcp.CallToolResult, *removeTLSPassthroughResult, error) {
	if s.passthrough == nil {
		return nil, nil, fmt.Errorf("TLS passthrough list is not initialized")
	}

	if input.Pattern == "" {
		return nil, nil, fmt.Errorf("pattern is required")
	}

	removed := s.passthrough.Remove(input.Pattern)

	result := &removeTLSPassthroughResult{
		Removed:       removed,
		TotalPatterns: s.passthrough.Len(),
	}
	return nil, result, nil
}

// listTLSPassthroughResult is the structured output of the list_tls_passthrough tool.
type listTLSPassthroughResult struct {
	// Patterns is the list of domain patterns in the passthrough list.
	Patterns []string `json:"patterns"`
	// Count is the number of patterns.
	Count int `json:"count"`
}

// registerListTLSPassthrough registers the list_tls_passthrough MCP tool.
func (s *Server) registerListTLSPassthrough() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "list_tls_passthrough",
		Description: "List all domain patterns in the TLS passthrough list. These patterns define which CONNECT destinations bypass MITM interception.",
	}, s.handleListTLSPassthrough)
}

// handleListTLSPassthrough handles the list_tls_passthrough tool invocation.
func (s *Server) handleListTLSPassthrough(_ context.Context, _ *gomcp.CallToolRequest, _ any) (*gomcp.CallToolResult, *listTLSPassthroughResult, error) {
	if s.passthrough == nil {
		return nil, nil, fmt.Errorf("TLS passthrough list is not initialized")
	}

	patterns := s.passthrough.List()
	sort.Strings(patterns)

	result := &listTLSPassthroughResult{
		Patterns: patterns,
		Count:    len(patterns),
	}
	return nil, result, nil
}
