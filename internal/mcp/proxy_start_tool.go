package mcp

import (
	"context"
	"fmt"
	"net"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// captureScopeInput is the JSON representation of capture scope configuration
// for the proxy_start tool.
type captureScopeInput struct {
	// Includes are rules for requests that should be captured.
	// If non-empty, only requests matching at least one include rule are captured.
	Includes []scopeRuleInput `json:"includes,omitempty" jsonschema:"include rules (capture only matching requests)"`

	// Excludes are rules for requests that should NOT be captured.
	// Exclude rules take precedence over include rules.
	Excludes []scopeRuleInput `json:"excludes,omitempty" jsonschema:"exclude rules (skip matching requests, takes precedence over includes)"`
}

// proxyStartInput is the input for the proxy_start tool.
type proxyStartInput struct {
	// ListenAddr is the TCP address to listen on (e.g. "127.0.0.1:8080", "127.0.0.1:9090").
	// Defaults to "127.0.0.1:8080" if empty.
	ListenAddr string `json:"listen_addr,omitempty" jsonschema:"TCP address to listen on, defaults to 127.0.0.1:8080 if omitted"`

	// CaptureScope configures which requests are recorded to the session store.
	// If omitted, all requests are captured (default behavior).
	CaptureScope *captureScopeInput `json:"capture_scope,omitempty" jsonschema:"capture scope configuration to control which requests are recorded"`

	// TLSPassthrough is a list of domain patterns that should bypass TLS interception.
	// Supported formats: exact match ("example.com") or wildcard ("*.example.com").
	// If omitted, no domains are passed through (all TLS is intercepted).
	TLSPassthrough []string `json:"tls_passthrough,omitempty" jsonschema:"domain patterns that bypass TLS interception (e.g. pinned-service.com, *.googleapis.com)"`

	// InterceptRules configures request/response intercept rules.
	// Rules define conditions for intercepting traffic based on host pattern, path pattern, method, and headers.
	// If omitted, no intercept rules are active.
	InterceptRules []interceptRuleInput `json:"intercept_rules,omitempty" jsonschema:"intercept rules for matching requests/responses to hold"`

	// AutoTransform configures auto-transform rules for automatic request/response modification.
	// Rules define conditions for matching and actions for transforming (add/set/remove headers, replace body).
	// If omitted, no auto-transform rules are active.
	AutoTransform []transformRuleInput `json:"auto_transform,omitempty" jsonschema:"auto-transform rules for automatic request/response modification"`
}

// proxyStartResult is the structured output of the proxy_start tool.
type proxyStartResult struct {
	// ListenAddr is the actual address the proxy is listening on.
	ListenAddr string `json:"listen_addr"`
	// Status indicates the proxy state after the operation.
	Status string `json:"status"`
}

// registerProxyStart registers the proxy_start MCP tool.
func (s *Server) registerProxyStart() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "proxy_start",
		Description: "Start the proxy server with optional configuration. " +
			"The proxy listens on the specified address and begins intercepting HTTP/HTTPS traffic. " +
			"Accepts optional capture_scope to control which requests are recorded, " +
			"tls_passthrough to specify domains that bypass TLS interception, " +
			"intercept_rules to define conditions for intercepting requests/responses, " +
			"and auto_transform to configure automatic request/response modification rules. " +
			"All fields are optional; defaults: listen_addr=127.0.0.1:8080, scope=capture all, passthrough=empty, intercept_rules=empty, auto_transform=empty.",
	}, s.handleProxyStart)
}

// handleProxyStart handles the proxy_start tool invocation.
func (s *Server) handleProxyStart(ctx context.Context, _ *gomcp.CallToolRequest, input proxyStartInput) (*gomcp.CallToolResult, *proxyStartResult, error) {
	if s.manager == nil {
		return nil, nil, fmt.Errorf("proxy manager is not initialized")
	}

	// Validate listen address format if provided.
	if input.ListenAddr != "" {
		if err := validateLoopbackAddr(input.ListenAddr); err != nil {
			return nil, nil, err
		}
	}

	// Validate and apply capture scope if provided.
	if input.CaptureScope != nil {
		if err := s.applyCaptureScope(input.CaptureScope); err != nil {
			return nil, nil, fmt.Errorf("capture_scope: %w", err)
		}
	}

	// Apply TLS passthrough patterns if provided.
	if len(input.TLSPassthrough) > 0 {
		if err := s.applyTLSPassthrough(input.TLSPassthrough); err != nil {
			return nil, nil, fmt.Errorf("tls_passthrough: %w", err)
		}
	}

	// Apply intercept rules if provided.
	if len(input.InterceptRules) > 0 {
		if err := s.applyInterceptRules(input.InterceptRules); err != nil {
			return nil, nil, fmt.Errorf("intercept_rules: %w", err)
		}
	}

	// Apply auto-transform rules if provided.
	if len(input.AutoTransform) > 0 {
		if err := s.applyTransformRules(input.AutoTransform); err != nil {
			return nil, nil, fmt.Errorf("auto_transform: %w", err)
		}
	}

	if err := s.manager.Start(s.appCtx, input.ListenAddr); err != nil {
		return nil, nil, fmt.Errorf("proxy start: %w", err)
	}

	_, addr := s.manager.Status()

	result := &proxyStartResult{
		ListenAddr: addr,
		Status:     "running",
	}
	return nil, result, nil
}

// validateLoopbackAddr validates that the given address is a loopback address.
func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen_addr %q: %w", addr, err)
	}
	// Reject empty host to prevent binding to all interfaces (0.0.0.0).
	if host == "" {
		return fmt.Errorf("invalid listen_addr %q: host must be specified (e.g. 127.0.0.1:8080)", addr)
	}
	// Restrict to loopback addresses for security.
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("invalid listen_addr %q: only loopback addresses are allowed", addr)
		}
	}
	return nil
}

// applyCaptureScope validates and sets the capture scope rules from the input.
func (s *Server) applyCaptureScope(input *captureScopeInput) error {
	if s.scope == nil {
		return fmt.Errorf("capture scope is not initialized")
	}

	// Validate that each rule has at least one field set.
	for i, r := range input.Includes {
		if r.Hostname == "" && r.URLPrefix == "" && r.Method == "" {
			return fmt.Errorf("include rule %d has no fields set: at least one of hostname, url_prefix, or method must be specified", i)
		}
	}
	for i, r := range input.Excludes {
		if r.Hostname == "" && r.URLPrefix == "" && r.Method == "" {
			return fmt.Errorf("exclude rule %d has no fields set: at least one of hostname, url_prefix, or method must be specified", i)
		}
	}

	includes := toScopeRules(input.Includes)
	excludes := toScopeRules(input.Excludes)

	s.scope.SetRules(includes, excludes)
	return nil
}

// applyTLSPassthrough validates and adds the TLS passthrough patterns.
func (s *Server) applyTLSPassthrough(patterns []string) error {
	if s.passthrough == nil {
		return fmt.Errorf("TLS passthrough list is not initialized")
	}

	// Validate all patterns before applying any.
	for i, p := range patterns {
		if p == "" {
			return fmt.Errorf("pattern at index %d is empty", i)
		}
	}

	for _, p := range patterns {
		if !s.passthrough.Add(p) {
			return fmt.Errorf("invalid pattern: %q", p)
		}
	}
	return nil
}

