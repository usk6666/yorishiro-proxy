package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

const (
	// minMaxConnections is the minimum allowed value for max_connections.
	minMaxConnections = 1
	// maxMaxConnections is the maximum allowed value for max_connections.
	maxMaxConnections = 100000
	// minTimeoutMs is the minimum allowed timeout in milliseconds.
	minTimeoutMs = 100
	// maxTimeoutMs is the maximum allowed timeout in milliseconds (10 minutes).
	maxTimeoutMs = 600000
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
	// Name is an optional name for this listener instance.
	// Allows running multiple listeners simultaneously with different names.
	// Defaults to "default" if empty.
	Name string `json:"name,omitempty" jsonschema:"listener name for multi-listener support, defaults to 'default' if omitted"`

	// ListenAddr is the TCP address to listen on (e.g. "127.0.0.1:8080", "127.0.0.1:9090").
	// Defaults to "127.0.0.1:8080" if empty.
	ListenAddr string `json:"listen_addr,omitempty" jsonschema:"TCP address to listen on, defaults to 127.0.0.1:8080 if omitted"`

	// UpstreamProxy is the URL of an upstream proxy to route all outgoing traffic through.
	// Supported schemes: http://host:port (HTTP CONNECT proxy), socks5://host:port (SOCKS5 proxy).
	// Authentication: http://user:pass@host:port (Basic auth), socks5://user:pass@host:port.
	// If omitted, traffic is sent directly to the target (no upstream proxy).
	// This setting takes precedence over HTTP_PROXY/HTTPS_PROXY environment variables.
	UpstreamProxy string `json:"upstream_proxy,omitempty" jsonschema:"upstream proxy URL (http://host:port or socks5://host:port) for chaining proxies"`

	// CaptureScope configures which requests are recorded to the flow store.
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

	// TCPForwards maps local listen ports to upstream TCP addresses for the Raw TCP handler.
	// Format: {"port": "upstream_host:port"} (e.g. {"3306": "db.example.com:3306"}).
	// Connections arriving on a mapped port are forwarded to the specified upstream.
	// If omitted, Raw TCP forwarding is not configured.
	TCPForwards map[string]string `json:"tcp_forwards,omitempty" jsonschema:"Raw TCP forwarding map: local port -> upstream host:port"`

	// Protocols specifies which protocols are enabled for detection.
	// Valid values: "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "TCP".
	// If omitted, all protocols are enabled (default behavior).
	Protocols []string `json:"protocols,omitempty" jsonschema:"enabled protocol list (default: all protocols enabled)"`

	// MaxConnections is the maximum number of concurrent proxy connections.
	// Defaults to 128 if omitted or zero.
	MaxConnections *int `json:"max_connections,omitempty" jsonschema:"maximum concurrent connections (default: 128)"`

	// PeekTimeoutMs is the timeout in milliseconds for protocol detection on new connections.
	// Defaults to 30000 (30s) if omitted or zero.
	PeekTimeoutMs *int `json:"peek_timeout_ms,omitempty" jsonschema:"protocol detection timeout in milliseconds (default: 30000)"`

	// RequestTimeoutMs is the timeout in milliseconds for reading HTTP request headers.
	// Defaults to 60000 (60s) if omitted or zero.
	RequestTimeoutMs *int `json:"request_timeout_ms,omitempty" jsonschema:"HTTP request header read timeout in milliseconds (default: 60000)"`
}

// proxyStartResult is the structured output of the proxy_start tool.
type proxyStartResult struct {
	// Name is the listener name.
	Name string `json:"name"`
	// ListenAddr is the actual address the proxy is listening on.
	ListenAddr string `json:"listen_addr"`
	// Status indicates the proxy state after the operation.
	Status string `json:"status"`
	// TCPForwards is the configured TCP forwarding map (if any).
	TCPForwards map[string]string `json:"tcp_forwards,omitempty"`
	// Protocols lists the enabled protocols (if explicitly configured).
	Protocols []string `json:"protocols,omitempty"`
}

// registerProxyStart registers the proxy_start MCP tool.
func (s *Server) registerProxyStart() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "proxy_start",
		Description: "Start a proxy listener with optional configuration. " +
			"Supports multiple simultaneous listeners with different names (use 'name' parameter). " +
			"The proxy listens on the specified address and begins intercepting HTTP/HTTPS traffic. " +
			"Accepts optional name to identify this listener (default: 'default'), " +
			"upstream_proxy to route all traffic through an upstream proxy (http://host:port or socks5://[user:pass@]host:port), " +
			"capture_scope to control which requests are recorded, " +
			"tls_passthrough to specify domains that bypass TLS interception, " +
			"intercept_rules to define conditions for intercepting requests/responses, " +
			"auto_transform to configure automatic request/response modification rules, " +
			"tcp_forwards to map local ports to upstream TCP addresses for Raw TCP forwarding, " +
			"protocols to specify which protocols are enabled for detection, " +
			"max_connections to set the concurrent connection limit (default: 128), " +
			"peek_timeout_ms for protocol detection timeout (default: 30000ms), " +
			"and request_timeout_ms for HTTP request header read timeout (default: 60000ms). " +
			"All fields are optional; defaults: name=default, listen_addr=127.0.0.1:8080, upstream_proxy=direct, scope=capture all, passthrough=empty, intercept_rules=empty, auto_transform=empty, tcp_forwards=empty, protocols=all, max_connections=128, peek_timeout_ms=30000, request_timeout_ms=60000.",
	}, s.handleProxyStart)
}

// handleProxyStart handles the proxy_start tool invocation.
func (s *Server) handleProxyStart(ctx context.Context, _ *gomcp.CallToolRequest, input proxyStartInput) (*gomcp.CallToolResult, *proxyStartResult, error) {
	if s.deps.manager == nil {
		return nil, nil, fmt.Errorf("proxy manager is not initialized")
	}

	// Merge config file defaults for fields not explicitly provided by the caller.
	s.applyProxyDefaults(&input)

	// Validate listen address format if provided.
	if input.ListenAddr != "" {
		if err := validateLoopbackAddr(input.ListenAddr); err != nil {
			return nil, nil, err
		}
	}

	// Validate and apply upstream proxy if provided.
	if input.UpstreamProxy != "" {
		if err := s.applyUpstreamProxy(input.UpstreamProxy); err != nil {
			return nil, nil, fmt.Errorf("upstream_proxy: %w", err)
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

	// Validate and store TCP forwards if provided.
	if len(input.TCPForwards) > 0 {
		if err := validateTCPForwards(input.TCPForwards); err != nil {
			return nil, nil, fmt.Errorf("tcp_forwards: %w", err)
		}
		if s.deps.tcpHandler == nil {
			return nil, nil, fmt.Errorf("tcp_forwards: TCP handler is not initialized")
		}
		s.deps.tcpForwards = input.TCPForwards
	}

	// Validate and store enabled protocols if provided.
	if len(input.Protocols) > 0 {
		if err := validateProtocols(input.Protocols); err != nil {
			return nil, nil, fmt.Errorf("protocols: %w", err)
		}
		s.deps.enabledProtocols = input.Protocols
	}

	// Apply connection limits and timeouts if provided.
	if input.MaxConnections != nil {
		n := *input.MaxConnections
		if n < minMaxConnections || n > maxMaxConnections {
			return nil, nil, fmt.Errorf("max_connections must be between %d and %d, got %d", minMaxConnections, maxMaxConnections, n)
		}
		s.deps.manager.SetMaxConnections(n)
	}
	if input.PeekTimeoutMs != nil {
		ms := *input.PeekTimeoutMs
		if ms < minTimeoutMs || ms > maxTimeoutMs {
			return nil, nil, fmt.Errorf("peek_timeout_ms must be between %d and %d, got %d", minTimeoutMs, maxTimeoutMs, ms)
		}
		s.deps.manager.SetPeekTimeout(time.Duration(ms) * time.Millisecond)
	}
	if input.RequestTimeoutMs != nil {
		ms := *input.RequestTimeoutMs
		if ms < minTimeoutMs || ms > maxTimeoutMs {
			return nil, nil, fmt.Errorf("request_timeout_ms must be between %d and %d, got %d", minTimeoutMs, maxTimeoutMs, ms)
		}
		s.applyRequestTimeout(time.Duration(ms) * time.Millisecond)
	}

	// Resolve listener name (default: "default").
	listenerName := input.Name
	if listenerName == "" {
		listenerName = proxy.DefaultListenerName
	}

	if err := s.deps.manager.StartNamed(s.deps.appCtx, listenerName, input.ListenAddr); err != nil {
		return nil, nil, fmt.Errorf("proxy start: %w", err)
	}

	// Start TCP forward listeners if configured.
	if len(input.TCPForwards) > 0 {
		// Update the TCP handler's forward mappings so it knows which
		// upstream to connect to for each local port.
		s.deps.tcpHandler.SetForwards(input.TCPForwards)

		if err := s.deps.manager.StartTCPForwardsNamed(s.deps.appCtx, listenerName, input.TCPForwards, s.deps.tcpHandler); err != nil {
			// Stop the listener since forward listeners failed.
			s.deps.manager.StopNamed(ctx, listenerName)
			return nil, nil, fmt.Errorf("tcp_forwards: %w", err)
		}
	}

	_, addr := s.deps.manager.Status()
	// For named listeners that are not the default, get address from ListenerStatuses.
	if listenerName != proxy.DefaultListenerName {
		statuses := s.deps.manager.ListenerStatuses()
		for _, st := range statuses {
			if st.Name == listenerName {
				addr = st.ListenAddr
				break
			}
		}
	}

	result := &proxyStartResult{
		Name:        listenerName,
		ListenAddr:  addr,
		Status:      "running",
		TCPForwards: input.TCPForwards,
		Protocols:   input.Protocols,
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
	if s.deps.scope == nil {
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

	s.deps.scope.SetRules(includes, excludes)
	return nil
}

// validProtocols is the set of protocol names accepted by the protocols parameter.
var validProtocols = map[string]bool{
	"HTTP/1.x":  true,
	"HTTPS":     true,
	"WebSocket": true,
	"HTTP/2":    true,
	"gRPC":      true,
	"TCP":       true,
}

// validateTCPForwards validates tcp_forwards entries.
func validateTCPForwards(forwards map[string]string) error {
	for port, target := range forwards {
		if port == "" {
			return fmt.Errorf("port key cannot be empty")
		}
		// Validate port key is a valid port number (0-65535).
		// Port 0 is allowed as it means OS-assigned ephemeral port.
		if err := validatePortNumber(port, true); err != nil {
			return fmt.Errorf("invalid port key %q: %w", port, err)
		}
		if target == "" {
			return fmt.Errorf("target for port %q cannot be empty", port)
		}
		// Validate target is host:port format.
		host, p, err := net.SplitHostPort(target)
		if err != nil {
			return fmt.Errorf("invalid target %q for port %q: must be host:port format", target, port)
		}
		if host == "" {
			return fmt.Errorf("invalid target %q for port %q: host cannot be empty", target, port)
		}
		if p == "" {
			return fmt.Errorf("invalid target %q for port %q: port cannot be empty", target, port)
		}
		// Validate target port is a valid port number (1-65535).
		if err := validatePortNumber(p, false); err != nil {
			return fmt.Errorf("invalid target %q for port %q: %w", target, port, err)
		}
	}
	return nil
}

// validatePortNumber checks that s is a valid TCP port number.
// If allowZero is true, the range is 0-65535 (for listen ports where 0 means
// OS-assigned ephemeral port). Otherwise the range is 1-65535.
func validatePortNumber(s string, allowZero bool) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("port must be a number, got %q", s)
	}
	minPort := 1
	if allowZero {
		minPort = 0
	}
	if n < minPort || n > 65535 {
		return fmt.Errorf("port must be between %d and 65535, got %d", minPort, n)
	}
	return nil
}

// validateProtocols validates that all protocol names are recognized.
func validateProtocols(protocols []string) error {
	for _, p := range protocols {
		if !validProtocols[p] {
			valid := make([]string, 0, len(validProtocols))
			for k := range validProtocols {
				valid = append(valid, k)
			}
			return fmt.Errorf("unknown protocol %q: valid protocols are %v", p, valid)
		}
	}
	return nil
}

// applyProxyDefaults merges config file defaults into the proxy_start input.
// Fields explicitly provided by the caller (non-zero values) take precedence
// over config file defaults.
func (s *Server) applyProxyDefaults(input *proxyStartInput) {
	if s.deps.proxyDefaults == nil {
		return
	}
	d := s.deps.proxyDefaults

	if input.ListenAddr == "" && d.ListenAddr != "" {
		input.ListenAddr = d.ListenAddr
	}

	if input.CaptureScope == nil && len(d.CaptureScope) > 0 {
		var scope captureScopeInput
		if json.Unmarshal(d.CaptureScope, &scope) == nil {
			input.CaptureScope = &scope
		}
	}

	if len(input.TLSPassthrough) == 0 && len(d.TLSPassthrough) > 0 {
		input.TLSPassthrough = d.TLSPassthrough
	}

	if len(input.InterceptRules) == 0 && len(d.InterceptRules) > 0 {
		var rules []interceptRuleInput
		if json.Unmarshal(d.InterceptRules, &rules) == nil {
			input.InterceptRules = rules
		}
	}

	if len(input.AutoTransform) == 0 && len(d.AutoTransform) > 0 {
		var transforms []transformRuleInput
		if json.Unmarshal(d.AutoTransform, &transforms) == nil {
			input.AutoTransform = transforms
		}
	}

	if len(input.TCPForwards) == 0 && len(d.TCPForwards) > 0 {
		input.TCPForwards = d.TCPForwards
	}

	if input.UpstreamProxy == "" && d.UpstreamProxy != "" {
		input.UpstreamProxy = d.UpstreamProxy
	}
}

// applyUpstreamProxy validates the upstream proxy URL and configures it on
// the manager and all registered protocol handlers.
func (s *Server) applyUpstreamProxy(rawURL string) error {
	proxyURL, err := proxy.ParseUpstreamProxy(rawURL)
	if err != nil {
		return err
	}

	// Store in manager for status reporting.
	if s.deps.manager != nil {
		s.deps.manager.SetUpstreamProxy(rawURL)
	}

	// Apply to all registered protocol handlers.
	for _, setter := range s.deps.upstreamProxySetters {
		setter.SetUpstreamProxy(proxyURL)
	}

	return nil
}

// applyTLSPassthrough validates and adds the TLS passthrough patterns.
func (s *Server) applyTLSPassthrough(patterns []string) error {
	if s.deps.passthrough == nil {
		return fmt.Errorf("TLS passthrough list is not initialized")
	}

	// Validate all patterns before applying any.
	for i, p := range patterns {
		if p == "" {
			return fmt.Errorf("pattern at index %d is empty", i)
		}
	}

	for _, p := range patterns {
		if !s.deps.passthrough.Add(p) {
			return fmt.Errorf("invalid pattern: %q", p)
		}
	}
	return nil
}

// applyRequestTimeout updates the request timeout on all registered protocol handlers.
func (s *Server) applyRequestTimeout(d time.Duration) {
	for _, setter := range s.deps.requestTimeoutSetters {
		setter.SetRequestTimeout(d)
	}
}

// currentRequestTimeout returns the effective request timeout from the first
// registered handler, or 0 if none is registered.
func (s *Server) currentRequestTimeout() time.Duration {
	if len(s.deps.requestTimeoutSetters) > 0 {
		return s.deps.requestTimeoutSetters[0].RequestTimeout()
	}
	return 0
}

