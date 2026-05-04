package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
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

	// defaultMaxConnections is the default concurrent connection limit.
	// Must match proxy.defaultMaxConnections (128).
	defaultMaxConnections = 128
	// defaultPeekTimeout is the default protocol detection timeout.
	// Must match proxy.defaultPeekTimeout (30s).
	defaultPeekTimeout = 30 * time.Second
	// defaultRequestTimeout is the default HTTP request header read timeout.
	// Must match http.defaultRequestTimeout (60s).
	defaultRequestTimeout = 60 * time.Second
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

	// TCPForwards maps local listen ports to forwarding configurations.
	// Values can be strings (legacy: "host:port") or ForwardConfig objects
	// ({target, protocol, tls}). Uses map[string]any to accept both formats
	// in the MCP JSON schema; parsed into *config.ForwardConfig by parseTCPForwardsAny.
	TCPForwards map[string]any `json:"tcp_forwards,omitempty" jsonschema:"TCP forwarding map: local port -> upstream host:port string or {target, protocol, tls} object"`

	// Protocols specifies which protocols are enabled for detection.
	// Valid values: "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "SOCKS5", "TCP".
	// If omitted, all protocols are enabled (default behavior).
	Protocols []string `json:"protocols,omitempty" jsonschema:"enabled protocol list (default: all protocols enabled)"`

	// SOCKS5Auth specifies the SOCKS5 authentication method.
	// Valid values: "none" (default), "password".
	// If omitted or "none", SOCKS5 clients connect without authentication.
	SOCKS5Auth string `json:"socks5_auth,omitempty" jsonschema:"SOCKS5 authentication method: none (default) or password"`

	// SOCKS5Username is the username for SOCKS5 password authentication.
	// Required when socks5_auth is "password".
	SOCKS5Username string `json:"socks5_username,omitempty" jsonschema:"username for SOCKS5 password authentication"`

	// SOCKS5Password is the password for SOCKS5 password authentication.
	// Required when socks5_auth is "password".
	SOCKS5Password string `json:"socks5_password,omitempty" jsonschema:"password for SOCKS5 password authentication"`

	// TLSFingerprint selects the TLS ClientHello fingerprint profile for upstream connections.
	// Valid values: "chrome" (default), "firefox", "safari", "edge", "random", "none" (standard crypto/tls).
	// If omitted, defaults to "chrome".
	TLSFingerprint string `json:"tls_fingerprint,omitempty" jsonschema:"TLS fingerprint profile: chrome (default), firefox, safari, edge, random, none"`

	// ClientCertPath is the path to a PEM-encoded client certificate for mTLS with upstream servers (global).
	// Must be used together with client_key. If omitted, no client certificate is presented.
	ClientCertPath string `json:"client_cert,omitempty" jsonschema:"PEM client certificate path for mTLS (global)"`

	// ClientKeyPath is the path to a PEM-encoded client private key for mTLS with upstream servers (global).
	// Must be used together with client_cert. If omitted, no client certificate is presented.
	ClientKeyPath string `json:"client_key,omitempty" jsonschema:"PEM client private key path for mTLS (global)"`

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

// parseTCPForwardsAny parses TCP forward values from the MCP input into structured ForwardConfig.
// Each value can be a string (legacy: "host:port") or an object with {target, protocol, tls}.
// Legacy string values are converted to ForwardConfig{Target: value, Protocol: "raw"}.
func parseTCPForwardsAny(raw map[string]any) (map[string]*config.ForwardConfig, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	result := make(map[string]*config.ForwardConfig, len(raw))
	for port, val := range raw {
		switch v := val.(type) {
		case string:
			result[port] = &config.ForwardConfig{
				Target:   v,
				Protocol: "raw",
			}
		case map[string]any:
			fc := &config.ForwardConfig{}
			if t, ok := v["target"].(string); ok {
				fc.Target = t
			}
			if p, ok := v["protocol"].(string); ok {
				fc.Protocol = p
			}
			if tls, ok := v["tls"].(bool); ok {
				fc.TLS = tls
			}
			result[port] = fc
		default:
			// Try JSON round-trip for other types (e.g. json.RawMessage from defaults).
			data, err := json.Marshal(val)
			if err != nil {
				return nil, fmt.Errorf("port %q: must be a string or ForwardConfig object", port)
			}
			var s string
			if json.Unmarshal(data, &s) == nil {
				result[port] = &config.ForwardConfig{
					Target:   s,
					Protocol: "raw",
				}
				continue
			}
			var fc config.ForwardConfig
			if err := json.Unmarshal(data, &fc); err != nil {
				return nil, fmt.Errorf("port %q: must be a string or ForwardConfig object: %w", port, err)
			}
			result[port] = &fc
		}
	}
	return result, nil
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
	TCPForwards map[string]*config.ForwardConfig `json:"tcp_forwards,omitempty"`

	// Protocols lists the enabled protocols (if explicitly configured).
	Protocols []string `json:"protocols,omitempty"`
}

// registerProxyStart registers the proxy_start MCP tool.
func (s *Server) registerProxyStart() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "proxy_start",
		Description: "Start a proxy listener with optional configuration. " +
			"Supports multiple simultaneous listeners with different names (use 'name' parameter). " +
			"The proxy listens on the specified address and begins intercepting HTTP/HTTPS/SOCKS5 traffic. " +
			"Accepts optional name to identify this listener (default: 'default'), " +
			"upstream_proxy to route all traffic through an upstream proxy (http://host:port or socks5://[user:pass@]host:port), " +
			"capture_scope to control which requests are recorded, " +
			"tls_passthrough to specify domains that bypass TLS interception, " +
			"intercept_rules to define conditions for intercepting requests/responses, " +
			"auto_transform to configure automatic request/response modification rules, " +
			"tcp_forwards to map local ports to upstream TCP addresses (string format: 'host:port' for raw TCP, or structured ForwardConfig: {target, protocol, tls} for L7 detection), " +
			"protocols to specify which protocols are enabled for detection (including SOCKS5), " +
			"socks5_auth to set SOCKS5 authentication method ('none' or 'password'), " +
			"socks5_username and socks5_password for SOCKS5 password authentication, " +
			"tls_fingerprint to set the TLS ClientHello fingerprint profile ('chrome' (default), 'firefox', 'safari', 'edge', 'random', 'none' for standard crypto/tls), " +
			"max_connections to set the concurrent connection limit (default: 128), " +
			"peek_timeout_ms for protocol detection timeout (default: 30000ms), " +
			"and request_timeout_ms for HTTP request header read timeout (default: 60000ms). " +
			"All fields are optional; defaults: name=default, listen_addr=127.0.0.1:8080, upstream_proxy=direct, scope=capture all, passthrough=empty, intercept_rules=empty, auto_transform=empty, tcp_forwards=empty, protocols=all, socks5_auth=none, tls_fingerprint=chrome, max_connections=128, peek_timeout_ms=30000, request_timeout_ms=60000.",
	}, s.handleProxyStart)
}

// handleProxyStart handles the proxy_start tool invocation.
func (s *Server) handleProxyStart(ctx context.Context, _ *gomcp.CallToolRequest, input proxyStartInput) (*gomcp.CallToolResult, *proxyStartResult, error) {
	start := time.Now()

	if managerIsNil(s.connector.manager) {
		return nil, nil, fmt.Errorf("proxy manager is not initialized")
	}

	// Merge config file defaults for fields not explicitly provided by the caller.
	s.applyProxyDefaults(&input)

	// Resolve listener name (default: "default").
	listenerName := input.Name
	if listenerName == "" {
		listenerName = proxy.DefaultListenerName
	}

	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "proxy_start",
		"listen_addr", input.ListenAddr,
		"name", listenerName,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "proxy_start",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	// Validate the listen address before attempting to start.
	if input.ListenAddr != "" {
		if err := validateLoopbackAddr(input.ListenAddr); err != nil {
			return nil, nil, err
		}
	}

	// Start the listener BEFORE resetting/applying settings.
	// This ensures a failed start (already running, bind error) does not
	// clear the active configuration (USK-407).
	if err := s.connector.manager.StartNamed(s.misc.appCtx, listenerName, input.ListenAddr); err != nil {
		return nil, nil, fmt.Errorf("proxy start: %w", err)
	}

	// Reset all settings to defaults, then apply the new configuration.
	// This is done after StartNamed succeeds to be atomic with listener start.
	// If settings application fails, stop the listener to avoid leaving a
	// running proxy with invalid/default-only configuration.
	s.resetSettingsToDefaults()

	// Parse raw TCP forwards into structured ForwardConfig.
	parsedForwards, err := parseTCPForwardsAny(input.TCPForwards)
	if err != nil {
		s.connector.manager.StopNamed(ctx, listenerName)
		return nil, nil, fmt.Errorf("tcp_forwards: %w", err)
	}

	if err := s.applyProxyStartSettings(&input, parsedForwards); err != nil {
		s.connector.manager.StopNamed(ctx, listenerName)
		return nil, nil, err
	}

	if err := s.startTCPForwards(ctx, listenerName, parsedForwards); err != nil {
		return nil, nil, err
	}

	addr := s.resolveListenerAddr(listenerName)

	result := &proxyStartResult{
		Name:        listenerName,
		ListenAddr:  addr,
		Status:      "running",
		TCPForwards: parsedForwards,
		Protocols:   input.Protocols,
	}
	return nil, result, nil
}

// resetSettingsToDefaults resets all proxy configuration to default values.
// This is called in handleProxyStart after StartNamed succeeds, ensuring a
// clean state without risk of clearing active configuration on start failure.
func (s *Server) resetSettingsToDefaults() {
	// Reset capture scope to empty (capture all).
	if s.connector.scope != nil {
		s.connector.scope.Clear()
	}

	// Reset TLS passthrough to empty (intercept all).
	if s.connector.passthrough != nil {
		s.connector.passthrough.Clear()
	}

	// Reset enabled protocols to nil (all protocols).
	s.connector.enabledProtocols = nil

	// Reset TCP forwards to nil (no forwards).
	s.connector.tcpForwards = nil

	// Reset per-protocol intercept rules to empty and drain any
	// in-flight held envelopes so a fresh proxy start observes a clean
	// slate.
	if s.pipeline.httpInterceptEngine != nil {
		s.pipeline.httpInterceptEngine.SetRules(nil)
	}
	if s.pipeline.wsInterceptEngine != nil {
		s.pipeline.wsInterceptEngine.SetRules(nil)
	}
	if s.pipeline.grpcInterceptEngine != nil {
		s.pipeline.grpcInterceptEngine.SetRules(nil)
	}
	if s.pipeline.holdQueue != nil {
		s.pipeline.holdQueue.Clear()
	}

	// Reset auto-transform rules to empty (no transforms).
	if s.pipeline.transformHTTPEngine != nil {
		s.pipeline.transformHTTPEngine.SetRules(nil)
	}

	// Reset connection limits and timeouts to defaults.
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.SetMaxConnections(defaultMaxConnections)
		s.connector.manager.SetPeekTimeout(defaultPeekTimeout)
	}

	// Reset request timeout to default.
	s.applyRequestTimeout(defaultRequestTimeout)

	// Reset upstream proxy to direct (no upstream).
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.SetUpstreamProxy("")
	}
	for _, setter := range s.connector.upstreamProxySetters {
		setter.SetUpstreamProxy(nil)
	}

	// Reset TLS fingerprint to default ("chrome"), including transport rebuild.
	// Use applyTLSFingerprint to ensure transport is reconstructed (USK-467).
	_ = s.applyTLSFingerprint("chrome")

	// Reset global client certificate.
	if s.connector.hostTLSRegistry != nil {
		s.connector.hostTLSRegistry.SetGlobal(nil)
	}
}

// applyProxyStartSettings validates and applies all proxy configuration sections
// from the proxy_start input. It handles listen address, upstream proxy, capture
// scope, TLS passthrough, intercept rules, auto-transform, TCP forwards,
// protocols, SOCKS5 auth, and connection limits/timeouts.
//
// NOTE: resetSettingsToDefaults() is intentionally NOT called here. The caller
// (handleProxyStart) is responsible for calling it after StartNamed() succeeds,
// so that a failed start (e.g. already running, bind error) does not clear the
// active configuration.
func (s *Server) applyProxyStartSettings(input *proxyStartInput, parsedForwards map[string]*config.ForwardConfig) error {
	if err := s.applyProxyStartPipeline(input); err != nil {
		return err
	}
	if err := s.applyTCPForwardsConfig(parsedForwards); err != nil {
		return err
	}
	if err := s.applyProtocolsConfig(input.Protocols); err != nil {
		return err
	}
	if err := s.applySOCKS5AuthFromInput(input); err != nil {
		return err
	}
	return s.applyProxyStartLimits(input)
}

// applyProxyStartPipeline validates and applies the proxy pipeline settings:
// listen address, upstream proxy, capture scope, TLS passthrough, intercept rules,
// and auto-transform rules.
func (s *Server) applyProxyStartPipeline(input *proxyStartInput) error {
	if input.ListenAddr != "" {
		if err := validateLoopbackAddr(input.ListenAddr); err != nil {
			return err
		}
	}
	if input.UpstreamProxy != "" {
		if err := s.applyUpstreamProxy(input.UpstreamProxy); err != nil {
			return fmt.Errorf("upstream_proxy: %w", err)
		}
	}
	if input.CaptureScope != nil {
		if err := s.applyCaptureScope(input.CaptureScope); err != nil {
			return fmt.Errorf("capture_scope: %w", err)
		}
	}
	if len(input.TLSPassthrough) > 0 {
		if err := s.applyTLSPassthrough(input.TLSPassthrough); err != nil {
			return fmt.Errorf("tls_passthrough: %w", err)
		}
	}
	if len(input.InterceptRules) > 0 {
		if err := s.applyInterceptRules(input.InterceptRules); err != nil {
			return fmt.Errorf("intercept_rules: %w", err)
		}
	}
	if len(input.AutoTransform) > 0 {
		if err := s.applyTransformRules(input.AutoTransform); err != nil {
			return fmt.Errorf("auto_transform: %w", err)
		}
	}
	return s.applyProxyStartTLS(input)
}

// applyProxyStartTLS validates and applies TLS-related settings (fingerprint, client cert).
func (s *Server) applyProxyStartTLS(input *proxyStartInput) error {
	if input.TLSFingerprint != "" {
		if err := s.applyTLSFingerprint(input.TLSFingerprint); err != nil {
			return fmt.Errorf("tls_fingerprint: %w", err)
		}
	}
	if input.ClientCertPath != "" || input.ClientKeyPath != "" {
		if err := s.applyClientCert(input.ClientCertPath, input.ClientKeyPath); err != nil {
			return fmt.Errorf("client_cert: %w", err)
		}
	}
	return nil
}

// applyClientCert validates and sets the global mTLS client certificate
// on the host TLS registry.
func (s *Server) applyClientCert(certPath, keyPath string) error {
	if certPath == "" {
		return fmt.Errorf("client_cert is required when client_key is set")
	}
	if keyPath == "" {
		return fmt.Errorf("client_key is required when client_cert is set")
	}
	if s.connector.hostTLSRegistry == nil {
		return fmt.Errorf("host TLS registry is not initialized")
	}
	cfg := &httputil.HostTLSConfig{
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	// Verify the certificate can actually be loaded.
	if _, err := cfg.LoadClientCert(); err != nil {
		return err
	}
	s.connector.hostTLSRegistry.SetGlobal(cfg)
	return nil
}

// currentClientCert returns the current global client cert/key paths, or empty strings.
func (s *Server) currentClientCert() (string, string) {
	if s.connector.hostTLSRegistry == nil {
		return "", ""
	}
	global := s.connector.hostTLSRegistry.Global()
	if global == nil {
		return "", ""
	}
	return global.ClientCertPath, global.ClientKeyPath
}

// applyTCPForwardsConfig validates and stores TCP forward mappings.
func (s *Server) applyTCPForwardsConfig(forwards map[string]*config.ForwardConfig) error {
	if len(forwards) == 0 {
		return nil
	}
	if err := validateTCPForwardsConfig(forwards); err != nil {
		return fmt.Errorf("tcp_forwards: %w", err)
	}
	if s.connector.tcpHandler == nil {
		return fmt.Errorf("tcp_forwards: TCP handler is not initialized")
	}
	s.connector.tcpForwards = forwards
	return nil
}

// applyProtocolsConfig validates and stores enabled protocols.
func (s *Server) applyProtocolsConfig(protocols []string) error {
	if len(protocols) == 0 {
		return nil
	}
	if err := validateProtocols(protocols); err != nil {
		return fmt.Errorf("protocols: %w", err)
	}
	s.connector.enabledProtocols = protocols
	return nil
}

// applySOCKS5AuthFromInput applies SOCKS5 authentication configuration from proxy_start input.
// When SOCKS5Auth is empty (omitted), it defaults to "none" to reset any previous auth
// configuration. This ensures that proxy_start always initializes auth to a known state,
// unlike configure which uses delta semantics and skips omitted fields.
func (s *Server) applySOCKS5AuthFromInput(input *proxyStartInput) error {
	authMethod := input.SOCKS5Auth
	if authMethod == "" {
		authMethod = "none"
	}
	listenerName := input.Name
	if listenerName == "" {
		listenerName = proxy.DefaultListenerName
	}
	if err := s.applySOCKS5Auth(authMethod, input.SOCKS5Username, input.SOCKS5Password, listenerName); err != nil {
		return fmt.Errorf("socks5_auth: %w", err)
	}
	return nil
}

// applyProxyStartLimits validates and applies connection limits and timeouts
// from the proxy_start input.
func (s *Server) applyProxyStartLimits(input *proxyStartInput) error {
	if input.MaxConnections != nil {
		n := *input.MaxConnections
		if n < minMaxConnections || n > maxMaxConnections {
			return fmt.Errorf("max_connections must be between %d and %d, got %d", minMaxConnections, maxMaxConnections, n)
		}
		s.connector.manager.SetMaxConnections(n)
	}
	if input.PeekTimeoutMs != nil {
		ms := *input.PeekTimeoutMs
		if ms < minTimeoutMs || ms > maxTimeoutMs {
			return fmt.Errorf("peek_timeout_ms must be between %d and %d, got %d", minTimeoutMs, maxTimeoutMs, ms)
		}
		s.connector.manager.SetPeekTimeout(time.Duration(ms) * time.Millisecond)
	}
	if input.RequestTimeoutMs != nil {
		ms := *input.RequestTimeoutMs
		if ms < minTimeoutMs || ms > maxTimeoutMs {
			return fmt.Errorf("request_timeout_ms must be between %d and %d, got %d", minTimeoutMs, maxTimeoutMs, ms)
		}
		s.applyRequestTimeout(time.Duration(ms) * time.Millisecond)
	}
	return nil
}

// startTCPForwards starts TCP forward listeners for the given listener name.
// If no forwards are configured, it is a no-op.
func (s *Server) startTCPForwards(ctx context.Context, listenerName string, forwards map[string]*config.ForwardConfig) error {
	if len(forwards) == 0 {
		return nil
	}
	s.connector.tcpHandler.SetForwards(forwards)

	params := proxy.TCPForwardParams{
		Forwards: forwards,
		Handler:  s.connector.tcpHandler,
		Detector: s.connector.detector,
		Issuer:   s.misc.issuer,
	}

	if err := s.connector.manager.StartTCPForwardsNamedAny(s.misc.appCtx, listenerName, params); err != nil {
		s.connector.manager.StopNamed(ctx, listenerName)
		return fmt.Errorf("tcp_forwards: %w", err)
	}
	return nil
}

// resolveListenerAddr returns the listen address for the given listener name.
func (s *Server) resolveListenerAddr(listenerName string) string {
	_, addr := s.connector.manager.Status()
	if listenerName != proxy.DefaultListenerName {
		statuses := listenerStatuses(s.connector.manager)
		for _, st := range statuses {
			if st.Name == listenerName {
				return st.ListenAddr
			}
		}
	}
	return addr
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
	if s.connector.scope == nil {
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

	s.connector.scope.SetRules(includes, excludes)
	return nil
}

// validProtocols is the set of protocol names accepted by the protocols parameter.
var validProtocols = map[string]bool{
	"HTTP/1.x":  true,
	"HTTPS":     true,
	"WebSocket": true,
	"HTTP/2":    true,
	"gRPC":      true,
	"SOCKS5":    true,
	"TCP":       true,
}

// validateTCPForwardsConfig validates tcp_forwards entries with ForwardConfig values.
func validateTCPForwardsConfig(forwards map[string]*config.ForwardConfig) error {
	for port, fc := range forwards {
		if port == "" {
			return fmt.Errorf("port key cannot be empty")
		}
		if err := validatePortNumber(port, true); err != nil {
			return fmt.Errorf("invalid port key %q: %w", port, err)
		}
		if err := config.ValidateForwardConfig(port, fc); err != nil {
			return err
		}
		// Warn about unusual but valid combination: TLS termination without L7 parsing.
		if fc.TLS && fc.Protocol == "raw" {
			slog.Warn("TCP forward: tls=true with protocol=raw means TLS termination without L7 parsing",
				"port", port, "target", fc.Target)
		}
		// Validate target is host:port format.
		host, p, err := net.SplitHostPort(fc.Target)
		if err != nil {
			return fmt.Errorf("invalid target %q for port %q: must be host:port format", fc.Target, port)
		}
		if host == "" {
			return fmt.Errorf("invalid target %q for port %q: host cannot be empty", fc.Target, port)
		}
		if p == "" {
			return fmt.Errorf("invalid target %q for port %q: port cannot be empty", fc.Target, port)
		}
		if err := validatePortNumber(p, false); err != nil {
			return fmt.Errorf("invalid target %q for port %q: %w", fc.Target, port, err)
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
	if s.connector.proxyDefaults == nil {
		return
	}
	d := s.connector.proxyDefaults

	s.applyProxyDefaultStrings(input, d)
	s.applyProxyDefaultJSON(input, d)
	s.applyProxyDefaultSlicesAndMaps(input, d)
}

// applyProxyDefaultStrings merges simple string defaults from config into the input.
func (s *Server) applyProxyDefaultStrings(input *proxyStartInput, d *config.ProxyConfig) {
	if input.ListenAddr == "" && d.ListenAddr != "" {
		input.ListenAddr = d.ListenAddr
	}
	if input.UpstreamProxy == "" && d.UpstreamProxy != "" {
		input.UpstreamProxy = d.UpstreamProxy
	}
	if input.SOCKS5Auth == "" && d.SOCKS5Auth != "" {
		input.SOCKS5Auth = d.SOCKS5Auth
	}
	if input.SOCKS5Username == "" && d.SOCKS5Username != "" {
		input.SOCKS5Username = d.SOCKS5Username
	}
	if input.SOCKS5Password == "" && d.SOCKS5Password != "" {
		input.SOCKS5Password = d.SOCKS5Password
	}
	s.applyProxyDefaultTLSStrings(input, d)
}

// applyProxyDefaultTLSStrings merges TLS-related string defaults from config into the input.
func (s *Server) applyProxyDefaultTLSStrings(input *proxyStartInput, d *config.ProxyConfig) {
	if input.TLSFingerprint == "" && d.TLSFingerprint != "" {
		input.TLSFingerprint = d.TLSFingerprint
	}
	if input.ClientCertPath == "" && d.ClientCertPath != "" {
		input.ClientCertPath = d.ClientCertPath
	}
	if input.ClientKeyPath == "" && d.ClientKeyPath != "" {
		input.ClientKeyPath = d.ClientKeyPath
	}
}

// applyProxyDefaultJSON merges JSON-encoded defaults (capture scope, intercept rules,
// auto-transform) from config into the input.
func (s *Server) applyProxyDefaultJSON(input *proxyStartInput, d *config.ProxyConfig) {
	if input.CaptureScope == nil && len(d.CaptureScope) > 0 {
		var scope captureScopeInput
		if json.Unmarshal(d.CaptureScope, &scope) == nil {
			input.CaptureScope = &scope
		}
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
}

// applyProxyDefaultSlicesAndMaps merges slice and map defaults from config into the input.
func (s *Server) applyProxyDefaultSlicesAndMaps(input *proxyStartInput, d *config.ProxyConfig) {
	if len(input.TLSPassthrough) == 0 && len(d.TLSPassthrough) > 0 {
		input.TLSPassthrough = d.TLSPassthrough
	}
	if len(input.TCPForwards) == 0 && len(d.TCPForwards) > 0 {
		// Serialize config ForwardConfig values to map[string]any for the input.
		input.TCPForwards = make(map[string]any, len(d.TCPForwards))
		for k, v := range d.TCPForwards {
			// Use JSON round-trip to convert *ForwardConfig to map[string]any.
			data, err := json.Marshal(v)
			if err != nil {
				slog.Warn("failed to marshal default ForwardConfig", "port", k, "error", err)
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				slog.Warn("failed to unmarshal default ForwardConfig", "port", k, "error", err)
				continue
			}
			input.TCPForwards[k] = m
		}
	}
}

// applySOCKS5Auth validates and applies SOCKS5 authentication configuration
// for a specific listener. If listenerName is empty, the default (global) auth is set.
func (s *Server) applySOCKS5Auth(authMethod, username, password, listenerName string) error {
	switch authMethod {
	case "none":
		if s.connector.socks5AuthSetter != nil {
			if listenerName != "" {
				s.connector.socks5AuthSetter.ClearAuthForListener(listenerName)
			} else {
				s.connector.socks5AuthSetter.ClearAuth()
			}
		}
		return nil
	case "password":
		if username == "" {
			return fmt.Errorf("socks5_username is required when socks5_auth is \"password\"")
		}
		if password == "" {
			return fmt.Errorf("socks5_password is required when socks5_auth is \"password\"")
		}
		if s.connector.socks5AuthSetter == nil {
			return fmt.Errorf("SOCKS5 handler is not initialized")
		}
		if listenerName != "" {
			s.connector.socks5AuthSetter.SetPasswordAuthForListener(listenerName, username, password)
		} else {
			s.connector.socks5AuthSetter.SetPasswordAuth(username, password)
		}
		return nil
	default:
		return fmt.Errorf("invalid socks5_auth %q: must be \"none\" or \"password\"", authMethod)
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
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.SetUpstreamProxy(rawURL)
	}

	// Apply to all registered protocol handlers.
	for _, setter := range s.connector.upstreamProxySetters {
		setter.SetUpstreamProxy(proxyURL)
	}

	return nil
}

// applyTLSPassthrough validates and adds the TLS passthrough patterns.
func (s *Server) applyTLSPassthrough(patterns []string) error {
	if s.connector.passthrough == nil {
		return fmt.Errorf("TLS passthrough list is not initialized")
	}

	// Validate all patterns before applying any.
	for i, p := range patterns {
		if p == "" {
			return fmt.Errorf("pattern at index %d is empty", i)
		}
	}

	for _, p := range patterns {
		if !s.connector.passthrough.Add(p) {
			return fmt.Errorf("invalid pattern: %q", p)
		}
	}
	return nil
}

// validTLSFingerprints is the set of accepted TLS fingerprint profile names.
var validTLSFingerprints = map[string]bool{
	"chrome":  true,
	"firefox": true,
	"safari":  true,
	"edge":    true,
	"random":  true,
	"none":    true,
}

// applyTLSFingerprint validates the profile name, builds the corresponding
// TLSTransport, and applies both the profile name and transport to all
// registered handlers and connector.tlsTransport (used by resend).
// The profile name is normalized to lowercase before validation.
func (s *Server) applyTLSFingerprint(profile string) error {
	profile = strings.ToLower(profile)
	if !validTLSFingerprints[profile] {
		return fmt.Errorf("invalid tls_fingerprint %q: valid values are chrome, firefox, safari, edge, random, none", profile)
	}

	transport := s.buildTLSTransport(profile)

	for _, setter := range s.connector.tlsFingerprintSetters {
		setter.SetTLSFingerprint(profile)
		setter.SetTLSTransport(transport)
	}

	// Update resend transport so that resend/resend_raw also use the new profile.
	s.connector.tlsTransport = transport

	return nil
}

// buildTLSTransport creates a TLSTransport for the given profile name.
// "none" produces a StandardTransport (Go crypto/tls); all others produce
// a UTLSTransport with the matching browser fingerprint.
func (s *Server) buildTLSTransport(profile string) httputil.TLSTransport {
	insecure := s.currentInsecureSkipVerify()

	if profile == "none" {
		return &httputil.StandardTransport{
			InsecureSkipVerify: insecure,
			HostTLS:            s.connector.hostTLSRegistry,
		}
	}

	bp, err := httputil.ParseBrowserProfile(profile)
	if err != nil {
		// Fallback — should not happen since profile was validated above.
		return &httputil.StandardTransport{
			InsecureSkipVerify: insecure,
			HostTLS:            s.connector.hostTLSRegistry,
		}
	}

	return &httputil.UTLSTransport{
		Profile:            bp,
		InsecureSkipVerify: insecure,
		HostTLS:            s.connector.hostTLSRegistry,
	}
}

// currentInsecureSkipVerify reads the InsecureSkipVerify setting from the
// current connector.tlsTransport. Returns false when no transport is set.
func (s *Server) currentInsecureSkipVerify() bool {
	switch t := s.connector.tlsTransport.(type) {
	case *httputil.UTLSTransport:
		return t.InsecureSkipVerify
	case *httputil.StandardTransport:
		return t.InsecureSkipVerify
	default:
		return false
	}
}

// currentTLSFingerprint returns the current TLS fingerprint profile from the first
// registered handler, or "chrome" (the default) if none is registered.
func (s *Server) currentTLSFingerprint() string {
	if len(s.connector.tlsFingerprintSetters) > 0 {
		p := s.connector.tlsFingerprintSetters[0].TLSFingerprint()
		if p != "" {
			return p
		}
	}
	return "chrome"
}

// applyRequestTimeout updates the request timeout on all registered protocol handlers.
func (s *Server) applyRequestTimeout(d time.Duration) {
	for _, setter := range s.connector.requestTimeoutSetters {
		setter.SetRequestTimeout(d)
	}
}

// currentRequestTimeout returns the effective request timeout from the first
// registered handler, or 0 if none is registered.
func (s *Server) currentRequestTimeout() time.Duration {
	if len(s.connector.requestTimeoutSetters) > 0 {
		return s.connector.requestTimeoutSetters[0].RequestTimeout()
	}
	return 0
}
