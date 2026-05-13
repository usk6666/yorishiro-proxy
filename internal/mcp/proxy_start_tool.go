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
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
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

	// minMaxConcurrentStreams / maxMaxConcurrentStreams bound the MCP-
	// surfaced HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS knob (USK-862). The
	// upper bound mirrors the SETTINGS wire field max sanity for an
	// operator-set value: u32 max is RFC-legal but unrealistic to
	// configure intentionally; 65535 is well above the highest concurrency
	// any production workload observed to date.
	minMaxConcurrentStreams = 1
	maxMaxConcurrentStreams = 65535

	// defaultMaxConnections is the default concurrent connection limit.
	// Must match connector.DefaultMaxConnections (128).
	defaultMaxConnections = 128
	// defaultPeekTimeout is the default protocol detection timeout.
	// Must match connector.DefaultPeekTimeout (30s).
	defaultPeekTimeout = 30 * time.Second
	// defaultRequestTimeout is the default HTTP request header read timeout.
	// Must match http.defaultRequestTimeout (60s).
	defaultRequestTimeout = 60 * time.Second
)

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

	// MaxConcurrentStreams caps the per-connection HTTP/2 stream
	// concurrency advertised to clients via SETTINGS_MAX_CONCURRENT_STREAMS
	// (USK-862). Omitted / nil falls back to the config-file value (or the
	// H2 layer default of 500 when the config file also omits it).
	MaxConcurrentStreams *int `json:"max_concurrent_streams,omitempty" jsonschema:"HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS advertised to clients (1-65535; default: 500)"`

	// PeekTimeoutMs is the timeout in milliseconds for protocol detection on new connections.
	// Defaults to 30000 (30s) if omitted or zero.
	PeekTimeoutMs *int `json:"peek_timeout_ms,omitempty" jsonschema:"protocol detection timeout in milliseconds (default: 30000)"`

	// RequestTimeoutMs is the timeout in milliseconds for reading HTTP request headers.
	// Defaults to 60000 (60s) if omitted or zero.
	RequestTimeoutMs *int `json:"request_timeout_ms,omitempty" jsonschema:"HTTP request header read timeout in milliseconds (default: 60000)"`

	// CaptureScope filters which flows are persisted to the flow store
	// without altering wire transmission (USK-776). Use this to suppress
	// noise from third-party CDNs, analytics, fonts, etc. while keeping
	// browser-driven sessions functional. See yorishiro://help/proxy_start.
	CaptureScope *captureScopeInput `json:"capture_scope,omitempty" jsonschema:"recording-only observability filter; out-of-scope flows are still proxied but not stored"`
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
		Description: "Start a proxy listener on a loopback address with HTTP/HTTPS/SOCKS5 MITM. " +
			"Multiple named listeners are supported via 'name' (default: 'default'). " +
			"All configuration sections (upstream proxy, TLS passthrough, intercept/transform rules, " +
			"SOCKS5 auth, TLS fingerprint, connection/timeout limits, tcp_forwards, protocols) are session-only " +
			"and are reset to defaults on each invocation; persistent settings belong in the config file. " +
			"See yorishiro://help/proxy_start for parameter details.",
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
		listenerName = proxybuild.DefaultListenerName
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

	// USK-861: cross-field validation — reject the case where a
	// tcp_forwards port key collides with the primary listen_addr port.
	// Run BEFORE StartNamed so a self-collision is rejected without
	// registering a half-broken listener (the original footgun: the
	// parent bind succeeded, the forward bind failed, but the listener
	// remained registered, blocking re-creation under the same name).
	if err := validateTCPForwardsAgainstListenAddr(input.ListenAddr, input.TCPForwards); err != nil {
		return nil, nil, err
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
	//
	// USK-826: the reset is scoped to the (re)starting listener for the
	// fields that are per-listener (upstream_proxy). Restarting listener A
	// must not wipe listener B's upstream_proxy override.
	s.resetSettingsToDefaults(listenerName)

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
		// USK-861: a tcp_forwards bind failure (e.g. another process
		// holds the port) leaves the parent listener registered but the
		// forward unbound — the user observes a half-broken listener
		// they cannot recreate under the same name. Roll back the
		// listener registration here, mirroring the sibling rollback
		// pattern at lines 265 and 270 above.
		s.connector.manager.StopNamed(ctx, listenerName)
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
//
// listenerName scopes per-listener fields (USK-826: upstream_proxy) so a
// proxy_start of listener A does not clobber listener B's overrides. The
// remaining sections (TLS passthrough, intercept rules, transform rules,
// connection limits, peek timeout, TLS fingerprint, client cert, capture
// scope) still reset globally pending follow-up per-listener scoping;
// they are documented as process-global in the configure tool description.
//
// An empty listenerName falls back to the default listener name so
// internal callers that do not yet propagate names hit the same slot
// as the implicit default.
func (s *Server) resetSettingsToDefaults(listenerName string) {
	if listenerName == "" {
		listenerName = proxybuild.DefaultListenerName
	}
	// Reset TLS passthrough to empty (intercept all).
	if s.connector.passthrough != nil {
		s.connector.passthrough.Clear()
	}

	// Reset enabled protocols to nil (all protocols).
	s.connector.enabledProtocols = nil
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.SetEnabledProtocols(nil)
	}

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
		// USK-862: clear the runtime override so the next stack assembly
		// falls back to the boot-time BuildConfig.MaxConcurrentStreams
		// (and ultimately the H2 Layer default). proxy_start observes a
		// clean slate; applyProxyStartLimits below reinstalls the
		// caller-supplied value if any.
		s.connector.manager.SetMaxConcurrentStreams(0)
	}

	// Reset request timeout to default.
	s.applyRequestTimeout(defaultRequestTimeout)

	// Reset upstream proxy to direct (no upstream) — scoped to the
	// (re)starting listener (USK-826). Restarting listener A must not
	// clear listener B's override; the per-listener clear matches the
	// SOCKS5 per-listener reset pattern in applySOCKS5Auth.
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.ClearUpstreamProxyForListener(listenerName)
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

	// USK-776: reset capture_scope back to "capture all" so each
	// proxy_start observes a clean recording filter; subsequent
	// applyCaptureScope reinstalls user-provided rules.
	if s.flowStore != nil && s.flowStore.recordScope != nil {
		s.flowStore.recordScope.Clear()
	}
}

// applyProxyStartSettings validates and applies all proxy configuration sections
// from the proxy_start input. It handles listen address, upstream proxy,
// TLS passthrough, intercept rules, auto-transform, TCP forwards,
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
// listen address, upstream proxy, TLS passthrough, intercept rules, and
// auto-transform rules.
func (s *Server) applyProxyStartPipeline(input *proxyStartInput) error {
	if input.ListenAddr != "" {
		if err := validateLoopbackAddr(input.ListenAddr); err != nil {
			return err
		}
	}
	if input.UpstreamProxy != "" {
		listenerName := input.Name
		if listenerName == "" {
			listenerName = proxybuild.DefaultListenerName
		}
		if err := s.applyUpstreamProxy(input.UpstreamProxy, listenerName); err != nil {
			return fmt.Errorf("upstream_proxy: %w", err)
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
	if input.CaptureScope != nil {
		if err := s.applyCaptureScope(input.CaptureScope); err != nil {
			return fmt.Errorf("capture_scope: %w", err)
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
	cfg := &transport.HostTLSConfig{
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
	s.connector.tcpForwards = forwards
	return nil
}

// applyProtocolsConfig validates and stores enabled protocols. The
// allow-list is forwarded to the proxybuild manager so the running
// listener's data path enforces it at peek-based detection (USK-732).
func (s *Server) applyProtocolsConfig(protocols []string) error {
	if len(protocols) == 0 {
		return nil
	}
	if err := validateProtocols(protocols); err != nil {
		return fmt.Errorf("protocols: %w", err)
	}
	s.connector.enabledProtocols = protocols
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.SetEnabledProtocols(protocols)
	}
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
		listenerName = proxybuild.DefaultListenerName
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
	// USK-862: thread max_concurrent_streams into the process-singleton
	// BuildConfig. Next-connection semantics — already-accepted H2
	// connections retain the value captured at their stack-assembly time,
	// the new value takes effect at the next listener-stack assembly.
	if input.MaxConcurrentStreams != nil {
		n := *input.MaxConcurrentStreams
		if n < minMaxConcurrentStreams || n > maxMaxConcurrentStreams {
			return fmt.Errorf("max_concurrent_streams must be between %d and %d, got %d", minMaxConcurrentStreams, maxMaxConcurrentStreams, n)
		}
		s.applyMaxConcurrentStreams(uint32(n))
	}
	return nil
}

// startTCPForwards starts TCP forward listeners for the given listener name
// by delegating to the proxybuild Manager. If no forwards are configured,
// it is a no-op. Errors are wrapped with the "tcp_forwards" prefix so MCP
// callers see a consistent failure message.
func (s *Server) startTCPForwards(ctx context.Context, listenerName string, forwards map[string]*config.ForwardConfig) error {
	if len(forwards) == 0 {
		return nil
	}
	if managerIsNil(s.connector.manager) {
		return fmt.Errorf("tcp_forwards: proxy manager is not initialized")
	}
	params := proxybuild.TCPForwardParams{Forwards: forwards}
	if err := s.connector.manager.StartTCPForwardsNamedAny(ctx, listenerName, params); err != nil {
		return fmt.Errorf("tcp_forwards: %w", err)
	}
	return nil
}

// resolveListenerAddr returns the listen address for the given listener name.
func (s *Server) resolveListenerAddr(listenerName string) string {
	_, addr := s.connector.manager.Status()
	if listenerName != proxybuild.DefaultListenerName {
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

// validateTCPForwardsAgainstListenAddr rejects tcp_forwards entries whose
// port key collides with the primary listen_addr port (USK-861).
//
// The forward listener and the parent listener both bind a 127.0.0.1
// socket; if their ports match, only one bind can succeed. Without this
// check, the parent bind wins, the forward bind fails with "address
// already in use", and the user is left with a registered-but-broken
// listener they cannot recreate under the same name. The check runs
// BEFORE StartNamed so a self-collision is rejected fail-fast with no
// side effects on the proxybuild registry.
//
// Forward listeners hardcode 127.0.0.1 (see proxybuild.startTCPForwardListener)
// and listen_addr is enforced loopback by validateLoopbackAddr, so a port
// match is sufficient for collision; host comparison is unnecessary.
//
// Port 0 on EITHER side is treated as a non-collision: it means
// "kernel-assigned ephemeral", and the kernel never hands out the same
// ephemeral port to two concurrent listeners. Skipping the 0 case
// preserves the established e2e idiom of binding both the parent and
// forward listeners to ephemeral ports for test isolation.
//
// Comparison is performed on parsed integer values so that
// non-canonical literals (e.g. "08080" with leading zero, "+8080" with
// explicit sign) cannot bypass the check by failing string equality
// against the canonical form. validateTCPForwardsConfig (run later
// from applyTCPForwardsConfig) is responsible for rejecting malformed
// or out-of-range port keys via validatePortNumber; this helper only
// addresses cross-field collision and silently defers to that check
// for any port literal it cannot parse, to avoid duplicating the
// format-validation error message.
//
// listenAddr "" (default 127.0.0.1:8080 applied later by proxybuild) and
// empty forwards short-circuit to nil to keep the happy path zero-cost.
func validateTCPForwardsAgainstListenAddr(listenAddr string, forwards map[string]any) error {
	if listenAddr == "" || len(forwards) == 0 {
		return nil
	}
	_, listenPortStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		// listen_addr is malformed; defer to validateLoopbackAddr's
		// dedicated error message rather than producing a confusing
		// "tcp_forwards: ..." error here. validateLoopbackAddr runs
		// immediately before this helper, so a bad listenAddr will
		// already have been rejected.
		return nil
	}
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil {
		// listen_addr port is non-numeric; defer to validateLoopbackAddr.
		return nil
	}
	// Two ephemeral ports never collide: the kernel assigns distinct
	// values to each net.Listen("tcp", "127.0.0.1:0"). Skip the check
	// when listen_addr asks for an ephemeral assignment.
	if listenPort == 0 {
		return nil
	}
	for portKey := range forwards {
		fwdPort, err := strconv.Atoi(portKey)
		if err != nil {
			// Non-integer port key; validateTCPForwardsConfig will
			// surface a precise error later via validatePortNumber.
			continue
		}
		if fwdPort == 0 {
			continue
		}
		if fwdPort == listenPort {
			return fmt.Errorf("tcp_forwards: port %d conflicts with listen_addr %q — pick a different port", listenPort, listenAddr)
		}
	}
	return nil
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

// applyProxyDefaultJSON merges JSON-encoded defaults (intercept rules,
// auto-transform) from config into the input.
func (s *Server) applyProxyDefaultJSON(input *proxyStartInput, d *config.ProxyConfig) {
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
// the manager for the named listener and all registered protocol handlers.
//
// USK-826: the URL is scoped to the named listener so a multi-listener
// chained MITM (listener B sending its traffic through listener A) does
// not propagate the override to every listener and cause listener A to
// recurse through itself. An empty listenerName falls back to the
// default listener ("default").
//
// The legacy upstreamProxySetters list (HTTP/1.x and HTTP/2 handler
// surfaces from the pre-RFC-001 era) is kept for legacy_options_test.go
// scaffolding; live mcpserver wiring passes a nil slice (USK-826) so the
// per-listener semantics is the only path mutated.
func (s *Server) applyUpstreamProxy(rawURL, listenerName string) error {
	proxyURL, err := connector.ParseUpstreamProxy(rawURL)
	if err != nil {
		return err
	}

	if listenerName == "" {
		listenerName = proxybuild.DefaultListenerName
	}

	// Store in manager (per-listener) for status reporting + dial-path
	// propagation to the bound BuildConfig.
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.SetUpstreamProxyForListener(listenerName, rawURL)
	}

	// Apply to all registered protocol handlers. Legacy/test-only path;
	// the live data path's per-listener scoping flows through the
	// manager → BuildConfig wiring above.
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
//
// The validated profile is also installed as a runtime override on the
// proxybuild.Manager's bound BuildConfig (USK-809), so the next live
// MITM data-path upstream dial uses the new uTLS profile. Without this
// step, the live wire path would silently keep dialing with the
// boot-time fingerprint regardless of runtime proxy_start / configure
// changes (the prior behaviour observed only by resend transport).
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

	// Install the runtime override on the live data-path BuildConfig so
	// the MITM dial picks up the new fingerprint (USK-809). The setter
	// loop above only fans out to resend handlers; the live wire path
	// reads through the manager's bound BuildConfig.
	if !managerIsNil(s.connector.manager) {
		s.connector.manager.SetTLSFingerprint(profile)
	}

	return nil
}

// buildTLSTransport creates a TLSTransport for the given profile name.
// "none" produces a StandardTransport (Go crypto/tls); all others produce
// a UTLSTransport with the matching browser fingerprint.
func (s *Server) buildTLSTransport(profile string) transport.TLSTransport {
	insecure := s.currentInsecureSkipVerify()

	if profile == "none" {
		return &transport.StandardTransport{
			InsecureSkipVerify: insecure,
			HostTLS:            s.connector.hostTLSRegistry,
		}
	}

	bp, err := transport.ParseBrowserProfile(profile)
	if err != nil {
		// Fallback — should not happen since profile was validated above.
		return &transport.StandardTransport{
			InsecureSkipVerify: insecure,
			HostTLS:            s.connector.hostTLSRegistry,
		}
	}

	return &transport.UTLSTransport{
		Profile:            bp,
		InsecureSkipVerify: insecure,
		HostTLS:            s.connector.hostTLSRegistry,
	}
}

// currentInsecureSkipVerify reads the InsecureSkipVerify setting from the
// current connector.tlsTransport. Returns false when no transport is set.
func (s *Server) currentInsecureSkipVerify() bool {
	switch t := s.connector.tlsTransport.(type) {
	case *transport.UTLSTransport:
		return t.InsecureSkipVerify
	case *transport.StandardTransport:
		return t.InsecureSkipVerify
	default:
		return false
	}
}

// currentTLSFingerprint returns the current TLS fingerprint profile that
// the live MITM data path will use for its next upstream dial.
//
// Resolution order (USK-809):
//
//  1. proxybuild.Manager.TLSFingerprint() — reflects the runtime
//     override installed by applyTLSFingerprint plus the boot-time
//     BuildConfig.TLSFingerprint. This is the canonical source for the
//     live data path; production deployments always populate it.
//  2. tlsFingerprintSetters[0].TLSFingerprint() — fallback for tests
//     that exercise applyTLSFingerprint via the legacy
//     WithTLSFingerprintSetter helper without binding a BuildConfig to
//     the manager.
//  3. empty string — neither source has a value; the live path uses
//     the standard TLS transport (no uTLS spoofing).
//
// This function intentionally does NOT substitute a "chrome" literal
// for an empty value. The previous "chrome" fallback was the live bug
// fixed by USK-809 (it masked all runtime fingerprint changes by
// always reporting "chrome" in production).
func (s *Server) currentTLSFingerprint() string {
	if !managerIsNil(s.connector.manager) {
		if p := s.connector.manager.TLSFingerprint(); p != "" {
			return p
		}
	}
	if len(s.connector.tlsFingerprintSetters) > 0 {
		if p := s.connector.tlsFingerprintSetters[0].TLSFingerprint(); p != "" {
			return p
		}
	}
	return ""
}

// applyRequestTimeout updates the request timeout on all registered protocol handlers.
func (s *Server) applyRequestTimeout(d time.Duration) {
	for _, setter := range s.connector.requestTimeoutSetters {
		setter.SetRequestTimeout(d)
	}
}

// applyMaxConcurrentStreams threads the HTTP/2
// SETTINGS_MAX_CONCURRENT_STREAMS override down to the live
// proxybuild.Manager's bound BuildConfig (USK-862). Next-connection
// semantics: in-flight H2 connections retain the cap captured at their
// stack-assembly time. Passing 0 clears the override so the next stack
// assembly falls back to the boot-time BuildConfig.MaxConcurrentStreams
// (and ultimately the H2 Layer default of 500). No-op when the manager
// is not initialized (test-only paths).
func (s *Server) applyMaxConcurrentStreams(v uint32) {
	if managerIsNil(s.connector.manager) {
		return
	}
	s.connector.manager.SetMaxConcurrentStreams(v)
}

// currentRequestTimeout returns the effective request timeout from the first
// registered handler, or 0 if none is registered.
func (s *Server) currentRequestTimeout() time.Duration {
	if len(s.connector.requestTimeoutSetters) > 0 {
		return s.connector.requestTimeoutSetters[0].RequestTimeout()
	}
	return 0
}
