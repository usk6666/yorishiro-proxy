package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// configureInput is the typed input for the configure tool.
type configureInput struct {
	// Operation specifies how the configuration should be applied.
	// "merge" (default) applies add/remove deltas to existing config.
	// "replace" replaces the specified fields entirely.
	Operation string `json:"operation,omitempty" jsonschema:"operation type: merge (default) or replace"`

	// UpstreamProxy configures the upstream proxy URL.
	// Set to a proxy URL (e.g. "http://proxy:3128" or "socks5://proxy:1080") to route traffic through it.
	// Set to empty string "" to disable (direct connection).
	// If omitted (nil pointer), the setting is not changed.
	UpstreamProxy *string `json:"upstream_proxy,omitempty" jsonschema:"upstream proxy URL (empty string to disable, omit to keep current)"`

	// TLSPassthrough configures TLS passthrough patterns.
	// For merge: use add/remove arrays.
	// For replace: use a string array to replace all patterns.
	TLSPassthrough *configureTLSPassthrough `json:"tls_passthrough,omitempty" jsonschema:"TLS passthrough configuration"`

	// InterceptRules configures intercept rules.
	// For merge: use add/remove/enable/disable to modify individual rules.
	// For replace: use rules to replace all rules entirely.
	InterceptRules *configureInterceptRules `json:"intercept_rules,omitempty" jsonschema:"intercept rules configuration"`

	// InterceptQueue configures the intercept queue behavior (timeout, timeout behavior).
	InterceptQueue *configureInterceptQueue `json:"intercept_queue,omitempty" jsonschema:"intercept queue configuration"`

	// AutoTransform configures auto-transform rules for automatic request/response modification.
	// For merge: use add/remove/enable/disable to modify individual rules.
	// For replace: use rules to replace all rules entirely.
	AutoTransform *configureAutoTransform `json:"auto_transform,omitempty" jsonschema:"auto-transform rules configuration"`

	// SOCKS5Auth configures the SOCKS5 authentication method at runtime.
	// If omitted, the current setting is not changed.
	SOCKS5Auth *configureSOCKS5Auth `json:"socks5_auth,omitempty" jsonschema:"SOCKS5 authentication configuration"`

	// TLSFingerprint sets the TLS ClientHello fingerprint profile for upstream connections.
	// Valid values: "chrome", "firefox", "safari", "edge", "random", "none" (standard crypto/tls).
	// If omitted, the current setting is not changed.
	TLSFingerprint *string `json:"tls_fingerprint,omitempty" jsonschema:"TLS fingerprint profile: chrome, firefox, safari, edge, random, none"`

	// MaxConnections dynamically changes the maximum number of concurrent proxy connections.
	// Existing connections exceeding the new limit are not interrupted.
	MaxConnections *int `json:"max_connections,omitempty" jsonschema:"maximum concurrent connections (1-100000)"`

	// PeekTimeoutMs dynamically changes the protocol detection timeout in milliseconds.
	// Takes effect for the next incoming connection.
	PeekTimeoutMs *int `json:"peek_timeout_ms,omitempty" jsonschema:"protocol detection timeout in milliseconds (100-600000)"`

	// RequestTimeoutMs dynamically changes the HTTP request header read timeout in milliseconds.
	// Takes effect for the next incoming request.
	RequestTimeoutMs *int `json:"request_timeout_ms,omitempty" jsonschema:"HTTP request header read timeout in milliseconds (100-600000)"`

	// Budget dynamically configures diagnostic session budget limits.
	// Agent layer budget values must not exceed policy limits.
	Budget *configureBudget `json:"budget,omitempty" jsonschema:"diagnostic session budget configuration"`

	// ClientCert configures the global mTLS client certificate for upstream connections.
	// Set both cert and key paths to enable, or set both to empty strings to disable.
	ClientCert *configureClientCert `json:"client_cert,omitempty" jsonschema:"global mTLS client certificate configuration"`
}

// configureClientCert holds mTLS client certificate configuration.
type configureClientCert struct {
	// CertPath is the path to the PEM-encoded client certificate file.
	// Set to empty string to remove the global client certificate.
	CertPath string `json:"cert_path" jsonschema:"PEM client certificate path (empty to remove)"`

	// KeyPath is the path to the PEM-encoded client private key file.
	// Set to empty string to remove the global client certificate.
	KeyPath string `json:"key_path" jsonschema:"PEM client private key path (empty to remove)"`
}

// configureSOCKS5Auth holds SOCKS5 authentication configuration.
type configureSOCKS5Auth struct {
	// Method is the authentication method: "none" or "password".
	Method string `json:"method" jsonschema:"authentication method: none or password"`

	// Username is the username for password authentication.
	Username string `json:"username,omitempty" jsonschema:"username for password authentication"`

	// Password is the password for password authentication.
	Password string `json:"password,omitempty" jsonschema:"password for password authentication"`

	// ListenerName is the name of the listener to configure.
	// If empty, the default listener is configured.
	ListenerName string `json:"listener_name,omitempty" jsonschema:"listener name to configure (default: 'default')"`
}

// configureSOCKS5AuthResult summarizes SOCKS5 auth state in the configure response.
type configureSOCKS5AuthResult struct {
	Method string `json:"method"`
}

// configureInterceptQueue holds intercept queue configuration.
type configureInterceptQueue struct {
	// TimeoutMs is the timeout in milliseconds for blocked requests (default: 300000 = 5 minutes).
	TimeoutMs *int `json:"timeout_ms,omitempty" jsonschema:"timeout in milliseconds for blocked requests"`

	// TimeoutBehavior specifies what happens when a blocked request times out.
	// Valid values: "auto_release" (default) or "auto_drop".
	TimeoutBehavior string `json:"timeout_behavior,omitempty" jsonschema:"timeout behavior: auto_release (default) or auto_drop"`
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

// configureAutoTransform holds auto-transform rule configuration for both merge and replace operations.
type configureAutoTransform struct {
	// Merge operation fields.
	Add     []transformRuleInput `json:"add,omitempty" jsonschema:"(merge) rules to add"`
	Remove  []string             `json:"remove,omitempty" jsonschema:"(merge) rule IDs to remove"`
	Enable  []string             `json:"enable,omitempty" jsonschema:"(merge) rule IDs to enable"`
	Disable []string             `json:"disable,omitempty" jsonschema:"(merge) rule IDs to disable"`

	// Replace operation fields: full replacement.
	Rules []transformRuleInput `json:"rules,omitempty" jsonschema:"(replace) full list of auto-transform rules"`
}

// configureInterceptRules holds intercept rule configuration for both merge and replace operations.
type configureInterceptRules struct {
	// Merge operation fields.
	Add     []interceptRuleInput `json:"add,omitempty" jsonschema:"(merge) rules to add"`
	Remove  []string             `json:"remove,omitempty" jsonschema:"(merge) rule IDs to remove"`
	Enable  []string             `json:"enable,omitempty" jsonschema:"(merge) rule IDs to enable"`
	Disable []string             `json:"disable,omitempty" jsonschema:"(merge) rule IDs to disable"`

	// Replace operation fields: full replacement.
	Rules []interceptRuleInput `json:"rules,omitempty" jsonschema:"(replace) full list of intercept rules"`
}

// interceptRuleInput is the JSON shape for an intercept rule. The
// Protocol discriminator selects which per-protocol conditions struct is
// consumed (HTTP / WS / GRPC). Empty Protocol defaults to "http" for
// backwards-friendly rule expression.
type interceptRuleInput struct {
	// ID is the unique identifier for this rule.
	ID string `json:"id" jsonschema:"unique rule identifier"`

	// Enabled indicates whether this rule is active.
	Enabled bool `json:"enabled" jsonschema:"whether the rule is active"`

	// Protocol selects the rule engine: "http" (default), "ws", or "grpc".
	Protocol string `json:"protocol,omitempty" jsonschema:"rule engine: http (default), ws, or grpc"`

	// Direction filters by envelope direction. Allowed values depend on
	// Protocol: HTTP accepts request|response|both; WS/gRPC accept
	// send|receive|both.
	Direction string `json:"direction" jsonschema:"direction filter; HTTP: request|response|both; WS/gRPC: send|receive|both"`

	// HTTP carries the HTTP-only conditions when Protocol is "http".
	HTTP *interceptHTTPConditions `json:"http,omitempty" jsonschema:"conditions for HTTP rules"`

	// WS carries the WebSocket-only conditions when Protocol is "ws".
	WS *interceptWSConditions `json:"ws,omitempty" jsonschema:"conditions for WebSocket rules"`

	// GRPC carries the gRPC-only conditions when Protocol is "grpc".
	GRPC *interceptGRPCConditions `json:"grpc,omitempty" jsonschema:"conditions for gRPC rules"`
}

// interceptHTTPConditions holds HTTP rule conditions. All non-empty
// fields are AND-combined.
type interceptHTTPConditions struct {
	HostPattern string            `json:"host_pattern,omitempty" jsonschema:"regex matched against the request hostname"`
	PathPattern string            `json:"path_pattern,omitempty" jsonschema:"regex matched against the URL path"`
	Methods     []string          `json:"methods,omitempty" jsonschema:"HTTP method whitelist (case-insensitive)"`
	HeaderMatch map[string]string `json:"header_match,omitempty" jsonschema:"header name → regex pattern (case-insensitive name lookup)"`
}

// interceptWSConditions holds WebSocket rule conditions.
type interceptWSConditions struct {
	HostPattern    string   `json:"host_pattern,omitempty" jsonschema:"regex matched against the upgrade request hostname"`
	PathPattern    string   `json:"path_pattern,omitempty" jsonschema:"regex matched against the upgrade request path"`
	OpcodeFilter   []string `json:"opcode_filter,omitempty" jsonschema:"opcode names to match: text|binary|close|ping|pong|continuation"`
	PayloadPattern string   `json:"payload_pattern,omitempty" jsonschema:"regex matched against the decompressed frame payload"`
}

// interceptGRPCConditions holds gRPC rule conditions.
type interceptGRPCConditions struct {
	ServicePattern string            `json:"service_pattern,omitempty" jsonschema:"regex matched against the gRPC service name"`
	MethodPattern  string            `json:"method_pattern,omitempty" jsonschema:"regex matched against the gRPC method name"`
	HeaderMatch    map[string]string `json:"header_match,omitempty" jsonschema:"metadata name → regex pattern (case-insensitive)"`
	PayloadPattern string            `json:"payload_pattern,omitempty" jsonschema:"regex matched against the decompressed LPM payload"`
}

// configureBudget holds budget configuration for the configure tool.
type configureBudget struct {
	// MaxTotalRequests sets the maximum number of requests for the session.
	// 0 clears the limit. Nil leaves it unchanged.
	MaxTotalRequests *int64 `json:"max_total_requests,omitempty" jsonschema:"max total requests for the session (0 to clear)"`

	// MaxDuration sets the maximum session duration as a duration string (e.g. "30m").
	// "0s" clears the limit. Nil leaves it unchanged.
	MaxDuration *string `json:"max_duration,omitempty" jsonschema:"max session duration e.g. 30m (0s to clear)"`
}

// configureBudgetResult summarizes budget state in the configure response.
type configureBudgetResult struct {
	Effective    connector.BudgetConfig `json:"effective"`
	RequestCount int64                  `json:"request_count"`
}

// configureResult is the structured output of the configure tool.
type configureResult struct {
	// Status indicates the result of the operation.
	Status string `json:"status"`

	// UpstreamProxy shows the current upstream proxy URL (empty string means direct).
	UpstreamProxy *string `json:"upstream_proxy,omitempty"`

	// TLSPassthrough summarizes the current TLS passthrough state.
	TLSPassthrough *configurePassthroughResult `json:"tls_passthrough,omitempty"`

	// InterceptRules summarizes the current intercept rules state.
	InterceptRules *configureInterceptResult `json:"intercept_rules,omitempty"`

	// InterceptQueue summarizes the current intercept queue configuration.
	InterceptQueue *configureInterceptQueueResult `json:"intercept_queue,omitempty"`

	// AutoTransform summarizes the current auto-transform rules state.
	AutoTransform *configureAutoTransformResult `json:"auto_transform,omitempty"`

	// SOCKS5Auth summarizes the current SOCKS5 authentication state.
	SOCKS5Auth *configureSOCKS5AuthResult `json:"socks5_auth,omitempty"`

	// MaxConnections is the current max connections value (set when changed).
	MaxConnections *int `json:"max_connections,omitempty"`

	// PeekTimeoutMs is the current peek timeout in milliseconds (set when changed).
	PeekTimeoutMs *int64 `json:"peek_timeout_ms,omitempty"`

	// RequestTimeoutMs is the current request timeout in milliseconds (set when changed).
	RequestTimeoutMs *int64 `json:"request_timeout_ms,omitempty"`

	// TLSFingerprint is the current TLS fingerprint profile (set when changed).
	TLSFingerprint *string `json:"tls_fingerprint,omitempty"`

	// Budget summarizes the current budget state (set when changed).
	Budget *configureBudgetResult `json:"budget,omitempty"`

	// ClientCert summarizes the current mTLS client certificate state (set when changed).
	ClientCert *configureClientCertResult `json:"client_cert,omitempty"`
}

// configureClientCertResult summarizes client cert state in the configure response.
type configureClientCertResult struct {
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
	Status   string `json:"status"`
}

// configureInterceptQueueResult summarizes intercept queue state in the configure response.
type configureInterceptQueueResult struct {
	TimeoutMs       int64  `json:"timeout_ms"`
	TimeoutBehavior string `json:"timeout_behavior"`
	QueuedItems     int    `json:"queued_items"`
}

// configurePassthroughResult summarizes TLS passthrough state in the configure response.
type configurePassthroughResult struct {
	TotalPatterns int `json:"total_patterns"`
}

// configureAutoTransformResult summarizes auto-transform rules state in the configure response.
type configureAutoTransformResult struct {
	TotalRules   int `json:"total_rules"`
	EnabledRules int `json:"enabled_rules"`
}

// configureInterceptResult summarizes intercept rules state in the configure response.
type configureInterceptResult struct {
	TotalRules   int `json:"total_rules"`
	EnabledRules int `json:"enabled_rules"`
}

// registerConfigure registers the configure MCP tool.
func (s *Server) registerConfigure() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "configure",
		Description: "Configure runtime proxy settings including upstream proxy, TLS passthrough, intercept rules, intercept queue, auto-transform rules, SOCKS5 authentication, TLS fingerprint profile, and connection limits/timeouts. " +
			"Supports two operations: 'merge' (default) applies incremental add/remove changes, " +
			"'replace' replaces entire configuration sections. " +
			"Upstream proxy routes all outgoing traffic through an HTTP CONNECT or SOCKS5 proxy; set to empty string to disable. " +
			"TLS passthrough controls which CONNECT destinations bypass MITM interception. " +
			"Intercept rules define conditions for intercepting requests/responses (host_pattern regex, path_pattern regex, method whitelist, header regex). " +
			"Intercept queue configures timeout and timeout behavior for blocked requests. " +
			"Auto-transform rules automatically modify matching requests/responses (add/set/remove headers, replace body patterns). " +
			"max_connections dynamically changes the concurrent connection limit. " +
			"peek_timeout_ms and request_timeout_ms dynamically change protocol detection and HTTP request timeouts. " +
			"All sections are optional; only specified sections are modified. " +
			"Note: all settings are session-only (in-memory); they are lost when the proxy restarts. To persist settings, define them in the config file (-config flag).",
	}, s.handleConfigure)
}

// handleConfigure handles the configure tool invocation.
func (s *Server) handleConfigure(ctx context.Context, _ *gomcp.CallToolRequest, input configureInput) (*gomcp.CallToolResult, *configureResult, error) {
	start := time.Now()
	op := input.Operation
	if op == "" {
		op = "merge"
	}
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "configure",
		"operation", op,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "configure",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

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

	if err := s.configureUpstreamProxy(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureMergePassthrough(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureMergeInterceptRules(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureInterceptQueue(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureMergeAutoTransform(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureSOCKS5(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureTLSFingerprint(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.applyConnectionLimits(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureBudgetLimits(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureClientCertSetting(input, result); err != nil {
		return nil, nil, err
	}

	return nil, result, nil
}

// handleConfigureReplace replaces entire configuration sections.
func (s *Server) handleConfigureReplace(input configureInput) (*gomcp.CallToolResult, *configureResult, error) {
	result := &configureResult{Status: "configured"}

	if err := s.configureUpstreamProxy(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureReplacePassthrough(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureReplaceInterceptRules(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureInterceptQueue(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureReplaceAutoTransform(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureSOCKS5(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureTLSFingerprint(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.applyConnectionLimits(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureBudgetLimitsReplace(input, result); err != nil {
		return nil, nil, err
	}
	if err := s.configureClientCertSetting(input, result); err != nil {
		return nil, nil, err
	}

	return nil, result, nil
}

// configureUpstreamProxy applies upstream proxy configuration if provided.
func (s *Server) configureUpstreamProxy(input configureInput, result *configureResult) error {
	if input.UpstreamProxy == nil {
		return nil
	}
	if err := s.applyUpstreamProxy(*input.UpstreamProxy); err != nil {
		return fmt.Errorf("upstream_proxy: %w", err)
	}
	current := ""
	if !managerIsNil(s.connector.manager) {
		current = connector.RedactProxyURL(s.connector.manager.UpstreamProxy())
	}
	result.UpstreamProxy = &current
	return nil
}

// configureMergePassthrough applies merge (delta) TLS passthrough changes if provided.
func (s *Server) configureMergePassthrough(input configureInput, result *configureResult) error {
	if input.TLSPassthrough == nil {
		return nil
	}
	if s.connector.passthrough == nil {
		return fmt.Errorf("TLS passthrough list is not initialized: proxy may not be running")
	}
	s.mergePassthrough(input.TLSPassthrough)
	result.TLSPassthrough = &configurePassthroughResult{
		TotalPatterns: s.connector.passthrough.Len(),
	}
	return nil
}

// configureReplacePassthrough replaces the entire TLS passthrough list if provided.
func (s *Server) configureReplacePassthrough(input configureInput, result *configureResult) error {
	if input.TLSPassthrough == nil {
		return nil
	}
	if s.connector.passthrough == nil {
		return fmt.Errorf("TLS passthrough list is not initialized: proxy may not be running")
	}
	s.replacePassthrough(input.TLSPassthrough)
	result.TLSPassthrough = &configurePassthroughResult{
		TotalPatterns: s.connector.passthrough.Len(),
	}
	return nil
}

// configureMergeInterceptRules applies merge (delta) intercept rule changes if provided.
func (s *Server) configureMergeInterceptRules(input configureInput, result *configureResult) error {
	if input.InterceptRules == nil {
		return nil
	}
	if !anyInterceptEngineReady(s.pipeline) {
		return fmt.Errorf("intercept engines are not initialized: proxy may not be running")
	}
	if err := s.mergeInterceptRules(input.InterceptRules); err != nil {
		return fmt.Errorf("intercept_rules merge: %w", err)
	}
	result.InterceptRules = s.interceptRulesResult()
	return nil
}

// configureReplaceInterceptRules replaces all intercept rules if provided.
func (s *Server) configureReplaceInterceptRules(input configureInput, result *configureResult) error {
	if input.InterceptRules == nil {
		return nil
	}
	if !anyInterceptEngineReady(s.pipeline) {
		return fmt.Errorf("intercept engines are not initialized: proxy may not be running")
	}
	if err := s.replaceInterceptRules(input.InterceptRules); err != nil {
		return fmt.Errorf("intercept_rules replace: %w", err)
	}
	result.InterceptRules = s.interceptRulesResult()
	return nil
}

// configureInterceptQueue applies intercept queue configuration if provided.
func (s *Server) configureInterceptQueue(input configureInput, result *configureResult) error {
	if input.InterceptQueue == nil {
		return nil
	}
	if s.pipeline.holdQueue == nil {
		return fmt.Errorf("intercept queue is not initialized: proxy may not be running")
	}
	if err := s.applyInterceptQueueConfig(input.InterceptQueue); err != nil {
		return fmt.Errorf("intercept_queue: %w", err)
	}
	result.InterceptQueue = s.interceptQueueResult()
	return nil
}

// configureMergeAutoTransform applies merge (delta) auto-transform rule changes if provided.
func (s *Server) configureMergeAutoTransform(input configureInput, result *configureResult) error {
	if input.AutoTransform == nil {
		return nil
	}
	if s.pipeline.transformHTTPEngine == nil {
		return fmt.Errorf("transform engine is not initialized: proxy may not be running")
	}
	if err := s.mergeAutoTransform(input.AutoTransform); err != nil {
		return fmt.Errorf("auto_transform merge: %w", err)
	}
	result.AutoTransform = s.autoTransformResult()
	return nil
}

// configureReplaceAutoTransform replaces all auto-transform rules if provided.
func (s *Server) configureReplaceAutoTransform(input configureInput, result *configureResult) error {
	if input.AutoTransform == nil {
		return nil
	}
	if s.pipeline.transformHTTPEngine == nil {
		return fmt.Errorf("transform engine is not initialized: proxy may not be running")
	}
	if err := s.replaceAutoTransform(input.AutoTransform); err != nil {
		return fmt.Errorf("auto_transform replace: %w", err)
	}
	result.AutoTransform = s.autoTransformResult()
	return nil
}

// configureSOCKS5 applies SOCKS5 authentication configuration if provided.
func (s *Server) configureSOCKS5(input configureInput, result *configureResult) error {
	if input.SOCKS5Auth == nil {
		return nil
	}
	if err := s.applySOCKS5Auth(input.SOCKS5Auth.Method, input.SOCKS5Auth.Username, input.SOCKS5Auth.Password, input.SOCKS5Auth.ListenerName); err != nil {
		return fmt.Errorf("socks5_auth: %w", err)
	}
	result.SOCKS5Auth = &configureSOCKS5AuthResult{Method: input.SOCKS5Auth.Method}
	return nil
}

// configureTLSFingerprint applies TLS fingerprint profile configuration if provided.
func (s *Server) configureTLSFingerprint(input configureInput, result *configureResult) error {
	if input.TLSFingerprint == nil {
		return nil
	}
	if err := s.applyTLSFingerprint(*input.TLSFingerprint); err != nil {
		return fmt.Errorf("tls_fingerprint: %w", err)
	}
	profile := s.currentTLSFingerprint()
	result.TLSFingerprint = &profile
	return nil
}

// applyConnectionLimits validates and applies max_connections, peek_timeout_ms,
// and request_timeout_ms from the configure input. It modifies the result to
// include the new values. This is shared between merge and replace handlers
// since these fields are scalar values, not collections.
func (s *Server) applyConnectionLimits(input configureInput, result *configureResult) error {
	if input.MaxConnections != nil {
		if managerIsNil(s.connector.manager) {
			return fmt.Errorf("proxy manager is not initialized: proxy may not be running")
		}
		n := *input.MaxConnections
		if n < minMaxConnections || n > maxMaxConnections {
			return fmt.Errorf("max_connections must be between %d and %d, got %d", minMaxConnections, maxMaxConnections, n)
		}
		s.connector.manager.SetMaxConnections(n)
		result.MaxConnections = &n
	}
	if input.PeekTimeoutMs != nil {
		if managerIsNil(s.connector.manager) {
			return fmt.Errorf("proxy manager is not initialized: proxy may not be running")
		}
		ms := *input.PeekTimeoutMs
		if ms < minTimeoutMs || ms > maxTimeoutMs {
			return fmt.Errorf("peek_timeout_ms must be between %d and %d, got %d", minTimeoutMs, maxTimeoutMs, ms)
		}
		s.connector.manager.SetPeekTimeout(time.Duration(ms) * time.Millisecond)
		msVal := int64(ms)
		result.PeekTimeoutMs = &msVal
	}
	if input.RequestTimeoutMs != nil {
		ms := *input.RequestTimeoutMs
		if ms < minTimeoutMs || ms > maxTimeoutMs {
			return fmt.Errorf("request_timeout_ms must be between %d and %d, got %d", minTimeoutMs, maxTimeoutMs, ms)
		}
		s.applyRequestTimeout(time.Duration(ms) * time.Millisecond)
		msVal := int64(ms)
		result.RequestTimeoutMs = &msVal
	}
	return nil
}

// mergePassthrough applies delta add/remove operations to the passthrough list.
func (s *Server) mergePassthrough(cfg *configureTLSPassthrough) {
	for _, p := range cfg.Add {
		s.connector.passthrough.Add(p)
	}
	for _, p := range cfg.Remove {
		s.connector.passthrough.Remove(p)
	}
}

// replacePassthrough replaces the entire passthrough list with new patterns.
func (s *Server) replacePassthrough(cfg *configureTLSPassthrough) {
	// Remove all existing patterns.
	for _, p := range s.connector.passthrough.List() {
		s.connector.passthrough.Remove(p)
	}
	// Add new patterns.
	for _, p := range cfg.Patterns {
		s.connector.passthrough.Add(p)
	}
}

// mergeInterceptRules applies delta add/remove/enable/disable operations
// to the per-protocol intercept engines. Each rule's Protocol field
// (defaulting to "http") routes the operation to the corresponding
// engine; rule IDs are looked up across all three engines for the
// remove/enable/disable arms because the input does not carry the
// protocol on those.
func (s *Server) mergeInterceptRules(cfg *configureInterceptRules) error {
	for i, input := range cfg.Add {
		if err := addInterceptRule(s.pipeline, input); err != nil {
			return fmt.Errorf("add[%d]: %w", i, err)
		}
	}
	for i, id := range cfg.Remove {
		if err := removeInterceptRuleAcrossEngines(s.pipeline, id); err != nil {
			return fmt.Errorf("remove[%d]: %w", i, err)
		}
	}
	for i, id := range cfg.Enable {
		if err := enableInterceptRuleAcrossEngines(s.pipeline, id, true); err != nil {
			return fmt.Errorf("enable[%d]: %w", i, err)
		}
	}
	for i, id := range cfg.Disable {
		if err := enableInterceptRuleAcrossEngines(s.pipeline, id, false); err != nil {
			return fmt.Errorf("disable[%d]: %w", i, err)
		}
	}
	return nil
}

// replaceInterceptRules replaces all per-protocol rule sets atomically:
// rules are partitioned by Protocol then SetRules is called on each
// engine (rules absent from a protocol bucket clear that engine).
func (s *Server) replaceInterceptRules(cfg *configureInterceptRules) error {
	return s.applyInterceptRules(cfg.Rules)
}

// interceptRulesResult returns the union state across the three
// per-protocol engines (HTTP / WS / gRPC). TotalRules and EnabledRules
// are summed.
func (s *Server) interceptRulesResult() *configureInterceptResult {
	total, enabled := countInterceptRules(s.pipeline)
	return &configureInterceptResult{
		TotalRules:   total,
		EnabledRules: enabled,
	}
}

// applyInterceptQueueConfig applies HoldQueue timeout and timeout-
// behavior settings.
func (s *Server) applyInterceptQueueConfig(cfg *configureInterceptQueue) error {
	if cfg.TimeoutMs != nil {
		ms := *cfg.TimeoutMs
		if ms < 1000 {
			return fmt.Errorf("timeout_ms must be >= 1000, got %d", ms)
		}
		s.pipeline.holdQueue.SetTimeout(time.Duration(ms) * time.Millisecond)
	}
	if cfg.TimeoutBehavior != "" {
		switch common.TimeoutBehavior(cfg.TimeoutBehavior) {
		case common.TimeoutAutoRelease, common.TimeoutAutoDrop:
			s.pipeline.holdQueue.SetTimeoutBehavior(common.TimeoutBehavior(cfg.TimeoutBehavior))
		default:
			return fmt.Errorf("invalid timeout_behavior %q: must be %q or %q",
				cfg.TimeoutBehavior, common.TimeoutAutoRelease, common.TimeoutAutoDrop)
		}
	}
	return nil
}

// interceptQueueResult returns the current HoldQueue configuration state.
func (s *Server) interceptQueueResult() *configureInterceptQueueResult {
	return &configureInterceptQueueResult{
		TimeoutMs:       s.pipeline.holdQueue.Timeout().Milliseconds(),
		TimeoutBehavior: string(s.pipeline.holdQueue.TimeoutBehavior()),
		QueuedItems:     s.pipeline.holdQueue.Len(),
	}
}

// applyInterceptRules partitions input rules by Protocol and SetRules
// onto the per-protocol engines. A protocol bucket with zero rules
// clears that engine; the helper validates that the corresponding
// engine pointer is non-nil before writing.
func (s *Server) applyInterceptRules(inputs []interceptRuleInput) error {
	httpRules, wsRules, grpcRules, err := compileInterceptRules(inputs)
	if err != nil {
		return err
	}
	if s.pipeline.httpInterceptEngine != nil {
		s.pipeline.httpInterceptEngine.SetRules(httpRules)
	} else if len(httpRules) > 0 {
		return fmt.Errorf("http intercept engine is not initialized")
	}
	if s.pipeline.wsInterceptEngine != nil {
		s.pipeline.wsInterceptEngine.SetRules(wsRules)
	} else if len(wsRules) > 0 {
		return fmt.Errorf("ws intercept engine is not initialized")
	}
	if s.pipeline.grpcInterceptEngine != nil {
		s.pipeline.grpcInterceptEngine.SetRules(grpcRules)
	} else if len(grpcRules) > 0 {
		return fmt.Errorf("grpc intercept engine is not initialized")
	}
	return nil
}

// compileInterceptRules partitions the input slice by Protocol and
// compiles each entry to its protocol-specific rule type.
func compileInterceptRules(inputs []interceptRuleInput) (
	[]httprules.InterceptRule,
	[]wsrules.InterceptRule,
	[]grpcrules.InterceptRule,
	error,
) {
	var httpRules []httprules.InterceptRule
	var wsRules []wsrules.InterceptRule
	var grpcRules []grpcrules.InterceptRule
	for i, input := range inputs {
		proto := protocolOrDefault(input.Protocol)
		switch proto {
		case "http":
			r, err := compileHTTPInterceptRule(input)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("rules[%d]: %w", i, err)
			}
			httpRules = append(httpRules, *r)
		case "ws":
			r, err := compileWSInterceptRule(input)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("rules[%d]: %w", i, err)
			}
			wsRules = append(wsRules, *r)
		case "grpc":
			r, err := compileGRPCInterceptRule(input)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("rules[%d]: %w", i, err)
			}
			grpcRules = append(grpcRules, *r)
		default:
			return nil, nil, nil, fmt.Errorf("rules[%d]: unknown protocol %q (expected http|ws|grpc)", i, input.Protocol)
		}
	}
	return httpRules, wsRules, grpcRules, nil
}

// addInterceptRule compiles a single input and appends it to the
// per-protocol engine. Used by the merge path.
//
// Rejects duplicate IDs across all three engines, matching the legacy
// single-engine intercept.Engine.AddRule contract that the
// configure_tool used to surface. Without this check, callers could
// silently double-register a rule and removeInterceptRuleAcrossEngines
// (which deletes only the first match per engine) would leave
// duplicates in place.
func addInterceptRule(p *Pipeline, input interceptRuleInput) error {
	if input.ID != "" && interceptRuleIDExists(p, input.ID) {
		return fmt.Errorf("rule %q already exists", input.ID)
	}
	proto := protocolOrDefault(input.Protocol)
	switch proto {
	case "http":
		if p.httpInterceptEngine == nil {
			return fmt.Errorf("http intercept engine is not initialized")
		}
		r, err := compileHTTPInterceptRule(input)
		if err != nil {
			return err
		}
		p.httpInterceptEngine.AddRule(*r)
	case "ws":
		if p.wsInterceptEngine == nil {
			return fmt.Errorf("ws intercept engine is not initialized")
		}
		r, err := compileWSInterceptRule(input)
		if err != nil {
			return err
		}
		p.wsInterceptEngine.AddRule(*r)
	case "grpc":
		if p.grpcInterceptEngine == nil {
			return fmt.Errorf("grpc intercept engine is not initialized")
		}
		r, err := compileGRPCInterceptRule(input)
		if err != nil {
			return err
		}
		p.grpcInterceptEngine.AddRule(*r)
	default:
		return fmt.Errorf("unknown protocol %q (expected http|ws|grpc)", input.Protocol)
	}
	return nil
}

// interceptRuleIDExists scans every per-protocol engine for a rule
// matching the supplied ID. Used to enforce the duplicate-ID
// rejection invariant on add and to distinguish missing-rule from
// silent-no-op on remove/enable/disable.
func interceptRuleIDExists(p *Pipeline, id string) bool {
	if p.httpInterceptEngine != nil {
		for _, r := range p.httpInterceptEngine.Rules() {
			if r.ID == id {
				return true
			}
		}
	}
	if p.wsInterceptEngine != nil {
		for _, r := range p.wsInterceptEngine.Rules() {
			if r.ID == id {
				return true
			}
		}
	}
	if p.grpcInterceptEngine != nil {
		for _, r := range p.grpcInterceptEngine.Rules() {
			if r.ID == id {
				return true
			}
		}
	}
	return false
}

// removeInterceptRuleAcrossEngines removes an ID from every per-protocol
// engine. Returns an error if no engine owns a rule with the supplied
// ID — matching the legacy single-engine intercept.Engine.RemoveRule
// contract that the configure_tool used to surface. Each engine's
// RemoveRule is silently idempotent at the engine level, so the
// pre-scan is the only place where the missing-ID case is observable.
func removeInterceptRuleAcrossEngines(p *Pipeline, id string) error {
	if !interceptRuleIDExists(p, id) {
		return fmt.Errorf("rule %q not found", id)
	}
	if p.httpInterceptEngine != nil {
		p.httpInterceptEngine.RemoveRule(id)
	}
	if p.wsInterceptEngine != nil {
		p.wsInterceptEngine.RemoveRule(id)
	}
	if p.grpcInterceptEngine != nil {
		p.grpcInterceptEngine.RemoveRule(id)
	}
	return nil
}

// enableInterceptRuleAcrossEngines toggles Enabled on every engine that
// owns a rule with the given ID. Returns an error if no engine
// reported a hit — matching the legacy contract surfaced by
// configure_tool.
func enableInterceptRuleAcrossEngines(p *Pipeline, id string, enabled bool) error {
	hit := false
	if p.httpInterceptEngine != nil {
		if p.httpInterceptEngine.EnableRule(id, enabled) {
			hit = true
		}
	}
	if p.wsInterceptEngine != nil {
		if p.wsInterceptEngine.EnableRule(id, enabled) {
			hit = true
		}
	}
	if p.grpcInterceptEngine != nil {
		if p.grpcInterceptEngine.EnableRule(id, enabled) {
			hit = true
		}
	}
	if !hit {
		return fmt.Errorf("rule %q not found", id)
	}
	return nil
}

// countInterceptRules sums the rule counts and enabled counts across
// the three per-protocol engines.
func countInterceptRules(p *Pipeline) (total, enabled int) {
	if p.httpInterceptEngine != nil {
		for _, r := range p.httpInterceptEngine.Rules() {
			total++
			if r.Enabled {
				enabled++
			}
		}
	}
	if p.wsInterceptEngine != nil {
		for _, r := range p.wsInterceptEngine.Rules() {
			total++
			if r.Enabled {
				enabled++
			}
		}
	}
	if p.grpcInterceptEngine != nil {
		for _, r := range p.grpcInterceptEngine.Rules() {
			total++
			if r.Enabled {
				enabled++
			}
		}
	}
	return total, enabled
}

// anyInterceptEngineReady returns true when at least one per-protocol
// intercept engine is non-nil. The configure_tool's intercept_rules
// path requires at least one ready engine to make progress.
func anyInterceptEngineReady(p *Pipeline) bool {
	return p.httpInterceptEngine != nil || p.wsInterceptEngine != nil || p.grpcInterceptEngine != nil
}

// protocolOrDefault returns the canonical protocol discriminator value.
// An empty input is treated as "http" so existing config payloads that
// omit the field continue to drive HTTP rule matching.
func protocolOrDefault(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "http":
		return "http"
	case "ws", "websocket":
		return "ws"
	case "grpc":
		return "grpc"
	default:
		return p
	}
}

// compileHTTPInterceptRule compiles an HTTP interceptRuleInput into a
// per-protocol rule. Direction and condition fields are validated.
func compileHTTPInterceptRule(input interceptRuleInput) (*httprules.InterceptRule, error) {
	if input.HTTP == nil {
		return nil, fmt.Errorf("http: conditions are required (set http.host_pattern, http.path_pattern, http.methods, or http.header_match)")
	}
	dir, err := normalizeHTTPDirection(input.Direction)
	if err != nil {
		return nil, err
	}
	rule, err := httprules.CompileInterceptRule(
		input.ID,
		dir,
		input.HTTP.HostPattern,
		input.HTTP.PathPattern,
		input.HTTP.Methods,
		input.HTTP.HeaderMatch,
	)
	if err != nil {
		return nil, err
	}
	rule.Enabled = input.Enabled
	return rule, nil
}

// compileWSInterceptRule compiles a WebSocket interceptRuleInput.
func compileWSInterceptRule(input interceptRuleInput) (*wsrules.InterceptRule, error) {
	if input.WS == nil {
		return nil, fmt.Errorf("ws: conditions are required")
	}
	dir, err := normalizeStreamDirection(input.Direction)
	if err != nil {
		return nil, err
	}
	opcodes, err := compileWSOpcodeFilter(input.WS.OpcodeFilter)
	if err != nil {
		return nil, err
	}
	rule, err := wsrules.CompileInterceptRule(
		input.ID,
		wsrules.RuleDirection(dir),
		input.WS.HostPattern,
		input.WS.PathPattern,
		opcodes,
		input.WS.PayloadPattern,
	)
	if err != nil {
		return nil, err
	}
	rule.Enabled = input.Enabled
	return rule, nil
}

// compileGRPCInterceptRule compiles a gRPC interceptRuleInput.
func compileGRPCInterceptRule(input interceptRuleInput) (*grpcrules.InterceptRule, error) {
	if input.GRPC == nil {
		return nil, fmt.Errorf("grpc: conditions are required")
	}
	dir, err := normalizeStreamDirection(input.Direction)
	if err != nil {
		return nil, err
	}
	rule, err := grpcrules.CompileInterceptRule(
		input.ID,
		grpcrules.RuleDirection(dir),
		input.GRPC.ServicePattern,
		input.GRPC.MethodPattern,
		input.GRPC.HeaderMatch,
		input.GRPC.PayloadPattern,
	)
	if err != nil {
		return nil, err
	}
	rule.Enabled = input.Enabled
	return rule, nil
}

// normalizeHTTPDirection canonicalises the direction string for HTTP
// rules. Empty defaults to "both".
func normalizeHTTPDirection(d string) (httprules.RuleDirection, error) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "", "both":
		return httprules.DirectionBoth, nil
	case "request":
		return httprules.DirectionRequest, nil
	case "response":
		return httprules.DirectionResponse, nil
	default:
		return "", fmt.Errorf("direction: unknown value %q (expected request|response|both)", d)
	}
}

// normalizeStreamDirection canonicalises the direction string for
// streaming rule kinds (WS, gRPC) that operate on send/receive frames.
// Empty defaults to "both".
func normalizeStreamDirection(d string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "", "both":
		return "both", nil
	case "send":
		return "send", nil
	case "receive":
		return "receive", nil
	default:
		return "", fmt.Errorf("direction: unknown value %q (expected send|receive|both)", d)
	}
}

// compileWSOpcodeFilter converts a list of opcode names into the
// numeric opcode constants used by the WS engine. Empty input means
// "match all opcodes".
func compileWSOpcodeFilter(names []string) ([]envelope.WSOpcode, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make([]envelope.WSOpcode, 0, len(names))
	for _, name := range names {
		op, err := wsOpcodeFromName(name)
		if err != nil {
			return nil, fmt.Errorf("opcode_filter: %w", err)
		}
		out = append(out, op)
	}
	return out, nil
}

// mergeAutoTransform applies delta add/remove/enable/disable operations to
// auto-transform rules on the per-protocol HTTP engine. Mirrors the
// per-rule dispatch pattern from intercept_rules (USK-692) collapsed to a
// single engine because the auto_transform schema is HTTP-only.
func (s *Server) mergeAutoTransform(cfg *configureAutoTransform) error {
	engine := s.pipeline.transformHTTPEngine
	for i, input := range cfg.Add {
		if input.ID != "" && transformRuleIDExists(engine, input.ID) {
			return fmt.Errorf("add[%d]: rule %q already exists", i, input.ID)
		}
		r, err := compileTransformRule(input)
		if err != nil {
			return fmt.Errorf("add[%d]: %w", i, err)
		}
		engine.AddRule(*r)
	}
	for i, id := range cfg.Remove {
		if !engine.RemoveRule(id) {
			return fmt.Errorf("remove[%d]: rule %q not found", i, id)
		}
	}
	for i, id := range cfg.Enable {
		if !engine.EnableRule(id, true) {
			return fmt.Errorf("enable[%d]: rule %q not found", i, id)
		}
	}
	for i, id := range cfg.Disable {
		if !engine.EnableRule(id, false) {
			return fmt.Errorf("disable[%d]: rule %q not found", i, id)
		}
	}
	return nil
}

// replaceAutoTransform replaces all auto-transform rules atomically.
func (s *Server) replaceAutoTransform(cfg *configureAutoTransform) error {
	return s.applyTransformRules(cfg.Rules)
}

// transformRuleIDExists returns true when the engine already holds a rule
// with the supplied ID. Used for duplicate-ID rejection on the merge add
// path.
func transformRuleIDExists(engine *httprules.TransformEngine, id string) bool {
	if engine == nil {
		return false
	}
	for _, r := range engine.Rules() {
		if r.ID == id {
			return true
		}
	}
	return false
}

// configureBudgetLimits applies budget configuration if provided.
// In merge mode: uses merge semantics — only explicitly provided fields are updated;
// omitted fields retain their current values.
// In replace mode: uses full-replace semantics — starts from a zero BudgetConfig;
// omitted fields reset to zero (no limit).
// For full-replace semantics via the security tool, use set_budget instead.
func (s *Server) configureBudgetLimits(input configureInput, result *configureResult) error {
	return s.configureBudgetLimitsWithOp(input, result, "merge")
}

// configureBudgetLimitsReplace applies budget configuration with replace semantics.
func (s *Server) configureBudgetLimitsReplace(input configureInput, result *configureResult) error {
	return s.configureBudgetLimitsWithOp(input, result, "replace")
}

// configureBudgetLimitsWithOp applies budget configuration with the specified operation mode.
func (s *Server) configureBudgetLimitsWithOp(input configureInput, result *configureResult, op string) error {
	if input.Budget == nil {
		return nil
	}
	if s.misc.budgetManager == nil {
		return fmt.Errorf("budget manager is not initialized")
	}

	// In merge mode, start from the current agent config (preserve omitted fields).
	// In replace mode, start from zero (omitted fields reset to no limit).
	var cfg connector.BudgetConfig
	if op == "merge" {
		cfg = s.misc.budgetManager.AgentBudget()
	}

	if input.Budget.MaxTotalRequests != nil {
		if *input.Budget.MaxTotalRequests < 0 {
			return fmt.Errorf("budget max_total_requests must be >= 0")
		}
		cfg.MaxTotalRequests = *input.Budget.MaxTotalRequests
	}
	if input.Budget.MaxDuration != nil {
		d, err := time.ParseDuration(*input.Budget.MaxDuration)
		if err != nil {
			return fmt.Errorf("budget invalid max_duration %q: %w", *input.Budget.MaxDuration, err)
		}
		if d < 0 {
			return fmt.Errorf("budget max_duration must be >= 0")
		}
		cfg.MaxDuration = d
	}

	if err := s.misc.budgetManager.SetAgentBudget(cfg); err != nil {
		return fmt.Errorf("budget: %w", err)
	}

	result.Budget = &configureBudgetResult{
		Effective:    s.misc.budgetManager.EffectiveBudget(),
		RequestCount: s.misc.budgetManager.RequestCount(),
	}
	return nil
}

// configureClientCertSetting applies global mTLS client certificate configuration if provided.
func (s *Server) configureClientCertSetting(input configureInput, result *configureResult) error {
	if input.ClientCert == nil {
		return nil
	}
	if s.connector.hostTLSRegistry == nil {
		return fmt.Errorf("host TLS registry is not initialized")
	}

	// Empty paths mean "remove the global client certificate".
	if input.ClientCert.CertPath == "" && input.ClientCert.KeyPath == "" {
		s.connector.hostTLSRegistry.SetGlobal(nil)
		result.ClientCert = &configureClientCertResult{Status: "removed"}
		return nil
	}

	if err := s.applyClientCert(input.ClientCert.CertPath, input.ClientCert.KeyPath); err != nil {
		return fmt.Errorf("client_cert: %w", err)
	}
	result.ClientCert = &configureClientCertResult{
		CertPath: input.ClientCert.CertPath,
		KeyPath:  input.ClientCert.KeyPath,
		Status:   "configured",
	}
	return nil
}

// autoTransformResult returns the current auto-transform rules state.
func (s *Server) autoTransformResult() *configureAutoTransformResult {
	rulesList := s.pipeline.transformHTTPEngine.Rules()
	enabled := 0
	for _, r := range rulesList {
		if r.Enabled {
			enabled++
		}
	}
	return &configureAutoTransformResult{
		TotalRules:   len(rulesList),
		EnabledRules: enabled,
	}
}
