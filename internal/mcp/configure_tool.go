package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
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

	// CaptureScope configures request capture scope rules.
	// For merge: use add_includes/remove_includes/add_excludes/remove_excludes.
	// For replace: use includes/excludes to replace all rules.
	CaptureScope *configureCaptureScope `json:"capture_scope,omitempty" jsonschema:"capture scope configuration"`

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
	Effective    proxy.BudgetConfig `json:"effective"`
	RequestCount int64              `json:"request_count"`
}

// configureResult is the structured output of the configure tool.
type configureResult struct {
	// Status indicates the result of the operation.
	Status string `json:"status"`

	// UpstreamProxy shows the current upstream proxy URL (empty string means direct).
	UpstreamProxy *string `json:"upstream_proxy,omitempty"`

	// CaptureScope summarizes the current capture scope state.
	CaptureScope *configureScopeResult `json:"capture_scope,omitempty"`

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

// configureScopeResult summarizes capture scope state in the configure response.
type configureScopeResult struct {
	IncludeCount int `json:"include_count"`
	ExcludeCount int `json:"exclude_count"`
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
		Description: "Configure runtime proxy settings including upstream proxy, capture scope, TLS passthrough, intercept rules, intercept queue, auto-transform rules, SOCKS5 authentication, TLS fingerprint profile, and connection limits/timeouts. " +
			"Supports two operations: 'merge' (default) applies incremental add/remove changes, " +
			"'replace' replaces entire configuration sections. " +
			"Upstream proxy routes all outgoing traffic through an HTTP CONNECT or SOCKS5 proxy; set to empty string to disable. " +
			"Capture scope controls which requests are recorded (include/exclude rules with hostname, url_prefix, method). " +
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
	if err := s.configureMergeScope(input, result); err != nil {
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
	if err := s.configureReplaceScope(input, result); err != nil {
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
	if s.connector.manager != nil {
		current = proxy.RedactProxyURL(s.connector.manager.UpstreamProxy())
	}
	result.UpstreamProxy = &current
	return nil
}

// configureMergeScope applies merge (delta) capture scope changes if provided.
func (s *Server) configureMergeScope(input configureInput, result *configureResult) error {
	if input.CaptureScope == nil {
		return nil
	}
	if s.connector.scope == nil {
		return fmt.Errorf("capture scope is not initialized: proxy may not be running")
	}
	if err := s.mergeScope(input.CaptureScope); err != nil {
		return fmt.Errorf("capture_scope merge: %w", err)
	}
	includes, excludes := s.connector.scope.Rules()
	result.CaptureScope = &configureScopeResult{
		IncludeCount: len(includes),
		ExcludeCount: len(excludes),
	}
	return nil
}

// configureReplaceScope replaces the entire capture scope if provided.
func (s *Server) configureReplaceScope(input configureInput, result *configureResult) error {
	if input.CaptureScope == nil {
		return nil
	}
	if s.connector.scope == nil {
		return fmt.Errorf("capture scope is not initialized: proxy may not be running")
	}
	if err := validateScopeRules("include", input.CaptureScope.Includes); err != nil {
		return fmt.Errorf("capture_scope replace: %w", err)
	}
	if err := validateScopeRules("exclude", input.CaptureScope.Excludes); err != nil {
		return fmt.Errorf("capture_scope replace: %w", err)
	}
	includes := toScopeRules(input.CaptureScope.Includes)
	excludes := toScopeRules(input.CaptureScope.Excludes)
	s.connector.scope.SetRules(includes, excludes)
	result.CaptureScope = &configureScopeResult{
		IncludeCount: len(includes),
		ExcludeCount: len(excludes),
	}
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
	if s.pipeline.interceptEngine == nil {
		return fmt.Errorf("intercept engine is not initialized: proxy may not be running")
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
	if s.pipeline.interceptEngine == nil {
		return fmt.Errorf("intercept engine is not initialized: proxy may not be running")
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
	if s.pipeline.interceptQueue == nil {
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
	if s.pipeline.transformPipeline == nil {
		return fmt.Errorf("transform pipeline is not initialized: proxy may not be running")
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
	if s.pipeline.transformPipeline == nil {
		return fmt.Errorf("transform pipeline is not initialized: proxy may not be running")
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
		if s.connector.manager == nil {
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
		if s.connector.manager == nil {
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

// mergeScope applies delta add/remove operations to the capture scope.
// It uses CaptureScope.MergeRules for atomic read-modify-write.
func (s *Server) mergeScope(cfg *configureCaptureScope) error {
	// Validate rules before applying.
	if err := validateScopeRules("add_includes", cfg.AddIncludes); err != nil {
		return err
	}
	if err := validateScopeRules("add_excludes", cfg.AddExcludes); err != nil {
		return err
	}

	s.connector.scope.MergeRules(
		toScopeRules(cfg.AddIncludes),
		toScopeRules(cfg.RemoveIncludes),
		toScopeRules(cfg.AddExcludes),
		toScopeRules(cfg.RemoveExcludes),
	)
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

// validateScopeRules checks that every rule has at least one non-empty field.
// It returns an error indicating the first invalid rule found.
func validateScopeRules(kind string, rules []scopeRuleInput) error {
	for i, r := range rules {
		if r.Hostname == "" && r.URLPrefix == "" && r.Method == "" {
			return fmt.Errorf("%s rule %d has no fields set: at least one of hostname, url_prefix, or method must be specified", kind, i)
		}
	}
	return nil
}

// mergeInterceptRules applies delta add/remove/enable/disable operations to intercept rules.
func (s *Server) mergeInterceptRules(cfg *configureInterceptRules) error {
	// Process additions first.
	for _, input := range cfg.Add {
		r := toInterceptRule(input)
		if err := s.pipeline.interceptEngine.AddRule(r); err != nil {
			return err
		}
	}

	// Process removals.
	for _, id := range cfg.Remove {
		if err := s.pipeline.interceptEngine.RemoveRule(id); err != nil {
			return err
		}
	}

	// Process enable.
	for _, id := range cfg.Enable {
		if err := s.pipeline.interceptEngine.EnableRule(id, true); err != nil {
			return err
		}
	}

	// Process disable.
	for _, id := range cfg.Disable {
		if err := s.pipeline.interceptEngine.EnableRule(id, false); err != nil {
			return err
		}
	}

	return nil
}

// replaceInterceptRules replaces all intercept rules atomically.
func (s *Server) replaceInterceptRules(cfg *configureInterceptRules) error {
	rules := make([]interceptRuleInput, len(cfg.Rules))
	copy(rules, cfg.Rules)

	return s.applyInterceptRules(rules)
}

// interceptRulesResult returns the current intercept rules state.
func (s *Server) interceptRulesResult() *configureInterceptResult {
	rules := s.pipeline.interceptEngine.Rules()
	enabled := 0
	for _, r := range rules {
		if r.Enabled {
			enabled++
		}
	}
	return &configureInterceptResult{
		TotalRules:   len(rules),
		EnabledRules: enabled,
	}
}

// applyInterceptQueueConfig applies intercept queue configuration.
func (s *Server) applyInterceptQueueConfig(cfg *configureInterceptQueue) error {
	if cfg.TimeoutMs != nil {
		ms := *cfg.TimeoutMs
		if ms < 1000 {
			return fmt.Errorf("timeout_ms must be >= 1000, got %d", ms)
		}
		s.pipeline.interceptQueue.SetTimeout(time.Duration(ms) * time.Millisecond)
	}
	if cfg.TimeoutBehavior != "" {
		switch intercept.TimeoutBehavior(cfg.TimeoutBehavior) {
		case intercept.TimeoutAutoRelease, intercept.TimeoutAutoDrop:
			s.pipeline.interceptQueue.SetTimeoutBehavior(intercept.TimeoutBehavior(cfg.TimeoutBehavior))
		default:
			return fmt.Errorf("invalid timeout_behavior %q: must be %q or %q",
				cfg.TimeoutBehavior, intercept.TimeoutAutoRelease, intercept.TimeoutAutoDrop)
		}
	}
	return nil
}

// interceptQueueResult returns the current intercept queue configuration state.
func (s *Server) interceptQueueResult() *configureInterceptQueueResult {
	return &configureInterceptQueueResult{
		TimeoutMs:       s.pipeline.interceptQueue.Timeout().Milliseconds(),
		TimeoutBehavior: string(s.pipeline.interceptQueue.TimeoutBehaviorValue()),
		QueuedItems:     s.pipeline.interceptQueue.Len(),
	}
}

// mergeAutoTransform applies delta add/remove/enable/disable operations to auto-transform rules.
func (s *Server) mergeAutoTransform(cfg *configureAutoTransform) error {
	// Process additions first.
	for _, input := range cfg.Add {
		r := toTransformRule(input)
		if err := s.pipeline.transformPipeline.AddRule(r); err != nil {
			return err
		}
	}

	// Process removals.
	for _, id := range cfg.Remove {
		if err := s.pipeline.transformPipeline.RemoveRule(id); err != nil {
			return err
		}
	}

	// Process enable.
	for _, id := range cfg.Enable {
		if err := s.pipeline.transformPipeline.EnableRule(id, true); err != nil {
			return err
		}
	}

	// Process disable.
	for _, id := range cfg.Disable {
		if err := s.pipeline.transformPipeline.EnableRule(id, false); err != nil {
			return err
		}
	}

	return nil
}

// replaceAutoTransform replaces all auto-transform rules atomically.
func (s *Server) replaceAutoTransform(cfg *configureAutoTransform) error {
	return s.applyTransformRules(cfg.Rules)
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
	var cfg proxy.BudgetConfig
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
	rulesList := s.pipeline.transformPipeline.Rules()
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
