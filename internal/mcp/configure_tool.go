package mcp

import (
	"context"
	"fmt"
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

	// MaxConnections dynamically changes the maximum number of concurrent proxy connections.
	// Existing connections exceeding the new limit are not interrupted.
	MaxConnections *int `json:"max_connections,omitempty" jsonschema:"maximum concurrent connections (1-100000)"`

	// PeekTimeoutMs dynamically changes the protocol detection timeout in milliseconds.
	// Takes effect for the next incoming connection.
	PeekTimeoutMs *int `json:"peek_timeout_ms,omitempty" jsonschema:"protocol detection timeout in milliseconds (100-600000)"`

	// RequestTimeoutMs dynamically changes the HTTP request header read timeout in milliseconds.
	// Takes effect for the next incoming request.
	RequestTimeoutMs *int `json:"request_timeout_ms,omitempty" jsonschema:"HTTP request header read timeout in milliseconds (100-600000)"`
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

	// MaxConnections is the current max connections value (set when changed).
	MaxConnections *int `json:"max_connections,omitempty"`

	// PeekTimeoutMs is the current peek timeout in milliseconds (set when changed).
	PeekTimeoutMs *int64 `json:"peek_timeout_ms,omitempty"`

	// RequestTimeoutMs is the current request timeout in milliseconds (set when changed).
	RequestTimeoutMs *int64 `json:"request_timeout_ms,omitempty"`
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
		Description: "Configure runtime proxy settings including upstream proxy, capture scope, TLS passthrough, intercept rules, intercept queue, auto-transform rules, and connection limits/timeouts. " +
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
			"All sections are optional; only specified sections are modified.",
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

	if input.UpstreamProxy != nil {
		if err := s.applyUpstreamProxy(*input.UpstreamProxy); err != nil {
			return nil, nil, fmt.Errorf("upstream_proxy: %w", err)
		}
		current := ""
		if s.manager != nil {
			current = proxy.RedactProxyURL(s.manager.UpstreamProxy())
		}
		result.UpstreamProxy = &current
	}

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

	if input.InterceptRules != nil {
		if s.interceptEngine == nil {
			return nil, nil, fmt.Errorf("intercept engine is not initialized: proxy may not be running")
		}
		if err := s.mergeInterceptRules(input.InterceptRules); err != nil {
			return nil, nil, fmt.Errorf("intercept_rules merge: %w", err)
		}
		result.InterceptRules = s.interceptRulesResult()
	}

	if input.InterceptQueue != nil {
		if s.interceptQueue == nil {
			return nil, nil, fmt.Errorf("intercept queue is not initialized: proxy may not be running")
		}
		if err := s.applyInterceptQueueConfig(input.InterceptQueue); err != nil {
			return nil, nil, fmt.Errorf("intercept_queue: %w", err)
		}
		result.InterceptQueue = s.interceptQueueResult()
	}

	if input.AutoTransform != nil {
		if s.transformPipeline == nil {
			return nil, nil, fmt.Errorf("transform pipeline is not initialized: proxy may not be running")
		}
		if err := s.mergeAutoTransform(input.AutoTransform); err != nil {
			return nil, nil, fmt.Errorf("auto_transform merge: %w", err)
		}
		result.AutoTransform = s.autoTransformResult()
	}

	if err := s.applyConnectionLimits(input, result); err != nil {
		return nil, nil, err
	}

	return nil, result, nil
}

// handleConfigureReplace replaces entire configuration sections.
func (s *Server) handleConfigureReplace(input configureInput) (*gomcp.CallToolResult, *configureResult, error) {
	result := &configureResult{Status: "configured"}

	if input.UpstreamProxy != nil {
		if err := s.applyUpstreamProxy(*input.UpstreamProxy); err != nil {
			return nil, nil, fmt.Errorf("upstream_proxy: %w", err)
		}
		current := ""
		if s.manager != nil {
			current = proxy.RedactProxyURL(s.manager.UpstreamProxy())
		}
		result.UpstreamProxy = &current
	}

	if input.CaptureScope != nil {
		if s.scope == nil {
			return nil, nil, fmt.Errorf("capture scope is not initialized: proxy may not be running")
		}
		// Validate rules before applying.
		if err := validateScopeRules("include", input.CaptureScope.Includes); err != nil {
			return nil, nil, fmt.Errorf("capture_scope replace: %w", err)
		}
		if err := validateScopeRules("exclude", input.CaptureScope.Excludes); err != nil {
			return nil, nil, fmt.Errorf("capture_scope replace: %w", err)
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

	if input.InterceptRules != nil {
		if s.interceptEngine == nil {
			return nil, nil, fmt.Errorf("intercept engine is not initialized: proxy may not be running")
		}
		if err := s.replaceInterceptRules(input.InterceptRules); err != nil {
			return nil, nil, fmt.Errorf("intercept_rules replace: %w", err)
		}
		result.InterceptRules = s.interceptRulesResult()
	}

	if input.InterceptQueue != nil {
		if s.interceptQueue == nil {
			return nil, nil, fmt.Errorf("intercept queue is not initialized: proxy may not be running")
		}
		if err := s.applyInterceptQueueConfig(input.InterceptQueue); err != nil {
			return nil, nil, fmt.Errorf("intercept_queue: %w", err)
		}
		result.InterceptQueue = s.interceptQueueResult()
	}

	if input.AutoTransform != nil {
		if s.transformPipeline == nil {
			return nil, nil, fmt.Errorf("transform pipeline is not initialized: proxy may not be running")
		}
		if err := s.replaceAutoTransform(input.AutoTransform); err != nil {
			return nil, nil, fmt.Errorf("auto_transform replace: %w", err)
		}
		result.AutoTransform = s.autoTransformResult()
	}

	if err := s.applyConnectionLimits(input, result); err != nil {
		return nil, nil, err
	}

	return nil, result, nil
}

// applyConnectionLimits validates and applies max_connections, peek_timeout_ms,
// and request_timeout_ms from the configure input. It modifies the result to
// include the new values. This is shared between merge and replace handlers
// since these fields are scalar values, not collections.
func (s *Server) applyConnectionLimits(input configureInput, result *configureResult) error {
	if input.MaxConnections != nil {
		if s.manager == nil {
			return fmt.Errorf("proxy manager is not initialized: proxy may not be running")
		}
		n := *input.MaxConnections
		if n < minMaxConnections || n > maxMaxConnections {
			return fmt.Errorf("max_connections must be between %d and %d, got %d", minMaxConnections, maxMaxConnections, n)
		}
		s.manager.SetMaxConnections(n)
		result.MaxConnections = &n
	}
	if input.PeekTimeoutMs != nil {
		if s.manager == nil {
			return fmt.Errorf("proxy manager is not initialized: proxy may not be running")
		}
		ms := *input.PeekTimeoutMs
		if ms < minTimeoutMs || ms > maxTimeoutMs {
			return fmt.Errorf("peek_timeout_ms must be between %d and %d, got %d", minTimeoutMs, maxTimeoutMs, ms)
		}
		s.manager.SetPeekTimeout(time.Duration(ms) * time.Millisecond)
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

	s.scope.MergeRules(
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
		if err := s.interceptEngine.AddRule(r); err != nil {
			return err
		}
	}

	// Process removals.
	for _, id := range cfg.Remove {
		if err := s.interceptEngine.RemoveRule(id); err != nil {
			return err
		}
	}

	// Process enable.
	for _, id := range cfg.Enable {
		if err := s.interceptEngine.EnableRule(id, true); err != nil {
			return err
		}
	}

	// Process disable.
	for _, id := range cfg.Disable {
		if err := s.interceptEngine.EnableRule(id, false); err != nil {
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
	rules := s.interceptEngine.Rules()
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
		s.interceptQueue.SetTimeout(time.Duration(ms) * time.Millisecond)
	}
	if cfg.TimeoutBehavior != "" {
		switch intercept.TimeoutBehavior(cfg.TimeoutBehavior) {
		case intercept.TimeoutAutoRelease, intercept.TimeoutAutoDrop:
			s.interceptQueue.SetTimeoutBehavior(intercept.TimeoutBehavior(cfg.TimeoutBehavior))
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
		TimeoutMs:       s.interceptQueue.Timeout().Milliseconds(),
		TimeoutBehavior: string(s.interceptQueue.TimeoutBehaviorValue()),
		QueuedItems:     s.interceptQueue.Len(),
	}
}

// mergeAutoTransform applies delta add/remove/enable/disable operations to auto-transform rules.
func (s *Server) mergeAutoTransform(cfg *configureAutoTransform) error {
	// Process additions first.
	for _, input := range cfg.Add {
		r := toTransformRule(input)
		if err := s.transformPipeline.AddRule(r); err != nil {
			return err
		}
	}

	// Process removals.
	for _, id := range cfg.Remove {
		if err := s.transformPipeline.RemoveRule(id); err != nil {
			return err
		}
	}

	// Process enable.
	for _, id := range cfg.Enable {
		if err := s.transformPipeline.EnableRule(id, true); err != nil {
			return err
		}
	}

	// Process disable.
	for _, id := range cfg.Disable {
		if err := s.transformPipeline.EnableRule(id, false); err != nil {
			return err
		}
	}

	return nil
}

// replaceAutoTransform replaces all auto-transform rules atomically.
func (s *Server) replaceAutoTransform(cfg *configureAutoTransform) error {
	return s.applyTransformRules(cfg.Rules)
}

// autoTransformResult returns the current auto-transform rules state.
func (s *Server) autoTransformResult() *configureAutoTransformResult {
	rulesList := s.transformPipeline.Rules()
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

