package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// securityInput is the typed input for the security tool.
type securityInput struct {
	// Action specifies the security action to execute.
	// Available actions: set_target_scope, update_target_scope, get_target_scope, test_target, set_rate_limits, get_rate_limits, set_budget, get_budget.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params securityParams `json:"params"`
}

// securityParams holds the union of all security action parameters.
// Only the fields relevant to the specified action are used.
type securityParams struct {
	// set_target_scope: replace all rules
	Allows []targetRuleInput `json:"allows,omitempty" jsonschema:"allow rules (set_target_scope)"`
	Denies []targetRuleInput `json:"denies,omitempty" jsonschema:"deny rules (set_target_scope)"`

	// update_target_scope: merge delta
	AddAllows    []targetRuleInput `json:"add_allows,omitempty" jsonschema:"allow rules to add (update_target_scope)"`
	RemoveAllows []targetRuleInput `json:"remove_allows,omitempty" jsonschema:"allow rules to remove (update_target_scope)"`
	AddDenies    []targetRuleInput `json:"add_denies,omitempty" jsonschema:"deny rules to add (update_target_scope)"`
	RemoveDenies []targetRuleInput `json:"remove_denies,omitempty" jsonschema:"deny rules to remove (update_target_scope)"`

	// test_target: dry-run URL check
	URL string `json:"url,omitempty" jsonschema:"URL to test against target scope rules (test_target)"`

	// set_rate_limits: agent layer rate limits
	MaxRequestsPerSecond        *float64 `json:"max_requests_per_second,omitempty" jsonschema:"global rate limit in RPS (set_rate_limits)"`
	MaxRequestsPerHostPerSecond *float64 `json:"max_requests_per_host_per_second,omitempty" jsonschema:"per-host rate limit in RPS (set_rate_limits)"`

	// set_budget: agent layer budget limits
	MaxTotalRequests *int64  `json:"max_total_requests,omitempty" jsonschema:"max total requests for the session (set_budget)"`
	MaxDuration      *string `json:"max_duration,omitempty" jsonschema:"max session duration e.g. 30m (set_budget)"`
}

// targetRuleInput is the JSON input representation of a target rule.
type targetRuleInput struct {
	Hostname   string   `json:"hostname"`
	Ports      []int    `json:"ports,omitempty"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	Schemes    []string `json:"schemes,omitempty"`
}

// availableSecurityActions lists the valid action names for error messages.
var availableSecurityActions = []string{"set_target_scope", "update_target_scope", "get_target_scope", "test_target", "set_rate_limits", "get_rate_limits", "set_budget", "get_budget", "get_safety_filter"}

// registerSecurity registers the security MCP tool.
func (s *Server) registerSecurity() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "security",
		Description: "Configure runtime security settings including target scope rules, rate limits, and diagnostic budgets. " +
			"Target scope uses a two-layer architecture: Policy Layer (immutable, set by config) " +
			"and Agent Layer (mutable via this tool). This tool only modifies Agent Layer rules; " +
			"Policy Layer rules are read-only. Agent allow rules must fall within the Policy " +
			"allow boundary. Rate limits and budgets also use the two-layer architecture. " +
			"Available actions: " +
			"'set_target_scope' replaces all Agent Layer allow/deny rules (use empty arrays to clear rules); " +
			"'update_target_scope' applies incremental add/remove changes to Agent Layer rules; " +
			"'get_target_scope' returns Policy and Agent Layer rules with enforcement mode; " +
			"'test_target' checks a URL against current rules and reports which layer decided; " +
			"'set_rate_limits' sets Agent Layer rate limits (max_requests_per_second, max_requests_per_host_per_second); " +
			"'get_rate_limits' returns Policy and Agent Layer rate limits with effective values; " +
			"'set_budget' sets Agent Layer diagnostic budget (max_total_requests, max_duration); " +
			"'get_budget' returns Policy and Agent Layer budgets with effective values and current usage; " +
			"'get_safety_filter' returns the current SafetyFilter configuration and rules (read-only).",
	}, s.handleSecurity)
}

// handleSecurity routes the security tool invocation to the appropriate action handler.
func (s *Server) handleSecurity(ctx context.Context, _ *gomcp.CallToolRequest, input securityInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "security",
		"action", input.Action,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "security",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	switch input.Action {
	case "set_target_scope":
		return s.handleSetTargetScope(input.Params)
	case "update_target_scope":
		return s.handleUpdateTargetScope(input.Params)
	case "get_target_scope":
		return s.handleGetTargetScope()
	case "test_target":
		return s.handleTestTarget(input.Params)
	case "set_rate_limits":
		return s.handleSetRateLimits(input.Params)
	case "get_rate_limits":
		return s.handleGetRateLimits()
	case "set_budget":
		return s.handleSetBudget(input.Params)
	case "get_budget":
		return s.handleGetBudget()
	case "get_safety_filter":
		return s.handleGetSafetyFilter()
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableSecurityActions, ", "))
	default:
		return nil, nil, fmt.Errorf("unknown action %q: available actions are %s", input.Action, strings.Join(availableSecurityActions, ", "))
	}
}

// setTargetScopeResult is the structured output for set_target_scope and update_target_scope.
type setTargetScopeResult struct {
	Status string             `json:"status"`
	Allows []proxy.TargetRule `json:"allows"`
	Denies []proxy.TargetRule `json:"denies"`
	Mode   string             `json:"mode"`
}

// getTargetScopeResult is the structured output for get_target_scope.
// It separates Policy Layer and Agent Layer rules into nested objects.
type getTargetScopeResult struct {
	Policy        policyLayerResult `json:"policy"`
	Agent         agentLayerResult  `json:"agent"`
	EffectiveMode string            `json:"effective_mode"`
}

// policyLayerResult represents the immutable Policy Layer in get_target_scope output.
type policyLayerResult struct {
	Allows    []proxy.TargetRule `json:"allows"`
	Denies    []proxy.TargetRule `json:"denies"`
	Source    string             `json:"source"`
	Immutable bool               `json:"immutable"`
}

// agentLayerResult represents the mutable Agent Layer in get_target_scope output.
type agentLayerResult struct {
	Allows []proxy.TargetRule `json:"allows"`
	Denies []proxy.TargetRule `json:"denies"`
}

// testTargetResult is the structured output for test_target.
type testTargetResult struct {
	Allowed      bool              `json:"allowed"`
	Reason       string            `json:"reason"`
	Layer        string            `json:"layer"`
	MatchedRule  *proxy.TargetRule `json:"matched_rule"`
	TestedTarget *testedTarget     `json:"tested_target"`
}

// testedTarget describes the parsed URL components that were evaluated.
type testedTarget struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Scheme   string `json:"scheme"`
	Path     string `json:"path"`
}

// handleSetTargetScope replaces all agent allow and deny rules.
func (s *Server) handleSetTargetScope(params securityParams) (*gomcp.CallToolResult, any, error) {
	if s.deps.targetScope == nil {
		return nil, nil, fmt.Errorf("target scope is not initialized")
	}

	// Validate rules.
	if err := validateTargetRules("allows", params.Allows); err != nil {
		return nil, nil, err
	}
	if err := validateTargetRules("denies", params.Denies); err != nil {
		return nil, nil, err
	}

	allows := toTargetRules(params.Allows)
	denies := toTargetRules(params.Denies)
	if err := s.deps.targetScope.SetAgentRules(allows, denies); err != nil {
		return nil, nil, fmt.Errorf("set agent rules: %w", err)
	}

	currentAllows, currentDenies := s.deps.targetScope.AgentRules()
	return nil, &setTargetScopeResult{
		Status: "updated",
		Allows: ensureNonNilRules(currentAllows),
		Denies: ensureNonNilRules(currentDenies),
		Mode:   targetScopeMode(s.deps.targetScope),
	}, nil
}

// handleUpdateTargetScope applies delta add/remove changes to agent rules.
// If remove_denies contains rules that match policy deny rules, an error is returned
// because policy denies are immutable and cannot be removed via the agent layer.
func (s *Server) handleUpdateTargetScope(params securityParams) (*gomcp.CallToolResult, any, error) {
	if s.deps.targetScope == nil {
		return nil, nil, fmt.Errorf("target scope is not initialized")
	}

	// Validate rules to add.
	if err := validateTargetRules("add_allows", params.AddAllows); err != nil {
		return nil, nil, err
	}
	if err := validateTargetRules("add_denies", params.AddDenies); err != nil {
		return nil, nil, err
	}

	// Reject removal of policy deny rules.
	if err := validateNotPolicyDenies(s.deps.targetScope, toTargetRules(params.RemoveDenies)); err != nil {
		return nil, nil, err
	}

	if err := s.deps.targetScope.MergeAgentRules(
		toTargetRules(params.AddAllows),
		toTargetRules(params.RemoveAllows),
		toTargetRules(params.AddDenies),
		toTargetRules(params.RemoveDenies),
	); err != nil {
		return nil, nil, fmt.Errorf("merge agent rules: %w", err)
	}

	currentAllows, currentDenies := s.deps.targetScope.AgentRules()
	return nil, &setTargetScopeResult{
		Status: "updated",
		Allows: ensureNonNilRules(currentAllows),
		Denies: ensureNonNilRules(currentDenies),
		Mode:   targetScopeMode(s.deps.targetScope),
	}, nil
}

// handleGetTargetScope returns the current Policy and Agent layer rules and mode.
func (s *Server) handleGetTargetScope() (*gomcp.CallToolResult, any, error) {
	if s.deps.targetScope == nil {
		return nil, nil, fmt.Errorf("target scope is not initialized")
	}

	agentAllows, agentDenies := s.deps.targetScope.AgentRules()
	policyAllows, policyDenies := s.deps.targetScope.PolicyRules()

	source := "none"
	if s.deps.targetScope.HasPolicyRules() {
		source = "config file"
	}

	return nil, &getTargetScopeResult{
		Policy: policyLayerResult{
			Allows:    ensureNonNilRules(policyAllows),
			Denies:    ensureNonNilRules(policyDenies),
			Source:    source,
			Immutable: true,
		},
		Agent: agentLayerResult{
			Allows: ensureNonNilRules(agentAllows),
			Denies: ensureNonNilRules(agentDenies),
		},
		EffectiveMode: targetScopeMode(s.deps.targetScope),
	}, nil
}

// handleTestTarget checks a URL against the current scope rules.
func (s *Server) handleTestTarget(params securityParams) (*gomcp.CallToolResult, any, error) {
	if s.deps.targetScope == nil {
		return nil, nil, fmt.Errorf("target scope is not initialized")
	}

	if params.URL == "" {
		return nil, nil, fmt.Errorf("url is required for test_target action")
	}

	u, err := url.Parse(params.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid url %q: %w", params.URL, err)
	}

	allowed, reason := s.deps.targetScope.CheckURL(u)

	// Find the matched rule and determine which layer decided.
	matchedRule, layer := findMatchedRuleAndLayer(s.deps.targetScope, u, allowed, reason)

	scheme := strings.ToLower(u.Scheme)
	port := targetDefaultPort(scheme, u.Port())

	return nil, &testTargetResult{
		Allowed:     allowed,
		Reason:      reason,
		Layer:       layer,
		MatchedRule: matchedRule,
		TestedTarget: &testedTarget{
			Hostname: u.Hostname(),
			Port:     port,
			Scheme:   scheme,
			Path:     u.Path,
		},
	}, nil
}

// findMatchedRuleAndLayer identifies which rule caused the allow/deny decision
// and which layer (policy or agent) made the decision.
// The reason string from CheckTarget is used to determine the layer when no
// specific deny rule matched (i.e., "not in X allow list" cases).
func findMatchedRuleAndLayer(ts *proxy.TargetScope, u *url.URL, allowed bool, reason string) (*proxy.TargetRule, string) {
	policyAllows, policyDenies := ts.PolicyRules()
	agentAllows, agentDenies := ts.AgentRules()

	scheme := strings.ToLower(u.Scheme)
	hostname := u.Hostname()
	port := targetDefaultPort(scheme, u.Port())
	path := u.Path

	// If denied, check policy denies first, then agent denies.
	if !allowed {
		for _, rule := range policyDenies {
			if matchTargetRuleFields(rule, scheme, hostname, port, path) {
				r := rule
				return &r, "policy"
			}
		}
		for _, rule := range agentDenies {
			if matchTargetRuleFields(rule, scheme, hostname, port, path) {
				r := rule
				return &r, "agent"
			}
		}
		// No specific deny rule matched — blocked because not in allow list.
		// Use the reason string to determine the layer.
		return nil, layerFromReason(reason)
	}

	// If allowed and there are agent allow rules, find the matching agent allow rule.
	if len(agentAllows) > 0 {
		for _, rule := range agentAllows {
			if matchTargetRuleFields(rule, scheme, hostname, port, path) {
				r := rule
				return &r, "agent"
			}
		}
	}

	// If allowed and there are policy allow rules, find the matching policy allow rule.
	if len(policyAllows) > 0 {
		for _, rule := range policyAllows {
			if matchTargetRuleFields(rule, scheme, hostname, port, path) {
				r := rule
				return &r, "policy"
			}
		}
	}

	// Allowed because no allow rules exist (open mode) — no specific matched rule.
	return nil, ""
}

// layerFromReason determines the layer from the reason string returned by CheckTarget.
func layerFromReason(reason string) string {
	switch {
	case strings.Contains(reason, "policy"):
		return "policy"
	case strings.Contains(reason, "agent"):
		return "agent"
	default:
		return ""
	}
}

// validateNotPolicyDenies checks that none of the rules to remove match policy deny rules.
// Returns an error if a remove_denies rule matches a policy deny rule, because policy
// deny rules are immutable and cannot be removed via the agent layer.
func validateNotPolicyDenies(ts *proxy.TargetScope, removeDenies []proxy.TargetRule) error {
	if len(removeDenies) == 0 {
		return nil
	}

	_, policyDenies := ts.PolicyRules()
	if len(policyDenies) == 0 {
		return nil
	}

	for _, rem := range removeDenies {
		for _, pd := range policyDenies {
			if targetRuleMatchesLocal(rem, pd) {
				return fmt.Errorf("cannot remove policy deny rule %q: policy rules are immutable", rem.Hostname)
			}
		}
	}
	return nil
}

// targetRuleMatchesLocal checks if two target rules are equivalent.
// Comparison is case-insensitive for hostname and schemes.
func targetRuleMatchesLocal(a, b proxy.TargetRule) bool {
	if !strings.EqualFold(a.Hostname, b.Hostname) {
		return false
	}
	if a.PathPrefix != b.PathPrefix {
		return false
	}
	if len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		if a.Ports[i] != b.Ports[i] {
			return false
		}
	}
	if len(a.Schemes) != len(b.Schemes) {
		return false
	}
	for i := range a.Schemes {
		if !strings.EqualFold(a.Schemes[i], b.Schemes[i]) {
			return false
		}
	}
	return true
}

// matchTargetRuleFields checks if a target matches a single TargetRule.
// This is a local re-implementation of the unexported proxy.matchTargetRule
// for use in the MCP handler.
func matchTargetRuleFields(rule proxy.TargetRule, scheme, hostname string, port int, path string) bool {
	if rule.Hostname != "" && !matchHostnameLocal(rule.Hostname, hostname) {
		return false
	}
	if len(rule.Ports) > 0 && !containsIntLocal(rule.Ports, port) {
		return false
	}
	if rule.PathPrefix != "" && !strings.HasPrefix(path, rule.PathPrefix) {
		return false
	}
	if len(rule.Schemes) > 0 && !containsStringFoldLocal(rule.Schemes, scheme) {
		return false
	}
	return true
}

// matchHostnameLocal performs case-insensitive hostname matching with wildcard support.
// Pattern "*.example.com" matches "sub.example.com" but not "example.com".
func matchHostnameLocal(pattern, hostname string) bool {
	pattern = strings.ToLower(pattern)
	hostname = strings.ToLower(hostname)

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(hostname, suffix) && hostname != pattern[2:]
	}
	return pattern == hostname
}

// containsIntLocal reports whether the slice contains the given value.
func containsIntLocal(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// containsStringFoldLocal reports whether the slice contains the given string
// (case-insensitive comparison).
func containsStringFoldLocal(slice []string, val string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, val) {
			return true
		}
	}
	return false
}

// targetDefaultPort returns the port number from the URL port string.
// If the port string is empty, returns the default port for the scheme.
func targetDefaultPort(scheme, portStr string) int {
	if portStr != "" {
		p := 0
		for _, c := range portStr {
			if c < '0' || c > '9' {
				return 0
			}
			p = p*10 + int(c-'0')
		}
		return p
	}
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// validateTargetRules validates each target rule's hostname, ports, and schemes.
func validateTargetRules(kind string, rules []targetRuleInput) error {
	for i, r := range rules {
		if r.Hostname == "" {
			return fmt.Errorf("%s rule %d: hostname is required", kind, i)
		}
		if err := validateHostname(r.Hostname); err != nil {
			return fmt.Errorf("%s rule %d: %w", kind, i, err)
		}
		for _, p := range r.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("%s rule %d: port %d is out of range (1-65535)", kind, i, p)
			}
		}
		for _, s := range r.Schemes {
			if !allowedSchemes[strings.ToLower(s)] {
				return fmt.Errorf("%s rule %d: scheme %q is not allowed (use http or https)", kind, i, s)
			}
		}
	}
	return nil
}

// validateHostname checks that a hostname is valid for target rules.
// It accepts exact hostnames, wildcard patterns (*.example.com), IPv4 addresses,
// and bracketed IPv6 addresses ([::1]).
func validateHostname(hostname string) error {
	// Strip wildcard prefix for validation of the domain part.
	h := hostname
	if strings.HasPrefix(h, "*.") {
		h = h[2:]
		if h == "" {
			return fmt.Errorf("hostname %q: wildcard must be followed by a domain", hostname)
		}
	}

	// Reject trailing dots to prevent normalization mismatches.
	if strings.HasSuffix(h, ".") {
		return fmt.Errorf("hostname %q: trailing dot is not allowed", hostname)
	}

	// IPv6 bracket notation: [::1]
	if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return fmt.Errorf("hostname %q: mismatched brackets for IPv6 address", hostname)
		}
		inner := h[1 : len(h)-1]
		if net.ParseIP(inner) == nil {
			return fmt.Errorf("hostname %q: invalid IPv6 address", hostname)
		}
		return nil
	}

	// IPv4 literal: all digits and dots, parse as IP.
	if isIPv4Like(h) {
		if net.ParseIP(h) == nil {
			return fmt.Errorf("hostname %q: invalid IPv4 address", hostname)
		}
		return nil
	}

	// Domain name validation: labels separated by dots.
	return validateDomainName(h, hostname)
}

// isIPv4Like reports whether s looks like an IPv4 address (digits and dots only).
func isIPv4Like(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// validateDomainName validates a DNS domain name.
func validateDomainName(domain, original string) error {
	if len(domain) > 253 {
		return fmt.Errorf("hostname %q: domain name too long", original)
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("hostname %q: empty label in domain name", original)
		}
		if len(label) > 63 {
			return fmt.Errorf("hostname %q: label %q exceeds 63 characters", original, label)
		}
		for _, c := range label {
			if !isValidLabelChar(c) {
				return fmt.Errorf("hostname %q: invalid character %q in domain name", original, c)
			}
		}
		// Labels must not start or end with hyphen.
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("hostname %q: label %q must not start or end with a hyphen", original, label)
		}
	}
	return nil
}

// isValidLabelChar reports whether c is a valid DNS label character
// (alphanumeric or hyphen).
func isValidLabelChar(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
}

// toTargetRules converts a slice of targetRuleInput to proxy.TargetRule.
// Schemes are normalized to lowercase.
func toTargetRules(inputs []targetRuleInput) []proxy.TargetRule {
	if len(inputs) == 0 {
		return nil
	}
	rules := make([]proxy.TargetRule, len(inputs))
	for i, input := range inputs {
		schemes := input.Schemes
		if len(schemes) > 0 {
			normalized := make([]string, len(schemes))
			for j, s := range schemes {
				normalized[j] = strings.ToLower(s)
			}
			schemes = normalized
		}
		rules[i] = proxy.TargetRule{
			Hostname:   input.Hostname,
			Ports:      input.Ports,
			PathPrefix: input.PathPrefix,
			Schemes:    schemes,
		}
	}
	return rules
}

// targetScopeMode returns the enforcement mode string based on the current scope.
// If either policy or agent layer has allow rules, the mode is "enforcing".
// If only deny rules exist (no allow rules), the mode is also "enforcing".
// Otherwise (no rules at all), the mode is "open".
func targetScopeMode(ts *proxy.TargetScope) string {
	if ts == nil || !ts.HasRules() {
		return "open"
	}
	return "enforcing"
}

// ensureNonNilRules returns the rules slice, or an empty slice if nil.
// This ensures consistent JSON output ([] instead of null).
func ensureNonNilRules(rules []proxy.TargetRule) []proxy.TargetRule {
	if rules == nil {
		return []proxy.TargetRule{}
	}
	return rules
}

// --- Rate limit actions ---

// rateLimitResult is the structured output for set_rate_limits.
type rateLimitResult struct {
	Status    string                `json:"status"`
	Effective proxy.RateLimitConfig `json:"effective"`
	Agent     proxy.RateLimitConfig `json:"agent"`
}

// getRateLimitsResult is the structured output for get_rate_limits.
type getRateLimitsResult struct {
	Policy    proxy.RateLimitConfig `json:"policy"`
	Agent     proxy.RateLimitConfig `json:"agent"`
	Effective proxy.RateLimitConfig `json:"effective"`
}

// handleSetRateLimits sets agent layer rate limits.
func (s *Server) handleSetRateLimits(params securityParams) (*gomcp.CallToolResult, any, error) {
	if s.deps.rateLimiter == nil {
		return nil, nil, fmt.Errorf("rate limiter is not initialized")
	}

	cfg := proxy.RateLimitConfig{}
	if params.MaxRequestsPerSecond != nil {
		if *params.MaxRequestsPerSecond < 0 {
			return nil, nil, fmt.Errorf("max_requests_per_second must be >= 0")
		}
		cfg.MaxRequestsPerSecond = *params.MaxRequestsPerSecond
	}
	if params.MaxRequestsPerHostPerSecond != nil {
		if *params.MaxRequestsPerHostPerSecond < 0 {
			return nil, nil, fmt.Errorf("max_requests_per_host_per_second must be >= 0")
		}
		cfg.MaxRequestsPerHostPerSecond = *params.MaxRequestsPerHostPerSecond
	}

	if err := s.deps.rateLimiter.SetAgentLimits(cfg); err != nil {
		return nil, nil, fmt.Errorf("set rate limits: %w", err)
	}

	return nil, &rateLimitResult{
		Status:    "updated",
		Effective: s.deps.rateLimiter.EffectiveLimits(),
		Agent:     s.deps.rateLimiter.AgentLimits(),
	}, nil
}

// handleGetRateLimits returns the current rate limit configuration.
func (s *Server) handleGetRateLimits() (*gomcp.CallToolResult, any, error) {
	if s.deps.rateLimiter == nil {
		return nil, nil, fmt.Errorf("rate limiter is not initialized")
	}

	return nil, &getRateLimitsResult{
		Policy:    s.deps.rateLimiter.PolicyLimits(),
		Agent:     s.deps.rateLimiter.AgentLimits(),
		Effective: s.deps.rateLimiter.EffectiveLimits(),
	}, nil
}

// --- Budget actions ---

// budgetResult is the structured output for set_budget.
type budgetResult struct {
	Status    string             `json:"status"`
	Effective proxy.BudgetConfig `json:"effective"`
	Agent     proxy.BudgetConfig `json:"agent"`
}

// getBudgetResult is the structured output for get_budget.
type getBudgetResult struct {
	Policy       proxy.BudgetConfig `json:"policy"`
	Agent        proxy.BudgetConfig `json:"agent"`
	Effective    proxy.BudgetConfig `json:"effective"`
	RequestCount int64              `json:"request_count"`
	StopReason   string             `json:"stop_reason,omitempty"`
}

// handleSetBudget sets agent layer budget limits using full-replace semantics.
// All fields start from zero; only explicitly provided fields are set.
// This matches the set_rate_limits pattern. Omitted fields reset to zero (no limit).
// For merge semantics (only update provided fields, keep others unchanged),
// use the configure tool's budget section instead.
func (s *Server) handleSetBudget(params securityParams) (*gomcp.CallToolResult, any, error) {
	if s.deps.budgetManager == nil {
		return nil, nil, fmt.Errorf("budget manager is not initialized")
	}

	cfg := proxy.BudgetConfig{}
	if params.MaxTotalRequests != nil {
		if *params.MaxTotalRequests < 0 {
			return nil, nil, fmt.Errorf("max_total_requests must be >= 0")
		}
		cfg.MaxTotalRequests = *params.MaxTotalRequests
	}
	if params.MaxDuration != nil {
		d, err := time.ParseDuration(*params.MaxDuration)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid max_duration %q: %w", *params.MaxDuration, err)
		}
		if d < 0 {
			return nil, nil, fmt.Errorf("max_duration must be >= 0")
		}
		cfg.MaxDuration = d
	}

	if err := s.deps.budgetManager.SetAgentBudget(cfg); err != nil {
		return nil, nil, fmt.Errorf("set budget: %w", err)
	}

	return nil, &budgetResult{
		Status:    "updated",
		Effective: s.deps.budgetManager.EffectiveBudget(),
		Agent:     s.deps.budgetManager.AgentBudget(),
	}, nil
}

// handleGetBudget returns the current budget configuration and usage.
func (s *Server) handleGetBudget() (*gomcp.CallToolResult, any, error) {
	if s.deps.budgetManager == nil {
		return nil, nil, fmt.Errorf("budget manager is not initialized")
	}

	return nil, &getBudgetResult{
		Policy:       s.deps.budgetManager.PolicyBudget(),
		Agent:        s.deps.budgetManager.AgentBudget(),
		Effective:    s.deps.budgetManager.EffectiveBudget(),
		RequestCount: s.deps.budgetManager.RequestCount(),
		StopReason:   s.deps.budgetManager.ShutdownReason(),
	}, nil
}

// --- SafetyFilter actions ---

// safetyFilterRuleResult describes a single SafetyFilter rule for display.
type safetyFilterRuleResult struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
	Action      string   `json:"action"`
	Replacement string   `json:"replacement,omitempty"`
	Category    string   `json:"category"`
}

// getSafetyFilterResult is the structured output for get_safety_filter.
type getSafetyFilterResult struct {
	Enabled     bool                     `json:"enabled"`
	InputRules  []safetyFilterRuleResult `json:"input_rules"`
	OutputRules []safetyFilterRuleResult `json:"output_rules"`
	Immutable   bool                     `json:"immutable"`
}

// handleGetSafetyFilter returns the current SafetyFilter configuration.
// This is a read-only action — SafetyFilter rules are part of the Policy Layer
// and cannot be modified at runtime.
func (s *Server) handleGetSafetyFilter() (*gomcp.CallToolResult, any, error) {
	if s.deps.safetyEngine == nil {
		return nil, &getSafetyFilterResult{
			Enabled:     false,
			InputRules:  []safetyFilterRuleResult{},
			OutputRules: []safetyFilterRuleResult{},
			Immutable:   true,
		}, nil
	}

	inputResults := convertRules(s.deps.safetyEngine.InputRules())
	outputResults := convertRules(s.deps.safetyEngine.OutputRules())

	return nil, &getSafetyFilterResult{
		Enabled:     true,
		InputRules:  inputResults,
		OutputRules: outputResults,
		Immutable:   true,
	}, nil
}

// convertRules converts compiled safety rules to their display representation.
func convertRules(rules []safety.Rule) []safetyFilterRuleResult {
	results := make([]safetyFilterRuleResult, 0, len(rules))
	for _, r := range rules {
		targets := make([]string, 0, len(r.Targets))
		for _, t := range r.Targets {
			targets = append(targets, t.String())
		}
		results = append(results, safetyFilterRuleResult{
			ID:          r.ID,
			Name:        r.Name,
			Pattern:     r.Pattern.String(),
			Targets:     targets,
			Action:      r.Action.String(),
			Replacement: r.Replacement,
			Category:    r.Category,
		})
	}
	return results
}
