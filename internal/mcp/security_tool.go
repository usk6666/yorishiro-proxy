package mcp

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// securityInput is the typed input for the security tool.
type securityInput struct {
	// Action specifies the security action to execute.
	// Available actions: set_target_scope, update_target_scope, get_target_scope, test_target.
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
}

// targetRuleInput is the JSON input representation of a target rule.
type targetRuleInput struct {
	Hostname   string   `json:"hostname"`
	Ports      []int    `json:"ports,omitempty"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	Schemes    []string `json:"schemes,omitempty"`
}

// availableSecurityActions lists the valid action names for error messages.
var availableSecurityActions = []string{"set_target_scope", "update_target_scope", "get_target_scope", "test_target"}

// registerSecurity registers the security MCP tool.
func (s *Server) registerSecurity() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "security",
		Description: "Configure runtime security settings including target scope rules. " +
			"Target scope uses a two-layer architecture: Policy Layer (immutable, set by config) " +
			"and Agent Layer (mutable via this tool). This tool only modifies Agent Layer rules; " +
			"Policy Layer rules are read-only. Agent allow rules must fall within the Policy " +
			"allow boundary. " +
			"Available actions: " +
			"'set_target_scope' replaces all Agent Layer allow/deny rules (use empty arrays to clear rules); " +
			"'update_target_scope' applies incremental add/remove changes to Agent Layer rules; " +
			"'get_target_scope' returns Policy and Agent Layer rules with enforcement mode; " +
			"'test_target' checks a URL against current rules and reports which layer decided.",
	}, s.handleSecurity)
}

// handleSecurity routes the security tool invocation to the appropriate action handler.
func (s *Server) handleSecurity(_ context.Context, _ *gomcp.CallToolRequest, input securityInput) (*gomcp.CallToolResult, any, error) {
	switch input.Action {
	case "set_target_scope":
		return s.handleSetTargetScope(input.Params)
	case "update_target_scope":
		return s.handleUpdateTargetScope(input.Params)
	case "get_target_scope":
		return s.handleGetTargetScope()
	case "test_target":
		return s.handleTestTarget(input.Params)
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
	Immutable bool              `json:"immutable"`
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
	if s.targetScope == nil {
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
	if err := s.targetScope.SetAgentRules(allows, denies); err != nil {
		return nil, nil, fmt.Errorf("set agent rules: %w", err)
	}

	currentAllows, currentDenies := s.targetScope.AgentRules()
	return nil, &setTargetScopeResult{
		Status: "updated",
		Allows: ensureNonNilRules(currentAllows),
		Denies: ensureNonNilRules(currentDenies),
		Mode:   targetScopeMode(s.targetScope),
	}, nil
}

// handleUpdateTargetScope applies delta add/remove changes to agent rules.
// If remove_denies contains rules that match policy deny rules, an error is returned
// because policy denies are immutable and cannot be removed via the agent layer.
func (s *Server) handleUpdateTargetScope(params securityParams) (*gomcp.CallToolResult, any, error) {
	if s.targetScope == nil {
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
	if err := validateNotPolicyDenies(s.targetScope, toTargetRules(params.RemoveDenies)); err != nil {
		return nil, nil, err
	}

	if err := s.targetScope.MergeAgentRules(
		toTargetRules(params.AddAllows),
		toTargetRules(params.RemoveAllows),
		toTargetRules(params.AddDenies),
		toTargetRules(params.RemoveDenies),
	); err != nil {
		return nil, nil, fmt.Errorf("merge agent rules: %w", err)
	}

	currentAllows, currentDenies := s.targetScope.AgentRules()
	return nil, &setTargetScopeResult{
		Status: "updated",
		Allows: ensureNonNilRules(currentAllows),
		Denies: ensureNonNilRules(currentDenies),
		Mode:   targetScopeMode(s.targetScope),
	}, nil
}

// handleGetTargetScope returns the current Policy and Agent layer rules and mode.
func (s *Server) handleGetTargetScope() (*gomcp.CallToolResult, any, error) {
	if s.targetScope == nil {
		return nil, nil, fmt.Errorf("target scope is not initialized")
	}

	agentAllows, agentDenies := s.targetScope.AgentRules()
	policyAllows, policyDenies := s.targetScope.PolicyRules()

	source := "none"
	if s.targetScope.HasPolicyRules() {
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
		EffectiveMode: targetScopeMode(s.targetScope),
	}, nil
}

// handleTestTarget checks a URL against the current scope rules.
func (s *Server) handleTestTarget(params securityParams) (*gomcp.CallToolResult, any, error) {
	if s.targetScope == nil {
		return nil, nil, fmt.Errorf("target scope is not initialized")
	}

	if params.URL == "" {
		return nil, nil, fmt.Errorf("url is required for test_target action")
	}

	u, err := url.Parse(params.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid url %q: %w", params.URL, err)
	}

	allowed, reason := s.targetScope.CheckURL(u)

	// Find the matched rule and determine which layer decided.
	matchedRule, layer := findMatchedRuleAndLayer(s.targetScope, u, allowed, reason)

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

// matchHostnameLocal matches a hostname against a pattern (case-insensitive).
// Supports wildcard prefix "*.example.com" to match all subdomains.
func matchHostnameLocal(pattern, hostname string) bool {
	pattern = strings.ToLower(pattern)
	hostname = strings.ToLower(hostname)

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(hostname, suffix)
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

// validateTargetRules validates that each target rule has a non-empty hostname.
func validateTargetRules(kind string, rules []targetRuleInput) error {
	for i, r := range rules {
		if r.Hostname == "" {
			return fmt.Errorf("%s rule %d: hostname is required", kind, i)
		}
	}
	return nil
}

// toTargetRules converts a slice of targetRuleInput to proxy.TargetRule.
func toTargetRules(inputs []targetRuleInput) []proxy.TargetRule {
	if len(inputs) == 0 {
		return nil
	}
	rules := make([]proxy.TargetRule, len(inputs))
	for i, input := range inputs {
		rules[i] = proxy.TargetRule{
			Hostname:   input.Hostname,
			Ports:      input.Ports,
			PathPrefix: input.PathPrefix,
			Schemes:    input.Schemes,
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
