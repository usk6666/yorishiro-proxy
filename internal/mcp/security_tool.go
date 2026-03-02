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
			"This tool is separate from 'configure' to allow MCP clients to apply different " +
			"approval policies (e.g., manual approval for security changes). " +
			"Available actions: " +
			"'set_target_scope' replaces all allow/deny rules (use empty arrays to clear rules and return to open mode); " +
			"'update_target_scope' applies incremental add/remove changes to allow/deny rules; " +
			"'get_target_scope' returns current rules and enforcement mode (open or enforcing); " +
			"'test_target' checks a URL against current rules without making a request (dry run).",
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
type getTargetScopeResult struct {
	Allows       []proxy.TargetRule `json:"allows"`
	Denies       []proxy.TargetRule `json:"denies"`
	PolicyAllows []proxy.TargetRule `json:"policy_allows"`
	PolicyDenies []proxy.TargetRule `json:"policy_denies"`
	Mode         string             `json:"mode"`
}

// testTargetResult is the structured output for test_target.
type testTargetResult struct {
	Allowed     bool              `json:"allowed"`
	Reason      string            `json:"reason"`
	MatchedRule *proxy.TargetRule `json:"matched_rule"`
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

// handleGetTargetScope returns the current rules and mode.
func (s *Server) handleGetTargetScope() (*gomcp.CallToolResult, any, error) {
	if s.targetScope == nil {
		return nil, nil, fmt.Errorf("target scope is not initialized")
	}

	allows, denies := s.targetScope.AgentRules()
	policyAllows, policyDenies := s.targetScope.PolicyRules()
	return nil, &getTargetScopeResult{
		Allows:       ensureNonNilRules(allows),
		Denies:       ensureNonNilRules(denies),
		PolicyAllows: ensureNonNilRules(policyAllows),
		PolicyDenies: ensureNonNilRules(policyDenies),
		Mode:         targetScopeMode(s.targetScope),
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

	// Find the matched rule by re-checking against each rule.
	matchedRule := findMatchedRule(s.targetScope, u, allowed)

	return nil, &testTargetResult{
		Allowed:     allowed,
		Reason:      reason,
		MatchedRule: matchedRule,
	}, nil
}

// findMatchedRule identifies which rule caused the allow/deny decision.
// It re-checks the URL against each rule in both layers to find the first match.
func findMatchedRule(ts *proxy.TargetScope, u *url.URL, allowed bool) *proxy.TargetRule {
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
				return &r
			}
		}
		for _, rule := range agentDenies {
			if matchTargetRuleFields(rule, scheme, hostname, port, path) {
				r := rule
				return &r
			}
		}
		// If not found in denies but blocked, it's because no allow rule matched.
		// There's no specific matched rule to return.
		return nil
	}

	// If allowed and there are agent allow rules, find the matching agent allow rule.
	if len(agentAllows) > 0 {
		for _, rule := range agentAllows {
			if matchTargetRuleFields(rule, scheme, hostname, port, path) {
				r := rule
				return &r
			}
		}
	}

	// If allowed and there are policy allow rules, find the matching policy allow rule.
	if len(policyAllows) > 0 {
		for _, rule := range policyAllows {
			if matchTargetRuleFields(rule, scheme, hostname, port, path) {
				r := rule
				return &r
			}
		}
	}

	// Allowed because no allow rules exist (open mode) — no specific matched rule.
	return nil
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
