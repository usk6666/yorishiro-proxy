package proxy

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// TargetScope controls which network targets are allowed or blocked.
// It supports allow and deny rules based on hostname, port, path prefix,
// and scheme. Deny rules take precedence over allow rules. When no allow
// rules are configured, all non-denied targets are permitted (open by default).
// TargetScope is safe for concurrent use.
type TargetScope struct {
	mu     sync.RWMutex
	allows []TargetRule
	denies []TargetRule
}

// TargetRule defines a single target scope matching rule.
// All non-empty/non-nil fields must match for the rule to apply (AND logic).
type TargetRule struct {
	// Hostname matches the target hostname (case-insensitive).
	// Supports wildcard prefix "*.example.com" to match all subdomains.
	// Required for the rule to be meaningful.
	Hostname string `json:"hostname"`

	// Ports restricts the rule to specific port numbers.
	// When nil or empty, all ports are matched.
	Ports []int `json:"ports,omitempty"`

	// PathPrefix matches the beginning of the request URL path (case-sensitive).
	// When empty, all paths are matched.
	PathPrefix string `json:"path_prefix,omitempty"`

	// Schemes restricts the rule to specific URL schemes (e.g., "http", "https").
	// Matching is case-insensitive. When nil or empty, all schemes are matched.
	Schemes []string `json:"schemes,omitempty"`
}

// NewTargetScope creates a new empty TargetScope that allows all targets.
func NewTargetScope() *TargetScope {
	return &TargetScope{}
}

// CheckTarget reports whether a target with the given scheme, hostname, port,
// and path is allowed by the current rules.
//
// The evaluation logic is:
//  1. If the target matches any deny rule, it is BLOCKED.
//  2. If no allow rules are configured, it is ALLOWED (open by default).
//  3. If the target matches any allow rule, it is ALLOWED.
//  4. If allow rules exist but none match, it is BLOCKED.
//
// Returns allowed=true if the target is permitted, and a reason string
// explaining the decision when blocked.
func (s *TargetScope) CheckTarget(scheme, hostname string, port int, path string) (allowed bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check denies first (highest priority).
	for _, rule := range s.denies {
		if matchTargetRule(rule, scheme, hostname, port, path) {
			return false, "denied by target scope"
		}
	}

	// If no allow rules, allow everything not denied.
	if len(s.allows) == 0 {
		return true, ""
	}

	// Check if any allow rule matches.
	for _, rule := range s.allows {
		if matchTargetRule(rule, scheme, hostname, port, path) {
			return true, ""
		}
	}

	// Allow rules exist but none matched.
	return false, "not in allow list"
}

// CheckURL is a convenience method that extracts scheme, hostname, port, and
// path from a parsed URL and delegates to CheckTarget.
func (s *TargetScope) CheckURL(u *url.URL) (allowed bool, reason string) {
	if u == nil {
		return s.CheckTarget("", "", 0, "")
	}

	scheme := strings.ToLower(u.Scheme)
	hostname := u.Hostname()
	port := defaultPort(scheme, u.Port())
	path := u.Path

	return s.CheckTarget(scheme, hostname, port, path)
}

// SetRules replaces all allow and deny rules atomically.
func (s *TargetScope) SetRules(allows, denies []TargetRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allows = cloneTargetRules(allows)
	s.denies = cloneTargetRules(denies)
}

// MergeRules atomically applies add/remove deltas to the current rules.
// Within a single lock, it reads the current rules, applies the deltas, and
// writes back. For add operations, duplicate rules are skipped.
// For remove operations, all matching rules are removed.
func (s *TargetScope) MergeRules(addAllows, removeAllows, addDenies, removeDenies []TargetRule) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Apply allow additions (skip duplicates, deep copy each rule).
	for _, add := range addAllows {
		if !containsTargetRule(s.allows, add) {
			s.allows = append(s.allows, cloneTargetRule(add))
		}
	}
	// Apply allow removals.
	for _, rem := range removeAllows {
		s.allows = filterTargetRule(s.allows, rem)
	}

	// Apply deny additions (skip duplicates, deep copy each rule).
	for _, add := range addDenies {
		if !containsTargetRule(s.denies, add) {
			s.denies = append(s.denies, cloneTargetRule(add))
		}
	}
	// Apply deny removals.
	for _, rem := range removeDenies {
		s.denies = filterTargetRule(s.denies, rem)
	}
}

// Rules returns a copy of the current allow and deny rules.
func (s *TargetScope) Rules() (allows, denies []TargetRule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTargetRules(s.allows), cloneTargetRules(s.denies)
}

// HasRules reports whether at least one allow or deny rule is configured.
func (s *TargetScope) HasRules() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.allows) > 0 || len(s.denies) > 0
}

// matchTargetRule checks if a target matches a single TargetRule.
// All non-empty/non-nil fields in the rule must match (AND logic).
func matchTargetRule(rule TargetRule, scheme, hostname string, port int, path string) bool {
	if rule.Hostname != "" && !matchHostname(rule.Hostname, hostname) {
		return false
	}
	if len(rule.Ports) > 0 && !containsInt(rule.Ports, port) {
		return false
	}
	if rule.PathPrefix != "" && !strings.HasPrefix(path, rule.PathPrefix) {
		return false
	}
	if len(rule.Schemes) > 0 && !containsStringFold(rule.Schemes, scheme) {
		return false
	}
	return true
}

// containsInt reports whether the slice contains the given value.
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// containsStringFold reports whether the slice contains the given string
// (case-insensitive comparison).
func containsStringFold(slice []string, val string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, val) {
			return true
		}
	}
	return false
}

// defaultPort returns the port number from the URL port string.
// If the port string is empty, it returns the default port for the given scheme
// (80 for http, 443 for https). Returns 0 if the port cannot be determined.
func defaultPort(scheme, portStr string) int {
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return 0
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

// targetRuleEqual reports whether two TargetRule values are equal.
func targetRuleEqual(a, b TargetRule) bool {
	if !strings.EqualFold(a.Hostname, b.Hostname) {
		return false
	}
	if a.PathPrefix != b.PathPrefix {
		return false
	}
	if !intSliceEqual(a.Ports, b.Ports) {
		return false
	}
	if !stringSliceEqualFold(a.Schemes, b.Schemes) {
		return false
	}
	return true
}

// intSliceEqual reports whether two int slices contain the same elements
// in the same order.
func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stringSliceEqualFold reports whether two string slices contain the same
// elements in the same order (case-insensitive comparison).
func stringSliceEqualFold(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// containsTargetRule reports whether rules contains a rule equal to target.
func containsTargetRule(rules []TargetRule, target TargetRule) bool {
	for _, r := range rules {
		if targetRuleEqual(r, target) {
			return true
		}
	}
	return false
}

// filterTargetRule returns rules with all occurrences of target removed.
func filterTargetRule(rules []TargetRule, target TargetRule) []TargetRule {
	result := make([]TargetRule, 0, len(rules))
	for _, r := range rules {
		if !targetRuleEqual(r, target) {
			result = append(result, r)
		}
	}
	return result
}

// cloneTargetRule returns a deep copy of a single TargetRule.
// The Ports and Schemes slices are independently copied.
func cloneTargetRule(r TargetRule) TargetRule {
	return TargetRule{
		Hostname:   r.Hostname,
		Ports:      cloneInts(r.Ports),
		PathPrefix: r.PathPrefix,
		Schemes:    cloneStrings(r.Schemes),
	}
}

// cloneTargetRules returns a deep copy of a TargetRule slice.
// Each rule's Ports and Schemes slices are also copied.
func cloneTargetRules(rules []TargetRule) []TargetRule {
	if rules == nil {
		return nil
	}
	out := make([]TargetRule, len(rules))
	for i, r := range rules {
		out[i] = cloneTargetRule(r)
	}
	return out
}

// cloneInts returns a copy of an int slice.
func cloneInts(s []int) []int {
	if s == nil {
		return nil
	}
	out := make([]int, len(s))
	copy(out, s)
	return out
}

// cloneStrings returns a copy of a string slice.
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
