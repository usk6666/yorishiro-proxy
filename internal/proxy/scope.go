package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// CaptureScope controls which requests are recorded to the session store.
// It supports include and exclude patterns based on hostname, URL prefix,
// and HTTP method. When include patterns are configured, only matching
// requests are recorded. Exclude patterns take precedence over include
// patterns. CaptureScope is safe for concurrent use.
type CaptureScope struct {
	mu       sync.RWMutex
	includes []ScopeRule
	excludes []ScopeRule
}

// ScopeRule defines a single capture scope matching rule.
// All non-empty fields must match for the rule to apply (AND logic).
type ScopeRule struct {
	// Hostname matches the request's hostname (case-insensitive, exact match).
	// Supports wildcard prefix "*.example.com" to match all subdomains.
	Hostname string `json:"hostname,omitempty"`

	// URLPrefix matches the beginning of the request URL path (case-sensitive).
	URLPrefix string `json:"url_prefix,omitempty"`

	// Method matches the HTTP method (case-insensitive, exact match).
	Method string `json:"method,omitempty"`
}

// NewCaptureScope creates a new empty CaptureScope that allows all requests.
func NewCaptureScope() *CaptureScope {
	return &CaptureScope{}
}

// SetRules replaces all include and exclude rules atomically.
func (s *CaptureScope) SetRules(includes, excludes []ScopeRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.includes = cloneRules(includes)
	s.excludes = cloneRules(excludes)
}

// Rules returns a copy of the current include and exclude rules.
func (s *CaptureScope) Rules() (includes, excludes []ScopeRule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRules(s.includes), cloneRules(s.excludes)
}

// MergeRules atomically applies add/remove deltas to the current rules.
// Within a single lock, it reads the current rules, applies the deltas, and writes back.
// For add operations, duplicate rules (where all fields match) are skipped.
// For remove operations, all matching rules are removed.
func (s *CaptureScope) MergeRules(addIncludes, removeIncludes, addExcludes, removeExcludes []ScopeRule) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Apply include additions (skip duplicates).
	for _, add := range addIncludes {
		if !containsRule(s.includes, add) {
			s.includes = append(s.includes, add)
		}
	}
	// Apply include removals.
	for _, rem := range removeIncludes {
		s.includes = filterRule(s.includes, rem)
	}

	// Apply exclude additions (skip duplicates).
	for _, add := range addExcludes {
		if !containsRule(s.excludes, add) {
			s.excludes = append(s.excludes, add)
		}
	}
	// Apply exclude removals.
	for _, rem := range removeExcludes {
		s.excludes = filterRule(s.excludes, rem)
	}
}

// containsRule reports whether rules contains a rule equal to target.
func containsRule(rules []ScopeRule, target ScopeRule) bool {
	for _, r := range rules {
		if r.Hostname == target.Hostname && r.URLPrefix == target.URLPrefix && r.Method == target.Method {
			return true
		}
	}
	return false
}

// filterRule returns rules with all occurrences of target removed.
func filterRule(rules []ScopeRule, target ScopeRule) []ScopeRule {
	result := make([]ScopeRule, 0, len(rules))
	for _, r := range rules {
		if r.Hostname != target.Hostname || r.URLPrefix != target.URLPrefix || r.Method != target.Method {
			result = append(result, r)
		}
	}
	return result
}

// Clear removes all include and exclude rules, allowing all requests.
func (s *CaptureScope) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.includes = nil
	s.excludes = nil
}

// ShouldCapture reports whether a request with the given method and URL
// should be recorded to the session store.
//
// The evaluation logic is:
//  1. If the request matches any exclude rule, it is NOT captured.
//  2. If include rules are configured and the request matches any, it IS captured.
//  3. If include rules are configured but none match, it is NOT captured.
//  4. If no include rules are configured (empty), all non-excluded requests are captured.
func (s *CaptureScope) ShouldCapture(method string, u *url.URL) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hostname := extractHostname(u)

	// Check excludes first (highest priority).
	for _, rule := range s.excludes {
		if matchRule(rule, method, hostname, u) {
			return false
		}
	}

	// If no include rules, capture everything not excluded.
	if len(s.includes) == 0 {
		return true
	}

	// Check if any include rule matches.
	for _, rule := range s.includes {
		if matchRule(rule, method, hostname, u) {
			return true
		}
	}

	// Include rules exist but none matched.
	return false
}

// ShouldCaptureRequest is a convenience wrapper that extracts method and URL
// from an http.Request.
func (s *CaptureScope) ShouldCaptureRequest(req *http.Request) bool {
	return s.ShouldCapture(req.Method, req.URL)
}

// IsEmpty reports whether no rules are configured (i.e., all requests are captured).
func (s *CaptureScope) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.includes) == 0 && len(s.excludes) == 0
}

// matchRule checks if a request matches a single ScopeRule.
// All non-empty fields in the rule must match (AND logic).
func matchRule(rule ScopeRule, method, hostname string, u *url.URL) bool {
	if rule.Hostname != "" && !matchHostname(rule.Hostname, hostname) {
		return false
	}
	if rule.URLPrefix != "" && !matchURLPrefix(rule.URLPrefix, u) {
		return false
	}
	if rule.Method != "" && !strings.EqualFold(rule.Method, method) {
		return false
	}
	return true
}

// matchHostname performs case-insensitive hostname matching with wildcard support.
// Pattern "*.example.com" matches "sub.example.com" but not "example.com".
// Exact patterns match exactly.
func matchHostname(pattern, hostname string) bool {
	pattern = strings.ToLower(pattern)
	hostname = strings.ToLower(hostname)

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(hostname, suffix) && hostname != pattern[2:]
	}

	return pattern == hostname
}

// matchURLPrefix checks if the URL path starts with the given prefix.
func matchURLPrefix(prefix string, u *url.URL) bool {
	if u == nil {
		return false
	}
	return strings.HasPrefix(u.Path, prefix)
}

// extractHostname extracts the hostname (without port) from a URL.
func extractHostname(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Hostname()
}

// cloneRules returns a shallow copy of a rule slice.
func cloneRules(rules []ScopeRule) []ScopeRule {
	if rules == nil {
		return nil
	}
	out := make([]ScopeRule, len(rules))
	copy(out, rules)
	return out
}
