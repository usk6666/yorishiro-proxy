package flow

import (
	"net"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// RecordScope filters which flows are persisted to the flow store. It
// implements the recording-only observability filter described in USK-776:
// MITM and transmission still happen for all traffic, but only flows that
// match the scope are written to the Stream/Flow tables.
//
// RecordScope is conceptually independent from connector.TargetScope:
//
//   - TargetScope controls SEND (security / enforcement). Out-of-scope
//     traffic is blocked at the connector boundary.
//   - RecordScope controls RECORD (observability / storage). Out-of-scope
//     traffic flows through the proxy unchanged but is not persisted.
//
// When no rules are configured, ShouldRecord returns true for every
// envelope (capture-all default — current behaviour). Includes and excludes
// support hostname/url_prefix/method matchers (AND-evaluated within a
// rule); excludes take precedence over includes.
//
// RecordScope is safe for concurrent use. A single instance is owned by
// the MCP Server and shared by reference between proxy_start_tool /
// configure_tool (writers) and the live data-path RecordStep (reader).
type RecordScope struct {
	mu       sync.RWMutex
	includes []ScopeRule
	excludes []ScopeRule
}

// ScopeRule is a single capture-scope matching rule. All non-empty fields
// must match for the rule to apply (AND semantics). At least one of
// Hostname / URLPrefix / Method must be set; the MCP layer rejects an
// empty rule before constructing one here.
type ScopeRule struct {
	// Hostname matches the request hostname (case-insensitive). Supports
	// the wildcard prefix "*.example.com" which matches every direct or
	// indirect subdomain of example.com but NOT the apex example.com.
	Hostname string `json:"hostname,omitempty"`

	// URLPrefix matches the request URL path with strings.HasPrefix
	// (case- and percent-encoding-sensitive — operators must escape
	// percent-encoded paths exactly as they appear on the wire).
	URLPrefix string `json:"url_prefix,omitempty"`

	// Method matches the HTTP method (case-insensitive). Non-HTTP
	// envelopes never carry a method, so any rule with a non-empty
	// Method is inert against WS / gRPC / SSE / Raw envelopes.
	Method string `json:"method,omitempty"`
}

// IsEmpty reports whether the rule has no matchers configured. The MCP
// layer treats an empty rule as a validation error.
func (r ScopeRule) IsEmpty() bool {
	return r.Hostname == "" && r.URLPrefix == "" && r.Method == ""
}

// NewRecordScope returns an empty RecordScope (capture-all).
func NewRecordScope() *RecordScope {
	return &RecordScope{}
}

// SetRules atomically replaces the entire include/exclude rule sets.
// Passing nil clears the corresponding side.
func (s *RecordScope) SetRules(includes, excludes []ScopeRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.includes = cloneScopeRules(includes)
	s.excludes = cloneScopeRules(excludes)
}

// Rules returns deep copies of the current include and exclude rules.
func (s *RecordScope) Rules() (includes, excludes []ScopeRule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneScopeRules(s.includes), cloneScopeRules(s.excludes)
}

// MergeRules applies add/remove deltas to the current rules atomically
// under a single lock. Add operations skip duplicates (rules that compare
// equal field-by-field). Remove operations strip every rule that compares
// equal to the supplied rule.
func (s *RecordScope) MergeRules(addIncludes, removeIncludes, addExcludes, removeExcludes []ScopeRule) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, add := range addIncludes {
		if !containsScopeRule(s.includes, add) {
			s.includes = append(s.includes, add)
		}
	}
	for _, rem := range removeIncludes {
		s.includes = filterScopeRule(s.includes, rem)
	}
	for _, add := range addExcludes {
		if !containsScopeRule(s.excludes, add) {
			s.excludes = append(s.excludes, add)
		}
	}
	for _, rem := range removeExcludes {
		s.excludes = filterScopeRule(s.excludes, rem)
	}
}

// Clear resets the scope back to empty (capture-all).
func (s *RecordScope) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.includes = nil
	s.excludes = nil
}

// IsEmpty reports whether no rules are configured. RecordStep uses this
// to bypass evaluation entirely on the hot path.
func (s *RecordScope) IsEmpty() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.includes) == 0 && len(s.excludes) == 0
}

// ShouldRecord reports whether env should be persisted to the flow
// store. A nil RecordScope is treated as the empty (capture-all) scope.
//
// Evaluation order:
//  1. Any matching exclude rule wins → not captured.
//  2. No include rules → captured (all non-excluded envelopes are kept).
//  3. At least one include rule must match → captured.
//
// Per RFC-001 wire-fidelity discipline, ShouldRecord does not mutate env
// or its Message. Callers (RecordStep) cache the result per StreamID to
// keep flow recording decisions consistent across every envelope on a
// stream — see the cache documented in record_step.go.
func (s *RecordScope) ShouldRecord(env *envelope.Envelope) bool {
	if s == nil || env == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.includes) == 0 && len(s.excludes) == 0 {
		return true
	}

	method, hostname, path := extractScopeFields(env)

	for _, rule := range s.excludes {
		if matchScopeRule(rule, method, hostname, path) {
			return false
		}
	}
	if len(s.includes) == 0 {
		return true
	}
	for _, rule := range s.includes {
		if matchScopeRule(rule, method, hostname, path) {
			return true
		}
	}
	return false
}

// extractScopeFields pulls the (method, hostname, path) triple used by
// rule evaluation out of an Envelope. HTTP envelopes get the typed view;
// every other Message family falls back to the connection-level metadata
// (TargetHost set by CONNECT/SOCKS5, then TLS.SNI). When no hostname is
// derivable the empty string is returned and any rule with a Hostname
// field will fail to match — which is correct for include-mode
// (out-of-scope) and harmless for exclude-only (kept).
func extractScopeFields(env *envelope.Envelope) (method, hostname, path string) {
	hostname = scopeHostnameFromContext(env)

	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		if m != nil {
			method = m.Method
			path = m.Path
			if h := scopeHostnameFromAuthority(m.Authority); h != "" {
				hostname = h
			}
		}
	case *envelope.GRPCStartMessage:
		// gRPC over HTTP/2 wire-literally carries `:method = POST` and
		// `:path = /<Service>/<Method>`. Exposing these to capture_scope
		// is wire-faithful, not normalization (MITM Principle 1). Both
		// native gRPC and gRPC-Web emit *envelope.GRPCStartMessage. The
		// 3-field guard suppresses synthesis when a malformed `:path`
		// envelope left Service or Method empty, so a partial path like
		// "/Service/" cannot spuriously prefix-match a rule.
		if m != nil && m.Service != "" && m.Method != "" {
			path = "/" + m.Service + "/" + m.Method
			method = "POST"
		}
	}
	return method, hostname, path
}

// scopeHostnameFromContext returns the connection-level hostname (Context
// TargetHost first, then TLS SNI). Both fields are populated by the
// Layer Stack before RecordStep runs, so RecordStep's view is stable per
// connection regardless of protocol family.
func scopeHostnameFromContext(env *envelope.Envelope) string {
	if h := scopeHostnameFromAuthority(env.Context.TargetHost); h != "" {
		return h
	}
	if env.Context.TLS != nil && env.Context.TLS.SNI != "" {
		return env.Context.TLS.SNI
	}
	return ""
}

// scopeHostnameFromAuthority strips an optional ":port" suffix from
// host[:port] using net.SplitHostPort, falling back to the raw value
// when there is no port present.
func scopeHostnameFromAuthority(authority string) string {
	if authority == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h
	}
	return authority
}

// matchScopeRule returns true when rule matches the (method, hostname,
// path) triple. All non-empty rule fields must match (AND); empty rule
// fields are ignored.
func matchScopeRule(rule ScopeRule, method, hostname, path string) bool {
	if rule.Hostname != "" && !matchScopeHostname(rule.Hostname, hostname) {
		return false
	}
	if rule.URLPrefix != "" {
		if path == "" || !strings.HasPrefix(path, rule.URLPrefix) {
			return false
		}
	}
	if rule.Method != "" {
		if method == "" || !strings.EqualFold(method, rule.Method) {
			return false
		}
	}
	return true
}

// matchScopeHostname performs case-insensitive hostname matching with
// wildcard support. "*.example.com" matches every direct or indirect
// subdomain of example.com but NOT the apex "example.com". Pattern and
// hostname are normalised to lower case before comparison (RFC 3986
// §3.2.2 hostnames are case-insensitive on the wire — this is not a MITM
// fidelity violation).
func matchScopeHostname(pattern, hostname string) bool {
	pattern = strings.ToLower(pattern)
	hostname = strings.ToLower(hostname)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(hostname, suffix) && hostname != pattern[2:]
	}
	return pattern == hostname
}

// scopeRuleEqual reports whether two ScopeRule values are equal under
// the same case-folding rules used by matching: hostname is compared
// case-insensitively (RFC 3986); URLPrefix is compared byte-exact (paths
// are case-sensitive); method is compared case-insensitively.
func scopeRuleEqual(a, b ScopeRule) bool {
	if !strings.EqualFold(a.Hostname, b.Hostname) {
		return false
	}
	if a.URLPrefix != b.URLPrefix {
		return false
	}
	if !strings.EqualFold(a.Method, b.Method) {
		return false
	}
	return true
}

// containsScopeRule reports whether rules contains a rule that compares
// equal to target.
func containsScopeRule(rules []ScopeRule, target ScopeRule) bool {
	for _, r := range rules {
		if scopeRuleEqual(r, target) {
			return true
		}
	}
	return false
}

// filterScopeRule returns rules with every entry that compares equal to
// target removed.
func filterScopeRule(rules []ScopeRule, target ScopeRule) []ScopeRule {
	out := make([]ScopeRule, 0, len(rules))
	for _, r := range rules {
		if !scopeRuleEqual(r, target) {
			out = append(out, r)
		}
	}
	return out
}

// cloneScopeRules returns a copy of rules (or nil for nil input).
func cloneScopeRules(rules []ScopeRule) []ScopeRule {
	if rules == nil {
		return nil
	}
	out := make([]ScopeRule, len(rules))
	copy(out, rules)
	return out
}
