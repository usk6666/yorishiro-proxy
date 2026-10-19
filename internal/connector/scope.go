package connector

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TargetScope controls which network targets are allowed or blocked using a
// two-layer architecture: Policy Layer and Agent Layer.
//
// The Policy Layer is set at initialization time and can afterwards be
// replaced only by the operator (ReplacePolicyRules, driven by the SIGHUP
// reload in internal/mcpserver — USK-1115); the agent can never change it.
// It defines the upper boundary for what the Agent Layer can permit. The Agent
// Layer is mutable at runtime via the security MCP tool and can further restrict
// access within the Policy Layer's boundaries.
//
// Evaluation order:
//  1. Policy denies — always block (reason: "blocked by policy deny rule")
//  2. Agent denies — block (reason: "blocked by agent deny rule")
//  3. Policy allows (if any) — must match, otherwise block (reason: "not in policy allow list")
//  4. Agent allows (if any) — must match, otherwise block (reason: "not in agent allow list")
//  5. All checks passed — allow
//
// When neither layer has rules, all targets are permitted (open by default).
// TargetScope is safe for concurrent use.
type TargetScope struct {
	mu sync.RWMutex

	// Policy Layer (operator-only: set at boot, replaced only by the
	// operator's reload path — never by the agent)
	policyAllows []TargetRule // upper boundary — agent can only operate within this range
	policyDenies []TargetRule // always BLOCK — agent cannot unblock
	policyOrigin PolicyOrigin // where the current policy came from

	// Agent Layer (mutable via security tool)
	agentAllows []TargetRule // further restrict within policy allows
	agentDenies []TargetRule // additional restrictions within policy
}

// TargetRule defines a single target scope matching rule.
// All non-empty/non-nil fields must match for the rule to apply (AND logic).
type TargetRule struct {
	// Hostname matches the target hostname (case-insensitive).
	// Supports wildcard prefix "*.example.com" to match all subdomains.
	// An IPv6 literal may be written bare ("::1") or bracketed ("[::1]").
	// Rule and target are compared in canonical form (canonicalScopeHost),
	// so every spelling that may dial the same host matches: any textual form
	// of an IPv6 address, with or without a zone ("[fe80::1%eth0]" matches
	// "fe80::1"); an IPv4-mapped IPv6 address and its IPv4 address
	// ("::ffff:10.0.0.5" and "10.0.0.5", in either direction); a single
	// trailing dot ("db.internal." matches "db.internal" and "*.internal");
	// and legacy inet_aton IPv4 spellings ("2130706433", "0x7f.0.0.1",
	// "127.1" match "127.0.0.1"; only a libc resolver or an upstream proxy
	// reads those as the address — Go's pure resolver looks them up in DNS,
	// so on an allow rule they may admit a different host; see
	// canonicalScopeHost) (USK-1129, USK-1250). The stored rule is
	// never rewritten. Empty matches any host (Policy layer only; the Agent
	// layer requires a hostname).
	Hostname string `json:"hostname"`

	// Ports restricts the rule to specific port numbers.
	// When nil or empty, all ports are matched.
	Ports []int `json:"ports,omitempty"`

	// PathPrefix matches the beginning of the request URL path with a
	// literal, case-sensitive prefix comparison — not a glob. It must start
	// with "/" and contain no "*", "?" or "#" (config.ValidateTargetRule).
	// The path is matched in either its wire form or its percent-decoded
	// form (USK-1139, see PathPrefixMatches).
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
// and path is allowed by the current two-layer rules.
//
// The evaluation logic is:
//  1. If the target matches any policy deny rule, it is BLOCKED.
//  2. If the target matches any agent deny rule, it is BLOCKED.
//  3. If policy allow rules exist and none match, it is BLOCKED.
//  4. If agent allow rules exist and none match, it is BLOCKED.
//  5. Otherwise, it is ALLOWED.
//
// Before step 1, when either layer has any rule, a hostname whose last
// label is a number but that is not a valid IPv4 address ("1.2.3.4.5",
// "999999999999") is BLOCKED: a resolver may still read it as an address
// no rule can name (USK-1250, see numericHostUnparsable). With no rules at
// all (open mode) it is allowed like any other host.
//
// Returns allowed=true if the target is permitted, and a reason string
// explaining the decision when blocked.
func (s *TargetScope) CheckTarget(scheme, hostname string, port int, path string) (allowed bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 0. Fail closed on an unparsable numeric host (rules exist only).
	if s.hasRulesLocked() && numericHostUnparsable(hostname) {
		return false, numericHostReason
	}

	// 1. Policy denies (highest priority).
	for _, rule := range s.policyDenies {
		if matchTargetRule(rule, scheme, hostname, port, path) {
			return false, "blocked by policy deny rule"
		}
	}

	// 2. Agent denies.
	for _, rule := range s.agentDenies {
		if matchTargetRule(rule, scheme, hostname, port, path) {
			return false, "blocked by agent deny rule"
		}
	}

	// 3. Policy allows (if any exist, target must match at least one).
	if len(s.policyAllows) > 0 {
		matched := false
		for _, rule := range s.policyAllows {
			if matchTargetRule(rule, scheme, hostname, port, path) {
				matched = true
				break
			}
		}
		if !matched {
			return false, "not in policy allow list"
		}
	}

	// 4. Agent allows (if any exist, target must match at least one).
	if len(s.agentAllows) > 0 {
		matched := false
		for _, rule := range s.agentAllows {
			if matchTargetRule(rule, scheme, hostname, port, path) {
				matched = true
				break
			}
		}
		if !matched {
			return false, "not in agent allow list"
		}
	}

	// 5. All checks passed.
	return true, ""
}

// CheckHost is the path-unknown form of CheckTarget (USK-1130). Not yet implemented.
func (s *TargetScope) CheckHost(scheme, hostname string, port int) (allowed, pathPending bool, reason string) {
	allowed, reason = s.CheckTarget(scheme, hostname, port, "")
	return allowed, false, reason
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
	// USK-1139: match on the wire-form path; matchTargetRule also tries
	// its percent-decoded form, so a net/url-parsed URL and a Flow.URL
	// built by envelope.URLFromWirePath decide identically.
	path := envelope.WirePath(u)

	return s.CheckTarget(scheme, hostname, port, path)
}

// SetPolicyRules sets the policy layer rules at initialization. The only
// runtime replacement is ReplacePolicyRules (operator reload); the agent
// layer cannot change policy rules.
func (s *TargetScope) SetPolicyRules(allows, denies []TargetRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyAllows = cloneTargetRules(allows)
	s.policyDenies = cloneTargetRules(denies)
}

// PolicyOrigin describes where the current Policy Layer was loaded from. It
// is reported to the agent by `security get_target_scope` (USK-1115).
type PolicyOrigin struct {
	// Source is "policy file", "config file", or "" when no policy source
	// is configured.
	Source string
	// LoadedAt is when the Policy Layer was last installed (boot or reload).
	LoadedAt time.Time
}

// ReplacePolicyRules replaces the policy layer rules and their origin in one
// critical section, so a concurrent CheckTarget sees either the old or the
// new policy, never a mix. It is the operator's runtime path (the
// SIGHUP-driven reload in internal/mcpserver, USK-1115); the agent-facing
// MCP must never call it.
//
// Agent rules are kept verbatim even when the new policy no longer covers
// them: pruning an agent allow would drop the agent's self-restriction and
// widen what it can reach, and rejecting the reload would let the agent
// block the operator's change. An agent allow outside the new policy simply
// stops matching (CheckTarget blocks it as "not in policy allow list"). The
// agent allows that are outside the new policy allow boundary are returned
// so the caller can tell the operator.
func (s *TargetScope) ReplacePolicyRules(allows, denies []TargetRule, origin PolicyOrigin) (outsideAgentAllows []TargetRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyAllows = cloneTargetRules(allows)
	s.policyDenies = cloneTargetRules(denies)
	s.policyOrigin = origin
	if len(s.policyAllows) == 0 {
		return nil
	}
	for _, r := range s.agentAllows {
		if !isRuleCoveredByPolicy(s.policyAllows, r) {
			outsideAgentAllows = append(outsideAgentAllows, cloneTargetRule(r))
		}
	}
	return outsideAgentAllows
}

// SetPolicyOrigin records where the boot-time Policy Layer came from. Boot
// installs the rules with SetPolicyRules and the origin here; a reload sets
// both at once with ReplacePolicyRules.
func (s *TargetScope) SetPolicyOrigin(origin PolicyOrigin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyOrigin = origin
}

// PolicyOrigin returns where the current Policy Layer came from.
func (s *TargetScope) PolicyOrigin() PolicyOrigin {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policyOrigin
}

// PolicyRules returns a copy of the current policy allow and deny rules.
func (s *TargetScope) PolicyRules() (allows, denies []TargetRule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTargetRules(s.policyAllows), cloneTargetRules(s.policyDenies)
}

// HasPolicyRules reports whether at least one policy allow or deny rule is configured.
func (s *TargetScope) HasPolicyRules() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.policyAllows) > 0 || len(s.policyDenies) > 0
}

// SetAgentRules replaces all agent allow and deny rules atomically.
// If policy allow rules are configured, the agent allows must be within the
// policy allow boundary. Returns an error if any agent allow rule falls outside
// the policy allow scope.
func (s *TargetScope) SetAgentRules(allows, denies []TargetRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateAgentAllowsLocked(s.policyAllows, allows); err != nil {
		return err
	}

	s.agentAllows = cloneTargetRules(allows)
	s.agentDenies = cloneTargetRules(denies)
	return nil
}

// MergeAgentRules atomically applies add/remove deltas to the agent layer rules.
// Within a single lock, it reads the current rules, applies the deltas, and
// writes back. For add operations, duplicate rules are skipped.
// For remove operations, all matching rules are removed.
// Returns an error if any new agent allow rule falls outside the policy allow scope.
func (s *TargetScope) MergeAgentRules(addAllows, removeAllows, addDenies, removeDenies []TargetRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate new allows against policy boundary before applying.
	if err := validateAgentAllowsLocked(s.policyAllows, addAllows); err != nil {
		return err
	}

	// Apply allow additions (skip duplicates, deep copy each rule).
	for _, add := range addAllows {
		if !containsTargetRule(s.agentAllows, add) {
			s.agentAllows = append(s.agentAllows, cloneTargetRule(add))
		}
	}
	// Apply allow removals.
	for _, rem := range removeAllows {
		s.agentAllows = filterTargetRule(s.agentAllows, rem)
	}

	// Apply deny additions (skip duplicates, deep copy each rule).
	for _, add := range addDenies {
		if !containsTargetRule(s.agentDenies, add) {
			s.agentDenies = append(s.agentDenies, cloneTargetRule(add))
		}
	}
	// Apply deny removals.
	for _, rem := range removeDenies {
		s.agentDenies = filterTargetRule(s.agentDenies, rem)
	}
	return nil
}

// AgentRules returns a copy of the current agent allow and deny rules.
func (s *TargetScope) AgentRules() (allows, denies []TargetRule) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneTargetRules(s.agentAllows), cloneTargetRules(s.agentDenies)
}

// HasRules reports whether at least one rule is configured in either
// the policy layer or the agent layer.
func (s *TargetScope) HasRules() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasRulesLocked()
}

// hasRulesLocked is HasRules for a caller already holding s.mu.
func (s *TargetScope) hasRulesLocked() bool {
	return len(s.policyAllows) > 0 || len(s.policyDenies) > 0 ||
		len(s.agentAllows) > 0 || len(s.agentDenies) > 0
}

// ValidateAgentAllows checks whether the given agent allow rules fall within
// the policy allow boundary. If no policy allows are configured, all agent
// allows are valid. Returns an error describing the first rule that is outside
// the policy boundary.
func (s *TargetScope) ValidateAgentAllows(allows []TargetRule) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return validateAgentAllowsLocked(s.policyAllows, allows)
}

// validateAgentAllowsLocked checks whether agent allow rules are within the
// policy allow boundary. Must be called with s.mu held (read or write).
// If no policy allows are configured, all agent allows are considered valid.
func validateAgentAllowsLocked(policyAllows, agentAllows []TargetRule) error {
	if len(policyAllows) == 0 {
		// No policy allows means no boundary restriction.
		return nil
	}

	for _, agentRule := range agentAllows {
		if !isRuleCoveredByPolicy(policyAllows, agentRule) {
			return fmt.Errorf("agent allow rule %q is outside policy allow boundary", agentRule.Hostname)
		}
	}
	return nil
}

// isRuleCoveredByPolicy checks if an agent allow rule is covered by at least
// one policy allow rule. An agent rule is considered "covered" if there exists
// a policy rule that would match the same or broader set of targets.
//
// Coverage check:
//   - The agent rule's hostname must be matchable by a policy rule's hostname pattern
//   - If the policy rule restricts ports, the agent rule's ports must be a subset
//   - If the policy rule restricts schemes, the agent rule's schemes must be a subset
//   - If the policy rule restricts path prefix, the agent rule's path prefix must
//     be equal to or more specific (longer) than the policy rule's
func isRuleCoveredByPolicy(policyAllows []TargetRule, agentRule TargetRule) bool {
	for _, policyRule := range policyAllows {
		if ruleCoversRule(policyRule, agentRule) {
			return true
		}
	}
	return false
}

// ruleCoversRule checks whether the covering rule encompasses the covered rule.
// The covering rule must match a superset of the targets matched by the covered rule.
func ruleCoversRule(covering, covered TargetRule) bool {
	// Hostname check: covering must match covered's hostname pattern.
	if !hostnameCoveredBy(covering.Hostname, covered.Hostname) {
		return false
	}

	// Ports check: if covering restricts ports, covered's ports must be a subset.
	if len(covering.Ports) > 0 {
		if len(covered.Ports) == 0 {
			// covered matches all ports but covering restricts — not covered.
			return false
		}
		for _, p := range covered.Ports {
			if !containsInt(covering.Ports, p) {
				return false
			}
		}
	}

	// Schemes check: if covering restricts schemes, covered's schemes must be a subset.
	if len(covering.Schemes) > 0 {
		if len(covered.Schemes) == 0 {
			// covered matches all schemes but covering restricts — not covered.
			return false
		}
		for _, s := range covered.Schemes {
			if !containsStringFold(covering.Schemes, s) {
				return false
			}
		}
	}

	// PathPrefix check: if covering restricts path, covered must be equal or more specific.
	if covering.PathPrefix != "" {
		if covered.PathPrefix == "" {
			// covered matches all paths but covering restricts — not covered.
			return false
		}
		if !strings.HasPrefix(covered.PathPrefix, covering.PathPrefix) {
			return false
		}
	}

	return true
}

// hostnameCoveredBy checks if the covering hostname pattern encompasses the
// covered hostname pattern. For example:
//   - "" covers every hostname (it matches any host, as in matchTargetRule)
//   - "*.example.com" covers "sub.example.com" (exact is subset of wildcard)
//   - "*.example.com" covers "*.example.com" (same wildcard)
//   - "example.com" covers "example.com" (same exact)
//   - "::1" covers "[::1]" (same IPv6 address, see canonicalScopeHost)
//   - "10.0.0.5" covers "::ffff:10.0.0.5" and vice versa (same address)
//   - "*.example.com" does NOT cover "*.other.com"
//   - a non-empty covering hostname does NOT cover "" (any host)
func hostnameCoveredBy(covering, covered string) bool {
	if covering == "" {
		return true
	}
	coveringLower := canonicalScopeHost(covering)
	coveredLower := canonicalScopeHost(covered)

	// Exact match.
	if coveringLower == coveredLower {
		return true
	}

	// Covering is a wildcard pattern.
	if strings.HasPrefix(coveringLower, "*.") {
		suffix := coveringLower[1:] // ".example.com"

		// Covered is also a wildcard — check if its suffix matches.
		if strings.HasPrefix(coveredLower, "*.") {
			coveredSuffix := coveredLower[1:]
			return strings.HasSuffix(coveredSuffix, suffix)
		}

		// Covered is an exact hostname — check if it ends with the suffix.
		return strings.HasSuffix(coveredLower, suffix)
	}

	// Covering is exact — only covers the same exact hostname (handled above).
	return false
}

// MatchTargetRule reports whether a target matches a single TargetRule —
// the exact predicate CheckTarget applies. It is exported so the MCP
// security tool can name the rule that decided a test_target verdict without
// keeping a copy that drifts from the engine (USK-1129).
func MatchTargetRule(rule TargetRule, scheme, hostname string, port int, path string) bool {
	return matchTargetRule(rule, scheme, hostname, port, path)
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
	if rule.PathPrefix != "" && !PathPrefixMatches(path, rule.PathPrefix) {
		return false
	}
	if len(rule.Schemes) > 0 && !containsStringFold(rule.Schemes, scheme) {
		return false
	}
	return true
}

// PathPrefixMatches reports whether a path_prefix rule matches path, which is
// the request path in wire form (USK-1139). The rule matches when either the
// wire form or its single-pass percent-decoded form
// (envelope.LenientDecodePath) starts with prefix, so "/admin" matches
// "/admin", "/%61dmin" and "/adm%69n" alike, and a prefix written in encoded
// form ("/a%20b") still matches the wire bytes it names. For deny rules this
// fails closed; every path a rule matched before USK-1139 on HTTP/1.x
// (decoded) or HTTP/2 (wire) is still matched. Dot-segment removal, "%2F"
// semantics and case folding are out of scope here (USK-1131).
func PathPrefixMatches(path, prefix string) bool {
	if strings.HasPrefix(path, prefix) {
		return true
	}
	return strings.HasPrefix(envelope.LenientDecodePath(path), prefix)
}

// matchHostname performs case-insensitive hostname matching with wildcard support.
// Pattern "*.example.com" matches "sub.example.com" but not "example.com".
// Exact patterns match exactly; both sides are compared in canonical form
// (canonicalScopeHost), so a rule matches every spelling of its host that
// dials the same destination (IPv6 forms and zones, IPv4-mapped IPv6, one
// trailing dot, legacy IPv4). A wildcard compares after the trailing dot
// is stripped: "a.internal." matches "*.internal", the apex "internal."
// does not.
func matchHostname(pattern, hostname string) bool {
	pattern = canonicalScopeHost(pattern)
	hostname = canonicalScopeHost(hostname)

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(hostname, suffix) && hostname != pattern[2:]
	}

	return pattern == hostname
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

// TargetRuleEqual reports whether two rules are the same rule — the
// equality TargetScope uses to dedupe added rules and to find rules to
// remove. Exported for the MCP security tool's policy-deny removal guard
// (USK-1129).
func TargetRuleEqual(a, b TargetRule) bool {
	return targetRuleEqual(a, b)
}

// targetRuleEqual reports whether two TargetRule values are equal.
// Hostnames compare in canonical form (canonicalScopeHost), so "::1" and
// "[::1]", "example.com." and "example.com", and "::ffff:10.0.0.5" and
// "10.0.0.5" are one rule.
func targetRuleEqual(a, b TargetRule) bool {
	if canonicalScopeHost(a.Hostname) != canonicalScopeHost(b.Hostname) {
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
