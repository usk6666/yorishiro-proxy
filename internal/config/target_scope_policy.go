package config

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// targetRuleSchemes is the closed vocabulary of TargetRule.Schemes
// (RFC-001 §3.8). `schemes` is a transport-confidentiality predicate —
// plaintext vs TLS — not an L7 protocol name, so WebSocket / raw TCP traffic
// is scoped as http / https too. Tokens are compared case-insensitively.
var targetRuleSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// ValidateTargetRule validates one target scope rule's hostname, ports,
// path_prefix and schemes. It is the per-rule core shared by both
// TargetScope layers: the Policy layer (TargetScopePolicyConfig.Validate) and
// the Agent layer (the MCP `security` tool, which adds its own "hostname is
// required" check). Remove operations on the Agent layer deliberately skip
// it, so a stale rule can always be removed.
//
// The rule it enforces: reject what is outside the closed scheme vocabulary
// or can never equal a data-path target, never reject a form that matches
// today. connector.matchTargetRule ANDs every condition, so a rule carrying
// an unmatchable condition matches nothing — for a deny that is fail-open.
// The one deliberate exception is a trailing-dot hostname (see below): it is
// rejected although it can match, and that rejection fails closed.
//
//   - hostname "" is accepted (the rule matches any host). Otherwise it must
//     be an exact name, a "*.domain" wildcard, an IPv4 literal, or an IPv6
//     literal, bare ("fd00:ec2::254") or bracketed ("[::1]"). The two IPv6
//     spellings are equivalent: connector compares hosts on a canonical form
//     (one enclosing bracket pair stripped, IPv6 in its RFC 5952 text form),
//     so "[::1]", "::1" and "0:0::1" are the same rule and match the same
//     targets (USK-1129). The comparison also ignores a target's IPv6
//     zone ("[fe80::1%eth0]" matches "fe80::1"; a rule cannot carry one),
//     unmaps IPv4-mapped IPv6 in both directions (a "::ffff:10.0.0.5"
//     rule is accepted and equals "10.0.0.5"), strips one trailing dot
//     from the target, and reads legacy inet_aton IPv4 target spellings
//     ("2130706433", "127.1") as dotted-quad (USK-1250). Those legacy
//     spellings are still rejected as rule hostnames ("invalid IPv4
//     address"): the dotted-quad rule already matches them. A wildcard
//     over an IP literal ("*.::1", "*.[::1]", "*.10.0.0.1") is rejected:
//     no host ends with ".::1".
//     Labels may contain letters, digits, '-' and '_'.
//   - a trailing-dot hostname ("internal.corp.") is rejected. connector
//     strips one trailing dot from both sides before comparing (USK-1250),
//     so such a rule would match exactly what its dotless form matches;
//     the dotless form is the one spelling the operator needs, and keeping
//     the rejection means no previously refused config starts loading.
//     Rejecting fails closed: startup (or the security tool call) refuses
//     loudly instead of installing the rule.
//   - ports must be in 1-65535.
//   - path_prefix "" is accepted (all paths). Otherwise it must start with
//     "/" and contain no "*", "?" or "#" (see validatePathPrefix).
//   - schemes must be http or https in any case; "" is rejected (omitting
//     schemes already matches both).
//
// Errors carry no location prefix; callers add one ("denies[0]: ...").
func ValidateTargetRule(r TargetRuleConfig) error {
	if r.Hostname != "" {
		if err := validateTargetHostname(r.Hostname); err != nil {
			return err
		}
	}
	if err := validatePathPrefix(r.PathPrefix); err != nil {
		return err
	}
	for _, p := range r.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d is out of range (1-65535)", p)
		}
	}
	for _, s := range r.Schemes {
		if s == "" {
			return fmt.Errorf("scheme %q is not allowed (use http or https; omit schemes to match both)", s)
		}
		if !targetRuleSchemes[strings.ToLower(s)] {
			return fmt.Errorf("scheme %q is not allowed (use http or https)", s)
		}
	}
	return nil
}

// validateTargetHostname checks a non-empty target rule hostname. See
// ValidateTargetRule for the accepted forms. It must not panic on any input.
func validateTargetHostname(hostname string) error {
	h := hostname
	wildcard := strings.HasPrefix(h, "*.")
	if wildcard {
		h = h[2:]
		if h == "" {
			return fmt.Errorf("hostname %q: wildcard must be followed by a domain", hostname)
		}
	}

	// A trailing-dot rule is rejected (see ValidateTargetRule): connector
	// compares hosts with one trailing dot stripped, so the dotless
	// spelling already matches both "x" and "x." targets. The rejection
	// fails closed: the caller refuses the rule.
	if strings.HasSuffix(h, ".") {
		return fmt.Errorf("hostname %q: trailing dot is not allowed", hostname)
	}

	// Bracketed IPv6: [::1].
	if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return fmt.Errorf("hostname %q: mismatched brackets for IPv6 address", hostname)
		}
		if net.ParseIP(h[1:len(h)-1]) == nil {
			return fmt.Errorf("hostname %q: invalid IPv6 address", hostname)
		}
		if wildcard {
			// No host ends with ".[::1]", so the rule could never match.
			return fmt.Errorf("hostname %q: wildcard is not allowed on an IP literal", hostname)
		}
		return nil
	}

	// Bare IPv6: fd00:ec2::254. A colon is otherwise never valid, so
	// "host:port" and URLs fall through to the domain check and fail there.
	if strings.Contains(h, ":") && net.ParseIP(h) != nil {
		if wildcard {
			// No host ends with ".fd00::1", so the rule could never match.
			return fmt.Errorf("hostname %q: wildcard is not allowed on an IP literal", hostname)
		}
		return nil
	}

	if isIPv4Like(h) {
		if net.ParseIP(h) == nil {
			return fmt.Errorf("hostname %q: invalid IPv4 address", hostname)
		}
		if wildcard {
			// A host ending in ".10.0.0.1" is not a name any client
			// resolves (an all-numeric final label is parsed as IPv4), so
			// the rule could never match a real target.
			return fmt.Errorf("hostname %q: wildcard is not allowed on an IP literal", hostname)
		}
		return nil
	}

	return validateDomainName(h, hostname)
}

// validatePathPrefix checks a target rule path_prefix. "" (all paths) is
// accepted. connector.matchTargetRule compares it with a literal,
// case-sensitive strings.HasPrefix against the request path, and every
// request path the data path produces for normal traffic starts with "/"
// (origin-form, absolute-form and HTTP/2 :path alike), is already split at
// "?" and never carries a fragment. A prefix that breaks any of those can
// never match, which for a deny is fail-open, so it is rejected with a hint
// rather than rewritten:
//
//   - "*" anywhere: path_prefix is already a prefix match, so "/api/*" is a
//     glob misreading of "/api/". Glob and regex are deliberately not
//     supported. Checked first so "*" gets this hint rather than the
//     leading-"/" one.
//   - "?" or "#": the query and fragment are not part of the matched path.
//   - no leading "/": "admin" never matches "/admin". "OPTIONS *" (path
//     "*") is not carved out; a rule for it would be a deny on a probe.
func validatePathPrefix(p string) error {
	if p == "" {
		return nil
	}
	if strings.ContainsAny(p, "?#") {
		return fmt.Errorf("path_prefix %q: query/fragment is not part of the path; use the path only", p)
	}
	if i := strings.IndexByte(p, '*'); i >= 0 {
		trimmed := strings.TrimRight(p, "*")
		if strings.Contains(trimmed, "*") {
			return fmt.Errorf("path_prefix %q: path_prefix is a literal prefix match and \"*\" is not a wildcard; use the literal prefix before it (e.g. %q)", p, withLeadingSlash(p[:i]))
		}
		if trimmed == "" {
			return fmt.Errorf("path_prefix %q: path_prefix is a literal prefix match; drop the trailing \"*\" (omit path_prefix to match every path)", p)
		}
		return fmt.Errorf("path_prefix %q: path_prefix is a literal prefix match; drop the trailing \"*\" (e.g. %q -> %q)", p, p, withLeadingSlash(trimmed))
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path_prefix %q must start with \"/\" (e.g. %q)", p, withLeadingSlash(p))
	}
	return nil
}

// withLeadingSlash returns p with a leading "/" for use in an error hint.
func withLeadingSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
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

// validateDomainName validates a DNS-style name: dot-separated labels of
// letters, digits, '-' and '_', none empty, none longer than 63 bytes, none
// starting or ending with '-', 253 bytes total at most. original is the
// operator's spelling, used in error messages.
func validateDomainName(domain, original string) error {
	if len(domain) > 253 {
		return fmt.Errorf("hostname %q: domain name too long", original)
	}
	for _, label := range strings.Split(domain, ".") {
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
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("hostname %q: label %q must not start or end with a hyphen", original, label)
		}
	}
	return nil
}

// isValidLabelChar reports whether c may appear in a target hostname label.
// Underscore is accepted: it is not a valid DNS hostname character, but
// internal names such as "db_primary" or "_dmarc.example.com" reach the data
// path verbatim and are matched by connector.matchHostname.
func isValidLabelChar(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

// Validate checks the Policy layer of TargetScope — allow / deny rules plus
// the rate_limits and budget ceilings that share this object — and returns
// the first problem found. A nil receiver is valid (no policy).
//
// It is the single reuse point for every path that installs a Policy layer:
// ProxyConfig.Validate (config-file target_scope_policy section) and
// LoadPolicyFile / ParsePolicyFile (-target-policy-file) call it, so startup
// refuses an invalid policy, and the SIGHUP Policy Layer reload (USK-1115,
// which parses through the same functions) rejects it while keeping the
// running policy. Validation rejects; it never rewrites the operator's values
// (uppercase schemes are accepted here and lowercased when the rules are
// converted to connector.TargetRule).
func (p *TargetScopePolicyConfig) Validate() error {
	if p == nil {
		return nil
	}
	for i, r := range p.Allows {
		if err := ValidateTargetRule(r); err != nil {
			return fmt.Errorf("allows[%d]: %w", i, err)
		}
	}
	for i, r := range p.Denies {
		if err := ValidateTargetRule(r); err != nil {
			return fmt.Errorf("denies[%d]: %w", i, err)
		}
	}
	if err := p.RateLimits.validate(); err != nil {
		return fmt.Errorf("rate_limits: %w", err)
	}
	if err := p.Budget.validate(); err != nil {
		return fmt.Errorf("budget: %w", err)
	}
	return nil
}

// validate rejects negative rate limits. Consumers treat only > 0 as a
// limit, so a negative value would silently mean "unlimited". Zero is the
// documented "no limit" value.
func (r *RateLimitPolicyConfig) validate() error {
	if r == nil {
		return nil
	}
	if r.MaxRequestsPerSecond < 0 {
		return fmt.Errorf("max_requests_per_second must be >= 0")
	}
	if r.MaxRequestsPerHostPerSecond < 0 {
		return fmt.Errorf("max_requests_per_host_per_second must be >= 0")
	}
	return nil
}

// validate rejects negative budget values, for the same reason as
// RateLimitPolicyConfig.validate. Unparsable durations are already rejected
// by Duration.UnmarshalJSON.
func (b *BudgetPolicyConfig) validate() error {
	if b == nil {
		return nil
	}
	if b.MaxTotalRequests < 0 {
		return fmt.Errorf("max_total_requests must be >= 0")
	}
	if time.Duration(b.MaxDuration) < 0 {
		return fmt.Errorf("max_duration must be >= 0")
	}
	return nil
}
