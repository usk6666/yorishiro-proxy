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

// ValidateTargetRule validates one target scope rule's hostname, ports and
// schemes. It is the per-rule core shared by both TargetScope layers: the
// Policy layer (TargetScopePolicyConfig.Validate) and the Agent layer (the
// MCP `security` tool, which adds its own "hostname is required" check).
//
// The rule it enforces: reject what is outside the closed scheme vocabulary
// or can never equal a data-path target, never reject a form that matches
// today. connector.matchTargetRule ANDs every condition, so a rule carrying
// an unmatchable condition matches nothing — for a deny that is fail-open.
//
//   - hostname "" is accepted (the rule matches any host). Otherwise it must
//     be an exact name, a "*.domain" wildcard, an IPv4 literal, or an IPv6
//     literal, bare ("fd00:ec2::254") or bracketed ("[::1]"). Data-path gates
//     pass hosts unbracketed (net.SplitHostPort / url.Hostname), so only the
//     bare form matches today; the bracketed form stays accepted on both
//     layers and its matching is a separate fix. Labels may contain letters,
//     digits, '-' and '_'.
//   - ports must be in 1-65535.
//   - schemes must be http or https in any case; "" is rejected (omitting
//     schemes already matches both).
//
// Errors carry no location prefix; callers add one ("denies[0]: ...").
func ValidateTargetRule(hostname string, ports []int, schemes []string) error {
	if hostname != "" {
		if err := validateTargetHostname(hostname); err != nil {
			return err
		}
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d is out of range (1-65535)", p)
		}
	}
	for _, s := range schemes {
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
	if strings.HasPrefix(h, "*.") {
		h = h[2:]
		if h == "" {
			return fmt.Errorf("hostname %q: wildcard must be followed by a domain", hostname)
		}
	}

	// A trailing dot never equals the dotless host the data path sees for
	// the same name, so a rule written as an FQDN would silently not match.
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
		return nil
	}

	// Bare IPv6: fd00:ec2::254. A colon is otherwise never valid, so
	// "host:port" and URLs fall through to the domain check and fail there.
	if strings.Contains(h, ":") && net.ParseIP(h) != nil {
		return nil
	}

	if isIPv4Like(h) {
		if net.ParseIP(h) == nil {
			return fmt.Errorf("hostname %q: invalid IPv4 address", hostname)
		}
		return nil
	}

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
// LoadPolicyFile (-target-policy-file) call it, so startup refuses an invalid
// policy, and a future reload path that goes through LoadPolicyFile inherits
// the same gate. Validation rejects; it never rewrites the operator's values
// (uppercase schemes are accepted here and lowercased when the rules are
// converted to connector.TargetRule).
func (p *TargetScopePolicyConfig) Validate() error {
	if p == nil {
		return nil
	}
	for i, r := range p.Allows {
		if err := ValidateTargetRule(r.Hostname, r.Ports, r.Schemes); err != nil {
			return fmt.Errorf("allows[%d]: %w", i, err)
		}
	}
	for i, r := range p.Denies {
		if err := ValidateTargetRule(r.Hostname, r.Ports, r.Schemes); err != nil {
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
