package connector

import (
	"net"
	"net/netip"
	"strings"
)

// Name legs (USK-1167).
//
// An HTTP request names its target twice over: the connection's dial
// target (Envelope.Context.TargetHost, or the resend / fuzz dial address)
// and the names the request itself carries — the authority (HTTP/1 Host
// as parsed, HTTP/2 :authority) and every Host header value. The dial
// target is what the proxy connects to; the names are what a virtual-host
// server on that address routes on. Both are scope-checked, but the names
// with a narrower allow semantic ("Option B"):
//
//   - Deny rules apply to a name exactly as to any target: a request that
//     names a denied host is refused whatever it dials.
//   - Per allow layer: if the dial target was admitted by an allow rule of
//     that layer whose hostname is an IP literal, the name does not also
//     have to match an allow rule of that layer. The operator allowed an
//     address, not a set of names; same-IP different-vhost testing and
//     Host-header injection stay possible.
//   - If the layer admitted the dial target only through domain-name
//     rules, the name must match an allow rule of that layer too: the
//     operator allowed names, and a different name may be a different
//     tenant on shared infrastructure.
//   - A layer with no allow rules passes, as in CheckTarget.
//   - Without a dial target (no live route sets none today) the name gets
//     the full CheckTarget check.

// CheckNameLeg checks a name leg — a host a request carries rather than
// the host it dials — against the rules: scheme, name, port and path as in
// CheckTarget, with dialTarget ("host:port", or "" when unknown) the
// connection's dial target. See the "Name legs" comment above for the
// allow semantics. The dial target itself must be checked separately
// with CheckTarget; this method only decides whether it exempts the name
// from an allow layer.
//
// CheckTarget is unchanged for every other caller.
func (s *TargetScope) CheckNameLeg(scheme, name string, port int, path, dialTarget string) (allowed bool, reason string) {
	if dialTarget == "" {
		return s.CheckTarget(scheme, name, port, path)
	}
	dialHost, dialPort := splitDialTarget(scheme, dialTarget)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.hasRulesLocked() && numericHostUnparsable(name) {
		return false, numericHostReason
	}
	for _, rule := range s.policyDenies {
		if matchTargetRule(rule, scheme, name, port, path) {
			return false, "blocked by policy deny rule"
		}
	}
	for _, rule := range s.agentDenies {
		if matchTargetRule(rule, scheme, name, port, path) {
			return false, "blocked by agent deny rule"
		}
	}
	if !matchAllowLayerName(s.policyAllows, scheme, name, port, path, dialHost, dialPort) {
		return false, "not in policy allow list"
	}
	if !matchAllowLayerName(s.agentAllows, scheme, name, port, path, dialHost, dialPort) {
		return false, "not in agent allow list"
	}
	return true, ""
}

// matchAllowLayerName evaluates one allow layer for a name leg: an empty
// layer passes, a layer whose IP-literal rule admits the dial target
// passes, and otherwise the name itself must match a rule of the layer.
func matchAllowLayerName(rules []TargetRule, scheme, name string, port int, path, dialHost string, dialPort int) bool {
	if len(rules) == 0 {
		return true
	}
	for _, rule := range rules {
		if isIPLiteralRule(rule) && matchTargetRule(rule, scheme, dialHost, dialPort, path) {
			return true
		}
	}
	for _, rule := range rules {
		if matchTargetRule(rule, scheme, name, port, path) {
			return true
		}
	}
	return false
}

// isIPLiteralRule reports whether rule names a single IP address (any
// spelling canonicalScopeHost reads as one). TargetScope has no CIDR form.
func isIPLiteralRule(rule TargetRule) bool {
	if rule.Hostname == "" {
		return false
	}
	_, isIP := canonicalScopeHostIP(rule.Hostname)
	return isIP
}

// splitDialTarget splits a dial target into host and port; a port-less or
// unparsable port takes the scheme default (0 when unknown). The dial
// target only decides an exemption here — its own verdict comes from the
// caller's CheckTarget on the strictly parsed target.
func splitDialTarget(scheme, target string) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, defaultPort(scheme, "")
	}
	return host, defaultPort(scheme, portStr)
}

// ReasonHostHeaderUninterpretable is the block reason for a Host header
// value whose port is not a decimal 1-65535 or whose host:port form cannot
// be split.
const ReasonHostHeaderUninterpretable = "blocked: Host header value has an uninterpretable host or port"

// CheckHostHeader checks one Host header value (already stripped of
// surrounding OWS, see envelope.HostHeaderValues) as a name leg
// (CheckNameLeg). The value is split as an RFC 9110 §7.2 uri-host [":"
// port]: a port-less value takes the scheme's default port, an empty port
// after the colon too. A port that is present but is not a decimal number
// in 1..65535 ("denied:abc", "denied:99999999999") — or a value with
// colons that is neither "host:port", "[v6]:port", "[v6]" nor a bare IPv6
// address — is refused when the scope has rules: a server may read the
// host part regardless, and no rule could name the port it would use
// (the same fail-closed stance as SplitTargetHostPort, USK-1249). The
// value itself is never rewritten.
func (s *TargetScope) CheckHostHeader(scheme, value, path, dialTarget string) (allowed bool, reason string) {
	if !s.HasRules() {
		return true, ""
	}
	host, port, ok := splitHostHeaderValue(scheme, value)
	if !ok {
		return false, ReasonHostHeaderUninterpretable
	}
	return s.CheckNameLeg(scheme, host, port, path, dialTarget)
}

// splitHostHeaderValue splits a Host header value into host and port for
// CheckHostHeader. ok is false when the value cannot be interpreted.
func splitHostHeaderValue(scheme, value string) (host string, port int, ok bool) {
	if strings.IndexByte(value, ':') < 0 {
		return value, defaultPort(scheme, ""), true
	}
	h, portStr, err := net.SplitHostPort(value)
	if err != nil {
		// "[v6]" without a port, or a bare IPv6 address.
		if len(value) > 2 && value[0] == '[' && value[len(value)-1] == ']' {
			if _, perr := netip.ParseAddr(value[1 : len(value)-1]); perr == nil {
				return value, defaultPort(scheme, ""), true
			}
			return "", 0, false
		}
		if _, perr := netip.ParseAddr(value); perr == nil {
			return value, defaultPort(scheme, ""), true
		}
		return "", 0, false
	}
	if portStr == "" {
		return h, defaultPort(scheme, ""), true
	}
	_, p, err := SplitTargetHostPort(value)
	if err != nil {
		return "", 0, false
	}
	return h, p, true
}
