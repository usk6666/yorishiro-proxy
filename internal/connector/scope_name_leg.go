package connector

import (
	"net"
	"strconv"
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
//     names a denied host is refused whatever it dials. A port-scoped deny
//     matches when either the port written in the name or the dial
//     target's port is one of its ports (USK-1306): the bytes reach the
//     dial port, so "Host: portd.example:8080" sent to port 80 is still
//     portd.example on port 80 to the server that receives it.
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
//
// A whole name value (CheckHostHeader, CheckAuthority) is additionally
// deny-checked under other readings a server may apply (USK-1304, U1):
// each comma-separated part (HAProxy's hdr(host), for one, routes on the
// last), and for an unbracketed IPv6 value the last-colon split into
// address and port. Those readings only ever add refusals; allow is
// judged on the whole value, and the value is never rewritten.

// CheckNameLeg checks a name leg — a host a request carries rather than
// the host it dials — against the rules: scheme, name, port and path as in
// CheckTarget, with dialTarget ("host:port", or "" when unknown) the
// connection's dial target. See the "Name legs" comment above for the
// deny and allow semantics. The dial target itself must be checked
// separately with CheckTarget; this method only decides whether it
// exempts the name from an allow layer and which port it adds to the
// deny match.
//
// CheckTarget is unchanged for every other caller.
func (s *TargetScope) CheckNameLeg(scheme, name string, port int, path, dialTarget string) (allowed bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.checkNameLegLocked(scheme, name, port, path, dialTarget)
}

// checkNameLegLocked is CheckNameLeg for a caller holding s.mu.
func (s *TargetScope) checkNameLegLocked(scheme, name string, port int, path, dialTarget string) (bool, string) {
	if dialTarget == "" {
		return s.checkTargetLocked(scheme, name, port, path)
	}
	dialHost, dialPort := splitDialTarget(scheme, dialTarget)
	if ok, reason := s.nameDenyLocked(scheme, name, port, dialPort, path); !ok {
		return false, reason
	}
	if !matchAllowLayerName(s.policyAllows, scheme, name, port, path, dialHost, dialPort) {
		return false, "not in policy allow list"
	}
	if !matchAllowLayerName(s.agentAllows, scheme, name, port, path, dialHost, dialPort) {
		return false, "not in agent allow list"
	}
	return true, ""
}

// nameDenyLocked applies the deny side of a name-leg check: the numeric
// host guard and both deny layers, where a rule matches on the name's own
// port or on dialPort (0 = no dial target, name port only). Caller holds
// s.mu.
func (s *TargetScope) nameDenyLocked(scheme, name string, port, dialPort int, path string) (bool, string) {
	if s.hasRulesLocked() && numericHostUnparsable(name) {
		return false, numericHostReason
	}
	for _, rule := range s.policyDenies {
		if matchNameDeny(rule, scheme, name, port, dialPort, path) {
			return false, "blocked by policy deny rule"
		}
	}
	for _, rule := range s.agentDenies {
		if matchNameDeny(rule, scheme, name, port, dialPort, path) {
			return false, "blocked by agent deny rule"
		}
	}
	return true, ""
}

// matchNameDeny reports whether a deny rule matches a name leg on the
// name's port or on the dial port (USK-1306).
func matchNameDeny(rule TargetRule, scheme, name string, port, dialPort int, path string) bool {
	if matchTargetRule(rule, scheme, name, port, path) {
		return true
	}
	return dialPort != 0 && dialPort != port && matchTargetRule(rule, scheme, name, dialPort, path)
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
// target only decides an exemption and adds a deny port here — its own
// verdict comes from the caller's CheckTarget on the strictly parsed
// target.
func splitDialTarget(scheme, target string) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, defaultPort(scheme, "")
	}
	return host, defaultPort(scheme, portStr)
}

// ReasonHostHeaderUninterpretable is the block reason for a Host header
// value (or one comma-separated part of it) whose port is not a decimal
// 1-65535 or whose host:port form cannot be split.
const ReasonHostHeaderUninterpretable = "blocked: Host header value has an uninterpretable host or port"

// CheckHostHeader checks one Host header value (already stripped of
// surrounding OWS, see envelope.HostHeaderValues) as a name leg
// (CheckNameLeg). The value is split as an RFC 9110 §7.2 uri-host [":"
// port]: a port-less value takes the scheme's default port, an empty port
// after the colon too. A port that is present but is not a decimal number
// in 1..65535 ("denied:abc", "denied:99999999999") — or a value with
// colons that is neither "host:port", "[v6]:port", "[v6]" nor a bare IPv6
// address, or a bracket holding anything but an IPv6 literal
// ("[db.internal:5432]:80") — is refused when the scope has rules: a
// server may read the host part regardless, and no rule could name the
// port it would use (the same fail-closed stance as SplitTargetHostPort,
// USK-1249, USK-1264).
//
// Deny rules are also applied to the value's other readings (USK-1304,
// U1): each comma-separated part, OWS-trimmed, empty parts skipped, split
// the same way (an uninterpretable part is refused); and, for an
// unbracketed IPv6 value, the last-colon split into address and strict
// port ("2001:db8::1:8080" → 2001:db8::1 port 8080). Allow rules judge the
// whole value only, so a comma value whose parts are not denied passes as
// before (Option B). The whole decision runs under one read lock, so a
// concurrent policy swap cannot split it. The value is never rewritten.
func (s *TargetScope) CheckHostHeader(scheme, value, path, dialTarget string) (allowed bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.hasRulesLocked() {
		return true, ""
	}
	host, port, ok := splitHostHeaderValue(scheme, value)
	if !ok {
		return false, ReasonHostHeaderUninterpretable
	}
	return s.checkNameValueLocked(scheme, value, host, port, path, dialTarget)
}

// ReasonAuthorityUninterpretable is the block reason for an authority
// whose host:port form cannot be split (see CheckAuthority).
const ReasonAuthorityUninterpretable = "blocked: authority has an uninterpretable host or port"

// CheckAuthority checks a request authority (HTTP/1 Host as parsed,
// HTTP/2 :authority) as a name leg against dialTarget. The whole value's
// port is read leniently, as the live path always has: a missing or
// non-numeric port takes the scheme default. Its host:port form is not:
// when the scope has rules, a value CheckHostHeader refuses for its form
// — colons that are neither a host:port split nor an IPv6 literal
// ("db.internal:5432:x"), or a bracket holding anything but an IPv6
// literal ("[db.internal:5432]:443") — is refused here too, so the
// HTTP/2 :authority leg (no host header) does not stay open where the
// Host leg is closed. Like CheckHostHeader it also deny-checks each
// comma-separated part (strictly split) and the bare-IPv6 last-colon
// reading (USK-1304), and the dial port joins the deny match (USK-1306).
// With dialTarget "" the whole value gets the full CheckTarget check.
func (s *TargetScope) CheckAuthority(scheme, authority, path, dialTarget string) (allowed bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.hasRulesLocked() && !authorityFormInterpretable(scheme, authority) {
		return false, ReasonAuthorityUninterpretable
	}
	host, port := splitAuthorityLenient(scheme, authority)
	return s.checkNameValueLocked(scheme, authority, host, port, path, dialTarget)
}

// authorityFormInterpretable reports whether authority's host:port form
// is one CheckHostHeader accepts, ignoring the port's value: either
// splitHostHeaderValue accepts it outright, or net.SplitHostPort splits it
// into a host that is a plain name (no colon) or, when bracketed, an IPv6
// literal — so only an unparsable port is left, which CheckAuthority
// reads leniently as the scheme default.
func authorityFormInterpretable(scheme, authority string) bool {
	if _, _, ok := splitHostHeaderValue(scheme, authority); ok {
		return true
	}
	h, _, err := net.SplitHostPort(authority)
	if err != nil {
		return false
	}
	if strings.HasPrefix(authority, "[") {
		return isIPv6Literal(h)
	}
	return strings.IndexByte(h, ':') < 0
}

// checkNameValueLocked deny-checks value's extra readings, then checks
// its whole reading (host, port) as a name leg. Caller holds s.mu.
func (s *TargetScope) checkNameValueLocked(scheme, value, host string, port int, path, dialTarget string) (bool, string) {
	if s.hasRulesLocked() {
		dialPort := 0
		if dialTarget != "" {
			_, dialPort = splitDialTarget(scheme, dialTarget)
		}
		if ok, reason := s.extraReadingsDenyLocked(scheme, value, path, dialPort); !ok {
			return false, reason
		}
	}
	return s.checkNameLegLocked(scheme, host, port, path, dialTarget)
}

// extraReadingsDenyLocked applies deny rules to the readings of value
// other than the whole one: the bare-IPv6 last-colon reading and every
// non-empty comma-separated part (each with its own bare-IPv6 reading).
// Caller holds s.mu.
func (s *TargetScope) extraReadingsDenyLocked(scheme, value, path string, dialPort int) (bool, string) {
	if h, p, ok := lastColonIPv6Reading(value); ok {
		if ok, reason := s.nameDenyLocked(scheme, h, p, dialPort, path); !ok {
			return false, reason
		}
	}
	if strings.IndexByte(value, ',') < 0 {
		return true, ""
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		h, p, ok := splitHostHeaderValue(scheme, part)
		if !ok {
			return false, ReasonHostHeaderUninterpretable
		}
		if ok, reason := s.nameDenyLocked(scheme, h, p, dialPort, path); !ok {
			return false, reason
		}
		if h, p, ok := lastColonIPv6Reading(part); ok {
			if ok, reason := s.nameDenyLocked(scheme, h, p, dialPort, path); !ok {
				return false, reason
			}
		}
	}
	return true, ""
}

// lastColonIPv6Reading returns the second reading of an unbracketed IPv6
// value: everything before the last colon as the address and the rest as
// a strict port (SplitTargetHostPort rules). ok is false unless value is
// itself an unbracketed IPv6 literal and both halves are valid. A server
// that splits "host:port" at the last colon reads "2001:db8::1:8080" this
// way, while the whole-value reading is the address 2001:db8::1:8080 on
// the default port (decision U1, see JoinDefaultPort).
func lastColonIPv6Reading(value string) (string, int, bool) {
	if !isIPv6Literal(value) {
		return "", 0, false
	}
	i := strings.LastIndexByte(value, ':')
	h := value[:i]
	if !isIPv6Literal(h) {
		return "", 0, false
	}
	_, port, err := SplitTargetHostPort("[" + h + "]:" + value[i+1:])
	if err != nil {
		return "", 0, false
	}
	return h, port, true
}

// splitHostHeaderValue splits a Host header value into host and port for
// CheckHostHeader. ok is false when the value cannot be interpreted,
// including a bracket whose content is not an IPv6 literal.
func splitHostHeaderValue(scheme, value string) (host string, port int, ok bool) {
	if strings.IndexByte(value, ':') < 0 {
		if strings.HasPrefix(value, "[") {
			// "[name]" without a colon: never an IPv6 literal.
			return "", 0, false
		}
		return value, defaultPort(scheme, ""), true
	}
	h, portStr, err := net.SplitHostPort(value)
	if err != nil {
		// "[v6]" without a port, or a bare IPv6 address.
		if len(value) > 2 && value[0] == '[' && value[len(value)-1] == ']' {
			if isIPv6Literal(value[1 : len(value)-1]) {
				return value, defaultPort(scheme, ""), true
			}
			return "", 0, false
		}
		if isIPv6Literal(value) {
			return value, defaultPort(scheme, ""), true
		}
		return "", 0, false
	}
	if strings.HasPrefix(value, "[") && !isIPv6Literal(h) {
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

// splitAuthorityLenient splits an authority for a scope check: a value
// without a port, or whose port does not parse as a number (or is 0),
// takes the scheme's default port. This is the split the live
// HTTPScopeStep has always used for the authority leg.
func splitAuthorityLenient(scheme, authority string) (string, int) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		host, portStr = authority, ""
	}
	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}
	if port == 0 {
		port = defaultPort(scheme, "")
	}
	return host, port
}
