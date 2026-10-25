package connector

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// SplitTargetHostPort splits a dial target "host:port" into host and a
// port that must be a non-empty run of ASCII decimal digits whose value is
// in 1..65535 (leading zeros allowed, as in RFC 3986 §3.2.3).
//
// The rule exists so the port a TargetScope check sees is the port the
// dialer connects to. net.Dial resolves service names ("postgresql" →
// 5432, "http" → 80) and wraps an overflowing decimal modulo 2^32
// ("4294967376" → 80), while strconv.Atoi reads the former as an error and
// the latter as a large value no rule names; either discrepancy would slip
// past a port-scoped deny (USK-1161 review S-1, USK-1249). Signs,
// whitespace, non-ASCII digits, 0 and out-of-range values are rejected.
//
// A bracketed host must hold an IPv6 literal (zone allowed), the only
// thing RFC 3986 §3.2.2 puts in brackets that a dialer can reach.
// net.SplitHostPort strips any bracket pair, so "[db.internal:5432]:80"
// would otherwise yield the host "db.internal:5432", which no rule for
// db.internal matches while a resolver or an upstream proxy may still
// read the part before the colon (USK-1264).
//
// The target itself is never rewritten.
func SplitTargetHostPort(target string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("invalid target %q: %w", target, err)
	}
	if strings.HasPrefix(target, "[") && !isIPv6Literal(host) {
		return "", 0, fmt.Errorf("invalid target %q: bracketed host %q is not an IPv6 address", target, host)
	}
	if portStr == "" || strings.Trim(portStr, "0123456789") != "" {
		return "", 0, fmt.Errorf("invalid target %q: port %q is not a decimal port number", target, portStr)
	}
	port, ok := parseStrictPort(portStr)
	if !ok {
		return "", 0, fmt.Errorf("invalid target %q: port %q is out of range 1-65535", target, portStr)
	}
	return host, port, nil
}

// parseStrictPort reads a port string with SplitTargetHostPort's rule: a
// non-empty run of ASCII decimal digits (leading zeros allowed) whose
// value is in 1..65535. ok is false for anything else — a sign,
// whitespace, a service name, 0, or a value net.Dial would wrap modulo
// 2^32 (USK-1262).
func parseStrictPort(portStr string) (port int, ok bool) {
	if portStr == "" || strings.Trim(portStr, "0123456789") != "" {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// isIPv6Literal reports whether s (without brackets) is an IPv6 address,
// optionally with a zone ("fe80::1%eth0"). IPv4-mapped forms count.
func isIPv6Literal(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6()
}

// JoinDefaultPort derives a dial target from an authority that may lack a
// port (USK-1264). It is shared by the plain-HTTP forward target
// (peekForwardTarget) and the MCP resend dial resolvers.
//
//   - "host:port" (net.SplitHostPort accepts it) is returned unchanged;
//     a bracketed host must hold an IPv6 literal.
//   - A host without a colon gets ":" + defaultPort.
//   - "[v6]" gets ":" + defaultPort; the content must be an IPv6 literal.
//   - An unbracketed host with colons is accepted only when the whole of
//     it is an IPv6 literal ("::1" → "[::1]:80"). Anything else
//     ("db.internal:5432:x") is an error: bracketing it would hand the
//     scope check the host "db.internal:5432:x" while a resolver or an
//     upstream proxy may read "db.internal", so it must never be dialled.
//
// Decision record (unbracketed IPv6): RFC 9110 / RFC 3986 require
// brackets around an IPv6 authority, but a client that writes "Host: ::1"
// is still accepted, so IP-literal Host-injection tests stay possible and
// the dial and the scope check agree on the same address. The other
// reading of such a value ("2001:db8::1:8080" as host 2001:db8::1, port
// 8080) is closed on the deny side by TargetScope.CheckHostHeader.
//
// Port validation is left to SplitTargetHostPort; the result is never
// otherwise rewritten.
func JoinDefaultPort(host, defaultPort string) (string, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		if strings.HasPrefix(host, "[") && !isIPv6Literal(h) {
			return "", fmt.Errorf("invalid authority %q: bracketed host %q is not an IPv6 address", host, h)
		}
		return host, nil
	}
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		if !isIPv6Literal(host[1 : len(host)-1]) {
			return "", fmt.Errorf("invalid authority %q: bracketed host is not an IPv6 address", host)
		}
		return host + ":" + defaultPort, nil
	}
	if strings.IndexByte(host, ':') < 0 {
		return net.JoinHostPort(host, defaultPort), nil
	}
	if isIPv6Literal(host) {
		return net.JoinHostPort(host, defaultPort), nil
	}
	return "", fmt.Errorf("invalid authority %q: host has colons but is not an IPv6 address", host)
}
