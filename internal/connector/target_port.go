package connector

import (
	"fmt"
	"net"
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
// The target itself is never rewritten.
func SplitTargetHostPort(target string) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("invalid target %q: %w", target, err)
	}
	if portStr == "" || strings.Trim(portStr, "0123456789") != "" {
		return "", 0, fmt.Errorf("invalid target %q: port %q is not a decimal port number", target, portStr)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target %q: port %q is out of range 1-65535", target, portStr)
	}
	return host, port, nil
}
