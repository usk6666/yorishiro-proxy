package config

import (
	"net"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/hostcanon"
)

// IsRawPassthrough reports whether the given host:port target is configured
// for raw passthrough mode (no L7 parsing). There are no wildcard patterns.
//
// Entry and target are compared in rawPassthroughKey form, so spellings
// verified to dial the same destination match the same entry (USK-1385):
// case, one trailing dot on a name, IPv6 RFC 5952 text, IPv4-mapped IPv6
// and dotted quad, the IPv6 zone, and a leading-zero port
// ("localhost.:443", "[::ffff:127.0.0.1]:443", "localhost:0443"). The raw
// route skips the Safety / Intercept / Transform steps, so the list is
// allow-like and legacy inet_aton IPv4 spellings ("127.1", "2130706433",
// "0x7f.0.0.1") are compared as written (hostcanon.FoldDialEquivalent).
// The fold is comparison-only: the dial target, the TLS name and the stored
// entries stay as written (MITM Principle 1).
func (c *ProxyConfig) IsRawPassthrough(target string) bool {
	key := rawPassthroughKey(target)
	if key == "" {
		return false
	}
	for _, h := range c.RawPassthroughHosts {
		if rawPassthroughKey(h) == key {
			return true
		}
	}
	return false
}

// rawPassthroughKey returns the comparison form of a raw_passthrough_hosts
// entry or target. A well-formed "host:port" (net.SplitHostPort, non-empty
// host) becomes JoinHostPort(FoldDialEquivalent(host), port), with the
// port as a decimal integer when hostcanon.ParseStrictPort accepts it (ASCII
// digits in 1..65535, leading zeros allowed — the rule
// connector.SplitTargetHostPort applies and the dialer reads) and as
// written otherwise. Anything else falls back to
// the lowercased, trimmed literal, the pre-USK-1385 behaviour. An empty
// input yields "", which never matches. It cannot panic.
func rawPassthroughKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return s
	}
	if n, ok := hostcanon.ParseStrictPort(port); ok {
		port = strconv.Itoa(n)
	}
	return net.JoinHostPort(hostcanon.FoldDialEquivalent(host), port)
}
