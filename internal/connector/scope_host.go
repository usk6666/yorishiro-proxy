package connector

import (
	"net/netip"
	"strings"
)

// Host comparison form for TargetScope (USK-1129, USK-1250).
//
// A TargetScope rule names a host; a data-path gate hands CheckTarget the
// host exactly as the client spelled it, and the dialer (or a libc
// resolver, or an upstream proxy) may read several spellings as the same
// destination. Each spelling the dial treats as the denied host must
// therefore compare equal to it, or the deny is bypassed while the
// connection still lands on the denied host. The folding below is
// comparison-only: dial targets, CONNECT replies, Host headers, recorded
// flows and stored rules all stay verbatim (MITM Principle 1).

// numericHostReason is CheckTarget's reason for the fail-closed numeric
// host case (see numericHostUnparsable).
const numericHostReason = "blocked: host ends in a number but is not a valid IPv4 address"

// canonicalScopeHost returns the form in which TargetScope compares a rule
// hostname with a target hostname (matchHostname, hostnameCoveredBy,
// targetRuleEqual). The steps, in order:
//
//  1. Lowercase.
//  2. Strip one enclosing "[...]" pair, regardless of content (mirroring
//     net.SplitHostPort). Data-path gates hand CheckTarget an IPv6 host
//     bracket-stripped when the authority carries a port and verbatim
//     "[::1]" when it does not, and rules may be authored either way
//     (USK-1129).
//  3. Strip exactly one trailing dot: "db.internal." is the fully
//     qualified spelling of "db.internal" (RFC 1034 §3.1) and resolves to
//     the same host. Two or more trailing dots are not a name any resolver
//     accepts, so "localhost.." is left as is. The dot is kept when it is
//     the whole host, so "." never folds into the any-host "".
//  4. An IPv6 literal (zone ignored) is rewritten to its RFC 5952 text
//     form via net/netip ("0:0::1" -> "::1"), with IPv4-mapped addresses
//     unmapped to dotted-quad ("::ffff:7f00:1" -> "127.0.0.1"; RFC 4291
//     §2.5.5.2 — the dial reaches the IPv4 host). The zone is dropped:
//     rules cannot carry one (config.ValidateTargetRule) and the dial
//     reaches the same address. "::a.b.c.d" (IPv4-compatible, deprecated)
//     is routed as IPv6 and stays distinct.
//  5. Otherwise, a host the inet_aton grammar reads as an IPv4 address
//     (parseLegacyIPv4: "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1",
//     "127.0.0.01") is rewritten to its dotted-quad form. A libc resolver
//     (GODEBUG=netdns=cgo) or an upstream proxy reads these as that
//     address. Go's pure resolver (the Linux default) does not parse them
//     as IPs; it looks them up in DNS, applying the resolv.conf search
//     list. So the deny side is exact, but an allow for "10.0.0.5" also
//     admits "10.5" or "0x0a.0.0.5", which under the pure resolver dials
//     whatever DNS returns for that name — not necessarily the allowed
//     host. Resolver-aware gating is a follow-up (USK-1250 D2/D3).
//
// The input may be an attacker-controlled Host header; nothing here can
// panic, and the "[", "]" and "[]" length guard keeps those verbatim.
func canonicalScopeHost(h string) string {
	c, _ := canonicalScopeHostIP(h)
	return c
}

// canonicalScopeHostIP is canonicalScopeHost that also reports whether the
// result is an IP address literal (IPv4 or IPv6).
func canonicalScopeHostIP(h string) (string, bool) {
	h = strings.ToLower(h)
	if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if len(h) > 1 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
	}
	if strings.IndexByte(h, ':') >= 0 {
		a := h
		if i := strings.IndexByte(a, '%'); i >= 0 {
			a = a[:i]
		}
		if addr, err := netip.ParseAddr(a); err == nil && addr.Is6() {
			return addr.Unmap().String(), true
		}
		return h, false
	}
	if v, ok := parseLegacyIPv4(h); ok {
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String(), true
	}
	return h, false
}

// numericHostUnparsable reports whether host's last label is a number —
// the WHATWG URL Standard's "ends in a number" test: all ASCII digits, or
// "0x" followed by zero or more hex digits (so a bare "0x" counts) — while the host as a whole is not an
// address canonicalScopeHost can read ("1.2.3.4.5", "999999999999",
// "08.0.0.1", "foo.123"). A resolver may still interpret such a host as an
// address the scope cannot name, so CheckTarget fails closed on it whenever
// rules exist (USK-1250 decision U1-B). Trailing dots are ignored for the
// last-label test so "1.2.3.4.." does not escape it.
func numericHostUnparsable(host string) bool {
	c, isIP := canonicalScopeHostIP(host)
	if isIP {
		return false
	}
	c = strings.TrimRight(c, ".")
	last := c[strings.LastIndexByte(c, '.')+1:]
	if last == "" {
		return false
	}
	if isDigits(last, 10) {
		return true
	}
	return len(last) >= 2 && last[0] == '0' && last[1] == 'x' && isDigits(last[2:], 16)
}

// parseLegacyIPv4 parses s with the inet_aton(3) / WHATWG IPv4 parser
// grammar: one to four dot-separated parts, each decimal, octal (leading
// "0") or hexadecimal ("0x" / "0X" followed by at least one hex digit).
// A bare "0x" part is rejected, as glibc inet_aton and getaddrinfo do,
// even though WHATWG reads it as 0: Go's pure resolver sends such a name
// to DNS, so folding "1.2.3.0x" into 1.2.3.0 would let an allow for
// 1.2.3.0 admit whatever DNS returns. CheckTarget still fails closed on
// it when rules exist, since its last label ends in a number (WHATWG; see
// numericHostUnparsable). Every part but the
// last is one byte; the last fills the remaining bytes ("127.1" is
// 127.0.0.1, "2130706433" is 127.0.0.1). Any out-of-range part, an empty
// part, an invalid digit, or trailing garbage rejects the whole string;
// values are range-checked as they accumulate, so overflow is rejected
// rather than wrapped. It allocates nothing and cannot panic.
func parseLegacyIPv4(s string) (uint32, bool) {
	if s == "" || strings.Count(s, ".") > 3 {
		return 0, false
	}
	var parts [4]uint64
	n := 0
	for {
		i := strings.IndexByte(s, '.')
		p := s
		if i >= 0 {
			p = s[:i]
		}
		v, ok := parseLegacyIPv4Part(p)
		if !ok {
			return 0, false
		}
		parts[n] = v
		n++
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	var out uint64
	for i := 0; i < n-1; i++ {
		if parts[i] > 0xff {
			return 0, false
		}
		out |= parts[i] << (8 * (3 - i))
	}
	last := parts[n-1]
	if last >= uint64(1)<<(8*(5-n)) {
		return 0, false
	}
	return uint32(out | last), true
}

// parseLegacyIPv4Part parses one inet_aton part, rejecting any value above
// 0xffffffff without wrapping.
func parseLegacyIPv4Part(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := uint64(10)
	switch {
	case len(p) >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
		base, p = 16, p[2:]
		if p == "" {
			// glibc inet_aton rejects a bare "0x" (WHATWG reads it as 0);
			// see parseLegacyIPv4.
			return 0, false
		}
	case len(p) >= 2 && p[0] == '0':
		base, p = 8, p[1:]
	}
	var v uint64
	for i := 0; i < len(p); i++ {
		d, ok := digitValue(p[i])
		if !ok || d >= base {
			return 0, false
		}
		v = v*base + d
		if v > 0xffffffff {
			return 0, false
		}
	}
	return v, true
}

// digitValue returns the value of an ASCII hex digit.
func digitValue(c byte) (uint64, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint64(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint64(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint64(c-'A') + 10, true
	}
	return 0, false
}

// isDigits reports whether every byte of s is a digit in base (10 or 16).
// It is true for "".
func isDigits(s string, base uint64) bool {
	for i := 0; i < len(s); i++ {
		d, ok := digitValue(s[i])
		if !ok || d >= base {
			return false
		}
	}
	return true
}
