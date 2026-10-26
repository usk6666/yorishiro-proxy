package hostcanon

import (
	"net/netip"
	"strings"
)

// Fold returns the deny-like comparison form of a host (TargetScope rule
// matching, RateLimiter bucket keys). The steps, in order:
//
//  1. Lowercase.
//  2. Strip one enclosing "[...]" pair, regardless of content (mirroring
//     net.SplitHostPort). Data-path gates hand TargetScope an IPv6 host
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
//     (ParseLegacyIPv4: "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1",
//     "127.0.0.01") is rewritten to its dotted-quad form. A libc resolver
//     (GODEBUG=netdns=cgo) or an upstream proxy reads these as that
//     address. Go's pure resolver (the Linux default) does not parse them
//     as IPs: it rejects the all-digit ones and looks the others
//     ("0x0a.0.0.5") up in DNS, applying the resolv.conf search list. The
//     folding is therefore exact for a deny but would widen an allow, so
//     as a dial host such a spelling is refused outright by TargetScope
//     whenever rules exist (USK-1273, LegacyIPv4Spelling), and allow-like
//     lists use FoldDialEquivalent instead. The fold still matters for
//     name legs (a deny for 127.0.0.1 blocks "Host: 0x7f.0.0.1"), for
//     NumericUnparsable, and for rule-side comparison.
//
// The input may be an attacker-controlled Host header; nothing here can
// panic, and the "[", "]" and "[]" length guard keeps those verbatim.
func Fold(h string) string {
	c, _ := FoldIP(h)
	return c
}

// FoldIP is Fold that also reports whether the result is an IP address
// literal (IPv4 or IPv6).
//
// Known approximation: the IPv6 zone is dropped, so different zones of the
// same link-local address ("fe80::1%eth0", "fe80::1%eth1") compare equal
// although they may reach different hosts on different links. For the
// deny-like Fold this only widens a deny. For allow-like lists
// (FoldDialEquivalent) it only widens which connections skip inspection;
// those connections have already passed the scope gate, which evaluates
// the host as written, so it is not a scope bypass.
func FoldIP(h string) (string, bool) {
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
	if v, ok := ParseLegacyIPv4(h); ok {
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String(), true
	}
	return h, false
}

// FoldDialEquivalent returns the allow-like comparison form of a
// lowercased host (USK-1263). It is Fold — one trailing dot on a name,
// one "[...]" pair, IPv6 RFC 5952 text, IPv4-mapped IPv6 to dotted quad,
// zone dropped — except for a host LegacyIPv4Spelling reports (integer /
// hex / octal / short IPv4, "127.0.0.1.", "[127.0.0.1]"), which is
// returned unchanged.
//
// Use it where a match means less inspection (TLS passthrough, raw
// passthrough): only spellings proven to dial the same host are folded.
// Go's pure resolver does not read a legacy IPv4 spelling as an address
// (it rejects the all-digit ones and looks the others up in DNS), so
// folding one onto an entry could relay an uninspected connection to
// whatever DNS returns; the same reasoning makes TargetScope refuse such
// dial hosts when rules exist.
//
// Two known approximations remain, both inherited from Fold:
//
//   - One trailing dot is stripped, so "db." folds to "db". Go's resolver
//     tries the resolv.conf search list first for a name with fewer dots
//     than "ndots" ("db.<search>") but resolves a name ending in a dot
//     only at the root, so the two spellings can resolve to different
//     hosts.
//   - The IPv6 zone is dropped, so different zones of the same link-local
//     address ("[fe80::1%eth0]", "[fe80::1%eth1]") compare equal.
//
// For an allow-like list these only widen which connections skip
// inspection. Such a connection has already passed the scope gate, which
// evaluates the host as written, so neither is a scope bypass. Both apply
// equally to the TLS passthrough list and to raw_passthrough_hosts.
func FoldDialEquivalent(h string) string {
	if LegacyIPv4Spelling(h) {
		return h
	}
	return Fold(h)
}

// ParseStrictPort reads a port string with the dial-target rule
// (connector.SplitTargetHostPort): a non-empty run of ASCII decimal digits
// (leading zeros allowed, as in RFC 3986 §3.2.3) whose value is in
// 1..65535. ok is false for anything else — a sign, whitespace, a service
// name, non-ASCII digits, 0, or a value above 65535, including one
// net.Dial would wrap modulo 2^32 (USK-1262). The value is range-checked
// as it accumulates, so a long digit run is rejected rather than wrapped.
// It allocates nothing and cannot panic.
func ParseStrictPort(p string) (port int, ok bool) {
	if p == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0, false
		}
	}
	if n == 0 {
		return 0, false
	}
	return n, true
}

// NumericUnparsable reports whether host's last label is a number — the
// WHATWG URL Standard's "ends in a number" test: all ASCII digits, or "0x"
// followed by zero or more hex digits (so a bare "0x" counts) — while the
// host as a whole is not an address Fold can read ("1.2.3.4.5",
// "999999999999", "08.0.0.1", "foo.123"). A resolver may still interpret
// such a host as an address no rule can name, so TargetScope fails closed
// on it whenever rules exist (USK-1250 decision U1-B). Trailing dots are
// ignored for the last-label test so "1.2.3.4.." does not escape it.
func NumericUnparsable(host string) bool {
	c, isIP := FoldIP(host)
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

// UnspecifiedOrEmpty reports whether a dial host is empty or, in Fold
// form, an unspecified address: "0.0.0.0", "::", and every spelling that
// folds to them ("[::]", "::ffff:0.0.0.0", "0:0::0", "::%lo", the legacy
// "0" / "0.0" / "0x0" / "00"). Go's net.Dial reads an empty host and an
// unspecified address as the local system ("[::]" reaches an IPv4
// 127.0.0.1-only listener too), so no deny rule naming 127.0.0.1 /
// localhost / ::1 would see such a dial. TargetScope therefore refuses it
// whenever rules exist (USK-1312, decision (b)).
func UnspecifiedOrEmpty(host string) bool {
	if host == "" {
		return true
	}
	c, isIP := FoldIP(host)
	if !isIP {
		return false
	}
	addr, err := netip.ParseAddr(c)
	return err == nil && addr.Unmap().IsUnspecified()
}

// ParseLegacyIPv4 parses s with the inet_aton(3) / WHATWG IPv4 parser
// grammar: one to four dot-separated parts, each decimal, octal (leading
// "0") or hexadecimal ("0x" / "0X" followed by at least one hex digit).
// A bare "0x" part is rejected, as glibc inet_aton and getaddrinfo do,
// even though WHATWG reads it as 0: Go's pure resolver sends such a name
// to DNS, so folding "1.2.3.0x" into 1.2.3.0 would let an allow for
// 1.2.3.0 admit whatever DNS returns. TargetScope still fails closed on
// it when rules exist, since its last label ends in a number (WHATWG; see
// NumericUnparsable). Every part but the last is one byte; the last fills
// the remaining bytes ("127.1" is 127.0.0.1, "2130706433" is 127.0.0.1).
// Any out-of-range part, an empty part, an invalid digit, or trailing
// garbage rejects the whole string; values are range-checked as they
// accumulate, so overflow is rejected rather than wrapped. It allocates
// nothing and cannot panic.
func ParseLegacyIPv4(s string) (uint32, bool) {
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
			// see ParseLegacyIPv4.
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

// LegacyIPv4Spelling reports whether host is an IPv4 address that Fold
// reads in a spelling other than canonical dotted-quad decimal: the
// inet_aton forms ("2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1",
// "127.0.0.01"), any of them or a dotted-quad with a trailing dot
// ("127.0.0.1."), and a bracketed IPv4 ("[127.0.0.1]"). Resolvers
// disagree on what such a host dials: a libc resolver or an upstream proxy
// reads it as the folded address, Go's pure resolver sends the hex forms
// to DNS (with the resolv.conf search list) and rejects the all-digit
// ones. So an allow for the folded address must not admit it, and
// TargetScope refuses it whenever rules exist (USK-1273). A host
// containing ":" is never reported: IPv6 literals, IPv4-mapped ones
// included, are dialed as IP literals and reach the folded address.
func LegacyIPv4Spelling(host string) bool {
	if strings.IndexByte(host, ':') >= 0 {
		return false
	}
	c, isIP := FoldIP(host)
	return isIP && c != host
}
