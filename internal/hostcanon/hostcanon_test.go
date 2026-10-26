package hostcanon

import (
	"strings"
	"testing"
)

// TestParseLegacyIPv4_EmptyHexPart pins the parser to glibc inet_aton(3),
// which rejects a "0x" / "0X" prefix with no hex digits after it. WHATWG
// reads such a part as 0, but Go's pure resolver sends the name to DNS, so
// folding it into an address would let an allow rule admit a host that
// dials whatever DNS returns (USK-1250 review S-1).
func TestParseLegacyIPv4_EmptyHexPart(t *testing.T) {
	for _, in := range []string{"0x", "0X", "0x.0.0.1", "0x7f.0x.0.1", "1.2.3.0x", "0X.1", "1.0x"} {
		if v, ok := ParseLegacyIPv4(in); ok {
			t.Errorf("ParseLegacyIPv4(%q) = %#x, true; want rejected", in, v)
		}
		if c, isIP := FoldIP(in); isIP {
			t.Errorf("FoldIP(%q) = %q, IP; want not an IP", in, c)
		}
	}
	// Controls: a hex part with digits still parses.
	for in, want := range map[string]uint32{"0x0": 0, "0x7f.0.0.1": 0x7f000001, "1.2.3.0x0": 0x01020300} {
		if v, ok := ParseLegacyIPv4(in); !ok || v != want {
			t.Errorf("ParseLegacyIPv4(%q) = %#x, %v; want %#x, true", in, v, ok, want)
		}
	}
}

// legacyIPv4Hosts are non-canonical spellings of an IPv4 address that Fold
// folds into a dotted-quad (all but "10.0.5" fold into 127.0.0.1).
var legacyIPv4Hosts = []string{
	"0x7f.0.0.1",      // hex first part: Go's pure resolver sends it to DNS
	"0X7F.0.0.1",      // uppercase hex prefix
	"2130706433",      // 32-bit integer
	"0x7f000001",      // hex integer
	"127.1",           // two-part short form
	"127.0.1",         // three-part short form
	"0177.0.0.1",      // octal first part
	"127.0.0.01",      // leading-zero last part
	"127.000.000.001", // leading zeros everywhere
	"127.0.0.1.",      // canonical dotted-quad with a trailing dot
	"2130706433.",     // integer with a trailing dot
	"0x7f.0.0.1.",     // hex with a trailing dot
	"[127.0.0.1]",     // bracketed IPv4
	"10.0.5",          // short form of an address the allow does not name
}

func TestLegacyIPv4Spelling(t *testing.T) {
	for _, h := range legacyIPv4Hosts {
		if !LegacyIPv4Spelling(h) {
			t.Errorf("LegacyIPv4Spelling(%q) = false, want true", h)
		}
	}
	for _, h := range []string{
		"127.0.0.1", "10.0.0.5", "0.0.0.0", "255.255.255.255", // canonical
		"::ffff:127.0.0.1", "[::ffff:7f00:1]", "::1", "[::1]", "fe80::1%eth0", // IPv6 is dialed as an IP literal
		"localhost", "example.com", "foo.0x7f", "1.2.3.4.5", "0x", "", ".", "[]", // not an IPv4 address
	} {
		if LegacyIPv4Spelling(h) {
			t.Errorf("LegacyIPv4Spelling(%q) = true, want false", h)
		}
	}
}

func TestUnspecifiedOrEmpty(t *testing.T) {
	for _, h := range []string{
		"", "0.0.0.0", "::", "[::]", "::ffff:0.0.0.0", "[::ffff:0.0.0.0]",
		"0:0::0", "::%lo", "[::%lo]", "0.0.0.0.", "0", "0.0", "0x0", "00",
	} {
		if !UnspecifiedOrEmpty(h) {
			t.Errorf("UnspecifiedOrEmpty(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"0.0.0.1", "127.0.0.1", "10.0.0.0", "::1", "::2", "0.example", "localhost", "[]", ".", "0x"} {
		if UnspecifiedOrEmpty(h) {
			t.Errorf("UnspecifiedOrEmpty(%q) = true, want false", h)
		}
	}
}

func TestNumericUnparsable(t *testing.T) {
	for _, h := range []string{"1.2.3.4.5", "999999999999", "08.0.0.1", "foo.123", "1.2.3.4..", "foo.0x", "1.2.3.0x"} {
		if !NumericUnparsable(h) {
			t.Errorf("NumericUnparsable(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"127.0.0.1", "127.1", "0x7f.0.0.1", "::1", "localhost", "foo.0x7g", "", ".", "[]"} {
		if NumericUnparsable(h) {
			t.Errorf("NumericUnparsable(%q) = true, want false", h)
		}
	}
}

// TestFold_DenyVsAllowForms pins the split between the deny-like Fold
// (legacy IPv4 folded) and the allow-like FoldDialEquivalent (legacy IPv4
// verbatim). Both fold the dial-equivalent spellings identically.
func TestFold_DenyVsAllowForms(t *testing.T) {
	tests := []struct {
		in, fold, dialEq string
	}{
		{"0x7f.0.0.1", "127.0.0.1", "0x7f.0.0.1"},
		{"2130706433", "127.0.0.1", "2130706433"},
		{"127.1", "127.0.0.1", "127.1"},
		{"127.0.0.1.", "127.0.0.1", "127.0.0.1."},
		{"[127.0.0.1]", "127.0.0.1", "[127.0.0.1]"},
		{"localhost.", "localhost", "localhost"},
		{"LOCALHOST", "localhost", "localhost"},
		{"localhost..", "localhost.", "localhost."},
		{"::ffff:127.0.0.1", "127.0.0.1", "127.0.0.1"},
		{"[::ffff:7f00:1]", "127.0.0.1", "127.0.0.1"},
		{"0:0::1", "::1", "::1"},
		{"::1%lo", "::1", "::1"},
		{"::127.0.0.1", "::7f00:1", "::7f00:1"},
		{".", ".", "."},
		{"", "", ""},
	}
	for _, tc := range tests {
		if got := Fold(tc.in); got != tc.fold {
			t.Errorf("Fold(%q) = %q, want %q", tc.in, got, tc.fold)
		}
		if got := FoldDialEquivalent(tc.in); got != tc.dialEq {
			t.Errorf("FoldDialEquivalent(%q) = %q, want %q", tc.in, got, tc.dialEq)
		}
	}
}

// TestFold_GarbageNoPanic (Principle 5): every helper takes
// attacker-controlled input and must not panic on any of it.
func TestFold_GarbageNoPanic(t *testing.T) {
	inputs := []string{
		"", ".", "..", "...", "[", "]", "[]", "[.]", "[%]", "%", "%%", "::%", "::1%",
		"[::1%]", "0x", "0X", "0x.", ".0x", "0x0x1", "00", "0", "-1", "+1", "1e3",
		strings.Repeat("9", 1<<16), "0x" + strings.Repeat("f", 1<<16), "0" + strings.Repeat("7", 1<<16),
		strings.Repeat("1.", 1<<12), strings.Repeat(".", 1<<12), "*.", "*..", "\x00", "1.2.3.4\x00",
		"\xff\xfe", "[::ffff:1.2.3.4", "::ffff:1.2.3.4]", "[[::1]]",
	}
	for _, in := range inputs {
		_ = Fold(in)
		_, _ = FoldIP(in)
		_ = FoldDialEquivalent(in)
		_ = LegacyIPv4Spelling(in)
		_ = NumericUnparsable(in)
		_ = UnspecifiedOrEmpty(in)
		_, _ = ParseLegacyIPv4(in)
	}
}
