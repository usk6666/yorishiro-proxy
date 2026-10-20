package connector

import (
	"strings"
	"testing"
)

// USK-1250 (absorbs USK-1132): TargetScope compared hosts after only
// lowercasing, bracket stripping and IPv6 text normalization, so a target
// spelled as an alias of a denied host slipped past the deny while the dial
// still landed on that host:
//
//   - IPv4-mapped IPv6 ("[::ffff:127.0.0.1]") vs a "127.0.0.1" rule, and the
//     reverse (a "::ffff:10.0.0.5" rule vs a "10.0.0.5" target);
//   - an IPv6 zone ("[::1%lo]") vs a zone-less rule;
//   - a single trailing dot ("localhost.", "db.internal.") vs a dotless rule;
//   - legacy inet_aton IPv4 spellings ("2130706433", "0x7f.0.0.1",
//     "0177.0.0.1", "127.1") resolved by libc getaddrinfo or an upstream
//     proxy.
//
// The comparison form now folds all of those; a host whose last label is
// numeric but that is not a parseable IPv4 address fails closed whenever the
// scope has rules. Normalization stays comparison-only.

// TestCheckTarget_HostAliasDeny is test-plan 7: a Policy deny written in one
// spelling blocks every alias spelling that dials the same host.
func TestCheckTarget_HostAliasDeny(t *testing.T) {
	tests := []struct {
		name     string
		denyHost string
		target   string
	}{
		{"mapped dotted vs ipv4", "127.0.0.1", "::ffff:127.0.0.1"},
		{"mapped dotted bracketed vs ipv4", "127.0.0.1", "[::ffff:127.0.0.1]"},
		{"mapped hex vs ipv4", "127.0.0.1", "::ffff:7f00:1"},
		{"mapped expanded vs ipv4", "127.0.0.1", "0:0:0:0:0:ffff:127.0.0.1"},
		{"mapped uppercase vs ipv4", "10.0.0.5", "[::FFFF:A00:5]"},
		{"mapped with zone vs ipv4", "127.0.0.1", "::ffff:127.0.0.1%bogus"},
		{"mapped with zone bracketed vs ipv4", "127.0.0.1", "[::ffff:127.0.0.1%bogus]"},
		{"zone vs zoneless ipv6", "::1", "::1%lo"},
		{"zone bracketed vs zoneless ipv6", "::1", "[::1%bogus]"},
		{"zone vs bracketed zoneless rule", "[fe80::1]", "fe80::1%eth0"},
		{"reverse: mapped rule vs ipv4 target", "::ffff:10.0.0.5", "10.0.0.5"},
		{"reverse: bracketed mapped rule vs ipv4 target", "[::ffff:10.0.0.5]", "10.0.0.5"},
		{"trailing dot vs exact name", "localhost", "localhost."},
		{"trailing dot vs exact name, case", "db.internal", "DB.Internal."},
		{"trailing dot vs wildcard", "*.internal", "db.internal."},
		{"trailing dot on ipv4", "127.0.0.1", "127.0.0.1."},
		{"legacy: single decimal", "127.0.0.1", "2130706433"},
		{"legacy: hex first part", "127.0.0.1", "0x7f.0.0.1"},
		{"legacy: uppercase hex prefix", "127.0.0.1", "0X7F.0.0.1"},
		{"legacy: octal first part", "127.0.0.1", "0177.0.0.1"},
		{"legacy: two parts", "127.0.0.1", "127.1"},
		{"legacy: three parts", "10.0.0.5", "10.0.5"},
		{"legacy: leading-zero octal last part", "127.0.0.1", "127.0.0.01"},
		{"legacy: hex single part", "10.0.0.5", "0xa000005"},
		{"legacy: octal single part", "10.0.0.5", "01200000005"},
		{"legacy: trailing dot", "127.0.0.1", "2130706433."},
		{"legacy: mixed", "192.168.1.1", "0300.0250.257"},
		{"empty hex part fails closed", "0.0.0.1", "0x.0.0.1"}, // not an alias (glibc rejects "0x"); Rule B blocks it
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope := NewTargetScope()
			scope.SetPolicyRules(nil, []TargetRule{{Hostname: tc.denyHost}})
			if got, reason := scope.CheckTarget("https", tc.target, 443, ""); got {
				t.Errorf("CheckTarget(deny %q, host %q) = allowed (%q), want blocked", tc.denyHost, tc.target, reason)
			}
		})
	}
}

// TestCheckTarget_NumericHostFailsClosed is test-plan 7 decision U1-B: a
// host whose last label is a number but that the inet_aton parser cannot
// read is blocked whenever the scope has rules — even rules that do not
// name it — because a resolver may still read it as an address.
func TestCheckTarget_NumericHostFailsClosed(t *testing.T) {
	hosts := []string{
		"999999999999", // single part overflow
		"4294967296",   // 2^32
		"1.2.3.4.5",    // five parts
		"256.0.0.1",    // non-last part > 255
		"1.2.3.256",    // last part > 255 with four parts
		"1.2.65536",    // last part > 65535 with three parts
		"1.16777216",   // last part > 2^24-1 with two parts
		"08.0.0.1",     // invalid octal digit
		"1.2.3.09",     // invalid octal digit in last part
		"1..2.3",       // empty part
		"0x1g.0.0.1",   // invalid hex digit (last label numeric)
		"foo.123",      // name ending in a number
		"foo.0x7f",     // name ending in a hex number
		"1.2.3.4..",    // two trailing dots: not folded, still numeric
		"[1.2.3.4.5]",  // bracketed garbage
		"0x",           // empty hex part: glibc inet_aton rejects it
		"0X",           // empty hex part, uppercase prefix
		"0x.0.0.1",     // empty hex first part
		"0x7f.0x.0.1",  // empty hex middle part
		"1.2.3.0x",     // empty hex last part
		"1.2.3.0x.",    // empty hex last part, trailing dot
		strings.Repeat("9", 4096),
	}
	for _, h := range hosts {
		name := h
		if len(name) > 32 {
			name = name[:32] + "..."
		}
		t.Run(name, func(t *testing.T) {
			deny := NewTargetScope()
			deny.SetPolicyRules(nil, []TargetRule{{Hostname: "unrelated.example"}})
			got, reason := deny.CheckTarget("https", h, 443, "")
			if got {
				t.Errorf("CheckTarget(%q) with an unrelated deny = allowed, want blocked (fail closed)", h)
			} else if reason == "" {
				t.Errorf("CheckTarget(%q) blocked without a reason", h)
			}

			allow := NewTargetScope()
			allow.SetPolicyRules([]TargetRule{{Hostname: ""}}, nil)
			if got, _ := allow.CheckTarget("https", h, 443, ""); got {
				t.Errorf("CheckTarget(%q) under an any-host allow = allowed, want blocked (fail closed)", h)
			}

			open := NewTargetScope()
			if got, reason := open.CheckTarget("https", h, 443, ""); !got {
				t.Errorf("CheckTarget(%q) with no rules = blocked (%q), want allowed (open mode)", h, reason)
			}
		})
	}
}

// TestCheckTarget_HostAliasAllowSymmetry is test-plan 8: the folding is
// symmetric, so an allow admits each alias of its host, and the negative
// controls stay unmatched.
func TestCheckTarget_HostAliasAllowSymmetry(t *testing.T) {
	tests := []struct {
		name      string
		allowHost string
		target    string
		wantAllow bool
	}{
		{"allow ipv4 admits mapped", "10.0.0.5", "::ffff:10.0.0.5", true},
		{"allow ipv4 admits legacy decimal", "10.0.0.5", "167772165", true},
		{"allow ipv4 admits legacy short", "10.0.0.5", "10.5", true}, // last part fills three bytes
		{"allow name admits trailing dot", "example.com", "example.com.", true},
		{"allow wildcard admits trailing dot", "*.example.com", "a.example.com.", true},
		{"allow mapped rule admits ipv4", "::ffff:10.0.0.5", "10.0.0.5", true},
		// Negative controls.
		{"ipv4-compatible is not ipv4", "10.0.0.5", "::10.0.0.5", false},
		{"two trailing dots not folded", "example.com", "example.com..", false},
		{"wildcard apex with trailing dot", "*.internal", "internal.", false},
		{"other ipv6 address", "::1", "[::2]", false},
		{"other ipv4 via mapped", "10.0.0.5", "::ffff:10.0.0.6", false},
		{"leading dot not folded", "example.com", ".example.com", false},
		{"empty hex part is not an alias", "1.2.3.0", "1.2.3.0x", false},
		{"bare empty hex is not an alias", "0.0.0.0", "0x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope := NewTargetScope()
			scope.SetPolicyRules([]TargetRule{{Hostname: tc.allowHost}}, nil)
			got, reason := scope.CheckTarget("https", tc.target, 443, "")
			if got != tc.wantAllow {
				t.Errorf("CheckTarget(allow %q, host %q) = %v (%q), want %v",
					tc.allowHost, tc.target, got, reason, tc.wantAllow)
			}
		})
	}
}

// TestParseLegacyIPv4_EmptyHexPart pins the parser to glibc inet_aton(3),
// which rejects a "0x" / "0X" prefix with no hex digits after it. WHATWG
// reads such a part as 0, but Go's pure resolver sends the name to DNS, so
// folding it into an address would let an allow rule admit a host that
// dials whatever DNS returns (USK-1250 review S-1).
func TestParseLegacyIPv4_EmptyHexPart(t *testing.T) {
	for _, in := range []string{"0x", "0X", "0x.0.0.1", "0x7f.0x.0.1", "1.2.3.0x", "0X.1", "1.0x"} {
		if v, ok := parseLegacyIPv4(in); ok {
			t.Errorf("parseLegacyIPv4(%q) = %#x, true; want rejected", in, v)
		}
		if c, isIP := canonicalScopeHostIP(in); isIP {
			t.Errorf("canonicalScopeHostIP(%q) = %q, IP; want not an IP", in, c)
		}
	}
	// Controls: a hex part with digits still parses.
	for in, want := range map[string]uint32{"0x0": 0, "0x7f.0.0.1": 0x7f000001, "1.2.3.0x0": 0x01020300} {
		if v, ok := parseLegacyIPv4(in); !ok || v != want {
			t.Errorf("parseLegacyIPv4(%q) = %#x, %v; want %#x, true", in, v, ok, want)
		}
	}
}

// TestHostnameCoveredBy_HostAliases is test-plan 9 (coverage half).
func TestHostnameCoveredBy_HostAliases(t *testing.T) {
	tests := []struct {
		covering, covered string
		want              bool
	}{
		{"10.0.0.5", "::ffff:10.0.0.5", true},
		{"::ffff:10.0.0.5", "10.0.0.5", true},
		{"[::ffff:10.0.0.5]", "10.0.0.5", true},
		{"*.internal", "db.internal", true},
		{"10.0.0.5", "10.0.0.6", false},
		{"10.0.0.5", "::10.0.0.5", false},
	}
	for _, tc := range tests {
		if got := hostnameCoveredBy(tc.covering, tc.covered); got != tc.want {
			t.Errorf("hostnameCoveredBy(%q, %q) = %v, want %v", tc.covering, tc.covered, got, tc.want)
		}
	}
}

// TestTargetRuleEqual_HostAliases is test-plan 9 (equality half): the
// dedupe / removal / policy-deny removal guard treats aliases as one rule.
func TestTargetRuleEqual_HostAliases(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"example.com.", "example.com", true},
		{"::ffff:10.0.0.5", "10.0.0.5", true},
		{"[::ffff:10.0.0.5]", "10.0.0.5", true},
		{"example.com..", "example.com", false},
		{"10.0.0.5", "10.0.0.6", false},
	}
	for _, tc := range tests {
		if got := targetRuleEqual(TargetRule{Hostname: tc.a}, TargetRule{Hostname: tc.b}); got != tc.want {
			t.Errorf("targetRuleEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestSetPolicyRules_KeepsAliasRuleVerbatim is test-plan 10 (unit half):
// folding is comparison-only, so stored rules are echoed as authored.
func TestSetPolicyRules_KeepsAliasRuleVerbatim(t *testing.T) {
	scope := NewTargetScope()
	authored := []TargetRule{{Hostname: "[::FFFF:10.0.0.5]"}, {Hostname: "DB.Internal"}}
	scope.SetPolicyRules(nil, authored)
	if err := scope.SetAgentRules(nil, []TargetRule{{Hostname: "::ffff:7f00:1"}}); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}
	_, pd := scope.PolicyRules()
	_, ad := scope.AgentRules()
	for i, r := range authored {
		if pd[i].Hostname != r.Hostname {
			t.Errorf("policy deny[%d] hostname = %q, want verbatim %q", i, pd[i].Hostname, r.Hostname)
		}
	}
	if ad[0].Hostname != "::ffff:7f00:1" {
		t.Errorf("agent deny hostname = %q, want verbatim %q", ad[0].Hostname, "::ffff:7f00:1")
	}
}

// TestCanonicalScopeHost_GarbageNoPanic is test-plan 11 (Principle 5): the
// canonicalizer and the numeric-host gate take attacker-controlled input
// and must not panic on any of it.
func TestCanonicalScopeHost_GarbageNoPanic(t *testing.T) {
	inputs := []string{
		"", ".", "..", "...", "[", "]", "[]", "[.]", "[%]", "%", "%%", "::%", "::1%",
		"[::1%]", "0x", "0X", "0x.", ".0x", "0x0x1", "00", "0", "-1", "+1", "1e3",
		strings.Repeat("9", 1<<16), "0x" + strings.Repeat("f", 1<<16), "0" + strings.Repeat("7", 1<<16),
		strings.Repeat("1.", 1<<12), strings.Repeat(".", 1<<12), "*.", "*..", "\x00", "1.2.3.4\x00",
		"\xff\xfe", "[::ffff:1.2.3.4", "::ffff:1.2.3.4]", "[[::1]]",
	}
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "127.0.0.1"}})
	for _, in := range inputs {
		_ = canonicalScopeHost(in)
		_, _ = scope.CheckTarget("https", in, 443, "")
		_ = hostnameCoveredBy(in, in)
		_ = matchHostname(in, in)
	}
}
