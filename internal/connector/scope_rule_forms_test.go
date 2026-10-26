package connector

import (
	"io"
	"log/slog"
	"testing"
)

// USK-1129: TargetScope rule forms that silently never took effect.
//
//  1. A bracketed IPv6 rule ("[::1]") never matched: every data-path gate
//     that sees a port strips the brackets (net.SplitHostPort, url.Hostname),
//     so matchHostname compared "[::1]" with "::1". The mirror bug — a bare
//     "::1" rule missing a port-less "Host: [::1]" that reaches the gate
//     verbatim — had the same cause. Rules are now compared on a canonical
//     host (one enclosing bracket pair stripped, IPv6 in netip text form);
//     stored rules and wire data stay verbatim.
//  2. An empty-hostname Policy allow matches every host in matchTargetRule
//     but covered no host in hostnameCoveredBy, so every Agent allow was
//     refused as "outside policy allow boundary".

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestConnectPolicyReject_IPv6RuleForms is T1: the CONNECT gate receives the
// target exactly as the client wrote it ("[::1]:443") and splits it with
// net.SplitHostPort before CheckTarget. A Policy deny written in either IPv6
// spelling must block every zone-less spelling of the same address.
func TestConnectPolicyReject_IPv6RuleForms(t *testing.T) {
	tests := []struct {
		name      string
		denyHost  string
		target    string
		wantAllow bool
	}{
		{"bracketed deny blocks bracketed target", "[::1]", "[::1]:443", false},
		{"bare deny blocks bracketed target", "::1", "[::1]:443", false},
		{"bare deny blocks non-canonical spelling", "::1", "[0:0::1]:443", false},
		{"bracketed deny blocks non-canonical spelling", "[::1]", "[0:0:0:0:0:0:0:1]:443", false},
		{"bracketed deny is case-insensitive", "[2001:DB8::1]", "[2001:db8::1]:443", false},
		// Controls: canonicalization must not widen a rule to other addresses.
		{"bracketed deny does not block another address", "[::1]", "[::2]:443", true},
		{"bracketed deny does not block ipv4 loopback", "[::1]", "127.0.0.1:443", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope := NewTargetScope()
			scope.SetPolicyRules(nil, []TargetRule{{Hostname: tc.denyHost}})
			resp, _ := connectPolicyReject(CONNECTHandlerConfig{Scope: scope}, tc.target, false, discardLogger())
			got := resp == nil
			if got != tc.wantAllow {
				t.Errorf("connectPolicyReject(deny %q, target %q) admitted = %v, want %v",
					tc.denyHost, tc.target, got, tc.wantAllow)
			}
		})
	}
}

// TestCheckTarget_IPv6RuleForms pins the same contract at CheckTarget for
// the host spellings the data-path gates hand it: bracket-stripped (with a
// port) and verbatim bracketed (port-less authority fallback).
func TestCheckTarget_IPv6RuleForms(t *testing.T) {
	tests := []struct {
		name      string
		allowHost string
		target    string
		wantAllow bool
	}{
		{"bracketed allow permits bare target", "[::1]", "::1", true},
		{"bare allow permits bracketed target", "::1", "[::1]", true},
		{"bracketed allow permits bracketed target", "[::1]", "[::1]", true},
		{"bare allow permits expanded target", "::1", "0:0:0:0:0:0:0:1", true},
		{"bracketed allow rejects other address", "[::1]", "::2", false},
		// IPv4-mapped IPv6 dials the IPv4 host (RFC 4291 §2.5.5.2), so it is
		// the same host for scope purposes (USK-1250, absorbing USK-1132).
		{"ipv4-mapped is ipv4", "127.0.0.1", "::ffff:127.0.0.1", true},
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

// TestSetPolicyRules_KeepsIPv6RuleVerbatim guards that canonicalization is
// comparison-only: the stored rule is echoed exactly as authored.
func TestSetPolicyRules_KeepsIPv6RuleVerbatim(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "[0:0::1]"}})
	if err := scope.SetAgentRules(nil, []TargetRule{{Hostname: "[2001:DB8::1]"}}); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}
	_, pd := scope.PolicyRules()
	_, ad := scope.AgentRules()
	if pd[0].Hostname != "[0:0::1]" {
		t.Errorf("policy deny hostname = %q, want verbatim %q", pd[0].Hostname, "[0:0::1]")
	}
	if ad[0].Hostname != "[2001:DB8::1]" {
		t.Errorf("agent deny hostname = %q, want verbatim %q", ad[0].Hostname, "[2001:DB8::1]")
	}
}

// TestHostnameCoveredBy_RuleForms is the coverage half of T5/T8: bracketed
// and bare spellings of one address cover each other, and an empty covering
// hostname (any host, as in matchTargetRule) covers every hostname.
func TestHostnameCoveredBy_RuleForms(t *testing.T) {
	tests := []struct {
		name     string
		covering string
		covered  string
		want     bool
	}{
		{"bare covers bracketed", "::1", "[::1]", true},
		{"bracketed covers bare", "[::1]", "::1", true},
		{"bracketed covers expanded", "[::1]", "0:0::1", true},
		{"bracketed does not cover other address", "[::1]", "[::2]", false},
		{"wildcard does not cover ipv6", "*.example.com", "[::1]", false},
		{"empty covers exact", "", "example.com", true},
		{"empty covers wildcard", "", "*.example.com", true},
		{"empty covers ipv6", "", "[::1]", true},
		{"empty covers empty", "", "", true},
		{"exact does not cover empty", "example.com", "", false},
		{"wildcard does not cover empty", "*.example.com", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostnameCoveredBy(tc.covering, tc.covered); got != tc.want {
				t.Errorf("hostnameCoveredBy(%q, %q) = %v, want %v", tc.covering, tc.covered, got, tc.want)
			}
		})
	}
}

// TestValidateAgentAllows_EmptyHostnamePolicyAllow is T8 at the connector
// seam: under a Policy allow {ports: [443]} (any host, port 443) an Agent
// allow inside that range is accepted; the ports subset check still binds.
func TestValidateAgentAllows_EmptyHostnamePolicyAllow(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules([]TargetRule{{Ports: []int{443}}}, nil)

	if err := scope.SetAgentRules([]TargetRule{{Hostname: "example.com", Ports: []int{443}}}, nil); err != nil {
		t.Errorf("SetAgentRules(example.com:443) = %v, want nil (inside the policy allow)", err)
	}
	if err := scope.MergeAgentRules([]TargetRule{{Hostname: "*.example.com", Ports: []int{443}}}, nil, nil, nil); err != nil {
		t.Errorf("MergeAgentRules(*.example.com:443) = %v, want nil (inside the policy allow)", err)
	}
	for _, outside := range []TargetRule{
		{Hostname: "example.com"},                        // all ports > {443}
		{Hostname: "example.com", Ports: []int{80}},      // port outside
		{Hostname: "example.com", Ports: []int{443, 80}}, // partially outside
	} {
		if err := scope.ValidateAgentAllows([]TargetRule{outside}); err == nil {
			t.Errorf("ValidateAgentAllows(%+v) = nil, want outside policy allow boundary", outside)
		}
	}
}

// TestMergeAgentRules_IPv6SpellingsAreOneRule is T11: dedupe on add and
// removal treat every spelling of one IPv6 address as the same rule.
func TestMergeAgentRules_IPv6SpellingsAreOneRule(t *testing.T) {
	scope := NewTargetScope()
	if err := scope.MergeAgentRules(nil, nil, []TargetRule{{Hostname: "::1"}}, nil); err != nil {
		t.Fatalf("add ::1: %v", err)
	}
	if err := scope.MergeAgentRules(nil, nil, []TargetRule{{Hostname: "[::1]"}}, nil); err != nil {
		t.Fatalf("add [::1]: %v", err)
	}
	if _, denies := scope.AgentRules(); len(denies) != 1 {
		t.Fatalf("agent denies = %+v, want one rule (::1 and [::1] are the same rule)", denies)
	}
	if err := scope.MergeAgentRules(nil, nil, nil, []TargetRule{{Hostname: "[0:0::1]"}}); err != nil {
		t.Fatalf("remove [0:0::1]: %v", err)
	}
	if _, denies := scope.AgentRules(); len(denies) != 0 {
		t.Errorf("agent denies after remove = %+v, want none", denies)
	}
}

func TestTargetRuleEqual_IPv6Spellings(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"::1", "[::1]", true},
		{"[::1]", "0:0::1", true},
		{"[2001:DB8::1]", "2001:db8::1", true},
		{"[::1]", "[::2]", false},
		{"[::1]", "*.[::1]", false},
	}
	for _, tc := range tests {
		if got := targetRuleEqual(TargetRule{Hostname: tc.a}, TargetRule{Hostname: tc.b}); got != tc.want {
			t.Errorf("targetRuleEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestHostComparison_MalformedInputs is T13: the canonicalization helper sits
// on attacker-reachable input (a port-less Host header reaches the gate
// verbatim) and must not panic or collapse degenerate bracket strings into
// the empty host (MITM Principle 5).
func TestHostComparison_MalformedInputs(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"[", "[", true},
		{"]", "]", true},
		{"[]", "[]", true},
		{"[", "", false},
		{"]", "", false},
		{"[]", "", false},
		{"[[::1]]", "::1", false},
		{"[::1]", "[", false},
		{"[", "[::1]", false},
		{"[::1", "::1", false},
		{"::1]", "::1", false},
		{"[%]", "%", true}, // brackets stripped, inner left as-is (not an IP)
	}
	for _, tc := range tests {
		if got := matchHostname(tc.pattern, tc.host); got != tc.want {
			t.Errorf("matchHostname(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
		if got := hostnameCoveredBy(tc.pattern, tc.host); got != tc.want {
			t.Errorf("hostnameCoveredBy(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}
