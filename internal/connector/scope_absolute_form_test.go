package connector

import "testing"

// USK-1274: the authority of an HTTP/1.x absolute-form request-target is a
// name leg. RFC 9112 §3.2.2 lets a server route on it and ignore Host, so
// a request carrying an allowed Host and a denied absolute-form authority
// must be refused. It is judged with the Option B allow semantic of
// CheckNameLeg; an authority net/url cannot read fails closed.

func TestTargetScope_CheckAbsoluteFormAuthority(t *testing.T) {
	denyVhost := []TargetRule{{Hostname: "denied.example"}}
	tests := []struct {
		name         string
		policyAllows []TargetRule
		policyDenies []TargetRule
		scheme       string
		authority    string
		dialTarget   string
		wantAllowed  bool
		wantReason   string
	}{
		{name: "empty authority is no leg", policyDenies: denyVhost, scheme: "http", authority: "", dialTarget: "127.0.0.1:80", wantAllowed: true},
		{name: "denied name", policyDenies: denyVhost, scheme: "http", authority: "denied.example", dialTarget: "127.0.0.1:80", wantAllowed: false},
		{name: "denied name with port", policyDenies: denyVhost, scheme: "http", authority: "denied.example:8080", dialTarget: "127.0.0.1:80", wantAllowed: false},
		{name: "case folds onto the deny", policyDenies: denyVhost, scheme: "http", authority: "DENIED.Example", dialTarget: "127.0.0.1:80", wantAllowed: false},
		{name: "userinfo stripped: denied host", policyDenies: denyVhost, scheme: "http", authority: "allowed.example@denied.example", dialTarget: "127.0.0.1:80", wantAllowed: false},
		{name: "userinfo stripped: denied name only in userinfo", policyDenies: denyVhost, scheme: "http", authority: "denied.example@ok.example", dialTarget: "127.0.0.1:80", wantAllowed: true},
		{name: "more than one @ fails closed", policyDenies: denyVhost, scheme: "http", authority: "a@b@denied.example", dialTarget: "127.0.0.1:80", wantAllowed: false, wantReason: ReasonAbsoluteFormAuthorityUninterpretable},
		{name: "percent-encoded ASCII host fails closed", policyDenies: denyVhost, scheme: "http", authority: "denied.ex%61mple", dialTarget: "127.0.0.1:80", wantAllowed: false, wantReason: ReasonAbsoluteFormAuthorityUninterpretable},
		{name: "unterminated IPv6 literal fails closed", policyDenies: denyVhost, scheme: "http", authority: "[bad", dialTarget: "127.0.0.1:80", wantAllowed: false, wantReason: ReasonAbsoluteFormAuthorityUninterpretable},
		{name: "port zero fails closed", policyDenies: denyVhost, scheme: "http", authority: "ok.example:0", dialTarget: "127.0.0.1:80", wantAllowed: false, wantReason: ReasonHostHeaderUninterpretable},
		{name: "10-digit wrapping port fails closed", policyDenies: denyVhost, scheme: "http", authority: "ok.example:4294967376", dialTarget: "127.0.0.1:80", wantAllowed: false, wantReason: ReasonHostHeaderUninterpretable},
		{name: "bracketed IPv6 deny", policyDenies: []TargetRule{{Hostname: "::1"}}, scheme: "http", authority: "[::1]", dialTarget: "127.0.0.1:80", wantAllowed: false},
		{name: "non-denied name passes", policyDenies: denyVhost, scheme: "http", authority: "ok.example:8080", dialTarget: "127.0.0.1:80", wantAllowed: true},
		{name: "port-less takes transport default: https hits a 443 deny", policyDenies: []TargetRule{{Hostname: "denied.example", Ports: []int{443}}}, scheme: "https", authority: "denied.example", dialTarget: "127.0.0.1:443", wantAllowed: false},
		{name: "port-less takes transport default: http misses a 443 deny", policyDenies: []TargetRule{{Hostname: "denied.example", Ports: []int{443}}}, scheme: "http", authority: "denied.example", dialTarget: "127.0.0.1:80", wantAllowed: true},
		{name: "IP-literal allow exempts an unlisted name", policyAllows: []TargetRule{{Hostname: "127.0.0.1"}}, scheme: "http", authority: "vhost.example", dialTarget: "127.0.0.1:80", wantAllowed: true},
		{name: "domain allow refuses an unlisted name", policyAllows: []TargetRule{{Hostname: "localhost"}}, scheme: "http", authority: "vhost.example", dialTarget: "localhost:80", wantAllowed: false},
		{name: "domain allow admits the allowed name", policyAllows: []TargetRule{{Hostname: "localhost"}}, scheme: "http", authority: "localhost:80", dialTarget: "localhost:80", wantAllowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tt.policyAllows, tt.policyDenies)
			got, reason := s.CheckAbsoluteFormAuthority(tt.scheme, tt.authority, "/", tt.dialTarget)
			if got != tt.wantAllowed {
				t.Fatalf("CheckAbsoluteFormAuthority(%q, %q) = %v (%q), want %v", tt.scheme, tt.authority, got, reason, tt.wantAllowed)
			}
			if tt.wantReason != "" && reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// With no rules every authority passes, even an uninterpretable one.
func TestTargetScope_CheckAbsoluteFormAuthority_OpenMode(t *testing.T) {
	s := NewTargetScope()
	for _, a := range []string{"a@b@c", "[bad", "x:0", ""} {
		if ok, reason := s.CheckAbsoluteFormAuthority("http", a, "/", "127.0.0.1:80"); !ok {
			t.Errorf("CheckAbsoluteFormAuthority(%q) in open mode = false (%q), want true", a, reason)
		}
	}
}
