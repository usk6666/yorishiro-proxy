package connector

import "testing"

// USK-1167: name legs (an HTTP request's authority and every Host header
// value) are checked against deny rules always, and against an allow layer
// only when the dial target was not admitted by an IP-literal allow rule of
// that layer ("Option B"). Same-IP different-vhost testing and Host-header
// injection stay possible; reaching a denied name never does.

func TestTargetScope_CheckNameLeg_OptionB(t *testing.T) {
	tests := []struct {
		name         string
		policyAllows []TargetRule
		policyDenies []TargetRule
		agentAllows  []TargetRule
		agentDenies  []TargetRule
		scheme       string
		leg          string
		legPort      int
		path         string
		dialTarget   string
		wantAllowed  bool
	}{
		{
			name:         "IP-literal allow admits dial target: unlisted vhost passes",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: true,
		},
		{
			name:         "IP-literal allow admits dial target: denied vhost still refused",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}},
			policyDenies: []TargetRule{{Hostname: "denied.example"}},
			scheme:       "https", leg: "denied.example", legPort: 443, path: "/",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: false,
		},
		{
			name:         "agent deny applies to the name leg too",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}},
			agentDenies:  []TargetRule{{Hostname: "denied.example"}},
			scheme:       "http", leg: "denied.example", legPort: 80, path: "/",
			dialTarget:  "10.0.0.5:80",
			wantAllowed: false,
		},
		{
			name:         "domain allow admits dial target: other domain refused",
			policyAllows: []TargetRule{{Hostname: "app.example"}},
			scheme:       "https", leg: "other.example", legPort: 443, path: "/",
			dialTarget:  "app.example:443",
			wantAllowed: false,
		},
		{
			name:         "domain allow admits dial target: same domain passes",
			policyAllows: []TargetRule{{Hostname: "app.example"}},
			scheme:       "https", leg: "app.example", legPort: 443, path: "/",
			dialTarget:  "app.example:443",
			wantAllowed: true,
		},
		{
			name:         "mixed allows, dial by IP: unlisted vhost passes",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}, {Hostname: "app.example"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: true,
		},
		{
			name:         "mixed allows, dial by domain: unlisted vhost refused",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}, {Hostname: "app.example"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/",
			dialTarget:  "app.example:443",
			wantAllowed: false,
		},
		{
			name:         "IP allow that does not match the dial target does not exempt",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}, {Hostname: "app.example"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/",
			dialTarget:  "10.0.0.6:443",
			wantAllowed: false,
		},
		{
			name:         "IP allow with ports exempts only on a matching dial port",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5", Ports: []int{8443}}},
			scheme:       "https", leg: "intranet.local", legPort: 8443, path: "/",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: false,
		},
		{
			name:         "IP allow with path_prefix exempts only for a matching path",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5", PathPrefix: "/api/"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/api/x",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: true,
		},
		{
			name:         "IP allow with path_prefix: other path is not exempt",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5", PathPrefix: "/api/"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/other",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: false,
		},
		{
			name:         "IPv6 literal allow exempts",
			policyAllows: []TargetRule{{Hostname: "::1"}},
			scheme:       "http", leg: "vhost.example", legPort: 80, path: "/",
			dialTarget:  "[::1]:80",
			wantAllowed: true,
		},
		{
			name:         "per layer: policy IP allow exempts, agent domain allow does not",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}, {Hostname: "app.example"}},
			agentAllows:  []TargetRule{{Hostname: "app.example"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: false,
		},
		{
			name:         "per layer: both layers IP-admit the dial target",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}},
			agentAllows:  []TargetRule{{Hostname: "10.0.0.5"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/",
			dialTarget:  "10.0.0.5:443",
			wantAllowed: true,
		},
		{
			name:         "empty dial target falls back to the full check",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}},
			scheme:       "https", leg: "intranet.local", legPort: 443, path: "/",
			dialTarget:  "",
			wantAllowed: false,
		},
		{
			name:         "deny-only scope: unlisted name passes",
			policyDenies: []TargetRule{{Hostname: "denied.example"}},
			scheme:       "http", leg: "other.example", legPort: 80, path: "/",
			dialTarget:  "127.0.0.1:80",
			wantAllowed: true,
		},
		{
			name:         "path-scoped deny on the name leg fires",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}},
			policyDenies: []TargetRule{{Hostname: "vhost.example", PathPrefix: "/admin"}},
			scheme:       "http", leg: "vhost.example", legPort: 80, path: "/admin/x",
			dialTarget:  "10.0.0.5:80",
			wantAllowed: false,
		},
		{
			name:         "unparsable numeric name fails closed even when exempt",
			policyAllows: []TargetRule{{Hostname: "10.0.0.5"}},
			scheme:       "http", leg: "1.2.3.4.5", legPort: 80, path: "/",
			dialTarget:  "10.0.0.5:80",
			wantAllowed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tt.policyAllows, tt.policyDenies)
			if err := s.SetAgentRules(tt.agentAllows, tt.agentDenies); err != nil {
				t.Fatalf("SetAgentRules: %v", err)
			}
			got, reason := s.CheckNameLeg(tt.scheme, tt.leg, tt.legPort, tt.path, tt.dialTarget)
			if got != tt.wantAllowed {
				t.Fatalf("CheckNameLeg(%q, %q, %d, %q, %q) = %v (%q), want %v",
					tt.scheme, tt.leg, tt.legPort, tt.path, tt.dialTarget, got, reason, tt.wantAllowed)
			}
			if !got && reason == "" {
				t.Errorf("blocked without a reason")
			}
		})
	}
}

// CheckTarget itself keeps the full check: the Option B exemption exists
// only on the name-leg API.
func TestTargetScope_CheckNameLeg_CheckTargetUnchanged(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "10.0.0.5"}}, nil)
	if ok, _ := s.CheckTarget("https", "intranet.local", 443, "/"); ok {
		t.Fatalf("CheckTarget admitted a name outside the allow list")
	}
}

func TestTargetScope_CheckHostHeader(t *testing.T) {
	tests := []struct {
		name         string
		policyAllows []TargetRule
		policyDenies []TargetRule
		scheme       string
		value        string
		dialTarget   string
		wantAllowed  bool
	}{
		{"denied bare name", nil, []TargetRule{{Hostname: "denied.example"}}, "http", "denied.example", "127.0.0.1:80", false},
		{"denied name with port", nil, []TargetRule{{Hostname: "denied.example"}}, "http", "denied.example:8080", "127.0.0.1:80", false},
		{"denied name, port-scoped deny, default port inferred", nil, []TargetRule{{Hostname: "denied.example", Ports: []int{443}}}, "https", "denied.example", "127.0.0.1:443", false},
		{"port-scoped deny, other port passes", nil, []TargetRule{{Hostname: "denied.example", Ports: []int{443}}}, "https", "denied.example:8443", "127.0.0.1:443", true},
		{"non-decimal port fails closed", nil, []TargetRule{{Hostname: "denied.example", Ports: []int{80}}}, "http", "denied.example:abc", "127.0.0.1:80", false},
		{"overflowing port fails closed", nil, []TargetRule{{Hostname: "denied.example", Ports: []int{80}}}, "http", "denied.example:99999999999", "127.0.0.1:80", false},
		{"port zero fails closed", nil, []TargetRule{{Hostname: "other.example"}}, "http", "allowed.example:0", "127.0.0.1:80", false},
		{"too many colons fails closed", nil, []TargetRule{{Hostname: "denied.example"}}, "http", "denied.example:80:90", "127.0.0.1:80", false},
		{"bracketed IPv6 with port", nil, []TargetRule{{Hostname: "::2"}}, "http", "[::2]:8080", "127.0.0.1:80", false},
		{"bracketed IPv6 without port", nil, []TargetRule{{Hostname: "::2"}}, "http", "[::2]", "127.0.0.1:80", false},
		{"allowed name passes", nil, []TargetRule{{Hostname: "denied.example"}}, "http", "ok.example:8080", "127.0.0.1:80", true},
		{"case and trailing dot fold onto the deny", nil, []TargetRule{{Hostname: "denied.example"}}, "http", "DENIED.Example.", "127.0.0.1:80", false},
		{"IP-literal allow exempts an unlisted vhost", []TargetRule{{Hostname: "127.0.0.1"}}, nil, "http", "vhost.example", "127.0.0.1:80", true},
		{"domain allow refuses an unlisted vhost", []TargetRule{{Hostname: "localhost"}}, nil, "http", "vhost.example", "localhost:80", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tt.policyAllows, tt.policyDenies)
			got, reason := s.CheckHostHeader(tt.scheme, tt.value, "/", tt.dialTarget)
			if got != tt.wantAllowed {
				t.Fatalf("CheckHostHeader(%q, %q) = %v (%q), want %v", tt.scheme, tt.value, got, reason, tt.wantAllowed)
			}
		})
	}
}

// With no rules at all every Host value passes, even an uninterpretable one.
func TestTargetScope_CheckHostHeader_OpenMode(t *testing.T) {
	s := NewTargetScope()
	for _, v := range []string{"denied.example:abc", "a:b:c", ""} {
		if ok, reason := s.CheckHostHeader("http", v, "/", "127.0.0.1:80"); !ok {
			t.Errorf("CheckHostHeader(%q) in open mode = false (%q), want true", v, reason)
		}
	}
}
