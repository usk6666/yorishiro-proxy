package connector

import (
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestCheckURL_PathPrefixMatchesEitherForm pins USK-1139's path_prefix
// contract on the URL-based entry point used by the MCP resend / macro /
// security test_target paths: the rule matches when either the wire path or
// its percent-decoded form starts with the prefix. Inputs are the two URL
// shapes those callers hand in — a Flow.URL / canonical URL built from a
// wire path, and an operator-typed URL parsed by net/url.
func TestCheckURL_PathPrefixMatchesEitherForm(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(nil, []TargetRule{{PathPrefix: "/admin"}, {PathPrefix: "/a%20b"}})

	mustParse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		return u
	}
	tests := []struct {
		name        string
		u           *url.URL
		wantAllowed bool
	}{
		{"wire plain", envelope.URLFromWirePath("https", "h", "/admin/x", ""), false},
		{"wire encoded unreserved", envelope.URLFromWirePath("https", "h", "/%61dmin/x", ""), false},
		{"wire raw-form prefix", envelope.URLFromWirePath("https", "h", "/a%20b/x", ""), false},
		{"wire unrelated", envelope.URLFromWirePath("https", "h", "/public", ""), true},
		{"parsed encoded unreserved", mustParse("https://h/%61dmin"), false},
		{"parsed raw-form prefix", mustParse("https://h/a%20b/x"), false},
		{"parsed unrelated", mustParse("https://h/public"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if allowed, _ := s.CheckURL(tt.u); allowed != tt.wantAllowed {
				t.Errorf("CheckURL(%q) allowed = %v, want %v", envelope.WireURLString(tt.u), allowed, tt.wantAllowed)
			}
		})
	}
}

// TestCheckTarget_PathPrefixMatchesEitherForm covers the string entry point
// HTTPScopeStep uses (HTTPMessage.Path is wire form after USK-1139).
func TestCheckTarget_PathPrefixMatchesEitherForm(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules(nil, []TargetRule{{PathPrefix: "/admin"}})
	for _, p := range []string{"/admin", "/%61dmin", "/%61%64%6d%69%6e/x", "/adm%69n"} {
		if allowed, _ := s.CheckTarget("https", "h", 443, p); allowed {
			t.Errorf("CheckTarget(path %q) allowed; want blocked by /admin deny", p)
		}
	}
	for _, p := range []string{"/public", "/%2561dmin", "/ad%zzmin"} {
		if allowed, _ := s.CheckTarget("https", "h", 443, p); !allowed {
			t.Errorf("CheckTarget(path %q) blocked; want allowed", p)
		}
	}
}
