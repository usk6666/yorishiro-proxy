package mcp

import (
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestFindMatchedRuleAndLayer_PathPrefixEitherForm pins that the
// test_target explainer reports the same path_prefix rule TargetScope
// itself matched (USK-1139: raw or percent-decoded form).
func TestFindMatchedRuleAndLayer_PathPrefixEitherForm(t *testing.T) {
	ts := connector.NewTargetScope()
	ts.SetPolicyRules(nil, []connector.TargetRule{{PathPrefix: "/admin"}, {PathPrefix: "/a%20b"}})

	for _, raw := range []string{"https://h/%61dmin", "https://h/a%20b/x", "https://h/admin"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		allowed, reason := ts.CheckURL(u)
		if allowed {
			t.Errorf("CheckURL(%q) allowed; want blocked", raw)
			continue
		}
		rule, layer := findMatchedRuleAndLayer(ts, u, allowed, reason)
		if rule == nil || layer != "policy" {
			t.Errorf("findMatchedRuleAndLayer(%q) = (%v, %q), want the policy path_prefix rule", raw, rule, layer)
		}
	}
}
