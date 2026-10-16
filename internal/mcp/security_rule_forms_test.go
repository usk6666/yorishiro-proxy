package mcp

import (
	"context"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1129: Agent-layer (MCP `security` tool) behavior for TargetScope rule
// forms that silently never took effect: bracketed IPv6 rules, path_prefix
// values that can never match a request path, and Agent allows under a
// Policy allow with an empty hostname.

// callSecurity invokes the security tool and returns the raw result.
func callSecurity(t *testing.T, cs *gomcp.ClientSession, action string, params securityParams) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "security",
		Arguments: securityMarshal(t, securityInput{Action: action, Params: params}),
	})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", action, err)
	}
	return result
}

func mustSecurityOK(t *testing.T, cs *gomcp.ClientSession, action string, params securityParams) *gomcp.CallToolResult {
	t.Helper()
	result := callSecurity(t, cs, action, params)
	if result.IsError {
		t.Fatalf("%s returned IsError=true: %s", action, extractTextContent(result))
	}
	return result
}

func mustSecurityErr(t *testing.T, cs *gomcp.ClientSession, action string, params securityParams, wantSubs ...string) {
	t.Helper()
	result := callSecurity(t, cs, action, params)
	if !result.IsError {
		t.Fatalf("%s succeeded, want an error containing %q", action, wantSubs)
	}
	text := extractTextContent(result)
	for _, s := range wantSubs {
		if !strings.Contains(text, s) {
			t.Errorf("%s error = %q, want substring %q", action, text, s)
		}
	}
}

func testTarget(t *testing.T, cs *gomcp.ClientSession, rawURL string) testTargetResult {
	t.Helper()
	result := mustSecurityOK(t, cs, "test_target", securityParams{URL: rawURL})
	var res testTargetResult
	securityUnmarshalResult(t, result, &res)
	return res
}

// TestSecurity_BracketedIPv6Deny_Enforces is T4: a deny written as "[::1]"
// is enforced against a ::1 target, test_target names the rule that decided,
// and get_target_scope echoes the rule as authored.
func TestSecurity_BracketedIPv6Deny_Enforces(t *testing.T) {
	ts := connector.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	mustSecurityOK(t, cs, "set_target_scope", securityParams{
		Denies: []targetRuleInput{{Hostname: "[::1]"}},
	})

	res := testTarget(t, cs, "http://[::1]:8080/")
	if res.Allowed {
		t.Fatalf("test_target(http://[::1]:8080/) allowed=true, want blocked by agent deny [::1]")
	}
	if res.Layer != "agent" {
		t.Errorf("layer = %q, want agent", res.Layer)
	}
	if res.MatchedRule == nil || res.MatchedRule.Hostname != "[::1]" {
		t.Errorf("matched_rule = %+v, want hostname [::1]", res.MatchedRule)
	}

	// Non-canonical spelling of the same address is the same target.
	if res := testTarget(t, cs, "https://[0:0::1]/"); res.Allowed {
		t.Errorf("test_target(https://[0:0::1]/) allowed=true, want blocked")
	}
	// The live data-path predicate agrees with test_target.
	if allowed, _ := ts.CheckTarget("https", "::1", 443, ""); allowed {
		t.Error("CheckTarget(::1) allowed, want blocked by agent deny [::1]")
	}

	// Stored verbatim.
	get := mustSecurityOK(t, cs, "get_target_scope", securityParams{})
	var scope getTargetScopeResult
	securityUnmarshalResult(t, get, &scope)
	if len(scope.Agent.Denies) != 1 || scope.Agent.Denies[0].Hostname != "[::1]" {
		t.Errorf("get_target_scope agent.denies = %+v, want verbatim [::1]", scope.Agent.Denies)
	}
}

// TestSecurity_BareIPv6Allow_TestTargetMatchedRule is the allow side of
// T4: test_target reports the agent allow that permitted the target even
// when the rule and URL spell the address differently.
func TestSecurity_BareIPv6Allow_TestTargetMatchedRule(t *testing.T) {
	ts := connector.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	mustSecurityOK(t, cs, "set_target_scope", securityParams{
		Allows: []targetRuleInput{{Hostname: "[::1]"}},
	})
	res := testTarget(t, cs, "http://[0:0::1]:8080/x")
	if !res.Allowed {
		t.Fatalf("test_target allowed=false (%q), want allowed by agent allow [::1]", res.Reason)
	}
	if res.Layer != "agent" || res.MatchedRule == nil || res.MatchedRule.Hostname != "[::1]" {
		t.Errorf("layer=%q matched_rule=%+v, want agent / [::1]", res.Layer, res.MatchedRule)
	}
}

// TestSecurity_IPv6AgentAllowUnderIPv6PolicyAllow is T5: bracketed and bare
// spellings cover each other across the Policy / Agent boundary; an
// unrelated policy still rejects.
func TestSecurity_IPv6AgentAllowUnderIPv6PolicyAllow(t *testing.T) {
	tests := []struct {
		name       string
		policyHost string
		agentHost  string
		wantErr    string // "" = accepted
	}{
		{"policy bare, agent bracketed", "::1", "[::1]", ""},
		{"policy bracketed, agent bare", "[::1]", "::1", ""},
		{"policy bracketed, agent expanded", "[::1]", "0:0::1", ""},
		{"policy wildcard, agent bracketed", "*.example.com", "[::1]", "outside policy allow boundary"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := connector.NewTargetScope()
			ts.SetPolicyRules([]connector.TargetRule{{Hostname: tc.policyHost}}, nil)
			cs := setupSecurityTestSession(t, ts)
			params := securityParams{Allows: []targetRuleInput{{Hostname: tc.agentHost}}}
			if tc.wantErr == "" {
				mustSecurityOK(t, cs, "set_target_scope", params)
				mustSecurityOK(t, cs, "update_target_scope", securityParams{AddAllows: params.Allows})
				return
			}
			mustSecurityErr(t, cs, "set_target_scope", params, tc.wantErr)
		})
	}
}

// TestSecurity_EmptyHostnamePolicyAllow is T8: a Policy allow without a
// hostname (any host) bounds only by the fields it does set.
func TestSecurity_EmptyHostnamePolicyAllow(t *testing.T) {
	ts := connector.NewTargetScope()
	ts.SetPolicyRules([]connector.TargetRule{{Ports: []int{443}}}, nil)
	cs := setupSecurityTestSession(t, ts)

	mustSecurityOK(t, cs, "set_target_scope", securityParams{
		Allows: []targetRuleInput{{Hostname: "example.com", Ports: []int{443}}},
	})
	mustSecurityOK(t, cs, "update_target_scope", securityParams{
		AddAllows: []targetRuleInput{{Hostname: "*.example.com", Ports: []int{443}}},
	})
	mustSecurityErr(t, cs, "set_target_scope", securityParams{
		Allows: []targetRuleInput{{Hostname: "example.com"}},
	}, "outside policy allow boundary")
	mustSecurityErr(t, cs, "set_target_scope", securityParams{
		Allows: []targetRuleInput{{Hostname: "example.com", Ports: []int{80}}},
	}, "outside policy allow boundary")
}

// TestSecurity_PathPrefixValidation is T6 at the Agent layer: the shared
// core rejects path_prefix forms that never match a request path, with the
// Agent layer's "<kind> rule <i>:" location prefix.
func TestSecurity_PathPrefixValidation(t *testing.T) {
	rejects := []struct {
		name   string
		action string
		params securityParams
		want   []string
	}{
		{"no leading slash", "set_target_scope",
			securityParams{Denies: []targetRuleInput{{Hostname: "h.test", PathPrefix: "admin"}}},
			[]string{`denies rule 0: path_prefix "admin" must start with "/" (e.g. "/admin")`}},
		{"bare star", "set_target_scope",
			securityParams{Allows: []targetRuleInput{{Hostname: "h.test", PathPrefix: "*"}}},
			[]string{"allows rule 0:", "literal prefix match"}},
		{"trailing star", "update_target_scope",
			securityParams{AddAllows: []targetRuleInput{{Hostname: "h.test", PathPrefix: "/api/*"}}},
			[]string{"add_allows rule 0:", `drop the trailing "*" (e.g. "/api/*" -> "/api/")`}},
		{"mid-path star", "update_target_scope",
			securityParams{AddDenies: []targetRuleInput{{Hostname: "h.test", PathPrefix: "/a/*/b"}}},
			[]string{"add_denies rule 0:", "literal prefix match"}},
		{"query", "set_target_scope",
			securityParams{Denies: []targetRuleInput{{Hostname: "h.test", PathPrefix: "/search?q="}}},
			[]string{"denies rule 0:", "query/fragment is not part of the path"}},
		{"fragment", "set_target_scope",
			securityParams{Denies: []targetRuleInput{{Hostname: "h.test", PathPrefix: "/x#y"}}},
			[]string{"denies rule 0:", "query/fragment is not part of the path"}},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			cs := setupSecurityTestSession(t, connector.NewTargetScope())
			mustSecurityErr(t, cs, tc.action, tc.params, tc.want...)
		})
	}

	t.Run("well-formed prefixes accepted", func(t *testing.T) {
		cs := setupSecurityTestSession(t, connector.NewTargetScope())
		mustSecurityOK(t, cs, "set_target_scope", securityParams{
			Denies: []targetRuleInput{
				{Hostname: "h.test", PathPrefix: "/admin"},
				{Hostname: "h.test", PathPrefix: "/"},
			},
		})
	})

	// Remove operations stay unvalidated so a stale rule can still be
	// removed (R5).
	t.Run("remove with malformed prefix is not validated", func(t *testing.T) {
		ts := connector.NewTargetScope()
		if err := ts.SetAgentRules(nil, []connector.TargetRule{{Hostname: "h.test", PathPrefix: "admin"}}); err != nil {
			t.Fatalf("seed stale rule: %v", err)
		}
		cs := setupSecurityTestSession(t, ts)
		mustSecurityOK(t, cs, "update_target_scope", securityParams{
			RemoveDenies: []targetRuleInput{{Hostname: "h.test", PathPrefix: "admin"}},
		})
		if _, denies := ts.AgentRules(); len(denies) != 0 {
			t.Errorf("agent denies = %+v, want the stale rule removed", denies)
		}
	})
}

// TestSecurity_UpdateTargetScope_IPv6SpellingsAreOneRule is T11 through the
// MCP handler: dedupe, removal, and the policy-deny removal guard treat
// "::1" and "[::1]" as one rule.
func TestSecurity_UpdateTargetScope_IPv6SpellingsAreOneRule(t *testing.T) {
	ts := connector.NewTargetScope()
	cs := setupSecurityTestSession(t, ts)

	mustSecurityOK(t, cs, "update_target_scope", securityParams{AddDenies: []targetRuleInput{{Hostname: "::1"}}})
	mustSecurityOK(t, cs, "update_target_scope", securityParams{AddDenies: []targetRuleInput{{Hostname: "[::1]"}}})
	if _, denies := ts.AgentRules(); len(denies) != 1 {
		t.Fatalf("agent denies = %+v, want one rule", denies)
	}
	mustSecurityOK(t, cs, "update_target_scope", securityParams{RemoveDenies: []targetRuleInput{{Hostname: "[0:0::1]"}}})
	if _, denies := ts.AgentRules(); len(denies) != 0 {
		t.Errorf("agent denies after remove = %+v, want none", denies)
	}

	pts := connector.NewTargetScope()
	pts.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "::1"}})
	pcs := setupSecurityTestSession(t, pts)
	mustSecurityErr(t, pcs, "update_target_scope", securityParams{
		RemoveDenies: []targetRuleInput{{Hostname: "[::1]"}},
	}, "cannot remove policy deny rule")
}

// TestSecurity_WildcardOverIPLiteralRejected is T12 at the Agent layer.
func TestSecurity_WildcardOverIPLiteralRejected(t *testing.T) {
	for _, host := range []string{"*.[::1]", "*.10.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			cs := setupSecurityTestSession(t, connector.NewTargetScope())
			mustSecurityErr(t, cs, "set_target_scope", securityParams{
				Denies: []targetRuleInput{{Hostname: host}},
			}, "denies rule 0:", "wildcard is not allowed on an IP literal")
		})
	}
}
