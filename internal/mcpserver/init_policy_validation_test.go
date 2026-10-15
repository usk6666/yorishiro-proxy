package mcpserver

import (
	"path/filepath"
	"strings"
	"testing"
)

// USK-1084: Policy-layer TargetScope rules (and the rate_limits / budget
// values sharing the same object) are validated at load. Both boot sources
// — the config file's target_scope_policy section and -target-policy-file —
// must refuse to start instead of loading a rule that silently matches
// nothing.

func assertLoadErr(t *testing.T, err error, subs ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("LoadConfigs error = nil, want an error containing %q", subs)
	}
	for _, s := range subs {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("LoadConfigs error = %q, want substring %q", err.Error(), s)
		}
	}
}

// TestLoadConfigs_ConfigFilePolicyOutOfVocabularyScheme is T1, the Issue's
// reproduction: a deny with schemes:["wss"] used to load and then match
// nothing, because §3.8 schemes is {http, https} and matchTargetRule ANDs.
func TestLoadConfigs_ConfigFilePolicyOutOfVocabularyScheme(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	writeTestFile(t, cfgPath, `{"target_scope_policy":{"denies":[{"hostname":"chat.internal","schemes":["wss"]}]}}`)

	_, err := LoadConfigs(cfgPath, "")
	assertLoadErr(t, err, "target_scope_policy", "denies[0]", `"wss"`)
}

// TestLoadConfigs_PolicyFileEmptyScheme is T2: schemes:[""] matched only the
// old blank scheme; post-USK-1081 it matches nothing on CONNECT / plain-HTTP
// forward / MCP paths, so the deny is fail-open there.
func TestLoadConfigs_PolicyFileEmptyScheme(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writeTestFile(t, policyPath, `{"denies":[{"hostname":"*.internal","schemes":[""]}]}`)

	_, err := LoadConfigs("", policyPath)
	assertLoadErr(t, err, "load target policy file", "denies[0]", `scheme ""`)
}

// TestLoadConfigs_ShadowedConfigPolicyStillValidated is T9: a valid
// -target-policy-file wins precedence, but an invalid target_scope_policy in
// the config file is still a config error, like every other section.
func TestLoadConfigs_ShadowedConfigPolicyStillValidated(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{"target_scope_policy":{"denies":[{"hostname":"chat.internal","schemes":["wss"]}]}}`)
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{"denies":[{"hostname":"chat.internal"}]}`)

	_, err := LoadConfigs(cfgPath, policyPath)
	assertLoadErr(t, err, "target_scope_policy", "denies[0]", `"wss"`)
}

// TestLoadConfigs_UppercaseSchemeNormalizedAndEnforced is T6: uppercase is
// accepted (validated case-insensitively), the ProxyConfig/policy struct
// keeps the operator's bytes, and the connector rule is lowercased the way
// the Agent layer's toTargetRules does — while the deny keeps enforcing.
func TestLoadConfigs_UppercaseSchemeNormalizedAndEnforced(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writeTestFile(t, policyPath, `{"denies":[{"hostname":"x.test","schemes":["HTTPS"]}]}`)

	result, err := LoadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}
	if got := result.TargetScopePolicy.Denies[0].Schemes; len(got) != 1 || got[0] != "HTTPS" {
		t.Errorf("policy struct Schemes = %v, want verbatim [HTTPS]", got)
	}

	scope := InitTargetScope(result.TargetScopePolicy)
	_, denies := scope.PolicyRules()
	if len(denies) != 1 || len(denies[0].Schemes) != 1 || denies[0].Schemes[0] != "https" {
		t.Fatalf("PolicyRules denies = %+v, want one rule with Schemes [https]", denies)
	}
	if allowed, _ := scope.CheckTarget("https", "x.test", 443, ""); allowed {
		t.Error("CheckTarget(https, x.test) allowed, want blocked by the uppercase-scheme deny")
	}
	if allowed, _ := scope.CheckTarget("http", "x.test", 80, ""); !allowed {
		t.Error("CheckTarget(http, x.test) blocked, want allowed (deny is https-only)")
	}
}

// TestLoadConfigs_WorkingPolicyFormsLoadAndEnforce is T7, a guard: every form
// here matches a data-path host today (gates pass hosts unbracketed — see
// net.SplitHostPort / url.Hostname), so validation must not reject it, and
// each deny must still block its target after InitTargetScope.
func TestLoadConfigs_WorkingPolicyFormsLoadAndEnforce(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writeTestFile(t, policyPath, `{"denies":[
		{"hostname":"fd00:ec2::254"},
		{"hostname":"::1"},
		{"hostname":"169.254.169.254"},
		{"hostname":"*.example.com"},
		{"hostname":"db_primary"},
		{"hostname":"empty-schemes.test","schemes":[]},
		{"ports":[22]}
	]}`)

	result, err := LoadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}
	scope := InitTargetScope(result.TargetScopePolicy)

	blocked := []struct {
		scheme, host string
		port         int
	}{
		{"http", "fd00:ec2::254", 80},
		{"https", "::1", 443},
		{"http", "169.254.169.254", 80},
		{"https", "api.example.com", 443},
		{"http", "db_primary", 5432},
		{"https", "empty-schemes.test", 443},
		{"http", "anything.test", 22},
	}
	for _, b := range blocked {
		if allowed, _ := scope.CheckTarget(b.scheme, b.host, b.port, ""); allowed {
			t.Errorf("CheckTarget(%s, %s, %d) allowed, want blocked by policy deny", b.scheme, b.host, b.port)
		}
	}
	if allowed, reason := scope.CheckTarget("https", "anything.test", 443, ""); !allowed {
		t.Errorf("CheckTarget(https, anything.test, 443) blocked (%s), want allowed", reason)
	}
}
