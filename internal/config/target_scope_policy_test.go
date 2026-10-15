package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// USK-1084: the Policy layer of TargetScope (operator ceiling, loaded from
// -target-policy-file or the config file's target_scope_policy section) was
// never validated. matchTargetRule is AND logic, so a rule whose schemes
// carries an out-of-vocabulary token (RFC-001 §3.8 closes the vocabulary to
// {http, https}) or whose hostname can never equal a data-path host matches
// nothing — an operator deny silently becomes a no-op (fail-open). These
// tests pin the load-time gate.

// policyRejectCase is one rejected Policy-layer form. body is the JSON of a
// complete policy object; wantSubs are substrings the error must contain
// (location prefix + the inner Agent-layer wording).
type policyRejectCase struct {
	name     string
	body     string
	wantSubs []string
}

// policyRejectCases is the T4/T5 table: every form here is outside the
// closed scheme vocabulary or provably never matches a data-path host/port.
func policyRejectCases() []policyRejectCase {
	return []policyRejectCase{
		// --- schemes outside {http, https} ---
		{"scheme ws", `{"denies":[{"hostname":"chat.internal","schemes":["ws"]}]}`,
			[]string{"denies[0]", `scheme "ws" is not allowed (use http or https)`}},
		{"scheme wss", `{"denies":[{"hostname":"chat.internal","schemes":["wss"]}]}`,
			[]string{"denies[0]", `scheme "wss" is not allowed (use http or https)`}},
		{"scheme tcp", `{"denies":[{"hostname":"db.internal","schemes":["tcp"]}]}`,
			[]string{"denies[0]", `scheme "tcp" is not allowed`}},
		{"scheme raw", `{"denies":[{"hostname":"db.internal","schemes":["raw"]}]}`,
			[]string{"denies[0]", `scheme "raw" is not allowed`}},
		{"scheme typo htps", `{"allows":[{"hostname":"target.test","schemes":["htps"]}]}`,
			[]string{"allows[0]", `scheme "htps" is not allowed`}},
		{"scheme empty string", `{"denies":[{"hostname":"*.internal","schemes":[""]}]}`,
			[]string{"denies[0]", `scheme "" is not allowed`, "omit schemes"}},
		{"bad scheme after valid one", `{"denies":[{"hostname":"a.test","schemes":["https","wss"]}]}`,
			[]string{"denies[0]", `scheme "wss"`}},
		// --- hostnames that can never equal a data-path host ---
		{"hostname bare star", `{"denies":[{"hostname":"*"}]}`,
			[]string{"denies[0]", `hostname "*"`}},
		{"hostname with port", `{"denies":[{"hostname":"example.com:443"}]}`,
			[]string{"denies[0]", `hostname "example.com:443"`}},
		{"hostname is a URL", `{"denies":[{"hostname":"https://x"}]}`,
			[]string{"denies[0]", `hostname "https://x"`}},
		{"wildcard without dot", `{"denies":[{"hostname":"*example.com"}]}`,
			[]string{"denies[0]", `hostname "*example.com"`}},
		{"mid-label wildcard", `{"denies":[{"hostname":"a.*.example.com"}]}`,
			[]string{"denies[0]", `hostname "a.*.example.com"`}},
		{"wildcard with empty domain", `{"denies":[{"hostname":"*."}]}`,
			[]string{"denies[0]", `hostname "*."`}},
		{"unterminated bracket", `{"denies":[{"hostname":"["}]}`,
			[]string{"denies[0]", `hostname "["`}},
		{"wildcard over bare ipv6", `{"denies":[{"hostname":"*.fd00::1"}]}`,
			[]string{"denies[0]", `hostname "*.fd00::1"`, "wildcard is not allowed on an IP literal"}},
		// --- ports outside 1-65535 ---
		{"port zero", `{"denies":[{"hostname":"a.test","ports":[0]}]}`,
			[]string{"denies[0]", "port 0 is out of range (1-65535)"}},
		{"port negative", `{"denies":[{"hostname":"a.test","ports":[-1]}]}`,
			[]string{"denies[0]", "port -1 is out of range (1-65535)"}},
		{"port too large", `{"denies":[{"ports":[70000]}]}`,
			[]string{"denies[0]", "port 70000 is out of range (1-65535)"}},
		// --- the location prefix names the offending index ---
		{"second deny is the bad one", `{"denies":[{"hostname":"ok.test"},{"hostname":"x.test","schemes":["wss"]}]}`,
			[]string{"denies[1]", `scheme "wss"`}},
		{"second allow is the bad one", `{"allows":[{"hostname":"ok.test"},{"hostname":"*"}]}`,
			[]string{"allows[1]", `hostname "*"`}},
	}
}

// writePolicyFile writes body into a fresh temp file and returns its path.
func writePolicyFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

func assertErrContains(t *testing.T, err error, subs ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want an error containing %q", subs)
	}
	for _, s := range subs {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error = %q, want substring %q", err.Error(), s)
		}
	}
}

// TestLoadPolicyFile_RejectsInvalidRules is T4: the dedicated policy file
// path refuses every form in the table.
func TestLoadPolicyFile_RejectsInvalidRules(t *testing.T) {
	for _, tc := range policyRejectCases() {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)
			_, err := LoadPolicyFile(path)
			assertErrContains(t, err, append([]string{"validate policy file", path}, tc.wantSubs...)...)
		})
	}
}

// TestProxyConfigValidate_RejectsInvalidTargetScopePolicy is T5: the same
// table wrapped in a config file's target_scope_policy section is refused by
// ProxyConfig.Validate (LoadFile itself stays lenient).
func TestProxyConfigValidate_RejectsInvalidTargetScopePolicy(t *testing.T) {
	for _, tc := range policyRejectCases() {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, `{"target_scope_policy":`+tc.body+`}`)
			cfg, err := LoadFile(path)
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			err = cfg.Validate()
			assertErrContains(t, err, append([]string{"target_scope_policy: "}, tc.wantSubs...)...)
		})
	}
}

// TestLoadPolicyFile_RejectsNegativeLimits is T8: rate_limits / budget share
// the policy object and negative values used to load as "unlimited" (the
// consumers test > 0). The Agent layer already rejects them.
func TestLoadPolicyFile_RejectsNegativeLimits(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantSubs []string
	}{
		{"negative global rps", `{"rate_limits":{"max_requests_per_second":-1}}`,
			[]string{"rate_limits", "max_requests_per_second must be >= 0"}},
		{"negative per-host rps", `{"rate_limits":{"max_requests_per_host_per_second":-0.5}}`,
			[]string{"rate_limits", "max_requests_per_host_per_second must be >= 0"}},
		{"negative max_total_requests", `{"budget":{"max_total_requests":-1}}`,
			[]string{"budget", "max_total_requests must be >= 0"}},
		{"negative max_duration string", `{"budget":{"max_duration":"-5m"}}`,
			[]string{"budget", "max_duration must be >= 0"}},
		{"negative max_duration nanoseconds", `{"budget":{"max_duration":-1}}`,
			[]string{"budget", "max_duration must be >= 0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)
			_, err := LoadPolicyFile(path)
			assertErrContains(t, err, append([]string{"validate policy file"}, tc.wantSubs...)...)
		})
	}
}

// TestLoadPolicyFile_AcceptsZeroAndPositiveLimits guards the boundary: zero
// is the documented "no limit" value and must keep loading.
func TestLoadPolicyFile_AcceptsZeroAndPositiveLimits(t *testing.T) {
	body := `{"rate_limits":{"max_requests_per_second":0,"max_requests_per_host_per_second":2.5},` +
		`"budget":{"max_total_requests":0,"max_duration":"30m"}}`
	if _, err := LoadPolicyFile(writePolicyFile(t, body)); err != nil {
		t.Fatalf("LoadPolicyFile: %v", err)
	}
}

// TestLoadPolicyFile_StrictDecoding is T12: a file overwritten with an
// unrelated JSON document must not load as an empty (allow-all) policy.
// The HAR shape mirrors internal/flow/har.go (HAR{Log:{Version,Creator,
// Entries}}) — what MCP `manage export_flows output_path=<policy file>`
// writes.
func TestLoadPolicyFile_StrictDecoding(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantSubs []string
	}{
		{"HAR document", `{"log":{"version":"1.2","creator":{"name":"yorishiro-proxy","version":"0.18.2"},"entries":[]}}`,
			[]string{`unknown field "log"`}},
		{"top-level typo", `{"denys":[{"hostname":"169.254.169.254"}]}`,
			[]string{`unknown field "denys"`}},
		{"rule-level typo", `{"denies":[{"hostnme":"169.254.169.254"}]}`,
			[]string{`unknown field "hostnme"`}},
		{"null document", `null`,
			[]string{"JSON object"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, tc.body)
			_, err := LoadPolicyFile(path)
			assertErrContains(t, err, append([]string{"policy file", path}, tc.wantSubs...)...)
		})
	}
}

// TestLoadPolicyFile_AcceptsWorkingForms is a guard (T7 at the config seam):
// every form here matches a data-path host today and must keep loading.
func TestLoadPolicyFile_AcceptsWorkingForms(t *testing.T) {
	body := `{
		"allows": [
			{"hostname": "*.example.com", "ports": [1, 443, 65535]},
			{"hostname": "api.staging.test", "path_prefix": "/v2/", "schemes": ["https"]}
		],
		"denies": [
			{"hostname": "fd00:ec2::254"},
			{"hostname": "::1"},
			{"hostname": "[::1]"},
			{"hostname": "169.254.169.254"},
			{"hostname": "db_primary"},
			{"hostname": "_dmarc.example.com"},
			{"hostname": "Mixed-Case.Example.COM"},
			{"hostname": "x.test", "schemes": []},
			{"hostname": "y.test", "schemes": ["HTTP", "Https"]},
			{"ports": [22]}
		]
	}`
	policy, err := LoadPolicyFile(writePolicyFile(t, body))
	if err != nil {
		t.Fatalf("LoadPolicyFile: %v", err)
	}
	// Validation rejects; it never rewrites the operator's bytes.
	if got := policy.Denies[8].Schemes; len(got) != 2 || got[0] != "HTTP" || got[1] != "Https" {
		t.Errorf("Denies[8].Schemes = %v, want verbatim [HTTP Https]", got)
	}
}

// TestValidateTargetRule is the per-rule core shared with the Agent layer
// (internal/mcp validateTargetRules delegates to it). Rows carried over from
// the Agent layer's former TestValidateHostname keep their verdicts except
// underscore labels, which the core now accepts (they match today).
func TestValidateTargetRule(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		ports    []int
		schemes  []string
		wantErr  string // "" = accept
	}{
		// accepted
		{"empty hostname (any host)", "", []int{22}, nil, ""},
		{"simple domain", "example.com", nil, nil, ""},
		{"subdomain", "sub.example.com", nil, nil, ""},
		{"wildcard", "*.example.com", nil, nil, ""},
		{"single label", "localhost", nil, nil, ""},
		{"hyphenated label", "my-host.example.com", nil, nil, ""},
		{"ipv4", "10.0.0.1", nil, nil, ""},
		{"ipv6 bracket", "[2001:db8::1]", nil, nil, ""},
		{"ipv6 bare", "fd00:ec2::254", nil, nil, ""},
		{"ipv6 loopback bare", "::1", nil, nil, ""},
		{"underscore label", "test_host.com", nil, nil, ""},
		{"underscore single label", "db_primary", nil, nil, ""},
		{"uppercase schemes", "example.com", nil, []string{"HTTP", "HTTPS"}, ""},
		{"port bounds", "example.com", []int{1, 65535}, nil, ""},
		// rejected hostnames
		{"trailing dot", "example.com.", nil, nil, "trailing dot"},
		{"wildcard trailing dot", "*.example.com.", nil, nil, "trailing dot"},
		{"empty wildcard domain", "*.", nil, nil, "wildcard must be followed by a domain"},
		{"double dot", "example..com", nil, nil, "empty label"},
		{"label too long", strings.Repeat("a", 64) + ".com", nil, nil, "exceeds 63 characters"},
		{"domain too long", strings.Repeat("a.", 127) + "com", nil, nil, "too long"},
		{"leading hyphen", "-example.com", nil, nil, "hyphen"},
		{"trailing hyphen", "example-.com", nil, nil, "hyphen"},
		{"control character", "exam\x00ple.com", nil, nil, "invalid character"},
		{"space", "exam ple.com", nil, nil, "invalid character"},
		{"invalid ipv4", "999.999.999.999", nil, nil, "invalid IPv4"},
		{"invalid ipv6 bracket", "[not-ipv6]", nil, nil, "invalid IPv6"},
		{"empty brackets", "[]", nil, nil, "invalid IPv6"},
		{"mismatched bracket", "[::1", nil, nil, "mismatched brackets"},
		{"lone open bracket", "[", nil, nil, "mismatched brackets"},
		{"bare star", "*", nil, nil, "invalid character"},
		{"host with port", "example.com:443", nil, nil, "invalid character"},
		{"url", "https://x", nil, nil, "invalid character"},
		{"star prefix without dot", "*example.com", nil, nil, "invalid character"},
		{"mid-label wildcard", "a.*.example.com", nil, nil, "invalid character"},
		{"bracketed ipv6 with port", "[::1]:443", nil, nil, "mismatched brackets"},
		// A wildcard over a bare IPv6 literal can never match: no host ends
		// with ".fd00::1". The bare literal itself stays accepted (above).
		{"wildcard over bare ipv6 loopback", "*.::1", nil, nil, "wildcard is not allowed on an IP literal"},
		{"wildcard over bare ipv6", "*.fd00::1", nil, nil, "wildcard is not allowed on an IP literal"},
		// rejected ports / schemes
		{"port zero", "example.com", []int{0}, nil, "port 0 is out of range (1-65535)"},
		{"port above max", "example.com", []int{99999}, nil, "port 99999 is out of range (1-65535)"},
		{"ftp scheme", "example.com", nil, []string{"ftp"}, `scheme "ftp" is not allowed (use http or https)`},
		{"empty scheme", "example.com", nil, []string{""}, "omit schemes to match both"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTargetRule(tc.hostname, tc.ports, tc.schemes)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateTargetRule(%q, %v, %q) = %v, want nil", tc.hostname, tc.ports, tc.schemes, err)
				}
				return
			}
			assertErrContains(t, err, tc.wantErr)
		})
	}
}

// TestTargetScopePolicyConfig_Validate_Nil proves the reload-callable entry
// point is nil-safe (no policy configured = nothing to validate).
func TestTargetScopePolicyConfig_Validate_Nil(t *testing.T) {
	var p *TargetScopePolicyConfig
	if err := p.Validate(); err != nil {
		t.Fatalf("nil policy Validate() = %v, want nil", err)
	}
	if err := (&TargetScopePolicyConfig{}).Validate(); err != nil {
		t.Fatalf("empty policy Validate() = %v, want nil", err)
	}
}
