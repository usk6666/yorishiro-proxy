package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// testLogger returns a quiet logger for test use.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool { return &b }

// --- initSafetyFilter tests ---

func TestInitSafetyFilter_DisabledByDefault(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	engine, err := initSafetyFilter(cfg, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine != nil {
		t.Fatal("expected nil engine when safety filter is disabled")
	}
}

func TestInitSafetyFilter_EnabledViaConfigFile(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
			Input: &config.SafetyFilterInputConfig{
				Rules: []config.SafetyFilterRuleConfig{
					{Preset: "destructive-sql"},
				},
			},
		},
	}

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine when safety filter is enabled")
	}
	if len(engine.InputRules()) == 0 {
		t.Error("expected input rules from destructive-sql preset")
	}
}

func TestInitSafetyFilter_EnabledViaCLIOverride(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.SafetyFilterEnabled = boolPtr(true)

	// No proxy config, but CLI override enables the filter.
	engine, err := initSafetyFilter(cfg, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine when CLI override enables safety filter")
	}
}

func TestInitSafetyFilter_CLIDisableOverridesConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.SafetyFilterEnabled = boolPtr(false)

	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
			Input: &config.SafetyFilterInputConfig{
				Rules: []config.SafetyFilterRuleConfig{
					{Preset: "destructive-sql"},
				},
			},
		},
	}

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine != nil {
		t.Fatal("expected nil engine when CLI override disables safety filter")
	}
}

func TestInitSafetyFilter_InputAndOutputRules(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
			Input: &config.SafetyFilterInputConfig{
				Rules: []config.SafetyFilterRuleConfig{
					{Preset: "destructive-sql"},
				},
			},
			Output: &config.SafetyFilterOutputConfig{
				Rules: []config.SafetyFilterRuleConfig{
					{Preset: "credit-card"},
				},
			},
		},
	}

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.InputRules()) == 0 {
		t.Error("expected input rules from destructive-sql preset")
	}
	if len(engine.OutputRules()) == 0 {
		t.Error("expected output rules from credit-card preset, got none (USK-320 regression)")
	}
}

func TestInitSafetyFilter_CustomInputRule(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
			Input: &config.SafetyFilterInputConfig{
				Action: "log_only",
				Rules: []config.SafetyFilterRuleConfig{
					{
						ID:      "custom-xss",
						Name:    "XSS detector",
						Pattern: `<script>`,
						Targets: []string{"body"},
					},
				},
			},
		},
	}

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.InputRules()) != 1 {
		t.Fatalf("expected 1 input rule, got %d", len(engine.InputRules()))
	}
	rule := engine.InputRules()[0]
	if rule.ID != "custom-xss" {
		t.Errorf("rule.ID = %q, want %q", rule.ID, "custom-xss")
	}
}

func TestInitSafetyFilter_CustomOutputRule(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
			Output: &config.SafetyFilterOutputConfig{
				Action: "mask",
				Rules: []config.SafetyFilterRuleConfig{
					{
						ID:          "custom-ssn",
						Name:        "SSN masker",
						Pattern:     `\d{3}-\d{2}-\d{4}`,
						Targets:     []string{"body"},
						Replacement: "[SSN]",
					},
				},
			},
		},
	}

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.OutputRules()) != 1 {
		t.Fatalf("expected 1 output rule, got %d", len(engine.OutputRules()))
	}
	rule := engine.OutputRules()[0]
	if rule.ID != "custom-ssn" {
		t.Errorf("rule.ID = %q, want %q", rule.ID, "custom-ssn")
	}
}

func TestInitSafetyFilter_SectionLevelAction(t *testing.T) {
	tests := []struct {
		name          string
		inputAction   string
		outputAction  string
		wantInputAct  string
		wantOutputAct string
	}{
		{
			name:          "default actions when not specified",
			wantInputAct:  "block",
			wantOutputAct: "mask",
		},
		{
			name:          "explicit log_only actions",
			inputAction:   "log_only",
			outputAction:  "log_only",
			wantInputAct:  "log_only",
			wantOutputAct: "log_only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := testLogger(t)
			cfg := config.Default()
			proxyCfg := &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Action: tt.inputAction,
						Rules: []config.SafetyFilterRuleConfig{
							{
								ID:      "test-input",
								Pattern: `testpattern`,
								Targets: []string{"body"},
							},
						},
					},
					Output: &config.SafetyFilterOutputConfig{
						Action: tt.outputAction,
						Rules: []config.SafetyFilterRuleConfig{
							{
								ID:      "test-output",
								Pattern: `testpattern`,
								Targets: []string{"body"},
							},
						},
					},
				},
			}

			engine, err := initSafetyFilter(cfg, proxyCfg, logger)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if engine == nil {
				t.Fatal("expected non-nil engine")
			}

			if len(engine.InputRules()) != 1 {
				t.Fatalf("expected 1 input rule, got %d", len(engine.InputRules()))
			}
			if got := engine.InputRules()[0].Action.String(); got != tt.wantInputAct {
				t.Errorf("input action = %q, want %q", got, tt.wantInputAct)
			}

			if len(engine.OutputRules()) != 1 {
				t.Fatalf("expected 1 output rule, got %d", len(engine.OutputRules()))
			}
			if got := engine.OutputRules()[0].Action.String(); got != tt.wantOutputAct {
				t.Errorf("output action = %q, want %q", got, tt.wantOutputAct)
			}
		})
	}
}

func TestInitSafetyFilter_NilProxyConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	engine, err := initSafetyFilter(cfg, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine != nil {
		t.Fatal("expected nil engine with nil proxyCfg and no CLI override")
	}
}

func TestInitSafetyFilter_EnabledButNoRules(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
		},
	}

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine even with no rules")
	}
	if len(engine.InputRules()) != 0 {
		t.Errorf("expected 0 input rules, got %d", len(engine.InputRules()))
	}
	if len(engine.OutputRules()) != 0 {
		t.Errorf("expected 0 output rules, got %d", len(engine.OutputRules()))
	}
}

func TestInitSafetyFilter_OutputReplacementOverride(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
			Output: &config.SafetyFilterOutputConfig{
				Rules: []config.SafetyFilterRuleConfig{
					{
						Preset:      "credit-card",
						Replacement: "[REDACTED-CC]",
					},
				},
			},
		},
	}

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.OutputRules()) == 0 {
		t.Fatal("expected output rules from credit-card preset")
	}
	// All rules in the preset should have the overridden replacement.
	for _, r := range engine.OutputRules() {
		if r.Replacement != "[REDACTED-CC]" {
			t.Errorf("rule %q replacement = %q, want %q", r.ID, r.Replacement, "[REDACTED-CC]")
		}
	}
}

// --- initHostTLSRegistry tests ---

func TestInitHostTLSRegistry_EmptyConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	reg, err := initHostTLSRegistry(cfg, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg == nil {
		t.Fatal("expected non-nil registry")
	}
	if reg.Global() != nil {
		t.Error("expected nil global config for empty config")
	}
	hosts := reg.Hosts()
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(hosts))
	}
}

func TestInitHostTLSRegistry_PerHostFromCLIConfig(t *testing.T) {
	logger := testLogger(t)

	verify := true
	cfg := &config.Config{
		HostTLS: map[string]*config.HostTLSEntry{
			"api.example.com": {
				TLSVerify: &verify,
			},
		},
	}

	reg, err := initHostTLSRegistry(cfg, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hosts := reg.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	hostCfg := reg.Lookup("api.example.com")
	if hostCfg == nil {
		t.Fatal("expected host config for api.example.com")
	}
	if hostCfg.TLSVerify == nil || !*hostCfg.TLSVerify {
		t.Error("expected TLSVerify=true for api.example.com")
	}
}

func TestInitHostTLSRegistry_PerHostFromProxyConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	verify := false
	proxyCfg := &config.ProxyConfig{
		HostTLS: map[string]*config.HostTLSEntry{
			"*.staging.com": {
				TLSVerify: &verify,
			},
		},
	}

	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hostCfg := reg.Lookup("api.staging.com")
	if hostCfg == nil {
		t.Fatal("expected host config for api.staging.com via wildcard")
	}
	if hostCfg.TLSVerify == nil || *hostCfg.TLSVerify {
		t.Error("expected TLSVerify=false for *.staging.com")
	}
}

func TestInitHostTLSRegistry_GlobalFromCLIConfig(t *testing.T) {
	logger := testLogger(t)

	// Placeholder content; Validate() only checks file existence, not PEM validity.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "global.crt")
	keyPath := filepath.Join(dir, "global.key")
	writeTestFile(t, certPath, "test-cert")
	writeTestFile(t, keyPath, "test-key")

	cfg := &config.Config{
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	}

	reg, err := initHostTLSRegistry(cfg, nil, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.Global() == nil {
		t.Fatal("expected non-nil global config")
	}
	if reg.Global().ClientCertPath != certPath {
		t.Errorf("global ClientCertPath = %q, want %q", reg.Global().ClientCertPath, certPath)
	}
}

func TestInitHostTLSRegistry_GlobalCLIPrecedence(t *testing.T) {
	logger := testLogger(t)

	dir := t.TempDir()
	cliCert := filepath.Join(dir, "cli.crt")
	cliKey := filepath.Join(dir, "cli.key")
	proxyCert := filepath.Join(dir, "proxy.crt")
	proxyKey := filepath.Join(dir, "proxy.key")
	writeTestFile(t, cliCert, "cli-cert")
	writeTestFile(t, cliKey, "cli-key")
	writeTestFile(t, proxyCert, "proxy-cert")
	writeTestFile(t, proxyKey, "proxy-key")

	cfg := &config.Config{
		ClientCertPath: cliCert,
		ClientKeyPath:  cliKey,
	}
	proxyCfg := &config.ProxyConfig{
		ClientCertPath: proxyCert,
		ClientKeyPath:  proxyKey,
	}

	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.Global() == nil {
		t.Fatal("expected non-nil global config")
	}
	// CLI config should take precedence over proxy config.
	if reg.Global().ClientCertPath != cliCert {
		t.Errorf("global ClientCertPath = %q, want CLI cert %q", reg.Global().ClientCertPath, cliCert)
	}
}

func TestInitHostTLSRegistry_GlobalFromProxyConfigFallback(t *testing.T) {
	logger := testLogger(t)

	dir := t.TempDir()
	proxyCert := filepath.Join(dir, "proxy.crt")
	proxyKey := filepath.Join(dir, "proxy.key")
	writeTestFile(t, proxyCert, "proxy-cert")
	writeTestFile(t, proxyKey, "proxy-key")

	cfg := config.Default() // no CLI global cert
	proxyCfg := &config.ProxyConfig{
		ClientCertPath: proxyCert,
		ClientKeyPath:  proxyKey,
	}

	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.Global() == nil {
		t.Fatal("expected non-nil global config from proxy config fallback")
	}
	if reg.Global().ClientCertPath != proxyCert {
		t.Errorf("global ClientCertPath = %q, want proxy cert %q", reg.Global().ClientCertPath, proxyCert)
	}
}

func TestLoadConfigs_NoFiles(t *testing.T) {
	result, err := loadConfigs("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.proxyCfg != nil {
		t.Error("expected nil proxyCfg when no config file specified")
	}
	if result.targetScopePolicy != nil {
		t.Error("expected nil targetScopePolicy when no files specified")
	}
	if result.targetScopePolicySource != "" {
		t.Errorf("expected empty source, got %q", result.targetScopePolicySource)
	}
}

func TestLoadConfigs_ConfigFileOnly(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{"listen_addr": "127.0.0.1:9090"}`)

	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.proxyCfg == nil {
		t.Fatal("expected non-nil proxyCfg")
	}
	if result.proxyCfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want %q", result.proxyCfg.ListenAddr, "127.0.0.1:9090")
	}
}

func TestLoadConfigs_PolicyFileOnly(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{"allows": [{"hostname": "*.target.com"}]}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.proxyCfg != nil {
		t.Error("expected nil proxyCfg when no config file specified")
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	if len(result.targetScopePolicy.Allows) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(result.targetScopePolicy.Allows))
	}
	if result.targetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "policy file")
	}
}

func TestLoadConfigs_PolicyFilePrecedence(t *testing.T) {
	dir := t.TempDir()

	// Config file with embedded target scope policy.
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [{"hostname": "from-config.com"}]
		}
	}`)

	// Dedicated policy file.
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{"allows": [{"hostname": "from-policy-file.com"}]}`)

	result, err := loadConfigs(cfgPath, policyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	// Policy file should take precedence over config file's target_scope_policy.
	if len(result.targetScopePolicy.Allows) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(result.targetScopePolicy.Allows))
	}
	if result.targetScopePolicy.Allows[0].Hostname != "from-policy-file.com" {
		t.Errorf("hostname = %q, want %q (policy file should take precedence)",
			result.targetScopePolicy.Allows[0].Hostname, "from-policy-file.com")
	}
	if result.targetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "policy file")
	}
}

func TestLoadConfigs_PolicyFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [{"hostname": "from-config.com"}],
			"denies": [{"hostname": "*.internal.corp"}]
		}
	}`)

	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy from config file")
	}
	if len(result.targetScopePolicy.Allows) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(result.targetScopePolicy.Allows))
	}
	if len(result.targetScopePolicy.Denies) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(result.targetScopePolicy.Denies))
	}
	if result.targetScopePolicySource != "config file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "config file")
	}
}

func TestLoadConfigs_InvalidConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	writeTestFile(t, cfgPath, `{invalid json}`)

	_, err := loadConfigs(cfgPath, "")
	if err == nil {
		t.Fatal("expected error for invalid config file")
	}
}

func TestLoadConfigs_NonexistentConfigFile(t *testing.T) {
	_, err := loadConfigs("/nonexistent/config.json", "")
	if err == nil {
		t.Fatal("expected error for nonexistent config file")
	}
}

func TestLoadConfigs_InvalidPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bad-policy.json")
	writeTestFile(t, policyPath, `not json`)

	_, err := loadConfigs("", policyPath)
	if err == nil {
		t.Fatal("expected error for invalid policy file")
	}
}

func TestLoadConfigs_NonexistentPolicyFile(t *testing.T) {
	_, err := loadConfigs("", "/nonexistent/policy.json")
	if err == nil {
		t.Fatal("expected error for nonexistent policy file")
	}
}

// --- helper ---

// writeTestFile writes content to a file, failing the test on error.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test file %s: %v", path, err)
	}
}
