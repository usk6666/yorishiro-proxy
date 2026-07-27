package mcpserver

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
)

// testLogger returns a quiet logger for test use.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool { return &b }

// --- InitSafetyFilter tests ---

func TestInitSafetyFilter_DisabledByDefault(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	engine, err := InitSafetyFilter(cfg, &config.ProxyConfig{}, logger)
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

	engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

	// Zero proxy config, but CLI override enables the filter.
	engine, err := InitSafetyFilter(cfg, &config.ProxyConfig{}, logger)
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

	engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

	engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

	engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

	engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

			engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

func TestInitSafetyFilter_ZeroProxyConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	engine, err := InitSafetyFilter(cfg, &config.ProxyConfig{}, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine != nil {
		t.Fatal("expected nil engine with zero proxyCfg and no CLI override")
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

	engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

	engine, err := InitSafetyFilter(cfg, proxyCfg, logger)
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

// --- InitHostTLSRegistry tests ---

func TestInitHostTLSRegistry_EmptyConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	reg, err := InitHostTLSRegistry(cfg, &config.ProxyConfig{}, logger)
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

	reg, err := InitHostTLSRegistry(cfg, &config.ProxyConfig{}, logger)
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

	reg, err := InitHostTLSRegistry(cfg, proxyCfg, logger)
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

// --- InitTLSTransport tests (USK-719) ---

// TestInitTLSTransport_Default verifies that the no-fingerprint case now
// resolves to the firefox default (USK-1013), yielding a UTLSTransport with
// ProfileFirefox rather than a StandardTransport.
func TestInitTLSTransport_Default(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()

	got := InitTLSTransport(cfg, &config.ProxyConfig{}, nil, logger)
	utls, ok := got.(*transport.UTLSTransport)
	if !ok {
		t.Fatalf("got %T, want *UTLSTransport (firefox default)", got)
	}
	if utls.Profile != transport.ProfileFirefox {
		t.Errorf("Profile = %v, want ProfileFirefox (default)", utls.Profile)
	}
}

// TestInitTLSTransport_NoneOptsOut verifies the "none" escape hatch: an
// explicit "none" resolves to "" (config.ResolveTLSFingerprint) so the resend
// axis falls back to StandardTransport instead of the firefox default
// (USK-1013 U1).
func TestInitTLSTransport_NoneOptsOut(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{TLSFingerprint: "none"}

	got := InitTLSTransport(cfg, proxyCfg, nil, logger)
	if _, ok := got.(*transport.StandardTransport); !ok {
		t.Errorf("got %T, want *StandardTransport for none opt-out", got)
	}
}

// TestInitTLSTransport_FromProxyConfig verifies the CLI flag / proxy-config
// path: ProxyConfig.TLSFingerprint must build a UTLSTransport. Pre-USK-719
// this was silently ignored because InitTLSTransport only read
// Config.TLSFingerprint.
func TestInitTLSTransport_FromProxyConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{TLSFingerprint: "chrome"}

	got := InitTLSTransport(cfg, proxyCfg, nil, logger)
	utls, ok := got.(*transport.UTLSTransport)
	if !ok {
		t.Fatalf("got %T, want *UTLSTransport", got)
	}
	if utls.Profile != transport.ProfileChrome {
		t.Errorf("Profile = %v, want ProfileChrome", utls.Profile)
	}
}

// TestInitTLSTransport_FromTopLevelConfig keeps the legacy
// Config.TLSFingerprint surface working when proxyCfg has no fingerprint set.
func TestInitTLSTransport_FromTopLevelConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.TLSFingerprint = "firefox"

	got := InitTLSTransport(cfg, &config.ProxyConfig{}, nil, logger)
	utls, ok := got.(*transport.UTLSTransport)
	if !ok {
		t.Fatalf("got %T, want *UTLSTransport", got)
	}
	if utls.Profile != transport.ProfileFirefox {
		t.Errorf("Profile = %v, want ProfileFirefox", utls.Profile)
	}
}

// TestInitTLSTransport_ProxyConfigBeatsTopLevel asserts the documented
// resolution order: ProxyConfig.TLSFingerprint takes precedence over
// Config.TLSFingerprint when both are set, because the former is what the
// CLI flag / proxy.json populates and is the surface most users reach for.
func TestInitTLSTransport_ProxyConfigBeatsTopLevel(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.TLSFingerprint = "firefox"
	proxyCfg := &config.ProxyConfig{TLSFingerprint: "safari"}

	got := InitTLSTransport(cfg, proxyCfg, nil, logger)
	utls, ok := got.(*transport.UTLSTransport)
	if !ok {
		t.Fatalf("got %T, want *UTLSTransport", got)
	}
	if utls.Profile != transport.ProfileSafari {
		t.Errorf("Profile = %v, want ProfileSafari (proxyCfg should win)", utls.Profile)
	}
}

// TestInitTLSTransport_InvalidProfileFallback ensures an unrecognised
// fingerprint name does not crash the boot — a Warn is logged and we fall
// back to StandardTransport so the server still starts.
func TestInitTLSTransport_InvalidProfileFallback(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	proxyCfg := &config.ProxyConfig{TLSFingerprint: "not-a-browser"}

	got := InitTLSTransport(cfg, proxyCfg, nil, logger)
	if _, ok := got.(*transport.StandardTransport); !ok {
		t.Errorf("got %T, want *StandardTransport on invalid profile", got)
	}
}

// TestNewLiveBuildConfig_TLSFingerprintDefault verifies the live-dial boot
// path (USK-1013): an unset fingerprint is pinned to the firefox default,
// "none" opts out to standard TLS, and an explicit profile passes through.
// The live path is proxyCfg-only, so a top-level cfg.TLSFingerprint must NOT
// leak in when proxyCfg is empty.
//
// USK-1021 contract change: an explicit "none" is now STORED verbatim (it was
// flattened to "" before) so the reporting surfaces can distinguish "operator
// opted out" from "nothing configured", matching what a runtime
// proxy_start / configure "none" override installs. The opt-out is applied at
// the dial seam instead — bc.EffectiveUTLSProfile() is "" and therefore
// selects clientStandard.
func TestNewLiveBuildConfig_TLSFingerprintDefault(t *testing.T) {
	tests := []struct {
		name       string
		proxyFP    string
		topLevelFP string
		wantStored string // bc.TLSFingerprint
		wantEffect string // bc.EffectiveTLSFingerprint() — claimed identity
		wantUTLS   string // bc.EffectiveUTLSProfile() — dial value
	}{
		{"unset defaults to firefox", "", "", "firefox", "firefox", "firefox"},
		{"none opts out to standard TLS at the dial seam", "none", "", "none", "none", ""},
		{"explicit chrome passes through", "chrome", "", "chrome", "chrome", "chrome"},
		{"live path ignores top-level cfg", "", "safari", "firefox", "firefox", "firefox"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.TLSFingerprint = tt.topLevelFP
			proxyCfg := &config.ProxyConfig{TLSFingerprint: tt.proxyFP}

			bc := NewLiveBuildConfig(cfg, proxyCfg, nil, nil, nil)
			if bc.TLSFingerprint != tt.wantStored {
				t.Errorf("bc.TLSFingerprint = %q, want %q", bc.TLSFingerprint, tt.wantStored)
			}
			if got := bc.EffectiveTLSFingerprint(); got != tt.wantEffect {
				t.Errorf("bc.EffectiveTLSFingerprint() = %q, want %q (claimed identity)", got, tt.wantEffect)
			}
			if got := bc.EffectiveUTLSProfile(); got != tt.wantUTLS {
				t.Errorf("bc.EffectiveUTLSProfile() = %q, want %q (selects clientStandard when empty)", got, tt.wantUTLS)
			}
		})
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

	reg, err := InitHostTLSRegistry(cfg, &config.ProxyConfig{}, logger)
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

	reg, err := InitHostTLSRegistry(cfg, proxyCfg, logger)
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

	reg, err := InitHostTLSRegistry(cfg, proxyCfg, logger)
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
	result, err := LoadConfigs("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// LoadConfigs guarantees a non-nil zero-valued ProxyConfig when no
	// -config file is provided so downstream consumers (proxybuild.BuildLiveStack)
	// can rely on the non-nil contract.
	if result.ProxyCfg == nil {
		t.Fatal("expected non-nil proxyCfg (zero-valued) when no config file specified")
	}
	if result.TargetScopePolicy != nil {
		t.Error("expected nil targetScopePolicy when no files specified")
	}
	if result.TargetScopePolicySource != "" {
		t.Errorf("expected empty source, got %q", result.TargetScopePolicySource)
	}
}

func TestLoadConfigs_ConfigFileOnly(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{"listen_addr": "127.0.0.1:9090"}`)

	result, err := LoadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ProxyCfg == nil {
		t.Fatal("expected non-nil proxyCfg")
	}
	if result.ProxyCfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want %q", result.ProxyCfg.ListenAddr, "127.0.0.1:9090")
	}
}

func TestLoadConfigs_PolicyFileOnly(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{"allows": [{"hostname": "*.target.com"}]}`)

	result, err := LoadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// LoadConfigs guarantees a non-nil zero-valued ProxyConfig when no
	// -config file is provided.
	if result.ProxyCfg == nil {
		t.Fatal("expected non-nil proxyCfg (zero-valued) when no config file specified")
	}
	if result.TargetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	if len(result.TargetScopePolicy.Allows) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(result.TargetScopePolicy.Allows))
	}
	if result.TargetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.TargetScopePolicySource, "policy file")
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

	result, err := LoadConfigs(cfgPath, policyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TargetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	// Policy file should take precedence over config file's target_scope_policy.
	if len(result.TargetScopePolicy.Allows) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(result.TargetScopePolicy.Allows))
	}
	if result.TargetScopePolicy.Allows[0].Hostname != "from-policy-file.com" {
		t.Errorf("hostname = %q, want %q (policy file should take precedence)",
			result.TargetScopePolicy.Allows[0].Hostname, "from-policy-file.com")
	}
	if result.TargetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.TargetScopePolicySource, "policy file")
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

	result, err := LoadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TargetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy from config file")
	}
	if len(result.TargetScopePolicy.Allows) != 1 {
		t.Fatalf("expected 1 allow rule, got %d", len(result.TargetScopePolicy.Allows))
	}
	if len(result.TargetScopePolicy.Denies) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(result.TargetScopePolicy.Denies))
	}
	if result.TargetScopePolicySource != "config file" {
		t.Errorf("source = %q, want %q", result.TargetScopePolicySource, "config file")
	}
}

func TestLoadConfigs_InvalidConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.json")
	writeTestFile(t, cfgPath, `{invalid json}`)

	_, err := LoadConfigs(cfgPath, "")
	if err == nil {
		t.Fatal("expected error for invalid config file")
	}
}

// TestLoadConfigs_InvalidTLSFingerprint pins the USK-1032 boot gate: a
// config-file typo must fail at load time. Before this, the value reached
// runtime unrejected — InitTLSTransport degraded to a Go-native ClientHello
// on the resend / fuzz dial path while `query config` kept reporting the typo.
func TestLoadConfigs_InvalidTLSFingerprint(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{"tls_fingerprint": "firefx"}`)

	_, err := LoadConfigs(cfgPath, "")
	if err == nil {
		t.Fatal("expected error for typo'd tls_fingerprint, got nil")
	}
	if !strings.Contains(err.Error(), "tls_fingerprint") {
		t.Errorf("error = %q, want it to name the tls_fingerprint field", err)
	}
}

// TestLoadConfigs_TLSFingerprintSpellingsAccepted proves the boot gate accepts
// every spelling the consumption seams already normalize (case-insensitive,
// whitespace-trimmed) and stores the operator's bytes verbatim — validation
// rejects, it never rewrites (USK-1021).
func TestLoadConfigs_TLSFingerprintSpellingsAccepted(t *testing.T) {
	for _, fingerprint := range []string{"firefox", "Firefox", "  NONE  ", "none", "random"} {
		t.Run(fingerprint, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.json")
			writeTestFile(t, cfgPath, `{"tls_fingerprint": "`+fingerprint+`"}`)

			result, err := LoadConfigs(cfgPath, "")
			if err != nil {
				t.Fatalf("LoadConfigs(%q): %v", fingerprint, err)
			}
			if result.ProxyCfg.TLSFingerprint != fingerprint {
				t.Errorf("TLSFingerprint = %q, want the verbatim file value %q",
					result.ProxyCfg.TLSFingerprint, fingerprint)
			}
		})
	}
}

func TestLoadConfigs_NonexistentConfigFile(t *testing.T) {
	_, err := LoadConfigs("/nonexistent/config.json", "")
	if err == nil {
		t.Fatal("expected error for nonexistent config file")
	}
}

func TestLoadConfigs_InvalidPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bad-policy.json")
	writeTestFile(t, policyPath, `not json`)

	_, err := LoadConfigs("", policyPath)
	if err == nil {
		t.Fatal("expected error for invalid policy file")
	}
}

func TestLoadConfigs_NonexistentPolicyFile(t *testing.T) {
	_, err := LoadConfigs("", "/nonexistent/policy.json")
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
