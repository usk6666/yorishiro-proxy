//go:build e2e

package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// e2eLogger returns a quiet logger for e2e test use.
func e2eLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// writeE2EFile writes content to a file within the test temp dir.
func writeE2EFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test file %s: %v", path, err)
	}
}

// --- SafetyFilter Input: config file -> runtime ---

func TestConfigE2E_SafetyFilter_InputPreset(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"rules": [
					{"preset": "destructive-sql"},
					{"preset": "destructive-os-command"}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.InputRules()) == 0 {
		t.Error("expected input rules from presets")
	}
	if len(engine.OutputRules()) != 0 {
		t.Errorf("expected 0 output rules, got %d", len(engine.OutputRules()))
	}

	// Verify rules have default block action.
	for _, r := range engine.InputRules() {
		if got := r.Action.String(); got != "block" {
			t.Errorf("input rule %q action = %q, want %q", r.ID, got, "block")
		}
	}
}

func TestConfigE2E_SafetyFilter_InputCustomRule(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"action": "log_only",
				"rules": [
					{
						"id": "custom-xss-e2e",
						"name": "XSS detector",
						"pattern": "<script[^>]*>",
						"targets": ["body", "url"]
					}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.InputRules()) != 1 {
		t.Fatalf("expected 1 input rule, got %d", len(engine.InputRules()))
	}
	rule := engine.InputRules()[0]
	if rule.ID != "custom-xss-e2e" {
		t.Errorf("rule.ID = %q, want %q", rule.ID, "custom-xss-e2e")
	}
	if got := rule.Action.String(); got != "log_only" {
		t.Errorf("rule action = %q, want %q", got, "log_only")
	}
}

// --- SafetyFilter Output: config file -> runtime ---

func TestConfigE2E_SafetyFilter_OutputPreset(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"output": {
				"rules": [
					{"preset": "credit-card"},
					{"preset": "email"}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.OutputRules()) == 0 {
		t.Error("expected output rules from presets (USK-320 regression guard)")
	}
	if len(engine.InputRules()) != 0 {
		t.Errorf("expected 0 input rules, got %d", len(engine.InputRules()))
	}

	// Verify rules have default mask action.
	for _, r := range engine.OutputRules() {
		if got := r.Action.String(); got != "mask" {
			t.Errorf("output rule %q action = %q, want %q", r.ID, got, "mask")
		}
	}
}

func TestConfigE2E_SafetyFilter_OutputCustomRule(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"output": {
				"action": "log_only",
				"rules": [
					{
						"id": "custom-ssn-e2e",
						"name": "SSN masker",
						"pattern": "\\d{3}-\\d{2}-\\d{4}",
						"targets": ["body"],
						"replacement": "[SSN-MASKED]"
					}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.OutputRules()) != 1 {
		t.Fatalf("expected 1 output rule, got %d", len(engine.OutputRules()))
	}
	rule := engine.OutputRules()[0]
	if rule.ID != "custom-ssn-e2e" {
		t.Errorf("rule.ID = %q, want %q", rule.ID, "custom-ssn-e2e")
	}
	if got := rule.Action.String(); got != "log_only" {
		t.Errorf("rule action = %q, want %q", got, "log_only")
	}
	if rule.Replacement != "[SSN-MASKED]" {
		t.Errorf("rule.Replacement = %q, want %q", rule.Replacement, "[SSN-MASKED]")
	}
}

// --- SafetyFilter: combined input + output config file ---

func TestConfigE2E_SafetyFilter_InputAndOutput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"rules": [
					{"preset": "destructive-sql"}
				]
			},
			"output": {
				"rules": [
					{"preset": "credit-card"},
					{"preset": "japan-my-number"}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.InputRules()) == 0 {
		t.Error("expected input rules from destructive-sql preset")
	}
	if len(engine.OutputRules()) == 0 {
		t.Error("expected output rules from credit-card and japan-my-number presets")
	}
}

// --- SafetyFilter: CLI override takes precedence ---

func TestConfigE2E_SafetyFilter_CLIOverrideDisables(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"rules": [{"preset": "destructive-sql"}]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	disabled := false
	cfg.SafetyFilterEnabled = &disabled
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine != nil {
		t.Fatal("expected nil engine when CLI disables safety filter")
	}
}

func TestConfigE2E_SafetyFilter_CLIOverrideEnables(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	// Config file has safety_filter disabled or absent.
	writeE2EFile(t, cfgPath, `{}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	enabled := true
	cfg.SafetyFilterEnabled = &enabled
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine when CLI enables safety filter")
	}
}

// --- SafetyFilter: output preset replacement override ---

func TestConfigE2E_SafetyFilter_OutputReplacementOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"output": {
				"rules": [
					{"preset": "credit-card", "replacement": "[REDACTED]"}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	for _, r := range engine.OutputRules() {
		if r.Replacement != "[REDACTED]" {
			t.Errorf("rule %q replacement = %q, want %q", r.ID, r.Replacement, "[REDACTED]")
		}
	}
}

// --- Target Scope Policy: config file -> runtime ---

func TestConfigE2E_TargetScopePolicy_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [
				{"hostname": "*.target.com", "ports": [80, 443]},
				{"hostname": "api.example.com", "schemes": ["https"]}
			],
			"denies": [
				{"hostname": "*.internal.corp"}
			]
		}
	}`)

	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	if result.targetScopePolicySource != "config file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "config file")
	}

	// Build TargetScope from policy and verify enforcement.
	scope := proxy.NewTargetScope()
	allows := convertTargetRules(result.targetScopePolicy.Allows)
	denies := convertTargetRules(result.targetScopePolicy.Denies)
	scope.SetPolicyRules(allows, denies)

	tests := []struct {
		name    string
		scheme  string
		host    string
		port    int
		path    string
		allowed bool
	}{
		{"allowed wildcard", "https", "app.target.com", 443, "/", true},
		{"allowed wildcard http port 80", "http", "app.target.com", 80, "/", true},
		{"denied internal", "https", "secret.internal.corp", 443, "/", false},
		{"allowed api.example.com https", "https", "api.example.com", 443, "/", true},
		{"blocked api.example.com http", "http", "api.example.com", 80, "/", false},
		{"blocked not in allow list", "https", "unknown.com", 443, "/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := scope.CheckTarget(tt.scheme, tt.host, tt.port, tt.path)
			if allowed != tt.allowed {
				t.Errorf("CheckTarget(%q, %q, %d, %q) = %v (%s), want %v",
					tt.scheme, tt.host, tt.port, tt.path, allowed, reason, tt.allowed)
			}
		})
	}
}

func TestConfigE2E_TargetScopePolicy_FromPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeE2EFile(t, policyPath, `{
		"allows": [
			{"hostname": "*.safe.com"}
		],
		"denies": [
			{"hostname": "evil.safe.com"}
		]
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	if result.targetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "policy file")
	}

	scope := proxy.NewTargetScope()
	allows := convertTargetRules(result.targetScopePolicy.Allows)
	denies := convertTargetRules(result.targetScopePolicy.Denies)
	scope.SetPolicyRules(allows, denies)

	// Allowed target.
	allowed, _ := scope.CheckTarget("https", "app.safe.com", 443, "/")
	if !allowed {
		t.Error("expected app.safe.com to be allowed")
	}

	// Denied target.
	allowed, _ = scope.CheckTarget("https", "evil.safe.com", 443, "/")
	if allowed {
		t.Error("expected evil.safe.com to be denied")
	}

	// Not in allow list.
	allowed, _ = scope.CheckTarget("https", "other.com", 443, "/")
	if allowed {
		t.Error("expected other.com to be blocked (not in allow list)")
	}
}

func TestConfigE2E_TargetScopePolicy_PolicyFilePrecedence(t *testing.T) {
	dir := t.TempDir()

	// Config file has one policy.
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [{"hostname": "from-config.com"}]
		}
	}`)

	// Policy file has a different policy.
	policyPath := filepath.Join(dir, "policy.json")
	writeE2EFile(t, policyPath, `{
		"allows": [{"hostname": "from-policy.com"}]
	}`)

	result, err := loadConfigs(cfgPath, policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	scope := proxy.NewTargetScope()
	allows := convertTargetRules(result.targetScopePolicy.Allows)
	scope.SetPolicyRules(allows, nil)

	// Policy file hostname should be allowed.
	allowed, _ := scope.CheckTarget("https", "from-policy.com", 443, "/")
	if !allowed {
		t.Error("expected from-policy.com to be allowed (policy file takes precedence)")
	}

	// Config file hostname should NOT be allowed.
	allowed, _ = scope.CheckTarget("https", "from-config.com", 443, "/")
	if allowed {
		t.Error("expected from-config.com to be blocked (policy file takes precedence)")
	}
}

func TestConfigE2E_TargetScopePolicy_WithPathAndSchemes(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [
				{
					"hostname": "api.target.com",
					"ports": [443],
					"path_prefix": "/api/v1/",
					"schemes": ["https"]
				}
			]
		}
	}`)

	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	scope := proxy.NewTargetScope()
	allows := convertTargetRules(result.targetScopePolicy.Allows)
	scope.SetPolicyRules(allows, nil)

	tests := []struct {
		name    string
		scheme  string
		host    string
		port    int
		path    string
		allowed bool
	}{
		{"exact match", "https", "api.target.com", 443, "/api/v1/users", true},
		{"wrong port", "https", "api.target.com", 8443, "/api/v1/users", false},
		{"wrong scheme", "http", "api.target.com", 443, "/api/v1/users", false},
		{"wrong path", "https", "api.target.com", 443, "/admin/", false},
		{"wrong host", "https", "other.target.com", 443, "/api/v1/users", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := scope.CheckTarget(tt.scheme, tt.host, tt.port, tt.path)
			if allowed != tt.allowed {
				t.Errorf("CheckTarget(%q, %q, %d, %q) = %v (%s), want %v",
					tt.scheme, tt.host, tt.port, tt.path, allowed, reason, tt.allowed)
			}
		})
	}
}

// --- mTLS: config file -> runtime ---

func TestConfigE2E_mTLS_GlobalFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	writeE2EFile(t, certPath, "test-cert-content")
	writeE2EFile(t, keyPath, "test-key-content")

	cfgPath := filepath.Join(dir, "config.json")
	cfgData := map[string]interface{}{
		"client_cert": certPath,
		"client_key":  keyPath,
	}
	raw, err := json.Marshal(cfgData)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	writeE2EFile(t, cfgPath, string(raw))

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initHostTLSRegistry: %v", err)
	}
	if reg.Global() == nil {
		t.Fatal("expected non-nil global TLS config")
	}
	if reg.Global().ClientCertPath != certPath {
		t.Errorf("global ClientCertPath = %q, want %q", reg.Global().ClientCertPath, certPath)
	}
	if reg.Global().ClientKeyPath != keyPath {
		t.Errorf("global ClientKeyPath = %q, want %q", reg.Global().ClientKeyPath, keyPath)
	}
}

func TestConfigE2E_mTLS_PerHostFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	hostCert := filepath.Join(dir, "host.crt")
	hostKey := filepath.Join(dir, "host.key")
	writeE2EFile(t, hostCert, "host-cert")
	writeE2EFile(t, hostKey, "host-key")

	cfgPath := filepath.Join(dir, "config.json")
	cfgData := map[string]interface{}{
		"host_tls": map[string]interface{}{
			"api.example.com": map[string]interface{}{
				"client_cert": hostCert,
				"client_key":  hostKey,
				"tls_verify":  false,
			},
			"*.staging.com": map[string]interface{}{
				"tls_verify": true,
			},
		},
	}
	raw, err := json.Marshal(cfgData)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	writeE2EFile(t, cfgPath, string(raw))

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initHostTLSRegistry: %v", err)
	}

	// Check exact host match.
	hostCfg := reg.Lookup("api.example.com")
	if hostCfg == nil {
		t.Fatal("expected host config for api.example.com")
	}
	if hostCfg.ClientCertPath != hostCert {
		t.Errorf("ClientCertPath = %q, want %q", hostCfg.ClientCertPath, hostCert)
	}
	if hostCfg.TLSVerify == nil || *hostCfg.TLSVerify {
		t.Error("expected TLSVerify=false for api.example.com")
	}

	// Check wildcard match.
	wildcardCfg := reg.Lookup("app.staging.com")
	if wildcardCfg == nil {
		t.Fatal("expected host config for app.staging.com via wildcard")
	}
	if wildcardCfg.TLSVerify == nil || !*wildcardCfg.TLSVerify {
		t.Error("expected TLSVerify=true for *.staging.com")
	}
}

func TestConfigE2E_mTLS_CLIPrecedenceOverConfigFile(t *testing.T) {
	dir := t.TempDir()

	// CLI cert paths.
	cliCert := filepath.Join(dir, "cli.crt")
	cliKey := filepath.Join(dir, "cli.key")
	writeE2EFile(t, cliCert, "cli-cert")
	writeE2EFile(t, cliKey, "cli-key")

	// Config file cert paths.
	proxyCert := filepath.Join(dir, "proxy.crt")
	proxyKey := filepath.Join(dir, "proxy.key")
	writeE2EFile(t, proxyCert, "proxy-cert")
	writeE2EFile(t, proxyKey, "proxy-key")

	cfgPath := filepath.Join(dir, "config.json")
	cfgData := map[string]interface{}{
		"client_cert": proxyCert,
		"client_key":  proxyKey,
	}
	raw, err := json.Marshal(cfgData)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	writeE2EFile(t, cfgPath, string(raw))

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	// Simulate CLI setting global client cert.
	cfg := config.Default()
	cfg.ClientCertPath = cliCert
	cfg.ClientKeyPath = cliKey
	logger := e2eLogger(t)

	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initHostTLSRegistry: %v", err)
	}
	if reg.Global() == nil {
		t.Fatal("expected non-nil global TLS config")
	}
	// CLI should take precedence.
	if reg.Global().ClientCertPath != cliCert {
		t.Errorf("global ClientCertPath = %q, want CLI cert %q", reg.Global().ClientCertPath, cliCert)
	}
}

func TestConfigE2E_mTLS_GlobalWithPerHost(t *testing.T) {
	dir := t.TempDir()
	globalCert := filepath.Join(dir, "global.crt")
	globalKey := filepath.Join(dir, "global.key")
	hostCert := filepath.Join(dir, "host.crt")
	hostKey := filepath.Join(dir, "host.key")
	writeE2EFile(t, globalCert, "global-cert")
	writeE2EFile(t, globalKey, "global-key")
	writeE2EFile(t, hostCert, "host-cert")
	writeE2EFile(t, hostKey, "host-key")

	cfgPath := filepath.Join(dir, "config.json")
	cfgData := map[string]interface{}{
		"client_cert": globalCert,
		"client_key":  globalKey,
		"host_tls": map[string]interface{}{
			"special.example.com": map[string]interface{}{
				"client_cert": hostCert,
				"client_key":  hostKey,
			},
		},
	}
	raw, err := json.Marshal(cfgData)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	writeE2EFile(t, cfgPath, string(raw))

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initHostTLSRegistry: %v", err)
	}

	// Global config should be set.
	if reg.Global() == nil {
		t.Fatal("expected non-nil global TLS config")
	}
	if reg.Global().ClientCertPath != globalCert {
		t.Errorf("global ClientCertPath = %q, want %q", reg.Global().ClientCertPath, globalCert)
	}

	// Per-host config should be set.
	hostCfg := reg.Lookup("special.example.com")
	if hostCfg == nil {
		t.Fatal("expected host config for special.example.com")
	}
	if hostCfg.ClientCertPath != hostCert {
		t.Errorf("host ClientCertPath = %q, want %q", hostCfg.ClientCertPath, hostCert)
	}

	// Non-special host should get global (via Lookup fallback, if global is returned).
	hosts := reg.Hosts()
	if len(hosts) != 1 {
		t.Errorf("expected 1 per-host entry, got %d", len(hosts))
	}
}

// --- SOCKS5 Auth: config file -> runtime ---

func TestConfigE2E_SOCKS5Auth_PasswordFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"socks5_auth": "password",
		"socks5_username": "testuser",
		"socks5_password": "testpass"
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if proxyCfg.SOCKS5Auth != "password" {
		t.Errorf("SOCKS5Auth = %q, want %q", proxyCfg.SOCKS5Auth, "password")
	}
	if proxyCfg.SOCKS5Username != "testuser" {
		t.Errorf("SOCKS5Username = %q, want %q", proxyCfg.SOCKS5Username, "testuser")
	}
	if proxyCfg.SOCKS5Password != "testpass" {
		t.Errorf("SOCKS5Password = %q, want %q", proxyCfg.SOCKS5Password, "testpass")
	}

	// Verify the adapter correctly applies auth to the staticSOCKS5Auth.
	adapter := &staticSOCKS5Auth{
		username: proxyCfg.SOCKS5Username,
		password: proxyCfg.SOCKS5Password,
	}
	if !adapter.Authenticate("testuser", "testpass") {
		t.Error("expected Authenticate to return true for correct credentials")
	}
	if adapter.Authenticate("testuser", "wrongpass") {
		t.Error("expected Authenticate to return false for wrong password")
	}
	if adapter.Authenticate("wronguser", "testpass") {
		t.Error("expected Authenticate to return false for wrong username")
	}
	if adapter.Authenticate("", "") {
		t.Error("expected Authenticate to return false for empty credentials")
	}
}

func TestConfigE2E_SOCKS5Auth_NoneByDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if proxyCfg.SOCKS5Auth != "" {
		t.Errorf("SOCKS5Auth = %q, want empty (no auth)", proxyCfg.SOCKS5Auth)
	}
}

func TestConfigE2E_SOCKS5Auth_PasswordButMissingCredentials(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"socks5_auth": "password"
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	// Auth mode is password but credentials are empty — the runtime should
	// log a warning and NOT set up auth. Verify the config parsed correctly.
	if proxyCfg.SOCKS5Auth != "password" {
		t.Errorf("SOCKS5Auth = %q, want %q", proxyCfg.SOCKS5Auth, "password")
	}
	if proxyCfg.SOCKS5Username != "" {
		t.Errorf("SOCKS5Username = %q, want empty", proxyCfg.SOCKS5Username)
	}
	if proxyCfg.SOCKS5Password != "" {
		t.Errorf("SOCKS5Password = %q, want empty", proxyCfg.SOCKS5Password)
	}
}

// --- Combined config: all security features in one config file ---

func TestConfigE2E_CombinedSecurityConfig(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "client.crt")
	key := filepath.Join(dir, "client.key")
	writeE2EFile(t, cert, "cert-content")
	writeE2EFile(t, key, "key-content")

	cfgPath := filepath.Join(dir, "config.json")
	cfgData := map[string]interface{}{
		"safety_filter": map[string]interface{}{
			"enabled": true,
			"input": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{"preset": "destructive-sql"},
				},
			},
			"output": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{"preset": "credit-card"},
				},
			},
		},
		"target_scope_policy": map[string]interface{}{
			"allows": []interface{}{
				map[string]interface{}{"hostname": "*.target.com"},
			},
			"denies": []interface{}{
				map[string]interface{}{"hostname": "*.internal.corp"},
			},
		},
		"client_cert": cert,
		"client_key":  key,
		"host_tls": map[string]interface{}{
			"api.target.com": map[string]interface{}{
				"tls_verify": false,
			},
		},
		"socks5_auth":     "password",
		"socks5_username": "admin",
		"socks5_password": "secret",
	}
	raw, err := json.Marshal(cfgData)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	writeE2EFile(t, cfgPath, string(raw))

	// Load config file.
	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	proxyCfg := result.proxyCfg

	cfg := config.Default()
	logger := e2eLogger(t)

	// Verify SafetyFilter.
	engine, err := initSafetyFilter(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil safety engine")
	}
	if len(engine.InputRules()) == 0 {
		t.Error("expected input rules")
	}
	if len(engine.OutputRules()) == 0 {
		t.Error("expected output rules")
	}

	// Verify Target Scope Policy.
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	scope := proxy.NewTargetScope()
	allows := convertTargetRules(result.targetScopePolicy.Allows)
	denies := convertTargetRules(result.targetScopePolicy.Denies)
	scope.SetPolicyRules(allows, denies)
	allowed, _ := scope.CheckTarget("https", "app.target.com", 443, "/")
	if !allowed {
		t.Error("expected app.target.com to be allowed")
	}
	allowed, _ = scope.CheckTarget("https", "secret.internal.corp", 443, "/")
	if allowed {
		t.Error("expected secret.internal.corp to be denied")
	}

	// Verify mTLS.
	reg, err := initHostTLSRegistry(cfg, proxyCfg, logger)
	if err != nil {
		t.Fatalf("initHostTLSRegistry: %v", err)
	}
	if reg.Global() == nil {
		t.Fatal("expected non-nil global TLS config")
	}
	hostCfg := reg.Lookup("api.target.com")
	if hostCfg == nil {
		t.Fatal("expected host config for api.target.com")
	}
	if hostCfg.TLSVerify == nil || *hostCfg.TLSVerify {
		t.Error("expected TLSVerify=false for api.target.com")
	}

	// Verify SOCKS5 Auth.
	if proxyCfg.SOCKS5Auth != "password" {
		t.Errorf("SOCKS5Auth = %q, want %q", proxyCfg.SOCKS5Auth, "password")
	}
	auth := &staticSOCKS5Auth{
		username: proxyCfg.SOCKS5Username,
		password: proxyCfg.SOCKS5Password,
	}
	if !auth.Authenticate("admin", "secret") {
		t.Error("expected SOCKS5 auth to succeed with correct credentials")
	}
}

// --- Error cases ---

func TestConfigE2E_SafetyFilter_InvalidPreset(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"rules": [
					{"preset": "nonexistent-preset"}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	_, err = initSafetyFilter(cfg, proxyCfg, logger)
	if err == nil {
		t.Fatal("expected error for invalid preset name")
	}
}

func TestConfigE2E_SafetyFilter_InvalidPattern(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"rules": [
					{
						"id": "bad-regex",
						"pattern": "[invalid",
						"targets": ["body"]
					}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	_, err = initSafetyFilter(cfg, proxyCfg, logger)
	if err == nil {
		t.Fatal("expected error for invalid regex pattern")
	}
}

func TestConfigE2E_SafetyFilter_InvalidAction(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeE2EFile(t, cfgPath, `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"action": "invalid_action",
				"rules": [
					{"preset": "destructive-sql"}
				]
			}
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	cfg := config.Default()
	logger := e2eLogger(t)

	_, err = initSafetyFilter(cfg, proxyCfg, logger)
	if err == nil {
		t.Fatal("expected error for invalid input action")
	}
}
