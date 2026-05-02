package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/logging"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	protosocks5 "github.com/usk6666/yorishiro-proxy/internal/protocol/socks5"
)

// --- initPassthroughList tests ---

func TestInitPassthroughList_EmptyConfig(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.TLSPassthrough = nil

	pl := initPassthroughList(cfg, logger)
	if pl == nil {
		t.Fatal("expected non-nil passthrough list")
	}
	if pl.Len() != 0 {
		t.Errorf("expected 0 patterns, got %d", pl.Len())
	}
}

func TestInitPassthroughList_MultiplePatterns(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.TLSPassthrough = []string{"example.com", "*.internal.corp", "bank.co.jp"}

	pl := initPassthroughList(cfg, logger)
	if pl.Len() != 3 {
		t.Fatalf("expected 3 patterns, got %d", pl.Len())
	}
	if !pl.Contains("example.com") {
		t.Error("expected passthrough to contain example.com")
	}
	if !pl.Contains("foo.internal.corp") {
		t.Error("expected passthrough to match *.internal.corp wildcard")
	}
	if !pl.Contains("bank.co.jp") {
		t.Error("expected passthrough to contain bank.co.jp")
	}
	if pl.Contains("other.com") {
		t.Error("expected passthrough to NOT contain other.com")
	}
}

func TestInitPassthroughList_InvalidPatterns(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.TLSPassthrough = []string{"valid.com", "", "  ", "also-valid.com"}

	pl := initPassthroughList(cfg, logger)
	// Empty/whitespace patterns are skipped.
	if pl.Len() != 2 {
		t.Errorf("expected 2 valid patterns, got %d", pl.Len())
	}
}

func TestInitPassthroughList_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"tls_passthrough": ["*.secure-bank.com", "payments.example.com"]
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	logger := testLogger(t)
	cfg := config.Default()
	// Simulate main.go behavior: config file tls_passthrough goes into cfg.TLSPassthrough
	// via proxy defaults merge. In reality, initPassthroughList reads from cfg directly.
	// The config file's tls_passthrough is stored in proxyCfg.TLSPassthrough.
	// Let's verify that config.LoadFile properly parses tls_passthrough.
	if len(proxyCfg.TLSPassthrough) != 2 {
		t.Fatalf("expected 2 TLS passthrough entries from config file, got %d", len(proxyCfg.TLSPassthrough))
	}

	// Copy to cfg to simulate the CLI->runtime path.
	cfg.TLSPassthrough = proxyCfg.TLSPassthrough
	pl := initPassthroughList(cfg, logger)
	if pl.Len() != 2 {
		t.Errorf("expected 2 patterns, got %d", pl.Len())
	}
	if !pl.Contains("api.secure-bank.com") {
		t.Error("expected wildcard *.secure-bank.com to match api.secure-bank.com")
	}
	if !pl.Contains("payments.example.com") {
		t.Error("expected exact match for payments.example.com")
	}
}

// --- applyTLSFingerprintFlag tests ---

func TestApplyTLSFingerprintFlag_Empty(t *testing.T) {
	proxyCfg := &config.ProxyConfig{TLSFingerprint: "firefox"}

	result, err := applyTLSFingerprintFlag("", proxyCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty flag should not modify the proxyCfg.
	if result.TLSFingerprint != "firefox" {
		t.Errorf("TLSFingerprint = %q, want %q", result.TLSFingerprint, "firefox")
	}
}

func TestApplyTLSFingerprintFlag_ValidProfiles(t *testing.T) {
	tests := []struct {
		name    string
		profile string
	}{
		{"chrome", "chrome"},
		{"firefox", "firefox"},
		{"safari", "safari"},
		{"edge", "edge"},
		{"random", "random"},
		{"none", "none"},
		{"uppercase", "Chrome"},
		{"mixed case", "FireFox"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := applyTLSFingerprintFlag(tt.profile, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil proxyCfg")
			}
		})
	}
}

func TestApplyTLSFingerprintFlag_InvalidProfile(t *testing.T) {
	_, err := applyTLSFingerprintFlag("invalid-browser", nil)
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}
}

func TestApplyTLSFingerprintFlag_NilProxyCfg(t *testing.T) {
	result, err := applyTLSFingerprintFlag("chrome", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil proxyCfg to be created")
	}
	if result.TLSFingerprint != "chrome" {
		t.Errorf("TLSFingerprint = %q, want %q", result.TLSFingerprint, "chrome")
	}
}

func TestApplyTLSFingerprintFlag_CLIOverridesConfig(t *testing.T) {
	proxyCfg := &config.ProxyConfig{TLSFingerprint: "firefox"}

	result, err := applyTLSFingerprintFlag("safari", proxyCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TLSFingerprint != "safari" {
		t.Errorf("TLSFingerprint = %q, want %q (CLI should override config)", result.TLSFingerprint, "safari")
	}
}

func TestApplyTLSFingerprintFlag_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{"tls_fingerprint": "edge"}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if proxyCfg.TLSFingerprint != "edge" {
		t.Fatalf("expected TLSFingerprint=edge from config, got %q", proxyCfg.TLSFingerprint)
	}

	// Empty CLI flag should preserve the config file value.
	result, err := applyTLSFingerprintFlag("", proxyCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TLSFingerprint != "edge" {
		t.Errorf("TLSFingerprint = %q, want %q", result.TLSFingerprint, "edge")
	}
}

// --- initTLSTransport / initStandardTransport tests ---

func TestInitTLSTransport_NoFingerprint(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.TLSFingerprint = ""
	reg := httputil.NewHostTLSRegistry()

	// We need a real HTTP handler. Use nil store/issuer since we won't make connections.
	httpHandler := newTestHTTPHandler(t)

	transport := initTLSTransport(cfg, reg, httpHandler, logger)
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	if _, ok := transport.(*httputil.StandardTransport); !ok {
		t.Errorf("expected StandardTransport, got %T", transport)
	}
}

func TestInitTLSTransport_WithFingerprint(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.TLSFingerprint = "chrome"
	reg := httputil.NewHostTLSRegistry()

	httpHandler := newTestHTTPHandler(t)

	transport := initTLSTransport(cfg, reg, httpHandler, logger)
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	ut, ok := transport.(*httputil.UTLSTransport)
	if !ok {
		t.Fatalf("expected UTLSTransport, got %T", transport)
	}
	if ut.Profile != httputil.ProfileChrome {
		t.Errorf("profile = %v, want ProfileChrome", ut.Profile)
	}
}

func TestInitTLSTransport_InsecureSkipVerify(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	cfg.InsecureSkipVerify = true
	cfg.TLSFingerprint = ""
	reg := httputil.NewHostTLSRegistry()

	httpHandler := newTestHTTPHandler(t)

	transport := initTLSTransport(cfg, reg, httpHandler, logger)
	st, ok := transport.(*httputil.StandardTransport)
	if !ok {
		t.Fatalf("expected StandardTransport, got %T", transport)
	}
	if !st.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true on transport")
	}
}

func TestInitStandardTransport_HostTLS(t *testing.T) {
	logger := testLogger(t)
	cfg := config.Default()
	reg := httputil.NewHostTLSRegistry()

	httpHandler := newTestHTTPHandler(t)

	transport := initStandardTransport(cfg, reg, httpHandler)
	_ = logger // Used only for doc consistency.
	st, ok := transport.(*httputil.StandardTransport)
	if !ok {
		t.Fatalf("expected StandardTransport, got %T", transport)
	}
	if st.HostTLS != reg {
		t.Error("expected HostTLS registry to be attached to transport")
	}
}

// --- initTargetScope tests ---

func TestInitTargetScope_NilPolicy(t *testing.T) {
	scope := initTargetScope(nil, nil)
	if scope != nil {
		t.Error("expected nil scope for nil policy")
	}
}

func TestInitTargetScope_WithAllowsAndDenies(t *testing.T) {
	policy := &config.TargetScopePolicyConfig{
		Allows: []config.TargetRuleConfig{
			{Hostname: "*.target.com"},
			{Hostname: "api.example.com", Ports: []int{443}},
		},
		Denies: []config.TargetRuleConfig{
			{Hostname: "*.internal.corp"},
		},
	}

	// initTargetScope requires a socks5 handler but we can't easily create one
	// without a logger. Use a minimal one.
	logger := testLogger(t)
	socks5Handler := newTestSOCKS5Handler(t, logger)

	scope := initTargetScope(policy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope")
	}

	allows, denies := scope.PolicyRules()
	if len(allows) != 2 {
		t.Errorf("expected 2 allow rules, got %d", len(allows))
	}
	if len(denies) != 1 {
		t.Errorf("expected 1 deny rule, got %d", len(denies))
	}
	if allows[0].Hostname != "*.target.com" {
		t.Errorf("allow[0].Hostname = %q, want %q", allows[0].Hostname, "*.target.com")
	}
	if allows[1].Ports[0] != 443 {
		t.Errorf("allow[1].Ports[0] = %d, want 443", allows[1].Ports[0])
	}
}

func TestInitTargetScope_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [
				{"hostname": "*.example.com", "ports": [80, 443]},
				{"hostname": "api.test.io", "path_prefix": "/v1/"}
			],
			"denies": [
				{"hostname": "internal.example.com"}
			]
		}
	}`)

	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	socks5Handler := newTestSOCKS5Handler(t, logger)

	scope := initTargetScope(result.targetScopePolicy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope")
	}

	allows, denies := scope.PolicyRules()
	if len(allows) != 2 {
		t.Fatalf("expected 2 allow rules, got %d", len(allows))
	}
	if allows[0].Hostname != "*.example.com" {
		t.Errorf("allow[0].Hostname = %q, want %q", allows[0].Hostname, "*.example.com")
	}
	if len(allows[0].Ports) != 2 {
		t.Errorf("expected 2 ports for allow[0], got %d", len(allows[0].Ports))
	}
	if allows[1].PathPrefix != "/v1/" {
		t.Errorf("allow[1].PathPrefix = %q, want %q", allows[1].PathPrefix, "/v1/")
	}
	if len(denies) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(denies))
	}
	if denies[0].Hostname != "internal.example.com" {
		t.Errorf("deny[0].Hostname = %q, want %q", denies[0].Hostname, "internal.example.com")
	}
}

// --- convertTargetRules tests ---

func TestConvertTargetRules_Empty(t *testing.T) {
	rules := convertTargetRules(nil)
	if rules != nil {
		t.Errorf("expected nil for empty input, got %v", rules)
	}
}

func TestConvertTargetRules_FullFields(t *testing.T) {
	cfgRules := []config.TargetRuleConfig{
		{
			Hostname:   "*.example.com",
			Ports:      []int{80, 443, 8080},
			PathPrefix: "/api/",
			Schemes:    []string{"https"},
		},
	}

	rules := convertTargetRules(cfgRules)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Hostname != "*.example.com" {
		t.Errorf("Hostname = %q, want %q", r.Hostname, "*.example.com")
	}
	if len(r.Ports) != 3 {
		t.Errorf("Ports len = %d, want 3", len(r.Ports))
	}
	if r.PathPrefix != "/api/" {
		t.Errorf("PathPrefix = %q, want %q", r.PathPrefix, "/api/")
	}
	if len(r.Schemes) != 1 || r.Schemes[0] != "https" {
		t.Errorf("Schemes = %v, want [https]", r.Schemes)
	}
}

// --- initRateLimiter tests ---

func TestInitRateLimiter_NilPolicy(t *testing.T) {
	logger := testLogger(t)
	rl := initRateLimiter(nil, logger)
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
	limits := rl.PolicyLimits()
	if limits.MaxRequestsPerSecond != 0 {
		t.Errorf("expected 0 global RPS, got %f", limits.MaxRequestsPerSecond)
	}
	if limits.MaxRequestsPerHostPerSecond != 0 {
		t.Errorf("expected 0 per-host RPS, got %f", limits.MaxRequestsPerHostPerSecond)
	}
}

func TestInitRateLimiter_WithLimits(t *testing.T) {
	logger := testLogger(t)
	policy := &config.TargetScopePolicyConfig{
		RateLimits: &config.RateLimitPolicyConfig{
			MaxRequestsPerSecond:        100.0,
			MaxRequestsPerHostPerSecond: 10.0,
		},
	}

	rl := initRateLimiter(policy, logger)
	limits := rl.PolicyLimits()
	if limits.MaxRequestsPerSecond != 100.0 {
		t.Errorf("MaxRequestsPerSecond = %f, want 100.0", limits.MaxRequestsPerSecond)
	}
	if limits.MaxRequestsPerHostPerSecond != 10.0 {
		t.Errorf("MaxRequestsPerHostPerSecond = %f, want 10.0", limits.MaxRequestsPerHostPerSecond)
	}
}

func TestInitRateLimiter_NoRateLimitsInPolicy(t *testing.T) {
	logger := testLogger(t)
	policy := &config.TargetScopePolicyConfig{
		Allows: []config.TargetRuleConfig{{Hostname: "*.example.com"}},
	}

	rl := initRateLimiter(policy, logger)
	limits := rl.PolicyLimits()
	if limits.MaxRequestsPerSecond != 0 {
		t.Errorf("expected 0 global RPS, got %f", limits.MaxRequestsPerSecond)
	}
}

func TestInitRateLimiter_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"rate_limits": {
				"max_requests_per_second": 50,
				"max_requests_per_host_per_second": 5
			}
		}
	}`)

	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	rl := initRateLimiter(result.targetScopePolicy, logger)
	limits := rl.PolicyLimits()
	if limits.MaxRequestsPerSecond != 50.0 {
		t.Errorf("MaxRequestsPerSecond = %f, want 50.0", limits.MaxRequestsPerSecond)
	}
	if limits.MaxRequestsPerHostPerSecond != 5.0 {
		t.Errorf("MaxRequestsPerHostPerSecond = %f, want 5.0", limits.MaxRequestsPerHostPerSecond)
	}
}

// --- Upstream Proxy config tests ---

func TestUpstreamProxy_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"upstream_proxy": "http://proxy.corp.com:3128"
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if proxyCfg.UpstreamProxy != "http://proxy.corp.com:3128" {
		t.Errorf("UpstreamProxy = %q, want %q", proxyCfg.UpstreamProxy, "http://proxy.corp.com:3128")
	}
}

func TestUpstreamProxy_EmptyByDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if proxyCfg.UpstreamProxy != "" {
		t.Errorf("expected empty UpstreamProxy, got %q", proxyCfg.UpstreamProxy)
	}
}

// --- TCP Forwards config tests ---

func TestTCPForwards_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"tcp_forwards": {
			"9001": "internal-db.corp:3306",
			"9002": "redis.corp:6379"
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(proxyCfg.TCPForwards) != 2 {
		t.Fatalf("expected 2 TCP forwards, got %d", len(proxyCfg.TCPForwards))
	}
	if fc := proxyCfg.TCPForwards["9001"]; fc == nil || fc.Target != "internal-db.corp:3306" {
		var got string
		if fc != nil {
			got = fc.Target
		}
		t.Errorf("TCPForwards[9001].Target = %q, want %q", got, "internal-db.corp:3306")
	}
	if fc := proxyCfg.TCPForwards["9002"]; fc == nil || fc.Target != "redis.corp:6379" {
		var got string
		if fc != nil {
			got = fc.Target
		}
		t.Errorf("TCPForwards[9002].Target = %q, want %q", got, "redis.corp:6379")
	}
}

func TestTCPForwards_EmptyByDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(proxyCfg.TCPForwards) != 0 {
		t.Errorf("expected empty TCPForwards, got %v", proxyCfg.TCPForwards)
	}
}

// --- Plugins (Starlark) config tests ---

func TestPlugins_FromConfigFile(t *testing.T) {
	dir := t.TempDir()

	// Create a valid Starlark plugin script. The pluginv2 shape has no
	// protocol/hooks at the config level — register_hook() inside the
	// script owns hook identity (RFC §9.3).
	pluginPath := filepath.Join(dir, "my-plugin.star")
	writeTestFile(t, pluginPath, `
def on_request_fn(env, msg, ctx):
    pass

register_hook("http", "on_request", on_request_fn)
`)

	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"plugins": []map[string]interface{}{
			{
				"path":     pluginPath,
				"on_error": "skip",
			},
		},
	})
	writeTestFile(t, cfgPath, string(cfgJSON))

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := proxyCfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if len(proxyCfg.Plugins) != 1 {
		t.Fatalf("expected 1 plugin config, got %d", len(proxyCfg.Plugins))
	}
	pc := proxyCfg.Plugins[0]
	if pc.Path != pluginPath {
		t.Errorf("plugin path = %q, want %q", pc.Path, pluginPath)
	}
	if pc.OnError != "skip" {
		t.Errorf("plugin on_error = %q, want %q", pc.OnError, "skip")
	}
}

func TestPlugins_WithVars(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"plugins": [
			{
				"path": "/some/plugin.star",
				"vars": {"api_key": "secret123", "region": "ap-northeast-1", "max_retries": 3}
			}
		]
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := proxyCfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	if len(proxyCfg.Plugins) != 1 {
		t.Fatalf("expected 1 plugin config, got %d", len(proxyCfg.Plugins))
	}
	vars := proxyCfg.Plugins[0].Vars
	if len(vars) != 3 {
		t.Errorf("expected 3 vars, got %d", len(vars))
	}
	if vars["api_key"] != "secret123" {
		t.Errorf("vars[api_key] = %v, want %q", vars["api_key"], "secret123")
	}
	// pluginv2.PluginConfig.Vars is map[string]any so non-string values
	// (e.g. JSON numbers) round-trip without lossy coercion.
	if got, want := vars["max_retries"], float64(3); got != want {
		t.Errorf("vars[max_retries] = %v, want %v", got, want)
	}
}

// TestPlugins_RejectsLegacyFields asserts that a config carrying the
// pre-RFC-001 `protocol` / `hooks` keys is rejected at load time by
// ProxyConfig.Validate via the pluginv2 tripwire (RFC §9.3 P-8 — no
// shims). The migration message points the user at the migration doc.
func TestPlugins_RejectsLegacyFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "legacy-config.json")
	writeTestFile(t, cfgPath, `{
		"plugins": [
			{
				"path":     "/tmp/x.star",
				"protocol": "http",
				"hooks":    ["on_request"]
			}
		]
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	err = proxyCfg.Validate()
	if err == nil {
		t.Fatal("expected legacy-field rejection, got nil")
	}
	var loadErr *pluginv2.LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("expected *pluginv2.LoadError, got %T (%v)", err, err)
	}
	if loadErr.Kind != pluginv2.LoadErrLegacyField {
		t.Errorf("LoadError.Kind = %v, want LoadErrLegacyField", loadErr.Kind)
	}
	if !strings.Contains(err.Error(), "plugin-migration.md") {
		t.Errorf("error = %q, want substring %q", err.Error(), "plugin-migration.md")
	}
}

// --- Logging config tests ---

func TestLogging_DefaultConfig(t *testing.T) {
	cfg := config.Default()
	if cfg.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.LogFormat != "text" {
		t.Errorf("default LogFormat = %q, want %q", cfg.LogFormat, "text")
	}
	if cfg.LogFile != "" {
		t.Errorf("default LogFile = %q, want empty", cfg.LogFile)
	}
}

func TestLogging_SetupFromConfig(t *testing.T) {
	tests := []struct {
		name      string
		level     string
		format    string
		wantError bool
	}{
		{"defaults", "info", "text", false},
		{"debug level", "debug", "text", false},
		{"warn level", "warn", "json", false},
		{"error level", "error", "text", false},
		{"invalid level", "invalid", "text", true},
		{"invalid format", "info", "xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, cleanup, err := logging.Setup(logging.Config{
				Level:  tt.level,
				Format: tt.format,
			})
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer cleanup()
			if logger == nil {
				t.Fatal("expected non-nil logger")
			}
		})
	}
}

func TestLogging_LogFileFromConfig(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "test.log")

	logger, cleanup, err := logging.Setup(logging.Config{
		Level:  "info",
		Format: "text",
		File:   logPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	// Verify the log file was created.
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("expected log file to be created")
	}
}

func TestLogging_FromProxyConfigFile(t *testing.T) {
	// Logging is configured via Config (CLI level), not ProxyConfig.
	// Verify that config.Default() provides valid logging config values.
	cfg := config.Default()
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}

	// Verify logging setup works with default config values.
	logger, cleanup, err := logging.Setup(logging.Config{
		Level:  cfg.LogLevel,
		Format: cfg.LogFormat,
		File:   cfg.LogFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

// --- Capture Scope config tests ---

func TestCaptureScope_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"capture_scope": {
			"include": ["*.example.com"],
			"exclude": ["static.example.com"]
		}
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(proxyCfg.CaptureScope) == 0 {
		t.Fatal("expected non-empty CaptureScope raw JSON")
	}

	// Verify it is valid JSON that can be parsed.
	var scope map[string]interface{}
	if err := json.Unmarshal(proxyCfg.CaptureScope, &scope); err != nil {
		t.Fatalf("unmarshal capture_scope: %v", err)
	}
	if _, ok := scope["include"]; !ok {
		t.Error("expected 'include' key in capture_scope")
	}
}

// --- Intercept Rules config tests ---

func TestInterceptRules_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"intercept_rules": [
			{
				"match": {"url_pattern": "*.example.com/api/*"},
				"action": "intercept"
			}
		]
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(proxyCfg.InterceptRules) == 0 {
		t.Fatal("expected non-empty InterceptRules raw JSON")
	}
}

// --- Auto-Transform config tests ---

func TestAutoTransform_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"auto_transform": [
			{
				"match": {"url_pattern": "*"},
				"actions": [{"type": "set_header", "name": "X-Test", "value": "1"}]
			}
		]
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(proxyCfg.AutoTransform) == 0 {
		t.Fatal("expected non-empty AutoTransform raw JSON")
	}
}

// --- SOCKS5 auth config tests ---

func TestSOCKS5Auth_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"socks5_auth": "password",
		"socks5_username": "user1",
		"socks5_password": "pass1"
	}`)

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if proxyCfg.SOCKS5Auth != "password" {
		t.Errorf("SOCKS5Auth = %q, want %q", proxyCfg.SOCKS5Auth, "password")
	}
	if proxyCfg.SOCKS5Username != "user1" {
		t.Errorf("SOCKS5Username = %q, want %q", proxyCfg.SOCKS5Username, "user1")
	}
	if proxyCfg.SOCKS5Password != "pass1" {
		t.Errorf("SOCKS5Password = %q, want %q", proxyCfg.SOCKS5Password, "pass1")
	}
}

// --- Full config file round-trip test ---

func TestFullConfigFile_AllSections(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "plugin.star")
	writeTestFile(t, pluginPath, `
def on_request(flow):
    pass
`)

	cfgJSON := map[string]interface{}{
		"listen_addr":     "127.0.0.1:9090",
		"tls_passthrough": []string{"*.bank.com"},
		"tls_fingerprint": "firefox",
		"upstream_proxy":  "socks5://proxy:1080",
		"tcp_forwards": map[string]string{
			"9001": "db.internal:3306",
		},
		"socks5_auth":     "password",
		"socks5_username": "admin",
		"socks5_password": "secret",
		"plugins": []map[string]interface{}{
			{
				"path": pluginPath,
			},
		},
		"capture_scope": map[string]interface{}{
			"include": []string{"*.example.com"},
		},
		"intercept_rules": []map[string]interface{}{
			{"match": map[string]string{"url_pattern": "*"}},
		},
		"auto_transform": []map[string]interface{}{
			{"match": map[string]string{"url_pattern": "*"}},
		},
		"target_scope_policy": map[string]interface{}{
			"allows": []map[string]interface{}{
				{"hostname": "*.example.com"},
			},
			"rate_limits": map[string]interface{}{
				"max_requests_per_second": 100,
			},
		},
		"safety_filter": map[string]interface{}{
			"enabled": true,
			"input": map[string]interface{}{
				"rules": []map[string]string{
					{"preset": "destructive-sql"},
				},
			},
		},
	}

	raw, err := json.Marshal(cfgJSON)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(dir, "full-config.json")
	writeTestFile(t, cfgPath, string(raw))

	proxyCfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Verify all sections were loaded.
	if proxyCfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want %q", proxyCfg.ListenAddr, "127.0.0.1:9090")
	}
	if len(proxyCfg.TLSPassthrough) != 1 {
		t.Errorf("TLSPassthrough len = %d, want 1", len(proxyCfg.TLSPassthrough))
	}
	if proxyCfg.TLSFingerprint != "firefox" {
		t.Errorf("TLSFingerprint = %q, want %q", proxyCfg.TLSFingerprint, "firefox")
	}
	if proxyCfg.UpstreamProxy != "socks5://proxy:1080" {
		t.Errorf("UpstreamProxy = %q, want %q", proxyCfg.UpstreamProxy, "socks5://proxy:1080")
	}
	if len(proxyCfg.TCPForwards) != 1 {
		t.Errorf("TCPForwards len = %d, want 1", len(proxyCfg.TCPForwards))
	}
	if proxyCfg.SOCKS5Auth != "password" {
		t.Errorf("SOCKS5Auth = %q, want %q", proxyCfg.SOCKS5Auth, "password")
	}
	if len(proxyCfg.Plugins) == 0 {
		t.Error("expected non-empty Plugins")
	}
	if len(proxyCfg.CaptureScope) == 0 {
		t.Error("expected non-empty CaptureScope")
	}
	if len(proxyCfg.InterceptRules) == 0 {
		t.Error("expected non-empty InterceptRules")
	}
	if len(proxyCfg.AutoTransform) == 0 {
		t.Error("expected non-empty AutoTransform")
	}
	if proxyCfg.TargetScopePolicy == nil {
		t.Error("expected non-nil TargetScopePolicy")
	}
	if proxyCfg.SafetyFilter == nil {
		t.Error("expected non-nil SafetyFilter")
	}

	// Verify config -> runtime conversion for applicable sections.
	logger := testLogger(t)

	// TLS Passthrough
	cfg := config.Default()
	cfg.TLSPassthrough = proxyCfg.TLSPassthrough
	pl := initPassthroughList(cfg, logger)
	if pl.Len() != 1 {
		t.Errorf("passthrough patterns = %d, want 1", pl.Len())
	}

	// TLS Fingerprint
	resultCfg, err := applyTLSFingerprintFlag("", proxyCfg)
	if err != nil {
		t.Fatalf("applyTLSFingerprintFlag: %v", err)
	}
	if resultCfg.TLSFingerprint != "firefox" {
		t.Errorf("after applyTLSFingerprintFlag, TLSFingerprint = %q, want %q",
			resultCfg.TLSFingerprint, "firefox")
	}

	// Rate Limiter
	rl := initRateLimiter(proxyCfg.TargetScopePolicy, logger)
	limits := rl.PolicyLimits()
	if limits.MaxRequestsPerSecond != 100 {
		t.Errorf("rate limit RPS = %f, want 100", limits.MaxRequestsPerSecond)
	}

	// Safety Filter
	engine, err := initSafetyFilter(config.Default(), proxyCfg, logger)
	if err != nil {
		t.Fatalf("initSafetyFilter: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil safety engine")
	}
	if len(engine.InputRules()) == 0 {
		t.Error("expected input rules from destructive-sql preset")
	}
}

// --- test helpers ---

// newTestHTTPHandler creates a minimal HTTP handler for testing transport initialization.
// The handler is not connected to a real store or issuer.
func newTestHTTPHandler(t *testing.T) *protohttp.Handler {
	t.Helper()
	logger := testLogger(t)
	return protohttp.NewHandler(nil, nil, logger)
}

// newTestSOCKS5Handler creates a minimal SOCKS5 handler for testing.
func newTestSOCKS5Handler(t *testing.T, logger *slog.Logger) *protosocks5.Handler {
	t.Helper()
	return protosocks5.NewHandler(logger)
}
