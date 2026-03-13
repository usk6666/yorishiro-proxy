//go:build e2e

package main

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// --- TargetScope: policy file -> initTargetScope -> enforcement ---

// TestPolicyFileE2E_TargetScope_FileLoadAndEnforcement verifies the full chain:
// JSON policy file on disk -> LoadPolicyFile() -> loadConfigs() -> initTargetScope() -> CheckTarget enforcement.
func TestPolicyFileE2E_TargetScope_FileLoadAndEnforcement(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{
		"allows": [
			{"hostname": "*.target.com", "ports": [80, 443]},
			{"hostname": "api.partner.io", "schemes": ["https"], "path_prefix": "/v2/"}
		],
		"denies": [
			{"hostname": "admin.target.com"},
			{"hostname": "*.internal.target.com"}
		]
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy from policy file")
	}
	if result.targetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "policy file")
	}

	logger := testLogger(t)
	socks5Handler := newTestSOCKS5Handler(t, logger)
	scope := initTargetScope(result.targetScopePolicy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope from initTargetScope")
	}

	tests := []struct {
		name    string
		scheme  string
		host    string
		port    int
		path    string
		allowed bool
		reason  string
	}{
		// Allow rules
		{"wildcard allow HTTPS 443", "https", "app.target.com", 443, "/", true, ""},
		{"wildcard allow HTTP 80", "http", "web.target.com", 80, "/page", true, ""},
		{"api partner HTTPS with path", "https", "api.partner.io", 443, "/v2/users", true, ""},

		// Deny rules take precedence
		{"deny admin.target.com", "https", "admin.target.com", 443, "/", false, "blocked by policy deny rule"},
		{"deny internal subdomain", "https", "db.internal.target.com", 443, "/", false, "blocked by policy deny rule"},

		// Not in allow list
		{"wrong port for target.com", "https", "app.target.com", 8443, "/", false, "not in policy allow list"},
		{"unknown host", "https", "unknown.com", 443, "/", false, "not in policy allow list"},
		{"partner wrong scheme", "http", "api.partner.io", 80, "/v2/users", false, "not in policy allow list"},
		{"partner wrong path", "https", "api.partner.io", 443, "/v1/old", false, "not in policy allow list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := scope.CheckTarget(tt.scheme, tt.host, tt.port, tt.path)
			if allowed != tt.allowed {
				t.Errorf("CheckTarget(%q, %q, %d, %q) = %v (%s), want %v",
					tt.scheme, tt.host, tt.port, tt.path, allowed, reason, tt.allowed)
			}
			if !tt.allowed && tt.reason != "" && reason != tt.reason {
				t.Errorf("reason = %q, want %q", reason, tt.reason)
			}
		})
	}
}

// TestPolicyFileE2E_TargetScope_DenyOnlyPolicy verifies a policy file with only deny rules.
// When no allow rules exist, all targets are permitted except those matching deny rules.
func TestPolicyFileE2E_TargetScope_DenyOnlyPolicy(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "deny-only.json")
	writeTestFile(t, policyPath, `{
		"denies": [
			{"hostname": "*.evil.com"},
			{"hostname": "malware.io", "ports": [80, 443]}
		]
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	socks5Handler := newTestSOCKS5Handler(t, logger)
	scope := initTargetScope(result.targetScopePolicy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope")
	}

	// Any host not in deny list should be allowed.
	allowed, _ := scope.CheckTarget("https", "good.com", 443, "/")
	if !allowed {
		t.Error("expected good.com to be allowed (deny-only policy)")
	}

	// Denied host.
	allowed, reason := scope.CheckTarget("https", "sub.evil.com", 443, "/")
	if allowed {
		t.Error("expected sub.evil.com to be denied")
	}
	if reason != "blocked by policy deny rule" {
		t.Errorf("reason = %q, want %q", reason, "blocked by policy deny rule")
	}

	// malware.io on port 443 should be denied.
	allowed, _ = scope.CheckTarget("https", "malware.io", 443, "/")
	if allowed {
		t.Error("expected malware.io:443 to be denied")
	}

	// malware.io on a non-listed port should be allowed (port restriction).
	allowed, _ = scope.CheckTarget("https", "malware.io", 8443, "/")
	if !allowed {
		t.Error("expected malware.io:8443 to be allowed (port not in deny rule)")
	}
}

// --- Policy file vs config file precedence ---

// TestPolicyFileE2E_TargetScope_PolicyFilePrecedenceEnforcement verifies that
// when both a config file with target_scope_policy and a dedicated policy file
// are provided, the policy file takes precedence and is enforced correctly.
func TestPolicyFileE2E_TargetScope_PolicyFilePrecedenceEnforcement(t *testing.T) {
	dir := t.TempDir()

	// Config file allows only config-host.com.
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [{"hostname": "config-host.com"}]
		}
	}`)

	// Policy file allows only policy-host.com.
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{
		"allows": [{"hostname": "policy-host.com"}]
	}`)

	result, err := loadConfigs(cfgPath, policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "policy file")
	}

	logger := testLogger(t)
	socks5Handler := newTestSOCKS5Handler(t, logger)
	scope := initTargetScope(result.targetScopePolicy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope")
	}

	// Policy file host should be allowed.
	allowed, _ := scope.CheckTarget("https", "policy-host.com", 443, "/")
	if !allowed {
		t.Error("expected policy-host.com to be allowed (policy file takes precedence)")
	}

	// Config file host should be blocked (not in policy file's allow list).
	allowed, reason := scope.CheckTarget("https", "config-host.com", 443, "/")
	if allowed {
		t.Error("expected config-host.com to be blocked (policy file takes precedence)")
	}
	if reason != "not in policy allow list" {
		t.Errorf("reason = %q, want %q", reason, "not in policy allow list")
	}
}

// TestPolicyFileE2E_TargetScope_ConfigFileOnlyFallback verifies that when no
// policy file is specified, the config file's target_scope_policy is used.
func TestPolicyFileE2E_TargetScope_ConfigFileOnlyFallback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"allows": [{"hostname": "config-only.com"}],
			"denies": [{"hostname": "blocked.com"}]
		}
	}`)

	result, err := loadConfigs(cfgPath, "")
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicySource != "config file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "config file")
	}

	logger := testLogger(t)
	socks5Handler := newTestSOCKS5Handler(t, logger)
	scope := initTargetScope(result.targetScopePolicy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope")
	}

	allowed, _ := scope.CheckTarget("https", "config-only.com", 443, "/")
	if !allowed {
		t.Error("expected config-only.com to be allowed from config file policy")
	}

	allowed, _ = scope.CheckTarget("https", "blocked.com", 443, "/")
	if allowed {
		t.Error("expected blocked.com to be denied from config file policy")
	}
}

// --- RateLimiter: policy file -> initRateLimiter -> enforcement ---

// TestPolicyFileE2E_RateLimiter_FileLoadAndEnforcement verifies the chain:
// JSON policy file -> LoadPolicyFile() -> loadConfigs() -> initRateLimiter() -> Allow() enforcement.
func TestPolicyFileE2E_RateLimiter_FileLoadAndEnforcement(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{
		"allows": [{"hostname": "*.target.com"}],
		"rate_limits": {
			"max_requests_per_second": 2,
			"max_requests_per_host_per_second": 1
		}
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy")
	}
	if result.targetScopePolicy.RateLimits == nil {
		t.Fatal("expected non-nil RateLimits from policy file")
	}

	logger := testLogger(t)
	rl := initRateLimiter(result.targetScopePolicy, logger)
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	limits := rl.PolicyLimits()
	if limits.MaxRequestsPerSecond != 2 {
		t.Errorf("MaxRequestsPerSecond = %f, want 2", limits.MaxRequestsPerSecond)
	}
	if limits.MaxRequestsPerHostPerSecond != 1 {
		t.Errorf("MaxRequestsPerHostPerSecond = %f, want 1", limits.MaxRequestsPerHostPerSecond)
	}

	// Verify enforcement: per-host limit is 1 RPS (burst = 2).
	// First two requests to the same host should be allowed (burst).
	if !rl.Allow("app.target.com") {
		t.Error("first request should be allowed")
	}
	if !rl.Allow("app.target.com") {
		t.Error("second request should be allowed (burst)")
	}
	// Third request should be rate limited (per-host burst exhausted).
	if rl.Allow("app.target.com") {
		t.Error("third request to same host should be rate limited")
	}
}

// TestPolicyFileE2E_RateLimiter_ConfigFileRateLimits verifies rate limits
// loaded from the config file's target_scope_policy section.
func TestPolicyFileE2E_RateLimiter_ConfigFileRateLimits(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"rate_limits": {
				"max_requests_per_second": 100,
				"max_requests_per_host_per_second": 20
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
	if limits.MaxRequestsPerSecond != 100 {
		t.Errorf("MaxRequestsPerSecond = %f, want 100", limits.MaxRequestsPerSecond)
	}
	if limits.MaxRequestsPerHostPerSecond != 20 {
		t.Errorf("MaxRequestsPerHostPerSecond = %f, want 20", limits.MaxRequestsPerHostPerSecond)
	}

	if !rl.HasLimits() {
		t.Error("expected HasLimits to return true")
	}
}

// TestPolicyFileE2E_RateLimiter_PolicyFilePrecedence verifies that rate limits
// from a dedicated policy file take precedence over config file rate limits.
func TestPolicyFileE2E_RateLimiter_PolicyFilePrecedence(t *testing.T) {
	dir := t.TempDir()

	// Config file with rate limits.
	cfgPath := filepath.Join(dir, "config.json")
	writeTestFile(t, cfgPath, `{
		"target_scope_policy": {
			"rate_limits": {
				"max_requests_per_second": 999
			}
		}
	}`)

	// Policy file with different rate limits.
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{
		"rate_limits": {
			"max_requests_per_second": 50
		}
	}`)

	result, err := loadConfigs(cfgPath, policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	rl := initRateLimiter(result.targetScopePolicy, logger)

	limits := rl.PolicyLimits()
	// Policy file should take precedence: 50 not 999.
	if limits.MaxRequestsPerSecond != 50 {
		t.Errorf("MaxRequestsPerSecond = %f, want 50 (policy file takes precedence)", limits.MaxRequestsPerSecond)
	}
}

// TestPolicyFileE2E_RateLimiter_NoRateLimitsInPolicyFile verifies that a policy file
// without rate_limits results in no rate limiting.
func TestPolicyFileE2E_RateLimiter_NoRateLimitsInPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{
		"allows": [{"hostname": "*.target.com"}]
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	rl := initRateLimiter(result.targetScopePolicy, logger)

	if rl.HasLimits() {
		t.Error("expected no rate limits when policy file omits rate_limits")
	}

	// All requests should be allowed.
	for i := 0; i < 100; i++ {
		if !rl.Allow("example.com") {
			t.Fatalf("request %d should be allowed (no rate limits)", i)
		}
	}
}

// --- RateLimiter: concurrent request enforcement ---

// TestPolicyFileE2E_RateLimiter_ConcurrentEnforcement verifies that rate limiting
// works correctly under concurrent load from multiple goroutines.
func TestPolicyFileE2E_RateLimiter_ConcurrentEnforcement(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	// Set a very low global rate (1 RPS) so we can detect limiting easily.
	writeTestFile(t, policyPath, `{
		"rate_limits": {
			"max_requests_per_second": 1
		}
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	rl := initRateLimiter(result.targetScopePolicy, logger)

	// Launch concurrent requests. With 1 RPS and burst=2, only 2 should succeed.
	const goroutines = 10
	const requestsPerGoroutine = 5

	var allowed atomic.Int64
	var denied atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				if rl.Allow("target.com") {
					allowed.Add(1)
				} else {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	totalAllowed := allowed.Load()
	totalDenied := denied.Load()
	total := totalAllowed + totalDenied

	if total != goroutines*requestsPerGoroutine {
		t.Errorf("total requests = %d, want %d", total, goroutines*requestsPerGoroutine)
	}

	// With 1 RPS and burst=2, at most 2 requests should be allowed instantly.
	if totalAllowed > 2 {
		t.Errorf("allowed = %d, want <= 2 (1 RPS with burst=2)", totalAllowed)
	}
	if totalDenied == 0 {
		t.Error("expected some denied requests under concurrent load with 1 RPS limit")
	}
}

// TestPolicyFileE2E_RateLimiter_ConcurrentPerHostEnforcement verifies per-host
// rate limiting under concurrent load. Different hosts should have independent limits.
func TestPolicyFileE2E_RateLimiter_ConcurrentPerHostEnforcement(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{
		"rate_limits": {
			"max_requests_per_host_per_second": 1
		}
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	rl := initRateLimiter(result.targetScopePolicy, logger)

	// Concurrent requests to different hosts should each get independent limits.
	const hosts = 5
	const requestsPerHost = 10
	hostResults := make([]atomic.Int64, hosts)

	var wg sync.WaitGroup
	for h := 0; h < hosts; h++ {
		wg.Add(1)
		go func(hostIdx int) {
			defer wg.Done()
			hostname := "host-" + string(rune('a'+hostIdx)) + ".example.com"
			for j := 0; j < requestsPerHost; j++ {
				if rl.Allow(hostname) {
					hostResults[hostIdx].Add(1)
				}
			}
		}(h)
	}
	wg.Wait()

	// Each host should have gotten exactly burst (2) allowed requests at 1 RPS.
	for h := 0; h < hosts; h++ {
		allowed := hostResults[h].Load()
		if allowed == 0 {
			t.Errorf("host %d: expected at least 1 allowed request", h)
		}
		if allowed > 2 {
			t.Errorf("host %d: allowed = %d, want <= 2 (1 RPS per host with burst=2)", h, allowed)
		}
	}
}

// --- Combined: TargetScope + RateLimiter from single policy file ---

// TestPolicyFileE2E_CombinedTargetScopeAndRateLimiter verifies that a single
// policy file can configure both TargetScope rules and RateLimiter limits,
// and both are independently enforced through the init chain.
func TestPolicyFileE2E_CombinedTargetScopeAndRateLimiter(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "combined-policy.json")
	writeTestFile(t, policyPath, `{
		"allows": [
			{"hostname": "*.target.com", "ports": [443]}
		],
		"denies": [
			{"hostname": "blocked.target.com"}
		],
		"rate_limits": {
			"max_requests_per_second": 10,
			"max_requests_per_host_per_second": 5
		}
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicySource != "policy file" {
		t.Errorf("source = %q, want %q", result.targetScopePolicySource, "policy file")
	}

	logger := testLogger(t)

	// Initialize TargetScope.
	socks5Handler := newTestSOCKS5Handler(t, logger)
	scope := initTargetScope(result.targetScopePolicy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope")
	}

	// Initialize RateLimiter.
	rl := initRateLimiter(result.targetScopePolicy, logger)
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}

	// Verify TargetScope enforcement.
	allowed, _ := scope.CheckTarget("https", "app.target.com", 443, "/")
	if !allowed {
		t.Error("expected app.target.com:443 to be allowed by target scope")
	}
	allowed, _ = scope.CheckTarget("https", "blocked.target.com", 443, "/")
	if allowed {
		t.Error("expected blocked.target.com to be denied by target scope")
	}

	// Verify RateLimiter enforcement.
	limits := rl.PolicyLimits()
	if limits.MaxRequestsPerSecond != 10 {
		t.Errorf("MaxRequestsPerSecond = %f, want 10", limits.MaxRequestsPerSecond)
	}
	if limits.MaxRequestsPerHostPerSecond != 5 {
		t.Errorf("MaxRequestsPerHostPerSecond = %f, want 5", limits.MaxRequestsPerHostPerSecond)
	}
	if !rl.HasLimits() {
		t.Error("expected HasLimits to return true")
	}
}

// --- Error cases ---

// TestPolicyFileE2E_InvalidJSON verifies that a malformed JSON policy file
// produces a clear error through the loadConfigs chain.
func TestPolicyFileE2E_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "bad.json")
	writeTestFile(t, policyPath, `{not valid json}`)

	_, err := loadConfigs("", policyPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON policy file")
	}
}

// TestPolicyFileE2E_EmptyPolicyFile verifies that an empty policy object
// results in nil TargetScope (no rules to enforce).
func TestPolicyFileE2E_EmptyPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "empty.json")
	writeTestFile(t, policyPath, `{}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}
	if result.targetScopePolicy == nil {
		t.Fatal("expected non-nil targetScopePolicy even for empty object")
	}

	logger := testLogger(t)
	socks5Handler := newTestSOCKS5Handler(t, logger)

	// initTargetScope with no allows/denies should still return a scope
	// (but with no rules, it allows everything).
	scope := initTargetScope(result.targetScopePolicy, socks5Handler)
	if scope == nil {
		t.Fatal("expected non-nil scope for empty policy")
	}

	// With no rules, everything should be allowed.
	allowed, _ := scope.CheckTarget("https", "any.com", 443, "/")
	if !allowed {
		t.Error("expected all targets to be allowed with empty policy")
	}

	// RateLimiter should have no limits.
	rl := initRateLimiter(result.targetScopePolicy, logger)
	if rl.HasLimits() {
		t.Error("expected no rate limits with empty policy")
	}
}

// TestPolicyFileE2E_NonexistentFile verifies error handling for missing policy file.
func TestPolicyFileE2E_NonexistentFile(t *testing.T) {
	_, err := loadConfigs("", "/nonexistent/path/policy.json")
	if err == nil {
		t.Fatal("expected error for nonexistent policy file")
	}
}

// --- RateLimiter: agent limits within policy from file ---

// TestPolicyFileE2E_RateLimiter_AgentWithinPolicyFromFile verifies that agent
// rate limits set at runtime must be within the policy limits loaded from a file.
func TestPolicyFileE2E_RateLimiter_AgentWithinPolicyFromFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeTestFile(t, policyPath, `{
		"rate_limits": {
			"max_requests_per_second": 100,
			"max_requests_per_host_per_second": 10
		}
	}`)

	result, err := loadConfigs("", policyPath)
	if err != nil {
		t.Fatalf("loadConfigs: %v", err)
	}

	logger := testLogger(t)
	rl := initRateLimiter(result.targetScopePolicy, logger)

	// Agent can set stricter limits.
	err = rl.SetAgentLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond:        50,
		MaxRequestsPerHostPerSecond: 5,
	})
	if err != nil {
		t.Fatalf("SetAgentLimits (stricter): %v", err)
	}
	effective := rl.EffectiveLimits()
	if effective.MaxRequestsPerSecond != 50 {
		t.Errorf("effective global = %f, want 50", effective.MaxRequestsPerSecond)
	}
	if effective.MaxRequestsPerHostPerSecond != 5 {
		t.Errorf("effective per-host = %f, want 5", effective.MaxRequestsPerHostPerSecond)
	}

	// Agent cannot exceed policy limits.
	err = rl.SetAgentLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 200,
	})
	if err == nil {
		t.Fatal("expected error when agent exceeds policy global limit from file")
	}

	err = rl.SetAgentLimits(proxy.RateLimitConfig{
		MaxRequestsPerHostPerSecond: 20,
	})
	if err == nil {
		t.Fatal("expected error when agent exceeds policy per-host limit from file")
	}
}
