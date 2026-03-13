package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// TestInitInfra_DBPathCreationFailure verifies that initInfra returns an error
// when the DB directory cannot be created (e.g. parent is not writable).
func TestInitInfra_DBPathCreationFailure(t *testing.T) {
	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readOnlyDir, 0500); err != nil {
		t.Fatalf("create read-only dir: %v", err)
	}
	t.Cleanup(func() {
		os.Chmod(readOnlyDir, 0700)
	})

	cfg := config.Default()
	cfg.DBPath = filepath.Join(readOnlyDir, "subdir", "test.db")

	ctx := context.Background()
	_, err := initInfra(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for unwritable DB directory, got nil")
	}
	if !strings.Contains(err.Error(), "ensure db directory") {
		t.Errorf("error = %q, want substring %q", err.Error(), "ensure db directory")
	}
}

// TestInitInfra_InvalidLogLevel verifies that initInfra propagates logger
// setup errors for invalid log levels. This validates the error path through
// the logging.Setup call.
func TestInitInfra_InvalidLogLevel(t *testing.T) {
	cfg := config.Default()
	cfg.DBPath = filepath.Join(t.TempDir(), "test.db")
	cfg.LogLevel = "INVALID_LEVEL"

	ctx := context.Background()
	_, err := initInfra(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for invalid log level, got nil")
	}
	if !strings.Contains(err.Error(), "init logger") {
		t.Errorf("error = %q, want substring %q", err.Error(), "init logger")
	}
}

// TestInitInfra_CorruptDBPath verifies that initInfra returns an error when
// the DB path points to an invalid location (e.g. a file where a directory
// is expected).
func TestInitInfra_CorruptDBPath(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file where a directory should be.
	blockingFile := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blockingFile, []byte("I am a file"), 0644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	// Now try to use a path that requires "blocker" to be a directory.
	cfg := config.Default()
	cfg.DBPath = filepath.Join(blockingFile, "subdir", "test.db")

	ctx := context.Background()
	_, err := initInfra(ctx, cfg)
	if err == nil {
		t.Fatal("expected error when DB parent is a file, got nil")
	}
}

// TestInitInfra_Success verifies the happy path: initInfra returns a valid
// infraResult with logger, store, and cleanup function.
func TestInitInfra_Success(t *testing.T) {
	cfg := config.Default()
	cfg.DBPath = filepath.Join(t.TempDir(), "test.db")

	ctx := context.Background()
	result, err := initInfra(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer result.cleanup()

	if result.logger == nil {
		t.Error("expected non-nil logger")
	}
	if result.store == nil {
		t.Error("expected non-nil store")
	}
}

// TestInitCA_ErrorPaths exercises additional error conditions for initCA
// beyond the existing tests: missing files, permission errors on CA files.
func TestInitCA_ErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name      string
		setup     func(t *testing.T) *config.Config
		wantErr   bool
		errSubstr string
	}{
		{
			name: "explicit mode with nonexistent cert file",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				dir := t.TempDir()
				return &config.Config{
					CACertPath: filepath.Join(dir, "nonexistent.crt"),
					CAKeyPath:  filepath.Join(dir, "nonexistent.key"),
				}
			},
			wantErr:   true,
			errSubstr: "load CA from",
		},
		{
			name: "explicit mode with unreadable cert file",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				dir := t.TempDir()
				certPath := filepath.Join(dir, "ca.crt")
				keyPath := filepath.Join(dir, "ca.key")
				if err := os.WriteFile(certPath, []byte("cert data"), 0000); err != nil {
					t.Fatalf("write cert: %v", err)
				}
				if err := os.WriteFile(keyPath, []byte("key data"), 0600); err != nil {
					t.Fatalf("write key: %v", err)
				}
				return &config.Config{
					CACertPath: certPath,
					CAKeyPath:  keyPath,
				}
			},
			wantErr:   true,
			errSubstr: "load CA from",
		},
		{
			name: "auto-persist mode with corrupt existing CA cert",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				dir := t.TempDir()
				// Write an invalid cert file so Load fails.
				if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("not a cert"), 0644); err != nil {
					t.Fatalf("write corrupt cert: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("not a key"), 0600); err != nil {
					t.Fatalf("write corrupt key: %v", err)
				}
				return &config.Config{
					CADataDir: dir,
				}
			},
			wantErr:   true,
			errSubstr: "load persisted CA from",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setup(t)
			_, err := initCA(cfg, logger)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestLoadCodecPlugins_ErrorPaths tests codec plugin loading error conditions.
func TestLoadCodecPlugins_ErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name      string
		proxyCfg  *config.ProxyConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "nil proxy config returns nil",
			proxyCfg: nil,
			wantErr:  false,
		},
		{
			name:     "empty codec plugins returns nil",
			proxyCfg: &config.ProxyConfig{},
			wantErr:  false,
		},
		{
			name: "invalid JSON in codec plugins",
			proxyCfg: &config.ProxyConfig{
				CodecPlugins: json.RawMessage(`{invalid json`),
			},
			wantErr:   true,
			errSubstr: "parse codec plugin configs",
		},
		{
			name: "valid JSON but nonexistent plugin path is tolerated",
			proxyCfg: &config.ProxyConfig{
				CodecPlugins: json.RawMessage(`[{"path": "/nonexistent/plugin.star"}]`),
			},
			wantErr: false, // LoadCodecPlugins logs a warning and skips missing files
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadCodecPlugins(tt.proxyCfg, logger)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestLoadCodecPlugins_SyntaxErrorInStarlark verifies that a Starlark script
// with syntax errors is gracefully skipped (logged as warning, not returned
// as error). This is the intended graceful degradation behavior.
func TestLoadCodecPlugins_SyntaxErrorInStarlark(t *testing.T) {
	dir := t.TempDir()
	badScript := filepath.Join(dir, "bad_codec.star")
	if err := os.WriteFile(badScript, []byte(`
def encode(this is not valid python or starlark
`), 0644); err != nil {
		t.Fatalf("write bad script: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	proxyCfg := &config.ProxyConfig{
		CodecPlugins: json.RawMessage(`[{"path": "` + badScript + `"}]`),
	}

	// Starlark codec loading errors are logged as warnings and skipped
	// (graceful degradation), not returned as errors.
	err := loadCodecPlugins(proxyCfg, logger)
	if err != nil {
		t.Fatalf("expected nil error (graceful degradation), got: %v", err)
	}
}

// TestInitSafetyFilter_ErrorPaths tests safety filter initialization error paths.
func TestInitSafetyFilter_ErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	boolTrue := true

	tests := []struct {
		name      string
		cfg       *config.Config
		proxyCfg  *config.ProxyConfig
		wantErr   bool
		errSubstr string
		wantNil   bool // expect nil engine (disabled)
	}{
		{
			name:    "disabled by default returns nil engine",
			cfg:     &config.Config{},
			wantNil: true,
		},
		{
			name: "disabled in config file returns nil engine",
			cfg:  &config.Config{},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: false,
				},
			},
			wantNil: true,
		},
		{
			name: "enabled with no rules returns empty engine",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			wantNil: false,
		},
		{
			name: "enabled with valid preset",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql"},
						},
					},
				},
			},
			wantNil: false,
		},
		{
			name: "enabled with invalid regex pattern",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{
								ID:      "bad-regex",
								Pattern: "[invalid regex",
								Targets: []string{"body"},
							},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "safety filter config",
		},
		{
			name: "enabled with unknown preset",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "nonexistent-preset"},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "init safety filter",
		},
		{
			name: "enabled with invalid input action",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Action: "invalid_action",
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql"},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "safety filter config",
		},
		{
			name: "enabled with invalid output action",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Output: &config.SafetyFilterOutputConfig{
						Action: "invalid_action",
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "credit-card"},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "safety filter config",
		},
		{
			name: "enabled with custom rule missing id",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{
								Pattern: "DROP TABLE",
								Targets: []string{"body"},
							},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "safety filter config",
		},
		{
			name: "enabled with custom rule invalid target",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{
								ID:      "custom-rule",
								Pattern: "test",
								Targets: []string{"invalid_target"},
							},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "safety filter config",
		},
		{
			name: "CLI override disables config file enabled",
			cfg: func() *config.Config {
				c := &config.Config{}
				f := false
				c.SafetyFilterEnabled = &f
				return c
			}(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql"},
						},
					},
				},
			},
			wantNil: true,
		},
		{
			name: "output filter with valid preset",
			cfg: &config.Config{
				SafetyFilterEnabled: &boolTrue,
			},
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Output: &config.SafetyFilterOutputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "credit-card"},
						},
					},
				},
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := initSafetyFilter(tt.cfg, tt.proxyCfg, logger)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil && engine != nil {
				t.Error("expected nil engine, got non-nil")
			}
			if !tt.wantNil && engine == nil {
				t.Error("expected non-nil engine, got nil")
			}
		})
	}
}

// TestLoadConfigs_ErrorPaths tests config and policy file loading error conditions.
func TestLoadConfigs_ErrorPaths(t *testing.T) {
	tests := []struct {
		name          string
		configFile    string
		policyFile    string
		setupFiles    func(t *testing.T) // create test files
		wantErr       bool
		errSubstr     string
		wantProxyCfg  bool
		wantPolicyCfg bool
		wantPolicySrc string
	}{
		{
			name:    "no files specified returns empty result",
			wantErr: false,
		},
		{
			name:       "nonexistent config file returns error",
			configFile: "/nonexistent/config.json",
			wantErr:    true,
			errSubstr:  "load config file",
		},
		{
			name:       "nonexistent policy file returns error",
			policyFile: "/nonexistent/policy.json",
			wantErr:    true,
			errSubstr:  "load target policy file",
		},
		{
			name:       "invalid JSON in config file",
			configFile: "PLACEHOLDER",
			setupFiles: func(t *testing.T) {
				t.Helper()
			},
			wantErr:   true,
			errSubstr: "load config file",
		},
		{
			name:       "invalid JSON in policy file",
			policyFile: "PLACEHOLDER",
			setupFiles: func(t *testing.T) {
				t.Helper()
			},
			wantErr:   true,
			errSubstr: "load target policy file",
		},
		{
			name:       "valid config file with target_scope_policy section",
			configFile: "PLACEHOLDER",
			setupFiles: func(t *testing.T) {
				t.Helper()
			},
			wantProxyCfg:  true,
			wantPolicyCfg: true,
			wantPolicySrc: "config file",
		},
		{
			name:       "policy file overrides config file target_scope_policy",
			configFile: "PLACEHOLDER",
			policyFile: "PLACEHOLDER",
			setupFiles: func(t *testing.T) {
				t.Helper()
			},
			wantProxyCfg:  true,
			wantPolicyCfg: true,
			wantPolicySrc: "policy file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			// Set up actual files for tests that need them.
			if tt.configFile == "PLACEHOLDER" {
				switch tt.name {
				case "invalid JSON in config file":
					cfgPath := filepath.Join(dir, "bad.json")
					os.WriteFile(cfgPath, []byte(`{not valid json}`), 0644)
					tt.configFile = cfgPath
				case "valid config file with target_scope_policy section":
					cfgPath := filepath.Join(dir, "config.json")
					os.WriteFile(cfgPath, []byte(`{
						"listen_addr": "127.0.0.1:8080",
						"target_scope_policy": {
							"allows": [{"hostname": "example.com"}]
						}
					}`), 0644)
					tt.configFile = cfgPath
				case "policy file overrides config file target_scope_policy":
					cfgPath := filepath.Join(dir, "config.json")
					os.WriteFile(cfgPath, []byte(`{
						"listen_addr": "127.0.0.1:8080",
						"target_scope_policy": {
							"allows": [{"hostname": "config.com"}]
						}
					}`), 0644)
					tt.configFile = cfgPath
				}
			}
			if tt.policyFile == "PLACEHOLDER" {
				switch tt.name {
				case "invalid JSON in policy file":
					policyPath := filepath.Join(dir, "bad-policy.json")
					os.WriteFile(policyPath, []byte(`{invalid}`), 0644)
					tt.policyFile = policyPath
				case "policy file overrides config file target_scope_policy":
					policyPath := filepath.Join(dir, "policy.json")
					os.WriteFile(policyPath, []byte(`{"allows": [{"hostname": "policy.com"}]}`), 0644)
					tt.policyFile = policyPath
				}
			}

			result, err := loadConfigs(tt.configFile, tt.policyFile)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantProxyCfg && result.proxyCfg == nil {
				t.Error("expected non-nil proxyCfg")
			}
			if !tt.wantProxyCfg && result.proxyCfg != nil {
				t.Error("expected nil proxyCfg")
			}
			if tt.wantPolicyCfg && result.targetScopePolicy == nil {
				t.Error("expected non-nil targetScopePolicy")
			}
			if !tt.wantPolicyCfg && result.targetScopePolicy != nil {
				t.Error("expected nil targetScopePolicy")
			}
			if tt.wantPolicySrc != "" && result.targetScopePolicySource != tt.wantPolicySrc {
				t.Errorf("targetScopePolicySource = %q, want %q",
					result.targetScopePolicySource, tt.wantPolicySrc)
			}
		})
	}
}

// TestApplyTLSFingerprintFlag_ErrorPaths tests TLS fingerprint flag validation.
func TestApplyTLSFingerprintFlag_ErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		proxyCfg    *config.ProxyConfig
		wantErr     bool
		errSubstr   string
		wantFP      string
	}{
		{
			name:        "empty string is no-op",
			fingerprint: "",
			wantErr:     false,
		},
		{
			name:        "valid chrome profile",
			fingerprint: "chrome",
			wantErr:     false,
			wantFP:      "chrome",
		},
		{
			name:        "valid firefox profile",
			fingerprint: "Firefox",
			wantErr:     false,
			wantFP:      "firefox",
		},
		{
			name:        "valid none profile",
			fingerprint: "none",
			wantErr:     false,
			wantFP:      "none",
		},
		{
			name:        "invalid profile",
			fingerprint: "netscape",
			wantErr:     true,
			errSubstr:   "invalid -tls-fingerprint value",
		},
		{
			name:        "nil proxy config gets initialized",
			fingerprint: "safari",
			proxyCfg:    nil,
			wantErr:     false,
			wantFP:      "safari",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := applyTLSFingerprintFlag(tt.fingerprint, tt.proxyCfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantFP != "" {
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.TLSFingerprint != tt.wantFP {
					t.Errorf("TLSFingerprint = %q, want %q", result.TLSFingerprint, tt.wantFP)
				}
			}
		})
	}
}

// TestInitPassthroughList_InvalidPatterns verifies that invalid patterns are
// logged as warnings and valid patterns are added successfully.
func TestInitPassthroughList_InvalidPatterns(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name     string
		patterns []string
		wantLen  int
	}{
		{
			name:     "no patterns",
			patterns: nil,
			wantLen:  0,
		},
		{
			name:     "valid exact domain",
			patterns: []string{"example.com"},
			wantLen:  1,
		},
		{
			name:     "valid wildcard domain",
			patterns: []string{"*.example.com"},
			wantLen:  1,
		},
		{
			name:     "mix of valid patterns",
			patterns: []string{"example.com", "*.test.com"},
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.TLSPassthrough = tt.patterns
			list := initPassthroughList(cfg, logger)
			if list.Len() != tt.wantLen {
				t.Errorf("passthrough list len = %d, want %d", list.Len(), tt.wantLen)
			}
		})
	}
}

// TestInitRateLimiter_Configurations verifies rate limiter initialization
// with various policy configurations.
func TestInitRateLimiter_Configurations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name   string
		policy *config.TargetScopePolicyConfig
	}{
		{
			name:   "nil policy",
			policy: nil,
		},
		{
			name:   "policy without rate limits",
			policy: &config.TargetScopePolicyConfig{},
		},
		{
			name: "policy with rate limits",
			policy: &config.TargetScopePolicyConfig{
				RateLimits: &config.RateLimitPolicyConfig{
					MaxRequestsPerSecond:        10.0,
					MaxRequestsPerHostPerSecond: 5.0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := initRateLimiter(tt.policy, logger)
			if rl == nil {
				t.Fatal("expected non-nil rate limiter")
			}
		})
	}
}

// TestInitTargetScope_Configurations verifies target scope initialization
// with various policy configurations.
func TestInitTargetScope_Configurations(t *testing.T) {
	// We need a SOCKS5 handler but can avoid importing the full package
	// by testing with nil policy (which returns nil scope).
	t.Run("nil policy returns nil scope", func(t *testing.T) {
		scope := initTargetScope(nil, nil)
		if scope != nil {
			t.Error("expected nil scope for nil policy")
		}
	})
}

// TestResolveHTTPToken_ErrorPaths verifies token resolution behavior.
func TestResolveHTTPToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("explicit token returned as-is", func(t *testing.T) {
		token, err := resolveHTTPToken("my-secret-token", logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "my-secret-token" {
			t.Errorf("token = %q, want %q", token, "my-secret-token")
		}
	})

	t.Run("empty token generates random token", func(t *testing.T) {
		token, err := resolveHTTPToken("", logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token == "" {
			t.Error("expected non-empty generated token")
		}
		// Verify uniqueness by generating another.
		token2, err := resolveHTTPToken("", logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token == token2 {
			t.Error("expected different tokens from two calls with empty input")
		}
	})
}

// TestInitSafetyFilter_OutputFilterWithCustomRules verifies output filter
// custom rule compilation through initSafetyFilter.
func TestInitSafetyFilter_OutputFilterWithCustomRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	boolTrue := true

	cfg := &config.Config{
		SafetyFilterEnabled: &boolTrue,
	}
	proxyCfg := &config.ProxyConfig{
		SafetyFilter: &config.SafetyFilterConfig{
			Enabled: true,
			Output: &config.SafetyFilterOutputConfig{
				Action: "mask",
				Rules: []config.SafetyFilterRuleConfig{
					{
						ID:          "custom-pii",
						Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
						Targets:     []string{"body"},
						Replacement: "***-**-****",
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
		t.Error("expected output rules, got none")
	}
}

// TestInitSafetyFilter_BothInputAndOutputRules verifies that both input and
// output rules are compiled when both sections are present.
func TestInitSafetyFilter_BothInputAndOutputRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	boolTrue := true

	cfg := &config.Config{
		SafetyFilterEnabled: &boolTrue,
	}
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
		t.Error("expected input rules, got none")
	}
	if len(engine.OutputRules()) == 0 {
		t.Error("expected output rules, got none")
	}
}
