package mcpserver

import (
	"crypto/sha256"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
)

func TestInitCA(t *testing.T) {
	// Helper: generate and save a valid CA to temporary files.
	setupValidCA := func(t *testing.T) (certPath, keyPath string) {
		t.Helper()
		dir := t.TempDir()
		certPath = filepath.Join(dir, "ca.crt")
		keyPath = filepath.Join(dir, "ca.key")

		ca := &cert.CA{}
		if err := ca.Generate(); err != nil {
			t.Fatalf("generate test CA: %v", err)
		}
		if err := ca.Save(certPath, keyPath); err != nil {
			t.Fatalf("save test CA: %v", err)
		}
		return certPath, keyPath
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name      string
		setup     func(t *testing.T) *config.Config
		wantErr   bool
		errSubstr string
		wantCA    bool // expect a non-nil CA with valid certificate
	}{
		{
			name: "both paths set with valid files loads CA (explicit mode)",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				certPath, keyPath := setupValidCA(t)
				return &config.Config{
					CACertPath: certPath,
					CAKeyPath:  keyPath,
				}
			},
			wantErr: false,
			wantCA:  true,
		},
		{
			name: "both paths set with invalid files returns error",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				dir := t.TempDir()
				certPath := filepath.Join(dir, "bad.crt")
				keyPath := filepath.Join(dir, "bad.key")
				if err := os.WriteFile(certPath, []byte("not a cert"), 0644); err != nil {
					t.Fatalf("write bad cert: %v", err)
				}
				if err := os.WriteFile(keyPath, []byte("not a key"), 0600); err != nil {
					t.Fatalf("write bad key: %v", err)
				}
				return &config.Config{
					CACertPath: certPath,
					CAKeyPath:  keyPath,
				}
			},
			wantErr: true,
		},
		{
			name: "only ca-cert set returns error",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				return &config.Config{
					CACertPath: "/some/cert.pem",
				}
			},
			wantErr:   true,
			errSubstr: "both -ca-cert and -ca-key must be specified together",
		},
		{
			name: "only ca-key set returns error",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				return &config.Config{
					CAKeyPath: "/some/key.pem",
				}
			},
			wantErr:   true,
			errSubstr: "both -ca-cert and -ca-key must be specified together",
		},
		{
			name: "ephemeral mode generates in-memory CA",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				return &config.Config{
					CAEphemeral: true,
				}
			},
			wantErr: false,
			wantCA:  true,
		},
		{
			name: "ephemeral with explicit paths returns error",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				return &config.Config{
					CACertPath:  "/some/cert.pem",
					CAKeyPath:   "/some/key.pem",
					CAEphemeral: true,
				}
			},
			wantErr:   true,
			errSubstr: "--ca-ephemeral cannot be used with -ca-cert/-ca-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setup(t)
			ca, err := InitCA(cfg, logger)

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

			if tt.wantCA {
				if ca == nil {
					t.Fatal("expected non-nil CA, got nil")
				}
				if ca.Certificate() == nil {
					t.Fatal("CA.Certificate() returned nil")
				}
				if ca.CertPEM() == nil {
					t.Fatal("CA.CertPEM() returned nil")
				}
			}
		})
	}
}

func TestInitCA_ExplicitMode_SetsSource(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	original := &cert.CA{}
	if err := original.Generate(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := original.Save(certPath, keyPath); err != nil {
		t.Fatalf("save: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &config.Config{
		CACertPath: certPath,
		CAKeyPath:  keyPath,
	}

	ca, err := InitCA(cfg, logger)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	source := ca.Source()
	if !source.Persisted {
		t.Error("expected Persisted=true for explicit mode")
	}
	if source.CertPath != certPath {
		t.Errorf("CertPath = %q, want %q", source.CertPath, certPath)
	}
	if source.KeyPath != keyPath {
		t.Errorf("KeyPath = %q, want %q", source.KeyPath, keyPath)
	}
	if !source.Explicit {
		t.Error("expected Explicit=true for explicit mode")
	}
}

func TestInitCA_EphemeralMode_SourceNotPersisted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &config.Config{
		CAEphemeral: true,
	}

	ca, err := InitCA(cfg, logger)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	source := ca.Source()
	if source.Persisted {
		t.Error("expected Persisted=false for ephemeral mode")
	}
	if source.CertPath != "" {
		t.Errorf("CertPath = %q, want empty for ephemeral mode", source.CertPath)
	}
}

func TestInitCA_AutoPersist_FirstRun(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &config.Config{
		CADataDir: dir,
	}

	ca, err := InitCA(cfg, logger)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	if ca.Certificate() == nil {
		t.Fatal("CA.Certificate() returned nil")
	}

	source := ca.Source()
	if !source.Persisted {
		t.Error("expected Persisted=true for auto-persist mode")
	}

	expectedCertPath := filepath.Join(dir, "ca.crt")
	expectedKeyPath := filepath.Join(dir, "ca.key")
	if source.CertPath != expectedCertPath {
		t.Errorf("CertPath = %q, want %q", source.CertPath, expectedCertPath)
	}

	// Verify files were created.
	if _, err := os.Stat(expectedCertPath); err != nil {
		t.Errorf("CA cert file not created: %v", err)
	}
	if _, err := os.Stat(expectedKeyPath); err != nil {
		t.Errorf("CA key file not created: %v", err)
	}
}

func TestInitCA_AutoPersist_SecondRun(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &config.Config{
		CADataDir: dir,
	}

	// First run: generate and save.
	ca1, err := InitCA(cfg, logger)
	if err != nil {
		t.Fatalf("first InitCA: %v", err)
	}
	fingerprint1 := sha256.Sum256(ca1.Certificate().Raw)

	// Second run: should load the same CA.
	ca2, err := InitCA(cfg, logger)
	if err != nil {
		t.Fatalf("second InitCA: %v", err)
	}
	fingerprint2 := sha256.Sum256(ca2.Certificate().Raw)

	if fingerprint1 != fingerprint2 {
		t.Error("second InitCA loaded a different CA than the first; expected same fingerprint")
	}

	source := ca2.Source()
	if !source.Persisted {
		t.Error("expected Persisted=true on second run")
	}
}

func TestInitCA_AutoPersist_SaveFailureFallback(t *testing.T) {
	// Use a non-writable directory to simulate save failure.
	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readOnlyDir, 0500); err != nil {
		t.Fatalf("create read-only dir: %v", err)
	}
	t.Cleanup(func() {
		os.Chmod(readOnlyDir, 0700) // allow cleanup
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &config.Config{
		CADataDir: filepath.Join(readOnlyDir, "subdir"),
	}

	ca, err := InitCA(cfg, logger)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	// CA should be generated successfully even if save fails.
	if ca.Certificate() == nil {
		t.Fatal("CA.Certificate() returned nil")
	}

	// Source should not be persisted since save failed.
	source := ca.Source()
	if source.Persisted {
		t.Error("expected Persisted=false when save fails")
	}
}

func TestApplyEnvFallback_Priority(t *testing.T) {
	// Table-driven tests for env var fallback with priority:
	// CLI flag > env var > default value.
	tests := []struct {
		name     string
		flagArgs []string
		envVars  map[string]string
		field    string
		want     string
	}{
		{
			name:  "default value when no flag or env",
			field: "LogLevel",
			want:  "info",
		},
		{
			name:    "env var overrides default",
			envVars: map[string]string{"YP_LOG_LEVEL": "debug"},
			field:   "LogLevel",
			want:    "debug",
		},
		{
			name:     "flag overrides env var",
			flagArgs: []string{"-log-level", "error"},
			envVars:  map[string]string{"YP_LOG_LEVEL": "debug"},
			field:    "LogLevel",
			want:     "error",
		},
		{
			name:     "flag overrides default",
			flagArgs: []string{"-log-level", "warn"},
			field:    "LogLevel",
			want:     "warn",
		},
		{
			name:    "db env var fallback",
			envVars: map[string]string{"YP_DB": "/tmp/test.db"},
			field:   "DBPath",
			want:    "/tmp/test.db",
		},
		{
			name:     "db flag overrides env",
			flagArgs: []string{"-db", "/opt/db.sqlite"},
			envVars:  map[string]string{"YP_DB": "/tmp/test.db"},
			field:    "DBPath",
			want:     "/opt/db.sqlite",
		},
		{
			name:    "log-format env var fallback",
			envVars: map[string]string{"YP_LOG_FORMAT": "json"},
			field:   "LogFormat",
			want:    "json",
		},
		{
			name:    "log-file env var fallback",
			envVars: map[string]string{"YP_LOG_FILE": "/var/log/proxy.log"},
			field:   "LogFile",
			want:    "/var/log/proxy.log",
		},
		{
			name:    "ca-cert env var fallback",
			envVars: map[string]string{"YP_CA_CERT": "/certs/ca.crt"},
			field:   "CACertPath",
			want:    "/certs/ca.crt",
		},
		{
			name:    "ca-key env var fallback",
			envVars: map[string]string{"YP_CA_KEY": "/certs/ca.key"},
			field:   "CAKeyPath",
			want:    "/certs/ca.key",
		},
		{
			name:    "mcp-http-addr env var fallback",
			envVars: map[string]string{"YP_MCP_HTTP_ADDR": "127.0.0.1:3000"},
			field:   "MCPHTTPAddr",
			want:    "127.0.0.1:3000",
		},
		{
			name:    "mcp-http-token env var fallback",
			envVars: map[string]string{"YP_MCP_HTTP_TOKEN": "secret-token"},
			field:   "MCPHTTPToken",
			want:    "secret-token",
		},
		{
			name:    "ui-dir env var fallback",
			envVars: map[string]string{"YP_UI_DIR": "/tmp/webui"},
			field:   "UIDir",
			want:    "/tmp/webui",
		},
		{
			name:     "ui-dir flag overrides env",
			flagArgs: []string{"-ui-dir", "/opt/ui"},
			envVars:  map[string]string{"YP_UI_DIR": "/tmp/webui"},
			field:    "UIDir",
			want:     "/opt/ui",
		},
		{
			name:    "empty env var does not override default",
			envVars: map[string]string{"YP_LOG_LEVEL": ""},
			field:   "LogLevel",
			want:    "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			cfg := config.Default()
			registerFlags(fs, cfg)

			if err := fs.Parse(tt.flagArgs); err != nil {
				t.Fatalf("flag.Parse: %v", err)
			}

			ApplyEnvFallback(fs)

			got := getStringConfigField(cfg, tt.field)
			if got != tt.want {
				t.Errorf("%s = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

func TestApplyEnvFallback_BoolFlags(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		envValue string
		field    string
		want     bool
	}{
		{"insecure true", "YP_INSECURE", "true", "InsecureSkipVerify", true},
		{"insecure false", "YP_INSECURE", "false", "InsecureSkipVerify", false},
		{"insecure 1", "YP_INSECURE", "1", "InsecureSkipVerify", true},
		{"insecure 0", "YP_INSECURE", "0", "InsecureSkipVerify", false},
		{"ca-ephemeral true", "YP_CA_EPHEMERAL", "true", "CAEphemeral", true},
		{"ca-ephemeral TRUE", "YP_CA_EPHEMERAL", "TRUE", "CAEphemeral", true},
		{"ca-ephemeral false", "YP_CA_EPHEMERAL", "false", "CAEphemeral", false},
		{"insecure invalid", "YP_INSECURE", "invalid", "InsecureSkipVerify", false},
		{"ca-ephemeral 0", "YP_CA_EPHEMERAL", "0", "CAEphemeral", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envVar, tt.envValue)

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			cfg := config.Default()
			registerFlags(fs, cfg)

			if err := fs.Parse(nil); err != nil {
				t.Fatalf("flag.Parse: %v", err)
			}

			ApplyEnvFallback(fs)

			got := getBoolConfigField(cfg, tt.field)
			if got != tt.want {
				t.Errorf("%s = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestDeprecatedFlagsNotRegistered(t *testing.T) {
	deprecatedFlags := []string{
		"stdio",
		"listen",
		"max-connections",
		"peek-timeout",
		"request-timeout",
		"retention-max-sessions",
		"retention-max-age",
		"cleanup-interval",
	}

	// registerFlags is the exact registration mcpserver.Run performs.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	registerFlags(fs, cfg)
	if fs.Lookup("db") == nil {
		t.Fatal("registerFlags did not register -db; the flag set under test is not the production one")
	}

	for _, name := range deprecatedFlags {
		if f := fs.Lookup(name); f != nil {
			t.Errorf("deprecated flag %q should not be registered, but found: %v", name, f.Usage)
		}
	}
}

// TestEnvVarMap_AllFlagsHaveMapping pins that EnvVarMap and the flags
// mcpserver.Run actually registers are the same set: every registered flag
// has a YP_ env var, and every EnvVarMap entry names a registered flag.
func TestEnvVarMap_AllFlagsHaveMapping(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	registerFlags(fs, cfg)

	registered := 0
	fs.VisitAll(func(f *flag.Flag) {
		registered++
		env, ok := EnvVarMap[f.Name]
		if !ok {
			t.Errorf("flag %q has no entry in EnvVarMap", f.Name)
			return
		}
		if !strings.HasPrefix(env, "YP_") {
			t.Errorf("EnvVarMap[%q] = %q, want a YP_ prefixed name", f.Name, env)
		}
	})
	if registered == 0 {
		t.Fatal("registerFlags registered no flags")
	}
	for name := range EnvVarMap {
		if fs.Lookup(name) == nil {
			t.Errorf("EnvVarMap has %q but no such flag is registered", name)
		}
	}
}

// getStringConfigField returns the string value of a named config field.
func getStringConfigField(cfg *config.Config, field string) string {
	switch field {
	case "DBPath":
		return cfg.DBPath
	case "LogLevel":
		return cfg.LogLevel
	case "LogFormat":
		return cfg.LogFormat
	case "LogFile":
		return cfg.LogFile
	case "CACertPath":
		return cfg.CACertPath
	case "CAKeyPath":
		return cfg.CAKeyPath
	case "MCPHTTPAddr":
		return cfg.MCPHTTPAddr
	case "MCPHTTPToken":
		return cfg.MCPHTTPToken
	case "UIDir":
		return cfg.UIDir
	default:
		return ""
	}
}

// getBoolConfigField returns the bool value of a named config field.
func getBoolConfigField(cfg *config.Config, field string) bool {
	switch field {
	case "InsecureSkipVerify":
		return cfg.InsecureSkipVerify
	case "CAEphemeral":
		return cfg.CAEphemeral
	default:
		return false
	}
}

func TestConfigFlag_EnvVarFallback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"listen_addr": "127.0.0.1:9090"}`), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("YP_CONFIG", cfgPath)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	flags := registerFlags(fs, cfg)

	if err := fs.Parse(nil); err != nil {
		t.Fatalf("flag.Parse: %v", err)
	}

	ApplyEnvFallback(fs)

	if flags.configFile != cfgPath {
		t.Errorf("configFile = %q, want %q", flags.configFile, cfgPath)
	}
}

func TestConfigFlag_CLIOverridesEnvVar(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "env.json")
	flagPath := filepath.Join(dir, "flag.json")
	if err := os.WriteFile(envPath, []byte(`{"listen_addr": "127.0.0.1:9090"}`), 0644); err != nil {
		t.Fatalf("write env config: %v", err)
	}
	if err := os.WriteFile(flagPath, []byte(`{"listen_addr": "127.0.0.1:7070"}`), 0644); err != nil {
		t.Fatalf("write flag config: %v", err)
	}

	t.Setenv("YP_CONFIG", envPath)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	flags := registerFlags(fs, cfg)

	if err := fs.Parse([]string{"-config", flagPath}); err != nil {
		t.Fatalf("flag.Parse: %v", err)
	}

	ApplyEnvFallback(fs)

	// CLI flag should take precedence over YP_CONFIG env var.
	if flags.configFile != flagPath {
		t.Errorf("configFile = %q, want %q (CLI should override env)", flags.configFile, flagPath)
	}
}

func TestConfigFlag_FileNotFound(t *testing.T) {
	// Verify that LoadFile returns an error for nonexistent paths.
	_, err := config.LoadFile("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected error for nonexistent config file, got nil")
	}
}

func TestTargetPolicyFileFlag_EnvVarFallback(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"allows": [{"hostname": "example.com"}]}`), 0644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	t.Setenv("YP_TARGET_POLICY_FILE", policyPath)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	flags := registerFlags(fs, cfg)

	if err := fs.Parse(nil); err != nil {
		t.Fatalf("flag.Parse: %v", err)
	}

	ApplyEnvFallback(fs)

	if flags.targetPolicyFile != policyPath {
		t.Errorf("targetPolicyFile = %q, want %q", flags.targetPolicyFile, policyPath)
	}
}

func TestTargetPolicyFileFlag_CLIOverridesEnvVar(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "env-policy.json")
	flagPath := filepath.Join(dir, "flag-policy.json")
	if err := os.WriteFile(envPath, []byte(`{"allows": [{"hostname": "env.com"}]}`), 0644); err != nil {
		t.Fatalf("write env policy file: %v", err)
	}
	if err := os.WriteFile(flagPath, []byte(`{"allows": [{"hostname": "flag.com"}]}`), 0644); err != nil {
		t.Fatalf("write flag policy file: %v", err)
	}

	t.Setenv("YP_TARGET_POLICY_FILE", envPath)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	flags := registerFlags(fs, cfg)

	if err := fs.Parse([]string{"-target-policy-file", flagPath}); err != nil {
		t.Fatalf("flag.Parse: %v", err)
	}

	ApplyEnvFallback(fs)

	// CLI flag should take precedence over YP_TARGET_POLICY_FILE env var.
	if flags.targetPolicyFile != flagPath {
		t.Errorf("targetPolicyFile = %q, want %q (CLI should override env)", flags.targetPolicyFile, flagPath)
	}
}

func TestConvertTargetRules(t *testing.T) {
	tests := []struct {
		name  string
		input []config.TargetRuleConfig
		want  int // expected number of converted rules
	}{
		{
			name:  "nil input",
			input: nil,
			want:  0,
		},
		{
			name:  "empty input",
			input: []config.TargetRuleConfig{},
			want:  0,
		},
		{
			name: "single rule with all fields",
			input: []config.TargetRuleConfig{
				{
					Hostname:   "*.target.com",
					Ports:      []int{80, 443},
					PathPrefix: "/api/",
					Schemes:    []string{"https"},
				},
			},
			want: 1,
		},
		{
			name: "multiple rules",
			input: []config.TargetRuleConfig{
				{Hostname: "example.com"},
				{Hostname: "*.target.com", Ports: []int{443}},
				{Hostname: "api.staging.com", PathPrefix: "/v2/"},
			},
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertTargetRules(tt.input)
			if len(got) != tt.want {
				t.Fatalf("ConvertTargetRules() returned %d rules, want %d", len(got), tt.want)
			}
		})
	}
}

func TestConvertTargetRules_FieldMapping(t *testing.T) {
	input := []config.TargetRuleConfig{
		{
			Hostname:   "*.target.com",
			Ports:      []int{80, 443},
			PathPrefix: "/api/v1/",
			Schemes:    []string{"http", "https"},
		},
	}

	got := ConvertTargetRules(input)
	if len(got) != 1 {
		t.Fatalf("ConvertTargetRules() returned %d rules, want 1", len(got))
	}

	rule := got[0]
	if rule.Hostname != "*.target.com" {
		t.Errorf("Hostname = %q, want %q", rule.Hostname, "*.target.com")
	}
	if len(rule.Ports) != 2 || rule.Ports[0] != 80 || rule.Ports[1] != 443 {
		t.Errorf("Ports = %v, want [80 443]", rule.Ports)
	}
	if rule.PathPrefix != "/api/v1/" {
		t.Errorf("PathPrefix = %q, want %q", rule.PathPrefix, "/api/v1/")
	}
	if len(rule.Schemes) != 2 || rule.Schemes[0] != "http" || rule.Schemes[1] != "https" {
		t.Errorf("Schemes = %v, want [http https]", rule.Schemes)
	}
}

func TestOpenBrowserFlag(t *testing.T) {
	tests := []struct {
		name     string
		flagArgs []string
		envVars  map[string]string
		want     bool
	}{
		{
			name: "default is false (browser not opened)",
			want: false,
		},
		{
			name:     "flag sets true",
			flagArgs: []string{"-open-browser"},
			want:     true,
		},
		{
			name:    "env var sets true",
			envVars: map[string]string{"YP_OPEN_BROWSER": "true"},
			want:    true,
		},
		{
			name:    "env var sets 1",
			envVars: map[string]string{"YP_OPEN_BROWSER": "1"},
			want:    true,
		},
		{
			name:    "env var sets false",
			envVars: map[string]string{"YP_OPEN_BROWSER": "false"},
			want:    false,
		},
		{
			name:     "flag overrides env var false",
			flagArgs: []string{"-open-browser"},
			envVars:  map[string]string{"YP_OPEN_BROWSER": "false"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var openBrowser bool
			fs.BoolVar(&openBrowser, "open-browser", false, "")

			if err := fs.Parse(tt.flagArgs); err != nil {
				t.Fatalf("flag.Parse: %v", err)
			}

			ApplyEnvFallback(fs)

			if openBrowser != tt.want {
				t.Errorf("open-browser = %v, want %v", openBrowser, tt.want)
			}
		})
	}
}

func TestStdioMCPFlag(t *testing.T) {
	tests := []struct {
		name     string
		flagArgs []string
		envVars  map[string]string
		want     bool
	}{
		{
			name: "default is false",
			want: false,
		},
		{
			name:     "flag sets true",
			flagArgs: []string{"-stdio-mcp"},
			want:     true,
		},
		{
			name:    "env var sets true",
			envVars: map[string]string{"YP_STDIO_MCP": "true"},
			want:    true,
		},
		{
			name:    "env var sets false",
			envVars: map[string]string{"YP_STDIO_MCP": "false"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var stdioMCP bool
			fs.BoolVar(&stdioMCP, "stdio-mcp", false, "")

			if err := fs.Parse(tt.flagArgs); err != nil {
				t.Fatalf("flag.Parse: %v", err)
			}

			ApplyEnvFallback(fs)

			if stdioMCP != tt.want {
				t.Errorf("stdio-mcp = %v, want %v", stdioMCP, tt.want)
			}
		})
	}
}

func TestNoHTTPMCPFlag(t *testing.T) {
	tests := []struct {
		name     string
		flagArgs []string
		envVars  map[string]string
		want     bool
	}{
		{
			name: "default is false (HTTP MCP enabled)",
			want: false,
		},
		{
			name:     "flag sets true",
			flagArgs: []string{"-no-http-mcp"},
			want:     true,
		},
		{
			name:    "env var sets true",
			envVars: map[string]string{"YP_NO_HTTP_MCP": "true"},
			want:    true,
		},
		{
			name:    "env var sets false",
			envVars: map[string]string{"YP_NO_HTTP_MCP": "false"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var noHTTPMCP bool
			fs.BoolVar(&noHTTPMCP, "no-http-mcp", false, "")

			if err := fs.Parse(tt.flagArgs); err != nil {
				t.Fatalf("flag.Parse: %v", err)
			}

			ApplyEnvFallback(fs)

			if noHTTPMCP != tt.want {
				t.Errorf("no-http-mcp = %v, want %v", noHTTPMCP, tt.want)
			}
		})
	}
}
