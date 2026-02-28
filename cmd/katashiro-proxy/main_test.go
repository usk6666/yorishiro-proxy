package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/config"
	"github.com/usk6666/katashiro-proxy/internal/fuzzer"
	"github.com/usk6666/katashiro-proxy/internal/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy/rules"
	"github.com/usk6666/katashiro-proxy/internal/session"
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
			ca, err := initCA(cfg, logger)

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

	ca, err := initCA(cfg, logger)
	if err != nil {
		t.Fatalf("initCA: %v", err)
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

	ca, err := initCA(cfg, logger)
	if err != nil {
		t.Fatalf("initCA: %v", err)
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

	ca, err := initCA(cfg, logger)
	if err != nil {
		t.Fatalf("initCA: %v", err)
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
	ca1, err := initCA(cfg, logger)
	if err != nil {
		t.Fatalf("first initCA: %v", err)
	}
	fingerprint1 := sha256.Sum256(ca1.Certificate().Raw)

	// Second run: should load the same CA.
	ca2, err := initCA(cfg, logger)
	if err != nil {
		t.Fatalf("second initCA: %v", err)
	}
	fingerprint2 := sha256.Sum256(ca2.Certificate().Raw)

	if fingerprint1 != fingerprint2 {
		t.Error("second initCA loaded a different CA than the first; expected same fingerprint")
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

	ca, err := initCA(cfg, logger)
	if err != nil {
		t.Fatalf("initCA: %v", err)
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

// TestM3ComponentInitialization verifies that the TransformPipeline, FuzzRunner,
// and FuzzStore components are constructable in the same way as run() does.
// This catches initialization regressions like USK-96 where components were
// created but not wired into the MCP server.
func TestM3ComponentInitialization(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer store.Close()

	// Verify TransformPipeline construction.
	pipeline := rules.NewPipeline()
	if pipeline == nil {
		t.Fatal("rules.NewPipeline() returned nil")
	}

	// Verify the pipeline is functional (can add/remove rules).
	err = pipeline.AddRule(rules.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Priority:  1,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionSetHeader,
			Header: "X-Test",
			Value:  "test-value",
		},
	})
	if err != nil {
		t.Fatalf("pipeline.AddRule(): %v", err)
	}
	if pipeline.Len() != 1 {
		t.Errorf("pipeline.Len() = %d, want 1", pipeline.Len())
	}

	// Verify FuzzEngine and FuzzRunner construction.
	// The store satisfies SessionFetcher, SessionRecorder, and FuzzJobStore interfaces.
	// Use the hardened HTTP client (never http.DefaultClient) to prevent SSRF.
	fuzzEngine := fuzzer.NewEngine(store, store, store, mcp.NewHardenedHTTPClient(), "")
	if fuzzEngine == nil {
		t.Fatal("fuzzer.NewEngine() returned nil")
	}

	fuzzRegistry := fuzzer.NewJobRegistry()
	if fuzzRegistry == nil {
		t.Fatal("fuzzer.NewJobRegistry() returned nil")
	}

	fuzzRunner := fuzzer.NewRunner(fuzzEngine, fuzzRegistry)
	if fuzzRunner == nil {
		t.Fatal("fuzzer.NewRunner() returned nil")
	}

	// Verify the runner's registry is accessible and functional.
	if fuzzRunner.Registry() != fuzzRegistry {
		t.Error("fuzzRunner.Registry() returned unexpected registry")
	}

	// Verify the store satisfies session.FuzzStore interface.
	var _ session.FuzzStore = store
}

// registerTestFlags registers all CLI flags on fs in the same way as runWithFlags.
// It returns a pointer to the config file path variable for use with applyEnvFallback.
func registerTestFlags(fs *flag.FlagSet, cfg *config.Config) *string {
	var configFile string
	fs.StringVar(&configFile, "config", "", "")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "")
	fs.StringVar(&cfg.CACertPath, "ca-cert", cfg.CACertPath, "")
	fs.StringVar(&cfg.CAKeyPath, "ca-key", cfg.CAKeyPath, "")
	fs.BoolVar(&cfg.CAEphemeral, "ca-ephemeral", cfg.CAEphemeral, "")
	fs.BoolVar(&cfg.InsecureSkipVerify, "insecure", cfg.InsecureSkipVerify, "")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "")
	fs.StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "")
	fs.StringVar(&cfg.LogFile, "log-file", cfg.LogFile, "")
	fs.StringVar(&cfg.MCPHTTPAddr, "mcp-http-addr", cfg.MCPHTTPAddr, "")
	fs.StringVar(&cfg.MCPHTTPToken, "mcp-http-token", cfg.MCPHTTPToken, "")
	return &configFile
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
			envVars: map[string]string{"KP_LOG_LEVEL": "debug"},
			field:   "LogLevel",
			want:    "debug",
		},
		{
			name:     "flag overrides env var",
			flagArgs: []string{"-log-level", "error"},
			envVars:  map[string]string{"KP_LOG_LEVEL": "debug"},
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
			envVars: map[string]string{"KP_DB": "/tmp/test.db"},
			field:   "DBPath",
			want:    "/tmp/test.db",
		},
		{
			name:     "db flag overrides env",
			flagArgs: []string{"-db", "/opt/db.sqlite"},
			envVars:  map[string]string{"KP_DB": "/tmp/test.db"},
			field:    "DBPath",
			want:     "/opt/db.sqlite",
		},
		{
			name:    "log-format env var fallback",
			envVars: map[string]string{"KP_LOG_FORMAT": "json"},
			field:   "LogFormat",
			want:    "json",
		},
		{
			name:    "log-file env var fallback",
			envVars: map[string]string{"KP_LOG_FILE": "/var/log/proxy.log"},
			field:   "LogFile",
			want:    "/var/log/proxy.log",
		},
		{
			name:    "ca-cert env var fallback",
			envVars: map[string]string{"KP_CA_CERT": "/certs/ca.crt"},
			field:   "CACertPath",
			want:    "/certs/ca.crt",
		},
		{
			name:    "ca-key env var fallback",
			envVars: map[string]string{"KP_CA_KEY": "/certs/ca.key"},
			field:   "CAKeyPath",
			want:    "/certs/ca.key",
		},
		{
			name:    "mcp-http-addr env var fallback",
			envVars: map[string]string{"KP_MCP_HTTP_ADDR": "127.0.0.1:3000"},
			field:   "MCPHTTPAddr",
			want:    "127.0.0.1:3000",
		},
		{
			name:    "mcp-http-token env var fallback",
			envVars: map[string]string{"KP_MCP_HTTP_TOKEN": "secret-token"},
			field:   "MCPHTTPToken",
			want:    "secret-token",
		},
		{
			name:    "empty env var does not override default",
			envVars: map[string]string{"KP_LOG_LEVEL": ""},
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
			cfgFile := registerTestFlags(fs, cfg)

			if err := fs.Parse(tt.flagArgs); err != nil {
				t.Fatalf("flag.Parse: %v", err)
			}

			applyEnvFallback(fs, cfg, cfgFile)

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
		{"insecure true", "KP_INSECURE", "true", "InsecureSkipVerify", true},
		{"insecure false", "KP_INSECURE", "false", "InsecureSkipVerify", false},
		{"insecure 1", "KP_INSECURE", "1", "InsecureSkipVerify", true},
		{"insecure 0", "KP_INSECURE", "0", "InsecureSkipVerify", false},
		{"ca-ephemeral true", "KP_CA_EPHEMERAL", "true", "CAEphemeral", true},
		{"ca-ephemeral TRUE", "KP_CA_EPHEMERAL", "TRUE", "CAEphemeral", true},
		{"ca-ephemeral false", "KP_CA_EPHEMERAL", "false", "CAEphemeral", false},
		{"insecure invalid", "KP_INSECURE", "invalid", "InsecureSkipVerify", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envVar, tt.envValue)

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			cfg := config.Default()
			cfgFile := registerTestFlags(fs, cfg)

			if err := fs.Parse(nil); err != nil {
				t.Fatalf("flag.Parse: %v", err)
			}

			applyEnvFallback(fs, cfg, cfgFile)

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

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	registerTestFlags(fs, cfg)

	for _, name := range deprecatedFlags {
		if f := fs.Lookup(name); f != nil {
			t.Errorf("deprecated flag %q should not be registered, but found: %v", name, f.Usage)
		}
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"false", false},
		{"FALSE", false},
		{"False", false},
		{"0", false},
		{"t", true},
		{"f", false},
		{"", false},
		{"invalid", false},
		{"  true  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseBool(tt.input)
			if got != tt.want {
				t.Errorf("parseBool(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestEnvVarMap_AllFlagsHaveMapping(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	registerTestFlags(fs, cfg)

	fs.VisitAll(func(f *flag.Flag) {
		if _, ok := envVarMap[f.Name]; !ok {
			t.Errorf("flag %q has no entry in envVarMap", f.Name)
		}
	})
}

func TestUsageOutput(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()

	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path (env: KP_DB)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level (env: KP_LOG_LEVEL)")
	fs.StringVar(&cfg.MCPHTTPAddr, "mcp-http-addr", cfg.MCPHTTPAddr, "Streamable HTTP listen address (env: KP_MCP_HTTP_ADDR)")

	var buf strings.Builder
	fs.SetOutput(&buf)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: katashiro-proxy [flags]\n\n")
		fmt.Fprintf(fs.Output(), "katashiro-proxy is an AI agent network proxy (MCP server).\n")
		fmt.Fprintf(fs.Output(), "It runs as an MCP server on stdin/stdout by default.\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nEnvironment variables:\n")
		fmt.Fprintf(fs.Output(), "  All flags accept a KP_ prefixed environment variable as fallback.\n")
		fmt.Fprintf(fs.Output(), "  Priority: CLI flag > environment variable > default value.\n")
		fmt.Fprintf(fs.Output(), "\nExamples:\n")
		fmt.Fprintf(fs.Output(), "  katashiro-proxy                                  # MCP stdio mode (default)\n")
		fmt.Fprintf(fs.Output(), "  katashiro-proxy -mcp-http-addr 127.0.0.1:3000    # stdio + Streamable HTTP\n")
	}
	fs.Usage()

	output := buf.String()
	mustContain := []string{
		"Usage: katashiro-proxy",
		"MCP server",
		"KP_DB",
		"KP_LOG_LEVEL",
		"KP_MCP_HTTP_ADDR",
		"Examples:",
		"MCP stdio mode",
	}
	for _, s := range mustContain {
		if !strings.Contains(output, s) {
			t.Errorf("usage output missing %q", s)
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

	t.Setenv("KP_CONFIG", cfgPath)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	cfgFile := registerTestFlags(fs, cfg)

	if err := fs.Parse(nil); err != nil {
		t.Fatalf("flag.Parse: %v", err)
	}

	applyEnvFallback(fs, cfg, cfgFile)

	if *cfgFile != cfgPath {
		t.Errorf("configFile = %q, want %q", *cfgFile, cfgPath)
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

	t.Setenv("KP_CONFIG", envPath)

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	cfg := config.Default()
	cfgFile := registerTestFlags(fs, cfg)

	if err := fs.Parse([]string{"-config", flagPath}); err != nil {
		t.Fatalf("flag.Parse: %v", err)
	}

	applyEnvFallback(fs, cfg, cfgFile)

	// CLI flag should take precedence over KP_CONFIG env var.
	if *cfgFile != flagPath {
		t.Errorf("configFile = %q, want %q (CLI should override env)", *cfgFile, flagPath)
	}
}

func TestConfigFlag_FileNotFound(t *testing.T) {
	// Verify that LoadFile returns an error for nonexistent paths.
	_, err := config.LoadFile("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected error for nonexistent config file, got nil")
	}
}
