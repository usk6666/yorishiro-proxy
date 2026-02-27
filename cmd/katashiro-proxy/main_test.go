package main

import (
	"crypto/sha256"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/config"
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
