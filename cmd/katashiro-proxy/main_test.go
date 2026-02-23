package main

import (
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
			name: "both paths empty generates ephemeral CA",
			setup: func(t *testing.T) *config.Config {
				t.Helper()
				return &config.Config{}
			},
			wantErr: false,
			wantCA:  true,
		},
		{
			name: "both paths set with valid files loads CA",
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
