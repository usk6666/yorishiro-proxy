package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
)

func TestCAInstallInstructions(t *testing.T) {
	certPath := "/home/user/.yorishiro-proxy/ca/ca.crt"
	quotedPath := "'" + certPath + "'"

	tests := []struct {
		name     string
		goos     string
		contains []string
	}{
		{
			name: "macOS instructions",
			goos: "darwin",
			contains: []string{
				"macOS",
				"security add-trusted-cert",
				quotedPath,
			},
		},
		{
			name: "Linux instructions",
			goos: "linux",
			contains: []string{
				"Linux",
				"/usr/share/ca-certificates/",
				"ca-certificates.conf",
				"update-ca-certificates",
				quotedPath,
			},
		},
		{
			name: "Windows instructions",
			goos: "windows",
			contains: []string{
				"Windows",
				"certutil",
				quotedPath,
			},
		},
		{
			name: "unknown OS instructions",
			goos: "plan9",
			contains: []string{
				"CA certificate path",
				certPath, // default case uses unquoted path for display
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := caInstallInstructionsForOS(certPath, tt.goos)
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("instructions for %s missing %q\ngot: %s", tt.goos, s, result)
				}
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple path",
			input: "/home/user/.yorishiro-proxy/ca/ca.crt",
			want:  "'/home/user/.yorishiro-proxy/ca/ca.crt'",
		},
		{
			name:  "path with spaces",
			input: "/home/my user/ca.crt",
			want:  "'/home/my user/ca.crt'",
		},
		{
			name:  "path with single quote",
			input: "/home/user's/ca.crt",
			want:  "'/home/user'\\''s/ca.crt'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "single byte",
			input: []byte{0xAB},
			want:  "AB",
		},
		{
			name:  "multiple bytes",
			input: []byte{0xAB, 0xCD, 0xEF, 0x01},
			want:  "AB:CD:EF:01",
		},
		{
			name:  "all zeros",
			input: []byte{0x00, 0x00},
			want:  "00:00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("formatFingerprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnsureCA_ExistingCA(t *testing.T) {
	// Set up a temporary CA directory to avoid touching the real one.
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatalf("create ca dir: %v", err)
	}

	// Generate and save a test CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("save CA: %v", err)
	}

	// EnsureCA with explicit caDir should load the existing CA.
	info, err := EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA() error: %v", err)
	}
	if info.Generated {
		t.Error("expected Generated=false for existing CA")
	}
	if info.CertPath != certPath {
		t.Errorf("CertPath = %q, want %q", info.CertPath, certPath)
	}
	if info.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestEnsureCA_NewCA(t *testing.T) {
	// Use an empty temp directory so EnsureCA generates a new CA.
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")

	info, err := EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA() error: %v", err)
	}
	if !info.Generated {
		t.Error("expected Generated=true for new CA")
	}
	if info.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Verify the files were created.
	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err != nil {
		t.Errorf("ca.crt not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.key")); err != nil {
		t.Errorf("ca.key not created: %v", err)
	}
}
