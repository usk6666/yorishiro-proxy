package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile_TLSFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected string
	}{
		{
			name:     "chrome",
			json:     `{"tls_fingerprint": "chrome"}`,
			expected: "chrome",
		},
		{
			name:     "firefox",
			json:     `{"tls_fingerprint": "firefox"}`,
			expected: "firefox",
		},
		{
			name:     "none",
			json:     `{"tls_fingerprint": "none"}`,
			expected: "none",
		},
		{
			name:     "omitted",
			json:     `{"listen_addr": "127.0.0.1:8080"}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, []byte(tt.json), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, err := LoadFile(path)
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}

			if cfg.TLSFingerprint != tt.expected {
				t.Errorf("TLSFingerprint = %q, want %q", cfg.TLSFingerprint, tt.expected)
			}
		})
	}
}
