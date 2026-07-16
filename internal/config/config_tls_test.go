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

// TestResolveTLSFingerprint covers the boot-time fingerprint resolution
// precedence (proxyCfg > cfg > firefox default) and the "none" opt-out
// sentinel that maps to "" (standard crypto/tls) — USK-1013.
func TestResolveTLSFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *Config
		proxyCfg *ProxyConfig
		want     string
	}{
		{
			name:     "both empty defaults to firefox",
			cfg:      &Config{},
			proxyCfg: &ProxyConfig{},
			want:     "firefox",
		},
		{
			name:     "nil both defaults to firefox",
			cfg:      nil,
			proxyCfg: nil,
			want:     "firefox",
		},
		{
			name:     "proxyCfg wins over cfg",
			cfg:      &Config{TLSFingerprint: "safari"},
			proxyCfg: &ProxyConfig{TLSFingerprint: "chrome"},
			want:     "chrome",
		},
		{
			name:     "cfg used when proxyCfg empty",
			cfg:      &Config{TLSFingerprint: "edge"},
			proxyCfg: &ProxyConfig{},
			want:     "edge",
		},
		{
			name:     "nil cfg skips top-level tier (live-path contract)",
			cfg:      nil,
			proxyCfg: &ProxyConfig{},
			want:     "firefox",
		},
		{
			name:     "explicit none maps to empty (standard TLS)",
			cfg:      &Config{},
			proxyCfg: &ProxyConfig{TLSFingerprint: "none"},
			want:     "",
		},
		{
			name:     "none is case-insensitive and trimmed",
			cfg:      &Config{},
			proxyCfg: &ProxyConfig{TLSFingerprint: "  NONE  "},
			want:     "",
		},
		{
			name:     "top-level none also opts out",
			cfg:      &Config{TLSFingerprint: "none"},
			proxyCfg: &ProxyConfig{},
			want:     "",
		},
		{
			name:     "explicit firefox passes through",
			cfg:      &Config{},
			proxyCfg: &ProxyConfig{TLSFingerprint: "firefox"},
			want:     "firefox",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveTLSFingerprint(tt.cfg, tt.proxyCfg); got != tt.want {
				t.Errorf("ResolveTLSFingerprint() = %q, want %q", got, tt.want)
			}
		})
	}
}
