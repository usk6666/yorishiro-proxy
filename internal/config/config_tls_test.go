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
// precedence (proxyCfg > cfg > firefox default) — USK-1013.
//
// USK-1021: the resolver is identity-preserving. The "none" opt-out sentinel
// is returned verbatim so reporting can distinguish "explicitly opted out"
// from "nothing configured"; mapping it to the uTLS parrot name ("") is
// UTLSProfileFor's job and happens at the dial seam.
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
			name:     "explicit none is preserved as an identity",
			cfg:      &Config{},
			proxyCfg: &ProxyConfig{TLSFingerprint: "none"},
			want:     "none",
		},
		{
			name:     "none spelling is preserved verbatim (no fold/trim)",
			cfg:      &Config{},
			proxyCfg: &ProxyConfig{TLSFingerprint: "  NONE  "},
			want:     "  NONE  ",
		},
		{
			name:     "top-level none is preserved as an identity",
			cfg:      &Config{TLSFingerprint: "none"},
			proxyCfg: &ProxyConfig{},
			want:     "none",
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

// TestUTLSProfileFor covers the "none" opt-out sentinel mapping applied at
// the uTLS dial seam (USK-1021). Only "none" (case-insensitive, trimmed)
// collapses to ""; every other value — including a typo — passes through
// unchanged so the tlslayer profile lookup keeps its fail-hard property
// rather than silently degrading to a Go-native ClientHello.
func TestUTLSProfileFor(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		want        string
	}{
		{"none opts out", "none", ""},
		{"none is case-insensitive", "NONE", ""},
		{"none is trimmed", "  none  ", ""},
		{"none is trimmed and folded", "  NoNe  ", ""},
		{"firefox passes through", "firefox", "firefox"},
		{"chrome passes through", "chrome", "chrome"},
		{"empty passes through", "", ""},
		{"unknown profile passes through for downstream validation", "firefx", "firefx"},
		{"substring of none is not the sentinel", "nonexistent", "nonexistent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UTLSProfileFor(tt.fingerprint); got != tt.want {
				t.Errorf("UTLSProfileFor(%q) = %q, want %q", tt.fingerprint, got, tt.want)
			}
		})
	}
}
