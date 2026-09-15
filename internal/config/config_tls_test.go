package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestValidTLSFingerprint covers the shared fingerprint vocabulary predicate
// (USK-1032). Acceptance is case-insensitive and whitespace-trimmed because
// every consumption seam already normalizes that way; the empty string is
// rejected here and handled as "unset" by the per-entry-point callers.
func TestValidTLSFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		want        bool
	}{
		{"chrome", "chrome", true},
		{"firefox", "firefox", true},
		{"safari", "safari", true},
		{"edge", "edge", true},
		{"random", "random", true},
		{"none", "none", true},
		{"mixed case is accepted", "FireFox", true},
		{"surrounding whitespace is trimmed", "  none  ", true},
		{"trimmed and folded", "\tNONE\n", true},
		{"empty is not a name", "", false},
		{"whitespace only is not a name", "   ", false},
		{"typo is rejected", "firefx", false},
		{"unknown browser is rejected", "netscape", false},
		{"substring of none is rejected", "nonexistent", false},
		{"inner whitespace is not collapsed", "fire fox", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidTLSFingerprint(tt.fingerprint); got != tt.want {
				t.Errorf("ValidTLSFingerprint(%q) = %v, want %v", tt.fingerprint, got, tt.want)
			}
		})
	}
}

// TestTLSFingerprintNamesList pins the error-message vocabulary shared by the
// config-file, CLI-flag, and MCP-tool surfaces.
func TestTLSFingerprintNamesList(t *testing.T) {
	const want = "chrome, firefox, safari, edge, random, none"
	if got := TLSFingerprintNamesList(); got != want {
		t.Errorf("TLSFingerprintNamesList() = %q, want %q", got, want)
	}
}

// TestProxyConfig_Validate_TLSFingerprint covers the config-file validation
// gap closed by USK-1032: a typo must be rejected at load time instead of
// reaching the resend / fuzz dial path as a Go-native ClientHello.
func TestProxyConfig_Validate_TLSFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		wantErr     bool
	}{
		{"chrome", "chrome", false},
		{"firefox", "firefox", false},
		{"safari", "safari", false},
		{"edge", "edge", false},
		{"random", "random", false},
		{"none", "none", false},
		{"unset means default firefox", "", false},
		{"mixed case is accepted", "Firefox", false},
		{"whitespace is trimmed", "  none  ", false},
		{"typo is rejected", "firefx", true},
		{"unknown browser is rejected", "netscape", true},
		{"whitespace only is rejected", "   ", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProxyConfig{TLSFingerprint: tt.fingerprint}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				return
			}
			if !strings.Contains(err.Error(), "tls_fingerprint") {
				t.Errorf("error = %q, want it to name the tls_fingerprint field", err)
			}
			if !strings.Contains(err.Error(), TLSFingerprintNamesList()) {
				t.Errorf("error = %q, want it to enumerate %q", err, TLSFingerprintNamesList())
			}
		})
	}
}

// TestProxyConfig_Validate_TLSFingerprintNotMutated guards the USK-1021
// invariant: validation rejects bad values but never rewrites the stored
// identity. ResolveTLSFingerprint / UTLSProfileFor — and through them the H2
// send-shape and the pool cache key — must observe the operator's exact bytes.
func TestProxyConfig_Validate_TLSFingerprintNotMutated(t *testing.T) {
	for _, fingerprint := range []string{"firefox", "Firefox", "  NONE  ", "none", ""} {
		t.Run(fingerprint, func(t *testing.T) {
			cfg := &ProxyConfig{TLSFingerprint: fingerprint}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate(): %v", err)
			}
			if cfg.TLSFingerprint != fingerprint {
				t.Errorf("TLSFingerprint = %q after Validate, want it unchanged (%q)",
					cfg.TLSFingerprint, fingerprint)
			}
		})
	}
}

// TestLoadFile_InvalidTLSFingerprint proves the file → Validate seam rejects
// a typo. LoadFile itself only unmarshals; the rejection happens in Validate,
// which mcpserver.LoadConfigs calls immediately afterwards.
func TestLoadFile_InvalidTLSFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"tls_fingerprint": "firefx"}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.TLSFingerprint != "firefx" {
		t.Fatalf("TLSFingerprint = %q, want the verbatim file value", cfg.TLSFingerprint)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for the typo'd tls_fingerprint")
	}
}

// TestConfig_Validate_TLSFingerprint covers the top-level Config tier. The
// field is not reachable from any config file today (LoadFile returns a
// *ProxyConfig), but InitTLSTransport still reads it as resolution tier 2, so
// the check is kept symmetric with ProxyConfig.Validate.
func TestConfig_Validate_TLSFingerprint(t *testing.T) {
	base := func(fingerprint string) *Config {
		return &Config{
			MaxConnections: 1,
			RequestTimeout: time.Second,
			PeekTimeout:    time.Second,
			TLSFingerprint: fingerprint,
		}
	}
	tests := []struct {
		name        string
		fingerprint string
		wantErr     bool
	}{
		{"unset", "", false},
		{"firefox", "firefox", false},
		{"none trimmed and folded", "  NONE  ", false},
		{"typo is rejected", "firefx", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base(tt.fingerprint)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if cfg.TLSFingerprint != tt.fingerprint {
				t.Errorf("TLSFingerprint = %q after Validate, want it unchanged (%q)",
					cfg.TLSFingerprint, tt.fingerprint)
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
