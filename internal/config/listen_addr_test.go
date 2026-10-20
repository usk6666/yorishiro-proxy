package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateListenAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr string // substring; "" means accept
	}{
		// Accepted forms.
		{name: "IPv4 loopback", addr: "127.0.0.1:8080"},
		{name: "IPv4 loopback ephemeral", addr: "127.0.0.1:0"},
		{name: "localhost", addr: "localhost:0"},
		{name: "IPv6 loopback", addr: "[::1]:8080"},
		{name: "IPv4 unspecified", addr: "0.0.0.0:8080"},
		{name: "IPv6 unspecified", addr: "[::]:8080"},
		{name: "private IPv4", addr: "10.0.0.5:8080"},
		{name: "public IPv6", addr: "[2001:db8::5]:8080"},
		{name: "link-local IPv6 with zone", addr: "[fe80::1%lo]:0"},
		{name: "max port", addr: "127.0.0.1:65535"},

		// Rejected forms.
		{name: "empty host", addr: ":8080", wantErr: "0.0.0.0"},
		{name: "empty host ephemeral", addr: ":0", wantErr: "0.0.0.0"},
		{name: "DNS name", addr: "example.com:8080", wantErr: "IP literal"},
		{name: "upper-case localhost", addr: "LOCALHOST:8080", wantErr: "IP literal"},
		{name: "short IPv4", addr: "127.1:8080", wantErr: "IP literal"},
		{name: "hex IPv4", addr: "0x7f.0.0.1:8080", wantErr: "IP literal"},
		{name: "integer IPv4", addr: "2130706433:8080", wantErr: "IP literal"},
		{name: "service-name port", addr: "127.0.0.1:http", wantErr: "port"},
		{name: "port out of range", addr: "127.0.0.1:65536", wantErr: "port"},
		{name: "empty port", addr: "127.0.0.1:", wantErr: "port"},
		{name: "signed port", addr: "127.0.0.1:+80", wantErr: "port"},
		{name: "missing port", addr: "127.0.0.1", wantErr: "invalid listen_addr"},
		{name: "garbage", addr: "not-an-address", wantErr: "invalid listen_addr"},
		{name: "unbracketed IPv6", addr: "::1:8080", wantErr: "invalid listen_addr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateListenAddr(tt.addr)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateListenAddr(%q) = %v, want nil", tt.addr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateListenAddr(%q) = nil, want error containing %q", tt.addr, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ValidateListenAddr(%q) = %q, want it to contain %q", tt.addr, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestProxyConfigValidate_ListenAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "unset", addr: ""},
		{name: "loopback", addr: "127.0.0.1:8080"},
		{name: "all interfaces", addr: "0.0.0.0:8080"},
		{name: "empty host", addr: ":8080", wantErr: true},
		{name: "DNS name", addr: "example.com:80", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProxyConfig{ListenAddr: tt.addr}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ProxyConfig{ListenAddr: %q}.Validate() = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "listen_addr") {
				t.Errorf("error %q should name the listen_addr field", err.Error())
			}
		})
	}
}

// TestLoadFile_RejectsInvalidListenAddr drives the boot-time config file
// path: a config file whose listen_addr has an empty host must fail to load
// rather than surfacing later as a proxy_start error.
func TestLoadFile_RejectsInvalidListenAddr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen_addr":":8080"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() on config file with listen_addr \":8080\" = nil, want error")
	}
}
