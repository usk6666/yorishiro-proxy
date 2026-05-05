package config

import "testing"

func TestProxyConfig_IsRawPassthrough(t *testing.T) {
	cfg := &ProxyConfig{
		RawPassthroughHosts: []string{
			"target.example.com:443",
			"OTHER.EXAMPLE.COM:8443",
		},
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"target.example.com:443", true},
		{"TARGET.EXAMPLE.COM:443", true},   // case-insensitive
		{"other.example.com:8443", true},   // stored uppercase, queried lowercase
		{"target.example.com:8080", false}, // different port
		{"unknown.com:443", false},
		{"", false},
		{"  target.example.com:443  ", true}, // trimmed
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			got := cfg.IsRawPassthrough(tt.target)
			if got != tt.want {
				t.Errorf("IsRawPassthrough(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestProxyConfig_IsRawPassthrough_Empty(t *testing.T) {
	cfg := &ProxyConfig{}
	if cfg.IsRawPassthrough("anything:443") {
		t.Error("expected false for empty RawPassthroughHosts")
	}
}

func TestRawPassthroughSet(t *testing.T) {
	cfg := &ProxyConfig{
		RawPassthroughHosts: []string{
			"target.example.com:443",
			"OTHER.EXAMPLE.COM:8443",
			"  spaces.example.com:443  ",
		},
	}

	set := NewRawPassthroughSet(cfg)

	tests := []struct {
		target string
		want   bool
	}{
		{"target.example.com:443", true},
		{"TARGET.EXAMPLE.COM:443", true},
		{"other.example.com:8443", true},
		{"spaces.example.com:443", true},
		{"unknown.com:443", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			got := set.Contains(tt.target)
			if got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}
