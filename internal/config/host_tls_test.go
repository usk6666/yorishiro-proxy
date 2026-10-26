package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// USK-1384: host_tls keys are matched in the dial-equivalent host form, so
// two keys that fold to the same key would name one destination with two
// different TLS settings, and which one applied would depend on map order.
// Validate rejects them, naming both keys in a deterministic order.
func TestProxyConfig_Validate_HostTLSDuplicateFoldedKeys(t *testing.T) {
	tests := []struct {
		name     string
		hostTLS  string
		wantErr  bool
		wantKeys []string
	}{
		{name: "trailing dot duplicate", hostTLS: `{"localhost":{},"localhost.":{}}`, wantErr: true, wantKeys: []string{`"localhost"`, `"localhost."`}},
		{name: "case duplicate", hostTLS: `{"A.x":{},"a.x":{}}`, wantErr: true, wantKeys: []string{`"A.x"`, `"a.x"`}},
		{name: "IPv4-mapped IPv6 duplicate", hostTLS: `{"127.0.0.1":{},"::ffff:127.0.0.1":{}}`, wantErr: true, wantKeys: []string{`"127.0.0.1"`, `"::ffff:127.0.0.1"`}},
		{name: "wildcard duplicate", hostTLS: `{"*.example.com":{},"*.Example.COM.":{}}`, wantErr: true, wantKeys: []string{`"*.Example.COM."`, `"*.example.com"`}},
		{name: "distinct keys", hostTLS: `{"localhost":{},"127.0.0.1":{},"::1":{},"a.x":{}}`},
		{name: "exact and wildcard of the same domain", hostTLS: `{"example.com":{},"*.example.com":{}}`},
		{name: "legacy IPv4 spelling is its own key", hostTLS: `{"127.0.0.1":{},"127.1":{},"0x7f.0.0.1":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg ProxyConfig
			if err := json.Unmarshal([]byte(`{"host_tls":`+tt.hostTLS+`}`), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for i := 0; i < 5; i++ { // map order varies; the message must not
				err := cfg.Validate()
				if !tt.wantErr {
					if err != nil {
						t.Fatalf("Validate() = %v, want nil", err)
					}
					return
				}
				if err == nil {
					t.Fatalf("Validate() = nil, want an error for host_tls keys that name the same host")
				}
				msg := err.Error()
				if !strings.Contains(msg, "host_tls") {
					t.Errorf("Validate() = %q, want it to name host_tls", msg)
				}
				prev := -1
				for _, k := range tt.wantKeys {
					idx := strings.Index(msg, k)
					if idx < 0 || idx < prev {
						t.Fatalf("Validate() = %q, want it to name %v in that order", msg, tt.wantKeys)
					}
					prev = idx
				}
			}
		})
	}
}

// USK-1389: a host_tls entry whose value is JSON null decodes to a nil
// *HostTLSEntry, which the startup wiring dereferences. Validate rejects it
// and names the entry — also for a single-entry map, ahead of the
// duplicate-key check, and with the same key on every run.
func TestProxyConfig_Validate_HostTLSNullEntry(t *testing.T) {
	tests := []struct {
		name    string
		hostTLS string
		wantKey string // "" means Validate must pass
	}{
		{name: "single null entry", hostTLS: `{"x":null}`, wantKey: `host_tls["x"]`},
		{name: "null beside a valid entry", hostTLS: `{"a":{},"x":null}`, wantKey: `host_tls["x"]`},
		{name: "several nulls name the first in sorted order", hostTLS: `{"y":null,"x":null}`, wantKey: `host_tls["x"]`},
		{name: "null reported before a duplicate key", hostTLS: `{"x":null,"x.":{}}`, wantKey: `host_tls["x"]`},
		{name: "empty object inherits the global settings", hostTLS: `{"x":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg ProxyConfig
			if err := json.Unmarshal([]byte(`{"host_tls":`+tt.hostTLS+`}`), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for i := 0; i < 5; i++ { // map order varies; the message must not
				err := cfg.Validate()
				if tt.wantKey == "" {
					if err != nil {
						t.Fatalf("Validate() = %v, want nil", err)
					}
					return
				}
				if err == nil {
					t.Fatalf("Validate() = nil, want an error for a null host_tls entry")
				}
				msg := err.Error()
				if !strings.Contains(msg, tt.wantKey) || !strings.Contains(msg, "null") {
					t.Fatalf("Validate() = %q, want it to name %s as null", msg, tt.wantKey)
				}
			}
		})
	}
}
