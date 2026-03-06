package plugin

import "testing"

func TestConnInfo_ToMap(t *testing.T) {
	ci := &ConnInfo{
		ClientAddr: "192.168.1.100:54321",
		ServerAddr: "93.184.216.34:443",
		TLSVersion: "TLS 1.3",
		TLSCipher:  "TLS_AES_128_GCM_SHA256",
		TLSALPN:    "h2",
	}

	m := ci.ToMap()

	tests := []struct {
		key  string
		want string
	}{
		{"client_addr", "192.168.1.100:54321"},
		{"server_addr", "93.184.216.34:443"},
		{"tls_version", "TLS 1.3"},
		{"tls_cipher", "TLS_AES_128_GCM_SHA256"},
		{"tls_alpn", "h2"},
	}

	for _, tt := range tests {
		v, ok := m[tt.key].(string)
		if !ok {
			t.Errorf("key %q: not a string", tt.key)
			continue
		}
		if v != tt.want {
			t.Errorf("key %q = %q, want %q", tt.key, v, tt.want)
		}
	}
}

func TestConnInfo_ToMap_Nil(t *testing.T) {
	var ci *ConnInfo
	m := ci.ToMap()
	if len(m) != 0 {
		t.Errorf("nil ConnInfo.ToMap() should return empty map, got %v", m)
	}
}

func TestConnInfo_ToMap_Empty(t *testing.T) {
	ci := &ConnInfo{}
	m := ci.ToMap()
	if len(m) != 5 {
		t.Errorf("empty ConnInfo.ToMap() should have 5 keys, got %d", len(m))
	}
	for _, key := range []string{"client_addr", "server_addr", "tls_version", "tls_cipher", "tls_alpn"} {
		if v, ok := m[key].(string); !ok || v != "" {
			t.Errorf("key %q = %v, want empty string", key, m[key])
		}
	}
}

func TestConnInfoFromMap(t *testing.T) {
	m := map[string]any{
		"client_addr": "10.0.0.1:1234",
		"server_addr": "10.0.0.2:443",
		"tls_version": "TLS 1.2",
		"tls_cipher":  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"tls_alpn":    "http/1.1",
	}

	ci := ConnInfoFromMap(m)

	if ci.ClientAddr != "10.0.0.1:1234" {
		t.Errorf("ClientAddr = %q, want %q", ci.ClientAddr, "10.0.0.1:1234")
	}
	if ci.ServerAddr != "10.0.0.2:443" {
		t.Errorf("ServerAddr = %q, want %q", ci.ServerAddr, "10.0.0.2:443")
	}
	if ci.TLSVersion != "TLS 1.2" {
		t.Errorf("TLSVersion = %q, want %q", ci.TLSVersion, "TLS 1.2")
	}
	if ci.TLSCipher != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("TLSCipher = %q, want %q", ci.TLSCipher, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	}
	if ci.TLSALPN != "http/1.1" {
		t.Errorf("TLSALPN = %q, want %q", ci.TLSALPN, "http/1.1")
	}
}

func TestConnInfoFromMap_Nil(t *testing.T) {
	ci := ConnInfoFromMap(nil)
	if ci == nil {
		t.Fatal("ConnInfoFromMap(nil) should return non-nil ConnInfo")
	}
	if ci.ClientAddr != "" {
		t.Errorf("ClientAddr = %q, want empty", ci.ClientAddr)
	}
}

func TestConnInfo_RoundTrip(t *testing.T) {
	original := &ConnInfo{
		ClientAddr: "127.0.0.1:8080",
		ServerAddr: "example.com:443",
		TLSVersion: "TLS 1.3",
		TLSCipher:  "TLS_AES_256_GCM_SHA384",
		TLSALPN:    "h2",
	}

	m := original.ToMap()
	restored := ConnInfoFromMap(m)

	if restored.ClientAddr != original.ClientAddr {
		t.Errorf("ClientAddr = %q, want %q", restored.ClientAddr, original.ClientAddr)
	}
	if restored.ServerAddr != original.ServerAddr {
		t.Errorf("ServerAddr = %q, want %q", restored.ServerAddr, original.ServerAddr)
	}
	if restored.TLSVersion != original.TLSVersion {
		t.Errorf("TLSVersion = %q, want %q", restored.TLSVersion, original.TLSVersion)
	}
	if restored.TLSCipher != original.TLSCipher {
		t.Errorf("TLSCipher = %q, want %q", restored.TLSCipher, original.TLSCipher)
	}
	if restored.TLSALPN != original.TLSALPN {
		t.Errorf("TLSALPN = %q, want %q", restored.TLSALPN, original.TLSALPN)
	}
}
