package mcp

import (
	"net/url"
	"testing"
)

// --- CRLF header injection validation tests (CWE-113) ---

func TestValidateHeaderValues_Clean(t *testing.T) {
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer token123",
		"X-Custom":      "some value",
	}
	if err := validateHeaderValues(headers); err != nil {
		t.Fatalf("expected no error for clean headers, got: %v", err)
	}
}

func TestValidateHeaderValues_CRLFInValue(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "CR in value",
			headers: map[string]string{"X-Evil": "value\rInjected: evil"},
		},
		{
			name:    "LF in value",
			headers: map[string]string{"X-Evil": "value\nInjected: evil"},
		},
		{
			name:    "CRLF in value",
			headers: map[string]string{"X-Evil": "value\r\nInjected: evil"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHeaderValues(tt.headers)
			if err == nil {
				t.Fatal("expected error for CRLF in header value, got nil")
			}
		})
	}
}

func TestValidateHeaderValues_CRLFInKey(t *testing.T) {
	headers := map[string]string{
		"X-Evil\r\nInjected": "value",
	}
	err := validateHeaderValues(headers)
	if err == nil {
		t.Fatal("expected error for CRLF in header key, got nil")
	}
}

func TestValidateHeaderValues_EmptyMap(t *testing.T) {
	if err := validateHeaderValues(nil); err != nil {
		t.Fatalf("expected no error for nil map, got: %v", err)
	}
	if err := validateHeaderValues(map[string]string{}); err != nil {
		t.Fatalf("expected no error for empty map, got: %v", err)
	}
}

func TestValidateHeaderKeys_Clean(t *testing.T) {
	keys := []string{"Content-Type", "Authorization", "X-Custom"}
	if err := validateHeaderKeys(keys); err != nil {
		t.Fatalf("expected no error for clean keys, got: %v", err)
	}
}

func TestValidateHeaderKeys_CRLF(t *testing.T) {
	tests := []struct {
		name string
		keys []string
	}{
		{
			name: "CR in key",
			keys: []string{"X-Evil\rInjected"},
		},
		{
			name: "LF in key",
			keys: []string{"X-Evil\nInjected"},
		},
		{
			name: "CRLF in key",
			keys: []string{"X-Evil\r\nInjected"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHeaderKeys(tt.keys)
			if err == nil {
				t.Fatal("expected error for CRLF in header key, got nil")
			}
		})
	}
}

func TestValidateResendHeaders_Clean(t *testing.T) {
	params := executeParams{
		OverrideHeaders: map[string]string{
			"Content-Type": "text/plain",
		},
		AddHeaders: map[string]string{
			"X-Custom": "value",
		},
		RemoveHeaders: []string{"X-Old"},
	}
	if err := validateResendHeaders(params); err != nil {
		t.Fatalf("expected no error for clean headers, got: %v", err)
	}
}

func TestValidateResendHeaders_CRLFInOverride(t *testing.T) {
	params := executeParams{
		OverrideHeaders: map[string]string{
			"X-Evil": "value\r\nInjected: evil",
		},
	}
	err := validateResendHeaders(params)
	if err == nil {
		t.Fatal("expected error for CRLF in override_headers, got nil")
	}
}

func TestValidateResendHeaders_CRLFInAdd(t *testing.T) {
	params := executeParams{
		AddHeaders: map[string]string{
			"X-Evil": "value\r\nInjected: evil",
		},
	}
	err := validateResendHeaders(params)
	if err == nil {
		t.Fatal("expected error for CRLF in add_headers, got nil")
	}
}

func TestValidateResendHeaders_CRLFInRemoveKey(t *testing.T) {
	params := executeParams{
		RemoveHeaders: []string{"X-Evil\r\nInjected"},
	}
	err := validateResendHeaders(params)
	if err == nil {
		t.Fatal("expected error for CRLF in remove_headers key, got nil")
	}
}

// --- SSRF protection tests ---

func TestDenyPrivateNetwork_Loopback(t *testing.T) {
	err := denyPrivateNetwork("tcp", "127.0.0.1:80", nil)
	if err == nil {
		t.Fatal("expected error for loopback address, got nil")
	}
}

func TestDenyPrivateNetwork_Private10(t *testing.T) {
	err := denyPrivateNetwork("tcp", "10.0.0.1:80", nil)
	if err == nil {
		t.Fatal("expected error for 10.x.x.x address, got nil")
	}
}

func TestDenyPrivateNetwork_Private172(t *testing.T) {
	err := denyPrivateNetwork("tcp", "172.16.0.1:80", nil)
	if err == nil {
		t.Fatal("expected error for 172.16.x.x address, got nil")
	}
}

func TestDenyPrivateNetwork_Private192(t *testing.T) {
	err := denyPrivateNetwork("tcp", "192.168.1.1:80", nil)
	if err == nil {
		t.Fatal("expected error for 192.168.x.x address, got nil")
	}
}

func TestDenyPrivateNetwork_LinkLocal(t *testing.T) {
	err := denyPrivateNetwork("tcp", "169.254.0.1:80", nil)
	if err == nil {
		t.Fatal("expected error for link-local address, got nil")
	}
}

func TestDenyPrivateNetwork_Unspecified(t *testing.T) {
	err := denyPrivateNetwork("tcp", "0.0.0.0:80", nil)
	if err == nil {
		t.Fatal("expected error for unspecified address, got nil")
	}
}

func TestDenyPrivateNetwork_IPv6Loopback(t *testing.T) {
	err := denyPrivateNetwork("tcp", "[::1]:80", nil)
	if err == nil {
		t.Fatal("expected error for IPv6 loopback address, got nil")
	}
}

func TestDenyPrivateNetwork_PublicIP(t *testing.T) {
	err := denyPrivateNetwork("tcp", "8.8.8.8:80", nil)
	if err != nil {
		t.Fatalf("expected no error for public IP, got: %v", err)
	}
}

// --- URL scheme validation tests ---

func TestValidateURLScheme_Valid(t *testing.T) {
	tests := []string{"http", "https"}
	for _, scheme := range tests {
		u := &testURL{scheme: scheme}
		if err := validateURLScheme(u.toURL()); err != nil {
			t.Errorf("expected no error for scheme %q, got: %v", scheme, err)
		}
	}
}

func TestValidateURLScheme_Invalid(t *testing.T) {
	tests := []string{"ftp", "file", "gopher", "javascript", "data", ""}
	for _, scheme := range tests {
		u := &testURL{scheme: scheme}
		if err := validateURLScheme(u.toURL()); err == nil {
			t.Errorf("expected error for scheme %q, got nil", scheme)
		}
	}
}

// --- Token generation tests (entropy characteristics) ---

func TestGenerateToken_HexEncoding(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	// Token should be 64 hex characters (32 bytes * 2).
	if len(token) != 64 {
		t.Errorf("expected 64-char token, got %d chars", len(token))
	}
	// All characters should be valid hex.
	for i, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("non-hex character at position %d: %c", i, c)
		}
	}
}

func TestGenerateToken_NoDuplicatesInBatch(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if seen[token] {
			t.Fatalf("duplicate token generated on iteration %d: %s", i, token)
		}
		seen[token] = true
	}
}

// --- Loopback address validation tests ---

func TestValidateLoopbackAddr_Valid(t *testing.T) {
	tests := []string{
		"127.0.0.1:8080",
		"127.0.0.1:3000",
		"[::1]:8080",
		"localhost:8080",
	}
	for _, addr := range tests {
		if err := validateLoopbackAddr(addr); err != nil {
			t.Errorf("expected no error for %q, got: %v", addr, err)
		}
	}
}

func TestValidateLoopbackAddr_Invalid(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{name: "public IP", addr: "8.8.8.8:8080"},
		{name: "private IP", addr: "192.168.1.1:8080"},
		{name: "all interfaces", addr: "0.0.0.0:8080"},
		{name: "empty host", addr: ":8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateLoopbackAddr(tt.addr); err == nil {
				t.Errorf("expected error for %q, got nil", tt.addr)
			}
		})
	}
}

// testURL is a helper for creating net/url.URL values in tests.
type testURL struct {
	scheme string
}

func (t *testURL) toURL() *url.URL {
	return &url.URL{Scheme: t.scheme, Host: "example.com"}
}
