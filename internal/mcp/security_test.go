package mcp

import (
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/macro"
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
	params := resendParams{
		OverrideHeaders: HeaderEntries{
			{Key: "Content-Type", Value: "text/plain"},
		},
		AddHeaders: HeaderEntries{
			{Key: "X-Custom", Value: "value"},
		},
		RemoveHeaders: []string{"X-Old"},
	}
	if err := validateResendHeaders(params); err != nil {
		t.Fatalf("expected no error for clean headers, got: %v", err)
	}
}

func TestValidateResendHeaders_CRLFInOverride(t *testing.T) {
	params := resendParams{
		OverrideHeaders: HeaderEntries{
			{Key: "X-Evil", Value: "value\r\nInjected: evil"},
		},
	}
	err := validateResendHeaders(params)
	if err == nil {
		t.Fatal("expected error for CRLF in override_headers, got nil")
	}
}

func TestValidateResendHeaders_CRLFInAdd(t *testing.T) {
	params := resendParams{
		AddHeaders: HeaderEntries{
			{Key: "X-Evil", Value: "value\r\nInjected: evil"},
		},
	}
	err := validateResendHeaders(params)
	if err == nil {
		t.Fatal("expected error for CRLF in add_headers, got nil")
	}
}

func TestValidateResendHeaders_CRLFInRemoveKey(t *testing.T) {
	params := resendParams{
		RemoveHeaders: []string{"X-Evil\r\nInjected"},
	}
	err := validateResendHeaders(params)
	if err == nil {
		t.Fatal("expected error for CRLF in remove_headers key, got nil")
	}
}

// --- Macro override_headers CRLF validation tests (CWE-113) ---

func TestValidateMacroDefinition_OverrideHeaders_CRLFInValue(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "CR in header value",
			headers: map[string]string{"X-Custom": "value\rInjected: evil"},
		},
		{
			name:    "LF in header value",
			headers: map[string]string{"X-Custom": "value\nInjected: evil"},
		},
		{
			name:    "CRLF in header value",
			headers: map[string]string{"X-Custom": "value\r\nInjected: evil"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &macro.Macro{
				Name: "test-macro",
				Steps: []macro.Step{
					{
						ID:              "step1",
						FlowID:          "flow-1",
						OverrideHeaders: tt.headers,
					},
				},
			}
			err := validateMacroDefinition(m)
			if err == nil {
				t.Fatal("expected error for CRLF in override_headers value, got nil")
			}
		})
	}
}

func TestValidateMacroDefinition_OverrideHeaders_CRLFInKey(t *testing.T) {
	m := &macro.Macro{
		Name: "test-macro",
		Steps: []macro.Step{
			{
				ID:              "step1",
				FlowID:          "flow-1",
				OverrideHeaders: map[string]string{"X-Evil\r\nInjected": "value"},
			},
		},
	}
	err := validateMacroDefinition(m)
	if err == nil {
		t.Fatal("expected error for CRLF in override_headers key, got nil")
	}
}

func TestValidateMacroDefinition_OverrideHeaders_Clean(t *testing.T) {
	m := &macro.Macro{
		Name: "test-macro",
		Steps: []macro.Step{
			{
				ID:     "step1",
				FlowID: "flow-1",
				OverrideHeaders: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Bearer token123",
				},
			},
		},
	}
	err := validateMacroDefinition(m)
	if err != nil {
		t.Fatalf("expected no error for clean override_headers, got: %v", err)
	}
}

func TestValidateMacroDefinition_OverrideHeaders_Empty(t *testing.T) {
	m := &macro.Macro{
		Name: "test-macro",
		Steps: []macro.Step{
			{
				ID:     "step1",
				FlowID: "flow-1",
			},
		},
	}
	err := validateMacroDefinition(m)
	if err != nil {
		t.Fatalf("expected no error for step without override_headers, got: %v", err)
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
