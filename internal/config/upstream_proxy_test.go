package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUpstreamProxyConfig_UnmarshalString verifies the polymorphic
// UnmarshalJSON honours the legacy USK-826 string form.
func TestUpstreamProxyConfig_UnmarshalString(t *testing.T) {
	var c UpstreamProxyConfig
	if err := json.Unmarshal([]byte(`"http://proxy.example:8080"`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.URL != "http://proxy.example:8080" {
		t.Errorf("URL = %q, want http://proxy.example:8080", c.URL)
	}
	if c.URLTemplate != "" || c.Rotation != nil {
		t.Errorf("string form should leave URLTemplate/Rotation empty: %+v", c)
	}
}

// TestUpstreamProxyConfig_UnmarshalObject verifies the polymorphic
// UnmarshalJSON honours the USK-959 structured form.
func TestUpstreamProxyConfig_UnmarshalObject(t *testing.T) {
	var c UpstreamProxyConfig
	body := `{
		"url_template": "http://session-§__nonce§:pass@proxy.example:8080",
		"rotation": {"policy": "per_request"}
	}`
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.URLTemplate == "" {
		t.Errorf("URLTemplate empty after unmarshal")
	}
	if c.Rotation == nil || c.Rotation.Policy != "per_request" {
		t.Errorf("Rotation = %+v, want policy=per_request", c.Rotation)
	}
}

// TestUpstreamProxyConfig_Validate_RotationProbeRejectsMalformed
// verifies Stage 1 probe-expansion at config-validate time rejects a
// malformed template before any live dial.
func TestUpstreamProxyConfig_Validate_RotationProbeRejectsMalformed(t *testing.T) {
	c := &UpstreamProxyConfig{
		URLTemplate: "ftp://nope.example:21",
		Rotation:    &UpstreamProxyRotation{Policy: "per_request"},
	}
	err := c.Validate()
	if err == nil {
		t.Fatalf("expected probe-expansion error for ftp scheme")
	}
	if !strings.Contains(err.Error(), "url_template") {
		t.Errorf("error missing user-facing prefix: %v", err)
	}
}

// TestUpstreamProxyConfig_Validate_RotationProbeRejectsIterationMacro
// verifies Stage 1 / Stage 2 KV parity: §__iteration§ is NOT exposed on
// the live data path (the runtime resolver populates only §__nonce§),
// so a template referencing §__iteration§ must be rejected at
// config-apply time rather than passing the probe and then failing at
// the first live dial. Locks in the USK-959 review fix (F-2).
func TestUpstreamProxyConfig_Validate_RotationProbeRejectsIterationMacro(t *testing.T) {
	c := &UpstreamProxyConfig{
		URLTemplate: "http://session-§__iteration§@proxy.example:8080",
		Rotation:    &UpstreamProxyRotation{Policy: "per_request"},
	}
	err := c.Validate()
	if err == nil {
		t.Fatalf("expected probe to reject §__iteration§ template at config time")
	}
	if !strings.Contains(err.Error(), "url_template") {
		t.Errorf("error missing user-facing prefix: %v", err)
	}
}

// TestUpstreamProxyConfig_Validate_URLAndTemplateMutuallyExclusive
// verifies the URL ⊕ URLTemplate guard.
func TestUpstreamProxyConfig_Validate_URLAndTemplateMutuallyExclusive(t *testing.T) {
	c := &UpstreamProxyConfig{
		URL:         "http://proxy.example:8080",
		URLTemplate: "http://§__nonce§@proxy.example:8080",
		Rotation:    &UpstreamProxyRotation{Policy: "per_request"},
	}
	err := c.Validate()
	if err == nil {
		t.Fatalf("expected error for URL + URLTemplate")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error message missing 'mutually exclusive': %v", err)
	}
}

// TestUpstreamProxyConfig_Validate_RotationRequiredWithTemplate
// verifies a URLTemplate without rotation is rejected.
func TestUpstreamProxyConfig_Validate_RotationRequiredWithTemplate(t *testing.T) {
	c := &UpstreamProxyConfig{
		URLTemplate: "http://§__nonce§@proxy.example:8080",
	}
	err := c.Validate()
	if err == nil {
		t.Fatalf("expected error for url_template without rotation")
	}
	if !strings.Contains(err.Error(), "rotation is required") {
		t.Errorf("error message missing 'rotation is required': %v", err)
	}
}

// TestUpstreamProxyConfig_ProxyConfigPolymorphism verifies the outer
// ProxyConfig.UnmarshalJSON correctly dispatches the polymorphic
// upstream_proxy key.
func TestUpstreamProxyConfig_ProxyConfigPolymorphism(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantURL  string
		wantTmpl string
		wantPol  string
	}{
		{
			name:    "string-form",
			input:   `{"upstream_proxy": "http://proxy.example:8080"}`,
			wantURL: "http://proxy.example:8080",
		},
		{
			name: "object-form-rotation",
			input: `{
				"upstream_proxy": {
					"url_template": "http://§__nonce§:pass@proxy.example:8080",
					"rotation": {"policy": "per_request"}
				}
			}`,
			wantTmpl: "http://§__nonce§:pass@proxy.example:8080",
			wantPol:  "per_request",
		},
		{
			name: "object-form-literal",
			input: `{
				"upstream_proxy": {
					"url": "http://proxy.example:8080"
				}
			}`,
			// Legacy string field is mirrored from object.URL.
			wantURL: "http://proxy.example:8080",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cfg ProxyConfig
			if err := json.Unmarshal([]byte(tc.input), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if cfg.UpstreamProxy != tc.wantURL {
				t.Errorf("UpstreamProxy = %q, want %q", cfg.UpstreamProxy, tc.wantURL)
			}
			if tc.wantTmpl != "" {
				if cfg.UpstreamProxyStruct == nil {
					t.Fatalf("UpstreamProxyStruct nil, want set")
				}
				if cfg.UpstreamProxyStruct.URLTemplate != tc.wantTmpl {
					t.Errorf("URLTemplate = %q, want %q", cfg.UpstreamProxyStruct.URLTemplate, tc.wantTmpl)
				}
				if cfg.UpstreamProxyStruct.Rotation == nil || cfg.UpstreamProxyStruct.Rotation.Policy != tc.wantPol {
					t.Errorf("Rotation = %+v, want policy=%s", cfg.UpstreamProxyStruct.Rotation, tc.wantPol)
				}
			}
		})
	}
}
