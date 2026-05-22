package mcp

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestParseUpstreamProxyInput_StringForm verifies that a plain string
// value (legacy USK-826 wire form) deserialises into the literal-URL
// shape with suppliedAsString=true so the consumer can distinguish
// "empty disable" from "object with empty url".
func TestParseUpstreamProxyInput_StringForm(t *testing.T) {
	got, err := parseUpstreamProxyInput("http://proxy.example:8080")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil")
	}
	if !got.IsLiteralURL() {
		t.Errorf("expected IsLiteralURL=true, got %+v", got)
	}
	if got.URL != "http://proxy.example:8080" {
		t.Errorf("URL = %q, want http://proxy.example:8080", got.URL)
	}
}

// TestParseUpstreamProxyInput_EmptyStringDisables verifies that the
// "" string value is honoured as a disable signal.
func TestParseUpstreamProxyInput_EmptyStringDisables(t *testing.T) {
	got, err := parseUpstreamProxyInput("")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.IsLiteralDisable() {
		t.Errorf("expected IsLiteralDisable=true, got %+v", got)
	}
}

// TestParseUpstreamProxyInput_ObjectRotation verifies that an object
// with url_template + rotation deserialises into the rotation shape.
func TestParseUpstreamProxyInput_ObjectRotation(t *testing.T) {
	got, err := parseUpstreamProxyInput(map[string]any{
		"url_template": "http://session-§__nonce§:pass@proxy.example:8080",
		"rotation": map[string]any{
			"policy": "per_request",
		},
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.IsRotation() {
		t.Errorf("expected IsRotation=true, got %+v", got)
	}
	cfg := got.RotationConfig()
	if cfg == nil {
		t.Fatalf("nil RotationConfig")
	}
	if cfg.Policy != connector.RotationPerRequest {
		t.Errorf("policy = %q, want per_request", cfg.Policy)
	}
}

// TestParseUpstreamProxyInput_UnknownTypeReturnsErr verifies that
// non-string / non-map inputs are rejected with a typed error.
func TestParseUpstreamProxyInput_UnknownTypeReturnsErr(t *testing.T) {
	_, err := parseUpstreamProxyInput(42)
	if err == nil {
		t.Fatalf("expected error for int input")
	}
	if !strings.Contains(err.Error(), "must be a string or object") {
		t.Errorf("error message missing expected text: %v", err)
	}
}

// TestUpstreamProxyInput_Validate_RotationMissingPolicyRejected
// verifies validation rejects a rotation object without a policy.
func TestUpstreamProxyInput_Validate_RotationMissingPolicyRejected(t *testing.T) {
	in := &configureUpstreamProxyInput{
		URLTemplate: "http://§__nonce§:pass@proxy.example:8080",
		Rotation:    &configureUpstreamProxyRotationInput{},
	}
	err := in.Validate()
	if err == nil {
		t.Fatalf("expected error for rotation with empty policy")
	}
	if !strings.Contains(err.Error(), "policy") {
		t.Errorf("error message missing 'policy': %v", err)
	}
}

// TestUpstreamProxyInput_Validate_URLPlusTemplateRejected verifies
// the URL ⊕ URLTemplate exclusivity guard.
func TestUpstreamProxyInput_Validate_URLPlusTemplateRejected(t *testing.T) {
	in := &configureUpstreamProxyInput{
		URL:         "http://proxy.example:8080",
		URLTemplate: "http://§__nonce§@proxy.example:8080",
	}
	err := in.Validate()
	if err == nil {
		t.Fatalf("expected error for url + url_template")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error message missing 'mutually exclusive': %v", err)
	}
}

// TestUpstreamProxyInput_Validate_UnknownPolicyRejected verifies the
// policy whitelist.
func TestUpstreamProxyInput_Validate_UnknownPolicyRejected(t *testing.T) {
	in := &configureUpstreamProxyInput{
		URLTemplate: "http://§__nonce§:pass@proxy.example:8080",
		Rotation:    &configureUpstreamProxyRotationInput{Policy: "bogus"},
	}
	err := in.Validate()
	if err == nil {
		t.Fatalf("expected error for unknown policy")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("error message missing 'not supported': %v", err)
	}
}

// TestProbeRotationTemplate_MalformedRejected verifies the Stage 1
// probe rejects malformed templates at the MCP tool-input boundary.
func TestProbeRotationTemplate_MalformedRejected(t *testing.T) {
	_, err := probeRotationTemplate("ftp://broken-§__nonce§.example:21")
	if err == nil {
		t.Fatalf("expected error for ftp scheme")
	}
}

// TestProbeRotationTemplate_WellFormedAccepted verifies a valid
// template passes Stage 1 probing.
func TestProbeRotationTemplate_WellFormedAccepted(t *testing.T) {
	u, err := probeRotationTemplate("http://session-§__nonce§:pass@proxy.example:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil {
		t.Fatalf("nil URL")
	}
	if u.Host != "proxy.example:8080" {
		t.Errorf("host = %q, want proxy.example:8080", u.Host)
	}
}
