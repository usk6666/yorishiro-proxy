package pluginv2

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPluginConfig_RejectsLegacyProtocolField(t *testing.T) {
	cfg := PluginConfig{Path: "/tmp/x.star", Protocol: "http"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for legacy protocol field")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LoadError, got %T (%v)", err, err)
	}
	if le.Kind != LoadErrLegacyField {
		t.Errorf("Kind = %v, want LoadErrLegacyField", le.Kind)
	}
	if !strings.Contains(err.Error(), "field hooks/protocol removed in RFC-001") {
		t.Errorf("error message missing migration text: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "register_hook()") {
		t.Errorf("error message missing register_hook hint: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "docs/rfc/plugin-migration.md") {
		t.Errorf("error message missing migration doc reference: %q", err.Error())
	}
}

func TestPluginConfig_RejectsLegacyHooksField(t *testing.T) {
	cfg := PluginConfig{Path: "/tmp/x.star", Hooks: []string{"on_receive_from_client"}}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for legacy hooks field")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LoadError, got %T", err)
	}
	if le.Kind != LoadErrLegacyField {
		t.Errorf("Kind = %v, want LoadErrLegacyField", le.Kind)
	}
}

func TestPluginConfig_RejectsLegacyJSONFields(t *testing.T) {
	// Acceptance criterion U1: a YAML/JSON document carrying the legacy
	// fields must be rejected with the migration message.
	const legacyJSON = `{"path":"/tmp/x.star","protocol":"http","hooks":["on_receive_from_client"]}`
	var cfg PluginConfig
	if err := json.Unmarshal([]byte(legacyJSON), &cfg); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if cfg.Protocol != "http" || len(cfg.Hooks) == 0 {
		t.Fatalf("tripwire fields not populated by JSON unmarshal: %+v", cfg)
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error after JSON unmarshal of legacy fields")
	}
	if !strings.Contains(err.Error(), "field hooks/protocol removed in RFC-001") {
		t.Errorf("error missing migration text: %v", err)
	}
}

func TestPluginConfig_AcceptsCleanRFC001Config(t *testing.T) {
	cfg := PluginConfig{
		Name:       "my-plugin",
		Path:       "/tmp/x.star",
		Vars:       map[string]any{"region": "us-east", "n": 42, "rate": 0.5, "on": true, "blob": []byte{1, 2}},
		OnError:    string(OnErrorAbort),
		MaxSteps:   500_000,
		RedactKeys: []string{"region"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() of clean config: %v", err)
	}
}

func TestPluginConfig_ValidatePathRequired(t *testing.T) {
	cfg := PluginConfig{}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "path must not be empty") {
		t.Errorf("expected path-empty error, got %v", err)
	}
}

func TestPluginConfig_ValidateOnError(t *testing.T) {
	cfg := PluginConfig{Path: "/tmp/x.star", OnError: "explode"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "invalid on_error") {
		t.Errorf("expected on_error error, got %v", err)
	}
}

func TestPluginConfig_ValidateRedactKeysNonEmpty(t *testing.T) {
	cfg := PluginConfig{Path: "/tmp/x.star", RedactKeys: []string{"a", ""}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "redact_keys[1]") {
		t.Errorf("expected redact_keys[1] empty error, got %v", err)
	}
}

func TestPluginConfig_DefaultMaxStepsAndOnError(t *testing.T) {
	cfg := PluginConfig{Path: "/tmp/x.star"}
	if got := cfg.maxSteps(); got != DefaultMaxSteps {
		t.Errorf("maxSteps() = %d, want %d", got, DefaultMaxSteps)
	}
	if got := cfg.onErrorBehavior(); got != OnErrorSkip {
		t.Errorf("onErrorBehavior() = %q, want %q", got, OnErrorSkip)
	}
}
