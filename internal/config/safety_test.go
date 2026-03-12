package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestValidateSafetyFilterConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *SafetyFilterConfig
		wantErr string
	}{
		{
			name: "nil config",
			cfg:  nil,
		},
		{
			name: "enabled with no input",
			cfg:  &SafetyFilterConfig{Enabled: true},
		},
		{
			name: "enabled with empty input",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input:   &SafetyFilterInputConfig{},
			},
		},
		{
			name: "preset reference",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Action: "block",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "destructive-sql"},
					},
				},
			},
		},
		{
			name: "custom rule",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Rules: []SafetyFilterRuleConfig{
						{
							ID:      "custom-1",
							Name:    "Custom Rule",
							Pattern: `(?i)DROP\s+TABLE`,
							Targets: []string{"body", "url"},
						},
					},
				},
			},
		},
		{
			name: "mixed preset and custom",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Action: "block",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "destructive-sql"},
						{Preset: "destructive-os-command"},
						{
							ID:      "custom-api",
							Name:    "Dangerous API",
							Pattern: `(?i)/api/v[0-9]+/(delete-all|reset)`,
							Targets: []string{"url"},
						},
					},
				},
			},
		},
		{
			name: "invalid action",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Action: "invalid",
				},
			},
			wantErr: "invalid value",
		},
		{
			name: "both preset and pattern",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Rules: []SafetyFilterRuleConfig{
						{Preset: "destructive-sql", Pattern: `DROP`},
					},
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "neither preset nor pattern",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "empty-rule"},
					},
				},
			},
			wantErr: "either preset or pattern is required",
		},
		{
			name: "custom rule missing id",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Rules: []SafetyFilterRuleConfig{
						{Pattern: `DROP`, Targets: []string{"body"}},
					},
				},
			},
			wantErr: "id is required",
		},
		{
			name: "custom rule missing targets",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "test", Pattern: `DROP`},
					},
				},
			},
			wantErr: "at least one target",
		},
		{
			name: "invalid regex pattern",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "bad-regex", Pattern: `(?P<invalid`, Targets: []string{"body"}},
					},
				},
			},
			wantErr: "invalid pattern",
		},
		{
			name: "log_only action",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Action: "log_only",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "destructive-sql"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSafetyFilterConfig(tt.cfg)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSafetyFilterConfigJSON(t *testing.T) {
	// Test that SafetyFilter config is properly unmarshalled from JSON.
	jsonData := `{
		"listen_addr": "127.0.0.1:8080",
		"safety_filter": {
			"enabled": true,
			"input": {
				"action": "block",
				"rules": [
					{"preset": "destructive-sql"},
					{"preset": "destructive-os-command"},
					{
						"id": "custom-api",
						"name": "Dangerous API",
						"pattern": "(?i)/api/v[0-9]+/(delete-all|reset)",
						"targets": ["url"]
					}
				]
			}
		}
	}`

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if cfg.SafetyFilter == nil {
		t.Fatal("safety_filter is nil after unmarshal")
	}
	if !cfg.SafetyFilter.Enabled {
		t.Error("safety_filter.enabled should be true")
	}
	if cfg.SafetyFilter.Input == nil {
		t.Fatal("safety_filter.input is nil")
	}
	if cfg.SafetyFilter.Input.Action != "block" {
		t.Errorf("action = %q, want %q", cfg.SafetyFilter.Input.Action, "block")
	}
	if len(cfg.SafetyFilter.Input.Rules) != 3 {
		t.Fatalf("rules count = %d, want 3", len(cfg.SafetyFilter.Input.Rules))
	}
	if cfg.SafetyFilter.Input.Rules[0].Preset != "destructive-sql" {
		t.Errorf("rule[0].preset = %q, want %q", cfg.SafetyFilter.Input.Rules[0].Preset, "destructive-sql")
	}
	if cfg.SafetyFilter.Input.Rules[2].ID != "custom-api" {
		t.Errorf("rule[2].id = %q, want %q", cfg.SafetyFilter.Input.Rules[2].ID, "custom-api")
	}
}

func TestSafetyFilterConfigLoadFile(t *testing.T) {
	// Test loading SafetyFilter config from a file.
	tmpFile := t.TempDir() + "/config.json"
	data := []byte(`{
		"safety_filter": {
			"enabled": true,
			"input": {
				"action": "log_only",
				"rules": [
					{"preset": "destructive-sql"}
				]
			}
		}
	}`)

	if err := writeTestFile(tmpFile, data); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	cfg, err := LoadFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}

	if cfg.SafetyFilter == nil {
		t.Fatal("safety_filter is nil")
	}
	if !cfg.SafetyFilter.Enabled {
		t.Error("safety_filter should be enabled")
	}
	if cfg.SafetyFilter.Input.Action != "log_only" {
		t.Errorf("action = %q, want %q", cfg.SafetyFilter.Input.Action, "log_only")
	}
}

func TestSafetyFilterConfigOmitted(t *testing.T) {
	// Test that SafetyFilter config is nil when omitted.
	jsonData := `{"listen_addr": "127.0.0.1:8080"}`

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if cfg.SafetyFilter != nil {
		t.Error("safety_filter should be nil when omitted")
	}
}

// writeTestFile writes data to a file for testing.
func writeTestFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
