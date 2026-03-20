package config

import (
	"encoding/json"
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
			name: "enabled with no input or output",
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
		{
			name: "invalid target value",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "bad-target", Pattern: `DROP`, Targets: []string{"cookie"}},
					},
				},
			},
			wantErr: "invalid target",
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

func TestValidateSafetyFilterConfig_Output(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *SafetyFilterConfig
		wantErr string
	}{
		{
			name: "output with empty config",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output:  &SafetyFilterOutputConfig{},
			},
		},
		{
			name: "output preset reference",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Action: "mask",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "credit-card"},
					},
				},
			},
		},
		{
			name: "output preset with replacement override",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{Preset: "email", Replacement: "[REDACTED]"},
					},
				},
			},
		},
		{
			name: "output custom rule with body target",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Action: "mask",
					Rules: []SafetyFilterRuleConfig{
						{
							ID:      "custom-pii",
							Pattern: `\b\d{3}-\d{2}-\d{4}\b`,
							Targets: []string{"body"},
						},
					},
				},
			},
		},
		{
			name: "output custom rule with header target",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{
							ID:      "cookie-mask",
							Pattern: `session=[a-f0-9]+`,
							Targets: []string{"header:Set-Cookie"},
						},
					},
				},
			},
		},
		{
			name: "output custom rule with headers target",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{
							ID:      "all-headers",
							Pattern: `secret-[a-z]+`,
							Targets: []string{"headers"},
						},
					},
				},
			},
		},
		{
			name: "output custom rule with multiple targets",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{
							ID:      "multi-target",
							Pattern: `\btoken=[a-f0-9]+\b`,
							Targets: []string{"body", "header:Authorization", "headers"},
						},
					},
				},
			},
		},
		{
			name: "output log_only action",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Action: "log_only",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "japan-phone"},
					},
				},
			},
		},
		{
			name: "output invalid action",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Action: "block",
				},
			},
			wantErr: "invalid value",
		},
		{
			name: "output invalid action unknown",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Action: "invalid",
				},
			},
			wantErr: "invalid value",
		},
		{
			name: "output invalid target url",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "bad", Pattern: `test`, Targets: []string{"url"}},
					},
				},
			},
			wantErr: "invalid target",
		},
		{
			name: "output invalid target query",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "bad", Pattern: `test`, Targets: []string{"query"}},
					},
				},
			},
			wantErr: "invalid target",
		},
		{
			name: "output invalid target plain header",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "bad", Pattern: `test`, Targets: []string{"header"}},
					},
				},
			},
			wantErr: "invalid target",
		},
		{
			name: "output header colon with empty name",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "bad", Pattern: `test`, Targets: []string{"header:"}},
					},
				},
			},
			wantErr: "invalid target",
		},
		{
			name: "output both preset and pattern",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{Preset: "credit-card", Pattern: `\d+`},
					},
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "output neither preset nor pattern",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "empty"},
					},
				},
			},
			wantErr: "either preset or pattern is required",
		},
		{
			name: "output custom rule missing id",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{Pattern: `\d+`, Targets: []string{"body"}},
					},
				},
			},
			wantErr: "id is required",
		},
		{
			name: "output custom rule missing targets",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "test", Pattern: `\d+`},
					},
				},
			},
			wantErr: "at least one target",
		},
		{
			name: "output invalid regex",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Output: &SafetyFilterOutputConfig{
					Rules: []SafetyFilterRuleConfig{
						{ID: "bad", Pattern: `(?P<invalid`, Targets: []string{"body"}},
					},
				},
			},
			wantErr: "invalid pattern",
		},
		{
			name: "mixed input and output valid",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Action: "block",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "destructive-sql"},
					},
				},
				Output: &SafetyFilterOutputConfig{
					Action: "mask",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "credit-card"},
					},
				},
			},
		},
		{
			name: "input valid output invalid",
			cfg: &SafetyFilterConfig{
				Enabled: true,
				Input: &SafetyFilterInputConfig{
					Action: "block",
					Rules: []SafetyFilterRuleConfig{
						{Preset: "destructive-sql"},
					},
				},
				Output: &SafetyFilterOutputConfig{
					Action: "invalid",
				},
			},
			wantErr: "safety_filter.output.action",
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

func TestSafetyFilterConfigJSON_Output(t *testing.T) {
	jsonData := `{
		"listen_addr": "127.0.0.1:8080",
		"safety_filter": {
			"enabled": true,
			"output": {
				"action": "mask",
				"rules": [
					{"preset": "credit-card"},
					{"preset": "email", "replacement": "[REDACTED]"},
					{
						"id": "custom-ssn",
						"name": "SSN Pattern",
						"pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
						"targets": ["body", "header:Set-Cookie"]
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
	if cfg.SafetyFilter.Output == nil {
		t.Fatal("safety_filter.output is nil")
	}
	if cfg.SafetyFilter.Output.Action != "mask" {
		t.Errorf("action = %q, want %q", cfg.SafetyFilter.Output.Action, "mask")
	}
	if len(cfg.SafetyFilter.Output.Rules) != 3 {
		t.Fatalf("rules count = %d, want 3", len(cfg.SafetyFilter.Output.Rules))
	}
	if cfg.SafetyFilter.Output.Rules[0].Preset != "credit-card" {
		t.Errorf("rule[0].preset = %q, want %q", cfg.SafetyFilter.Output.Rules[0].Preset, "credit-card")
	}
	if cfg.SafetyFilter.Output.Rules[1].Replacement != "[REDACTED]" {
		t.Errorf("rule[1].replacement = %q, want %q", cfg.SafetyFilter.Output.Rules[1].Replacement, "[REDACTED]")
	}
	if cfg.SafetyFilter.Output.Rules[2].ID != "custom-ssn" {
		t.Errorf("rule[2].id = %q, want %q", cfg.SafetyFilter.Output.Rules[2].ID, "custom-ssn")
	}
	if len(cfg.SafetyFilter.Output.Rules[2].Targets) != 2 {
		t.Fatalf("rule[2].targets count = %d, want 2", len(cfg.SafetyFilter.Output.Rules[2].Targets))
	}
}

func TestSafetyFilterConfigJSON_InputAndOutput(t *testing.T) {
	jsonData := `{
		"safety_filter": {
			"enabled": true,
			"input": {
				"action": "block",
				"rules": [{"preset": "destructive-sql"}]
			},
			"output": {
				"action": "mask",
				"rules": [{"preset": "credit-card"}]
			}
		}
	}`

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if cfg.SafetyFilter == nil {
		t.Fatal("safety_filter is nil")
	}
	if cfg.SafetyFilter.Input == nil {
		t.Fatal("safety_filter.input is nil")
	}
	if cfg.SafetyFilter.Output == nil {
		t.Fatal("safety_filter.output is nil")
	}
	if cfg.SafetyFilter.Input.Action != "block" {
		t.Errorf("input.action = %q, want %q", cfg.SafetyFilter.Input.Action, "block")
	}
	if cfg.SafetyFilter.Output.Action != "mask" {
		t.Errorf("output.action = %q, want %q", cfg.SafetyFilter.Output.Action, "mask")
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

func TestIsValidTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		targets map[string]bool
		want    bool
	}{
		{
			name:    "input body",
			target:  "body",
			targets: validInputTargets,
			want:    true,
		},
		{
			name:    "input url",
			target:  "url",
			targets: validInputTargets,
			want:    true,
		},
		{
			name:    "input header",
			target:  "header",
			targets: validInputTargets,
			want:    true,
		},
		{
			name:    "input header:Name rejected",
			target:  "header:X-Custom",
			targets: validInputTargets,
			want:    false,
		},
		{
			name:    "output body",
			target:  "body",
			targets: validOutputTargets,
			want:    true,
		},
		{
			name:    "output headers",
			target:  "headers",
			targets: validOutputTargets,
			want:    true,
		},
		{
			name:    "output header:Name accepted",
			target:  "header:Set-Cookie",
			targets: validOutputTargets,
			want:    true,
		},
		{
			name:    "output header: empty name rejected",
			target:  "header:",
			targets: validOutputTargets,
			want:    false,
		},
		{
			name:    "output url rejected",
			target:  "url",
			targets: validOutputTargets,
			want:    false,
		},
		{
			name:    "output query rejected",
			target:  "query",
			targets: validOutputTargets,
			want:    false,
		},
		{
			name:    "output plain header rejected",
			target:  "header",
			targets: validOutputTargets,
			want:    false,
		},
		{
			name:    "unknown target",
			target:  "cookie",
			targets: validInputTargets,
			want:    false,
		},
		{
			name:    "case insensitive body",
			target:  "Body",
			targets: validInputTargets,
			want:    true,
		},
		{
			name:    "case insensitive Header:Name",
			target:  "Header:Authorization",
			targets: validOutputTargets,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidTarget(tt.target, tt.targets)
			if got != tt.want {
				t.Errorf("isValidTarget(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}
