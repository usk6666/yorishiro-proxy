package mcpserver

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// TestInitPerProtocolSafetyEngines covers the safety.Config →
// per-protocol engine bridge: enabled/disabled gating, preset
// expansion, custom-rule compilation, and the documented error paths.
//
// The bridge is the wiring fix for USK-760; the data-path effect is
// asserted end-to-end by
// internal/mcptest/security_safetyfilter_smoke_integration_test.go.
func TestInitPerProtocolSafetyEngines(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.Config
		proxyCfg       *config.ProxyConfig
		wantHTTPRules  int // -1 means: any non-zero
		wantWSRules    int
		wantGRPCRules  int
		wantNilEngines bool
		wantErr        bool
		errSubstr      string
	}{
		{
			name:           "disabled by default",
			cfg:            config.Default(),
			proxyCfg:       &config.ProxyConfig{},
			wantNilEngines: true,
		},
		{
			name: "enabled but no input rules",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{Enabled: true},
			},
			wantNilEngines: true,
		},
		{
			name: "preset only — destructive-sql",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql"},
						},
					},
				},
			},
			// destructive-sql contributes 6 rules per per-protocol engine.
			wantHTTPRules: 6,
			wantWSRules:   6,
			wantGRPCRules: 6,
		},
		{
			name: "custom rule only — body target",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{ID: "custom-secret", Pattern: "secret", Targets: []string{"body"}},
						},
					},
				},
			},
			wantHTTPRules: 1,
			wantWSRules:   1,
			wantGRPCRules: 1,
		},
		{
			name: "mixed preset + custom",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql"},
							{ID: "custom-token", Pattern: `token=\w+`, Targets: []string{"body", "url"}},
						},
					},
				},
			},
			wantHTTPRules: 7,
			wantWSRules:   7,
			wantGRPCRules: 7,
		},
		{
			name: "CLI override disables config-enabled filter",
			cfg: func() *config.Config {
				c := config.Default()
				disabled := false
				c.SafetyFilterEnabled = &disabled
				return c
			}(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql"},
						},
					},
				},
			},
			wantNilEngines: true,
		},
		{
			name: "CLI override enables config-disabled filter",
			cfg: func() *config.Config {
				c := config.Default()
				enabled := true
				c.SafetyFilterEnabled = &enabled
				return c
			}(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql"},
						},
					},
				},
			},
			wantHTTPRules: 6,
			wantWSRules:   6,
			wantGRPCRules: 6,
		},
		{
			name: "unknown preset",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "no-such-preset"},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "no-such-preset",
		},
		{
			name: "invalid regex",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{ID: "bad-regex", Pattern: `[invalid`, Targets: []string{"body"}},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "bad-regex",
		},
		{
			name: "preset and pattern mutually exclusive",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Preset: "destructive-sql", Pattern: "x", Targets: []string{"body"}},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "mutually exclusive",
		},
		{
			name: "custom rule missing id",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{Pattern: "x", Targets: []string{"body"}},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "id is required",
		},
		{
			name: "custom rule missing targets",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{ID: "no-targets", Pattern: "x"},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "at least one target",
		},
		{
			name: "duplicate custom rule ids",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{ID: "dup", Pattern: "a", Targets: []string{"body"}},
							{ID: "dup", Pattern: "b", Targets: []string{"body"}},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "duplicate id",
		},
		{
			name: "header:Name shorthand rejected at boot",
			cfg:  config.Default(),
			proxyCfg: &config.ProxyConfig{
				SafetyFilter: &config.SafetyFilterConfig{
					Enabled: true,
					Input: &config.SafetyFilterInputConfig{
						Rules: []config.SafetyFilterRuleConfig{
							{ID: "leak", Pattern: "x", Targets: []string{"header:Authorization"}},
						},
					},
				},
			},
			wantErr:   true,
			errSubstr: "not supported on the live data path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engines, err := InitPerProtocolSafetyEngines(tt.cfg, tt.proxyCfg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil; engines=%+v", engines)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantNilEngines {
				if engines.HTTP != nil || engines.WS != nil || engines.GRPC != nil {
					t.Fatalf("expected zero-value engines, got %+v", engines)
				}
				return
			}

			if engines.HTTP == nil || engines.WS == nil || engines.GRPC == nil {
				t.Fatalf("expected non-nil engines, got %+v", engines)
			}
			if got := engines.HTTP.RuleCount(); got != tt.wantHTTPRules {
				t.Errorf("HTTP rule count = %d, want %d", got, tt.wantHTTPRules)
			}
			if got := engines.WS.RuleCount(); got != tt.wantWSRules {
				t.Errorf("WS rule count = %d, want %d", got, tt.wantWSRules)
			}
			if got := engines.GRPC.RuleCount(); got != tt.wantGRPCRules {
				t.Errorf("gRPC rule count = %d, want %d", got, tt.wantGRPCRules)
			}
		})
	}
}
