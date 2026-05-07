package mcpserver

import (
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// PerProtocolSafetyEngines bundles the three live-path Send-direction
// safety engines that pipeline.SafetyStep dispatches to. Any field may
// be nil, in which case the corresponding protocol arm in SafetyStep
// short-circuits to pass-through.
type PerProtocolSafetyEngines struct {
	HTTP *httprules.SafetyEngine
	WS   *wsrules.SafetyEngine
	GRPC *grpcrules.SafetyEngine
}

// InitPerProtocolSafetyEngines compiles the user-facing
// SafetyFilter Input rules into one engine per protocol so the live
// pipeline.SafetyStep can enforce them. The same source-of-truth
// (cfg.SafetyFilter.Input) feeds three engines because each protocol
// has its own canonical rule type — per CLAUDE.md MITM principle #2,
// no shared canonical rule type exists.
//
// Output rules are intentionally skipped: SafetyStep is Send-direction
// only; output masking lives on the MCP response path via
// internal/safety.Engine.FilterOutput, never inside the live pipeline.
//
// Returns a zero-value PerProtocolSafetyEngines (all fields nil) when
// SafetyFilter is disabled by config or by CLI override. This matches
// InitSafetyFilter's nil-engine contract so callers that build both
// stay aligned on the same enabled/disabled decision.
//
// Boot-time errors (unknown preset, invalid regex, missing custom rule
// fields) propagate up — a misconfigured filter is fatal, never a
// silent degrade to "no rules" (CLAUDE.md error handling guidance).
func InitPerProtocolSafetyEngines(cfg *config.Config, proxyCfg *config.ProxyConfig) (PerProtocolSafetyEngines, error) {
	sfCfg := proxyCfg.SafetyFilter

	enabled := false
	if sfCfg != nil {
		enabled = sfCfg.Enabled
	}
	if cfg.SafetyFilterEnabled != nil {
		enabled = *cfg.SafetyFilterEnabled
	}
	if !enabled || sfCfg == nil || sfCfg.Input == nil {
		return PerProtocolSafetyEngines{}, nil
	}

	httpEng := httprules.NewSafetyEngine()
	wsEng := wsrules.NewSafetyEngine()
	grpcEng := grpcrules.NewSafetyEngine()

	seen := make(map[string]bool)
	for i, rule := range sfCfg.Input.Rules {
		if rule.Preset != "" && rule.Pattern != "" {
			return PerProtocolSafetyEngines{}, fmt.Errorf("safety filter input rule[%d]: preset and pattern are mutually exclusive", i)
		}

		if rule.Preset != "" {
			if err := loadPresetIntoAll(httpEng, wsEng, grpcEng, rule.Preset); err != nil {
				return PerProtocolSafetyEngines{}, fmt.Errorf("safety filter input rule[%d]: %w", i, err)
			}
			continue
		}

		compiled, err := compileCustomInputRule(i, rule, seen)
		if err != nil {
			return PerProtocolSafetyEngines{}, err
		}
		httpEng.AddRule(compiled)
		wsEng.AddRule(compiled)
		grpcEng.AddRule(compiled)
	}

	return PerProtocolSafetyEngines{HTTP: httpEng, WS: wsEng, GRPC: grpcEng}, nil
}

// loadPresetIntoAll loads a preset by name into all three per-protocol
// engines. WS silently skips non-WS targets at evaluation time and gRPC
// treats common.TargetBody as TargetPayload — both are documented in
// their respective safety.go LoadPreset comments — so the same
// destructive-sql / destructive-os-command preset is meaningful in
// every protocol's pipeline.
func loadPresetIntoAll(httpEng *httprules.SafetyEngine, wsEng *wsrules.SafetyEngine, grpcEng *grpcrules.SafetyEngine, name string) error {
	if err := httpEng.LoadPreset(name); err != nil {
		return fmt.Errorf("http: %w", err)
	}
	if err := wsEng.LoadPreset(name); err != nil {
		return fmt.Errorf("ws: %w", err)
	}
	if err := grpcEng.LoadPreset(name); err != nil {
		return fmt.Errorf("grpc: %w", err)
	}
	return nil
}

// compileCustomInputRule converts a single user-facing
// SafetyFilterRuleConfig into a common.CompiledRule suitable for any
// per-protocol SafetyEngine. The HTTP/WS/gRPC engines all consume
// common.CompiledRule and translate Targets in their per-protocol
// extractTarget switch.
func compileCustomInputRule(index int, rule config.SafetyFilterRuleConfig, seen map[string]bool) (common.CompiledRule, error) {
	if rule.ID == "" {
		return common.CompiledRule{}, fmt.Errorf("safety filter input rule[%d]: id is required for custom rules", index)
	}
	if rule.Pattern == "" {
		return common.CompiledRule{}, fmt.Errorf("safety filter input rule %q: pattern is required for custom rules", rule.ID)
	}
	if len(rule.Targets) == 0 {
		return common.CompiledRule{}, fmt.Errorf("safety filter input rule %q: at least one target is required", rule.ID)
	}
	if seen[rule.ID] {
		return common.CompiledRule{}, fmt.Errorf("safety filter input rule %q: duplicate id", rule.ID)
	}
	seen[rule.ID] = true

	re, err := common.CompilePattern(rule.Pattern)
	if err != nil {
		return common.CompiledRule{}, fmt.Errorf("safety filter input rule %q: %w", rule.ID, err)
	}

	targets := make([]common.Target, 0, len(rule.Targets))
	for _, ts := range rule.Targets {
		// "header:Name" is a custom-rule shorthand for the safety.Engine
		// header-target lookup. The per-protocol engines do not implement
		// a per-name header lookup in CheckInput today (only the
		// CheckHeaderTarget side-channel does), so reject the shorthand
		// loudly at boot rather than silently dropping the rule.
		if len(ts) >= 7 && ts[:7] == "header:" {
			return common.CompiledRule{}, fmt.Errorf("safety filter input rule %q: %q is not supported on the live data path; use \"headers\" to scan all headers", rule.ID, ts)
		}
		targets = append(targets, common.Target(ts))
	}

	name := rule.Name
	if name == "" {
		name = rule.ID
	}

	return common.CompiledRule{
		ID:       rule.ID,
		Name:     name,
		Pattern:  re,
		Targets:  targets,
		Category: "custom",
	}, nil
}
