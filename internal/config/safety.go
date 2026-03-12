package config

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateSafetyFilterConfig validates the SafetyFilter configuration.
// It checks that:
//   - The action (if set) is "block" or "log_only"
//   - Each rule has either preset or pattern set (not both)
//   - Custom rules have required fields (id, pattern, targets)
//   - Regex patterns compile successfully
//   - Preset names are not empty
func ValidateSafetyFilterConfig(cfg *SafetyFilterConfig) error {
	if cfg == nil {
		return nil
	}

	if cfg.Input == nil {
		return nil
	}

	// Validate action.
	if cfg.Input.Action != "" && cfg.Input.Action != "block" && cfg.Input.Action != "log_only" {
		return fmt.Errorf("safety_filter.input.action: invalid value %q (must be \"block\" or \"log_only\")", cfg.Input.Action)
	}

	for i, rule := range cfg.Input.Rules {
		if err := validateSafetyFilterRule(i, rule); err != nil {
			return fmt.Errorf("safety_filter.input.rules[%d]: %w", i, err)
		}
	}

	return nil
}

// validTargets lists the accepted target values for custom safety filter rules.
var validTargets = map[string]bool{
	"body":    true,
	"url":     true,
	"query":   true,
	"header":  true,
	"headers": true,
}

// validateSafetyFilterRule validates a single rule config entry.
func validateSafetyFilterRule(index int, rule SafetyFilterRuleConfig) error {
	hasPreset := rule.Preset != ""
	hasPattern := rule.Pattern != ""

	if hasPreset && hasPattern {
		return fmt.Errorf("rule[%d]: preset and pattern are mutually exclusive", index)
	}
	if !hasPreset && !hasPattern {
		return fmt.Errorf("rule[%d]: either preset or pattern is required", index)
	}

	if hasPreset {
		// Preset reference — no further validation needed at config level;
		// the actual preset lookup is done by the safety package.
		return nil
	}

	// Custom rule validation.
	if rule.ID == "" {
		return fmt.Errorf("rule[%d]: id is required for custom rules", index)
	}
	if len(rule.Targets) == 0 {
		return fmt.Errorf("rule[%d]: at least one target is required for custom rules", index)
	}

	// Validate target values.
	for _, t := range rule.Targets {
		if !validTargets[strings.ToLower(t)] {
			return fmt.Errorf("rule[%d]: invalid target %q (must be one of: body, url, query, header, headers)", index, t)
		}
	}

	// Validate regex compiles.
	if _, err := regexp.Compile(rule.Pattern); err != nil {
		return fmt.Errorf("rule[%d]: invalid pattern %q: %w", index, rule.Pattern, err)
	}

	return nil
}
