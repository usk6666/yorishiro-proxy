package config

import (
	"fmt"
	"regexp"
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

// validateSafetyFilterRule validates a single rule config entry.
func validateSafetyFilterRule(index int, rule SafetyFilterRuleConfig) error {
	hasPreset := rule.Preset != ""
	hasPattern := rule.Pattern != ""

	if hasPreset && hasPattern {
		return fmt.Errorf("preset and pattern are mutually exclusive")
	}
	if !hasPreset && !hasPattern {
		return fmt.Errorf("either preset or pattern is required")
	}

	if hasPreset {
		// Preset reference — no further validation needed at config level;
		// the actual preset lookup is done by the safety package.
		return nil
	}

	// Custom rule validation.
	if rule.ID == "" {
		return fmt.Errorf("id is required for custom rules")
	}
	if len(rule.Targets) == 0 {
		return fmt.Errorf("at least one target is required for custom rules")
	}

	// Validate regex compiles.
	if _, err := regexp.Compile(rule.Pattern); err != nil {
		return fmt.Errorf("invalid pattern %q: %w", rule.Pattern, err)
	}

	return nil
}
