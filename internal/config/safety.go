package config

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateSafetyFilterConfig validates the SafetyFilter configuration.
// It checks that:
//   - The action (if set) is valid for the section type
//   - Each rule has either preset or pattern set (not both)
//   - Custom rules have required fields (id, pattern, targets)
//   - Regex patterns compile successfully
//   - Preset names are not empty
//   - Target values are valid for the section type (input vs output)
func ValidateSafetyFilterConfig(cfg *SafetyFilterConfig) error {
	if cfg == nil {
		return nil
	}

	if cfg.Input != nil {
		// Validate input action.
		if cfg.Input.Action != "" && cfg.Input.Action != "block" && cfg.Input.Action != "log_only" {
			return fmt.Errorf("safety_filter.input.action: invalid value %q (must be \"block\" or \"log_only\")", cfg.Input.Action)
		}

		for i, rule := range cfg.Input.Rules {
			if err := validateSafetyFilterRule(i, rule, validInputTargets, "safety_filter.input"); err != nil {
				return err
			}
		}
	}

	if cfg.Output != nil {
		// Validate output action.
		if cfg.Output.Action != "" && cfg.Output.Action != "mask" && cfg.Output.Action != "log_only" {
			return fmt.Errorf("safety_filter.output.action: invalid value %q (must be \"mask\" or \"log_only\")", cfg.Output.Action)
		}

		for i, rule := range cfg.Output.Rules {
			if err := validateSafetyFilterRule(i, rule, validOutputTargets, "safety_filter.output"); err != nil {
				return err
			}
		}
	}

	return nil
}

// validInputTargets lists the accepted target values for input filter rules.
var validInputTargets = map[string]bool{
	"body":    true,
	"url":     true,
	"query":   true,
	"header":  true,
	"headers": true,
}

// validOutputTargets lists the accepted target values for output filter rules.
// Output targets support "body", "headers" (all headers), and "header:<name>"
// for specific header matching (e.g. "header:Set-Cookie").
var validOutputTargets = map[string]bool{
	"body":    true,
	"headers": true,
	// "header:*" is validated dynamically in validateOutputTarget.
}

// validateSafetyFilterRule validates a single rule config entry.
// The section parameter is used for error message context (e.g. "safety_filter.input").
func validateSafetyFilterRule(index int, rule SafetyFilterRuleConfig, targets map[string]bool, section string) error {
	hasPreset := rule.Preset != ""
	hasPattern := rule.Pattern != ""

	if hasPreset && hasPattern {
		return fmt.Errorf("%s.rules[%d]: preset and pattern are mutually exclusive", section, index)
	}
	if !hasPreset && !hasPattern {
		return fmt.Errorf("%s.rules[%d]: either preset or pattern is required", section, index)
	}

	if hasPreset {
		// Preset reference — no further validation needed at config level;
		// the actual preset lookup is done by the safety package.
		return nil
	}

	// Custom rule validation.
	if rule.ID == "" {
		return fmt.Errorf("%s.rules[%d]: id is required for custom rules", section, index)
	}
	if len(rule.Targets) == 0 {
		return fmt.Errorf("%s.rules[%d]: at least one target is required for custom rules", section, index)
	}

	// Validate target values.
	for _, t := range rule.Targets {
		if !isValidTarget(t, targets) {
			return fmt.Errorf("%s.rules[%d]: invalid target %q", section, index, t)
		}
	}

	// Validate regex compiles.
	if _, err := regexp.Compile(rule.Pattern); err != nil {
		return fmt.Errorf("%s.rules[%d]: invalid pattern %q: %w", section, index, rule.Pattern, err)
	}

	return nil
}

// isValidTarget checks whether t is a valid target for the given target set.
// It handles the "header:<name>" syntax which is valid only for output targets.
func isValidTarget(t string, targets map[string]bool) bool {
	lower := strings.ToLower(t)
	if targets[lower] {
		return true
	}
	// Check for "header:<name>" pattern (e.g. "header:Set-Cookie").
	// This syntax is only valid for output filter targets.
	if strings.HasPrefix(lower, "header:") {
		headerName := t[len("header:"):]
		// The header name must be non-empty, and the targets map must be
		// the output targets (which lacks the plain "header" key that input has).
		return headerName != "" && !targets["header"]
	}
	return false
}
