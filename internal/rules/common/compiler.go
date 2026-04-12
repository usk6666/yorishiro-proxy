package common

import (
	"fmt"
	"regexp"
)

// MaxPatternLength is the maximum allowed regex pattern length in bytes.
// Prevents ReDoS from excessively complex patterns.
const MaxPatternLength = 1024

// CompilePattern compiles a regex pattern with length validation.
func CompilePattern(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > MaxPatternLength {
		return nil, fmt.Errorf("pattern length %d exceeds maximum %d", len(pattern), MaxPatternLength)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	return re, nil
}

// CompileHeaderMatch compiles header match conditions.
// Keys are NOT lowercased — that is the caller's responsibility
// (HTTP engines lowercase; HTTP/2 engines may not need to).
func CompileHeaderMatch(match map[string]string) (map[string]*regexp.Regexp, error) {
	if len(match) == 0 {
		return nil, nil
	}
	compiled := make(map[string]*regexp.Regexp, len(match))
	for name, pattern := range match {
		re, err := CompilePattern(pattern)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", name, err)
		}
		compiled[name] = re
	}
	return compiled, nil
}

// CompilePreset compiles a Preset's rules into CompiledRules.
func CompilePreset(p Preset) ([]CompiledRule, error) {
	rules := make([]CompiledRule, 0, len(p.Rules))
	for _, rc := range p.Rules {
		re, err := CompilePattern(rc.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", rc.ID, err)
		}
		rules = append(rules, CompiledRule{
			ID:          rc.ID,
			Name:        rc.Name,
			Pattern:     re,
			Targets:     rc.Targets,
			Replacement: rc.Replacement,
			Category:    p.Name,
			Validator:   rc.Validator,
		})
	}
	return rules, nil
}
