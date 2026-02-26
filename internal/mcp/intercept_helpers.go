package mcp

import (
	"fmt"

	"github.com/usk6666/katashiro-proxy/internal/proxy/intercept"
)

// interceptRuleInput is the JSON representation of an intercept rule for MCP tool input.
type interceptRuleInput struct {
	// ID is the unique identifier for this rule.
	ID string `json:"id" jsonschema:"unique rule identifier"`

	// Enabled indicates whether this rule is active.
	Enabled bool `json:"enabled" jsonschema:"whether the rule is active"`

	// Direction specifies whether the rule applies to requests, responses, or both.
	Direction string `json:"direction" jsonschema:"request, response, or both"`

	// Conditions defines the matching criteria.
	Conditions interceptConditionsInput `json:"conditions" jsonschema:"matching conditions"`
}

// interceptConditionsInput is the JSON representation of intercept rule conditions.
type interceptConditionsInput struct {
	// HostPattern is a regular expression matched against the request hostname (port excluded).
	HostPattern string `json:"host_pattern,omitempty" jsonschema:"regex pattern for hostname matching"`

	// PathPattern is a regular expression matched against the request URL path.
	PathPattern string `json:"path_pattern,omitempty" jsonschema:"regex pattern for URL path matching"`

	// Methods is a whitelist of HTTP methods (case-insensitive).
	Methods []string `json:"methods,omitempty" jsonschema:"HTTP method whitelist (e.g. POST, PUT, DELETE)"`

	// HeaderMatch maps header names to regular expressions (AND logic).
	HeaderMatch map[string]string `json:"header_match,omitempty" jsonschema:"header name to regex pattern mapping"`
}

// interceptRuleOutput is the JSON representation of an intercept rule for MCP tool output.
type interceptRuleOutput struct {
	ID         string                    `json:"id"`
	Enabled    bool                      `json:"enabled"`
	Direction  string                    `json:"direction"`
	Conditions interceptConditionsOutput `json:"conditions"`
}

// interceptConditionsOutput is the JSON representation of intercept conditions in output.
type interceptConditionsOutput struct {
	HostPattern string            `json:"host_pattern,omitempty"`
	PathPattern string            `json:"path_pattern,omitempty"`
	Methods     []string          `json:"methods,omitempty"`
	HeaderMatch map[string]string `json:"header_match,omitempty"`
}

// toInterceptRule converts an MCP input rule to an intercept.Rule.
func toInterceptRule(input interceptRuleInput) intercept.Rule {
	return intercept.Rule{
		ID:        input.ID,
		Enabled:   input.Enabled,
		Direction: intercept.Direction(input.Direction),
		Conditions: intercept.Conditions{
			HostPattern: input.Conditions.HostPattern,
			PathPattern: input.Conditions.PathPattern,
			Methods:     input.Conditions.Methods,
			HeaderMatch: input.Conditions.HeaderMatch,
		},
	}
}

// fromInterceptRule converts an intercept.Rule to an MCP output rule.
func fromInterceptRule(r intercept.Rule) interceptRuleOutput {
	return interceptRuleOutput{
		ID:        r.ID,
		Enabled:   r.Enabled,
		Direction: string(r.Direction),
		Conditions: interceptConditionsOutput{
			HostPattern: r.Conditions.HostPattern,
			PathPattern: r.Conditions.PathPattern,
			Methods:     r.Conditions.Methods,
			HeaderMatch: r.Conditions.HeaderMatch,
		},
	}
}

// fromInterceptRules converts a slice of intercept.Rule to MCP output rules.
func fromInterceptRules(rules []intercept.Rule) []interceptRuleOutput {
	if rules == nil {
		return nil
	}
	out := make([]interceptRuleOutput, len(rules))
	for i, r := range rules {
		out[i] = fromInterceptRule(r)
	}
	return out
}

// applyInterceptRules validates and sets intercept rules from the input.
func (s *Server) applyInterceptRules(inputs []interceptRuleInput) error {
	if s.interceptEngine == nil {
		return fmt.Errorf("intercept engine is not initialized")
	}

	rules := make([]intercept.Rule, len(inputs))
	for i, input := range inputs {
		rules[i] = toInterceptRule(input)
	}

	if err := s.interceptEngine.SetRules(rules); err != nil {
		return err
	}
	return nil
}
