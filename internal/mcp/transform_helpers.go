package mcp

import (
	"fmt"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
)

// transformRuleInput is the JSON representation of an auto-transform rule for MCP tool input.
type transformRuleInput struct {
	// ID is the unique identifier for this rule.
	ID string `json:"id" jsonschema:"unique rule identifier"`

	// Enabled indicates whether this rule is active.
	Enabled bool `json:"enabled" jsonschema:"whether the rule is active"`

	// Priority determines the order in which rules are applied (lower values first).
	Priority int `json:"priority" jsonschema:"rule priority (lower values applied first)"`

	// Direction specifies whether the rule applies to requests, responses, or both.
	Direction string `json:"direction" jsonschema:"request, response, or both"`

	// Conditions defines the matching criteria.
	Conditions transformConditionsInput `json:"conditions" jsonschema:"matching conditions"`

	// Action defines the transformation to apply.
	Action transformActionInput `json:"action" jsonschema:"transformation action"`
}

// transformConditionsInput is the JSON representation of auto-transform rule conditions.
type transformConditionsInput struct {
	// URLPattern is a regular expression matched against the full request URL.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"regex pattern for URL matching"`

	// Methods is a whitelist of HTTP methods (case-insensitive).
	Methods []string `json:"methods,omitempty" jsonschema:"HTTP method whitelist (e.g. POST, PUT, DELETE)"`

	// HeaderMatch maps header names to regular expressions (AND logic).
	HeaderMatch map[string]string `json:"header_match,omitempty" jsonschema:"header name to regex pattern mapping"`
}

// transformActionInput is the JSON representation of a transform action.
type transformActionInput struct {
	// Type is the action type: add_header, set_header, remove_header, or replace_body.
	Type string `json:"type" jsonschema:"action type: add_header, set_header, remove_header, or replace_body"`

	// Header is the header name (for add_header, set_header, remove_header).
	Header string `json:"header,omitempty" jsonschema:"header name for header actions"`

	// Value is the header value (for add_header, set_header) or replacement string (for replace_body).
	Value string `json:"value,omitempty" jsonschema:"header value or replacement string"`

	// Pattern is the search pattern (regex) for replace_body.
	Pattern string `json:"pattern,omitempty" jsonschema:"search pattern (regex) for replace_body"`
}

// transformRuleOutput is the JSON representation of an auto-transform rule for MCP tool output.
type transformRuleOutput struct {
	ID         string                    `json:"id"`
	Enabled    bool                      `json:"enabled"`
	Priority   int                       `json:"priority"`
	Direction  string                    `json:"direction"`
	Conditions transformConditionsOutput `json:"conditions"`
	Action     transformActionOutput     `json:"action"`
}

// transformConditionsOutput is the JSON representation of transform conditions in output.
type transformConditionsOutput struct {
	URLPattern  string            `json:"url_pattern,omitempty"`
	Methods     []string          `json:"methods,omitempty"`
	HeaderMatch map[string]string `json:"header_match,omitempty"`
}

// transformActionOutput is the JSON representation of a transform action in output.
type transformActionOutput struct {
	Type    string `json:"type"`
	Header  string `json:"header,omitempty"`
	Value   string `json:"value,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

// toTransformRule converts an MCP input rule to a rules.Rule.
func toTransformRule(input transformRuleInput) rules.Rule {
	return rules.Rule{
		ID:        input.ID,
		Enabled:   input.Enabled,
		Priority:  input.Priority,
		Direction: rules.Direction(input.Direction),
		Conditions: rules.Conditions{
			URLPattern:  input.Conditions.URLPattern,
			Methods:     input.Conditions.Methods,
			HeaderMatch: input.Conditions.HeaderMatch,
		},
		Action: rules.Action{
			Type:    rules.ActionType(input.Action.Type),
			Header:  input.Action.Header,
			Value:   input.Action.Value,
			Pattern: input.Action.Pattern,
		},
	}
}

// fromTransformRule converts a rules.Rule to an MCP output rule.
func fromTransformRule(r rules.Rule) transformRuleOutput {
	return transformRuleOutput{
		ID:        r.ID,
		Enabled:   r.Enabled,
		Priority:  r.Priority,
		Direction: string(r.Direction),
		Conditions: transformConditionsOutput{
			URLPattern:  r.Conditions.URLPattern,
			Methods:     r.Conditions.Methods,
			HeaderMatch: r.Conditions.HeaderMatch,
		},
		Action: transformActionOutput{
			Type:    string(r.Action.Type),
			Header:  r.Action.Header,
			Value:   r.Action.Value,
			Pattern: r.Action.Pattern,
		},
	}
}

// fromTransformRules converts a slice of rules.Rule to MCP output rules.
func fromTransformRules(rulesList []rules.Rule) []transformRuleOutput {
	if rulesList == nil {
		return nil
	}
	out := make([]transformRuleOutput, len(rulesList))
	for i, r := range rulesList {
		out[i] = fromTransformRule(r)
	}
	return out
}

// validateTransformRuleInput checks a transform rule for CRLF injection in
// header names and values (CWE-113).
func validateTransformRuleInput(input transformRuleInput) error {
	switch input.Action.Type {
	case "add_header", "set_header":
		if strings.ContainsAny(input.Action.Header, "\r\n") {
			return fmt.Errorf("rule %q: header name contains CR/LF characters", input.ID)
		}
		if strings.ContainsAny(input.Action.Value, "\r\n") {
			return fmt.Errorf("rule %q: header value contains CR/LF characters", input.ID)
		}
	case "remove_header":
		if strings.ContainsAny(input.Action.Header, "\r\n") {
			return fmt.Errorf("rule %q: header name contains CR/LF characters", input.ID)
		}
	}
	return nil
}

// applyTransformRules validates and sets auto-transform rules from the input.
func (s *Server) applyTransformRules(inputs []transformRuleInput) error {
	return applyTransformRulesHelper(s.deps.transformPipeline, inputs)
}

// applyTransformRulesHelper validates and sets auto-transform rules on the given pipeline.
// This is a standalone version of Server.applyTransformRules for use by handler structs.
func applyTransformRulesHelper(pipeline *rules.Pipeline, inputs []transformRuleInput) error {
	if pipeline == nil {
		return fmt.Errorf("transform pipeline is not initialized")
	}

	rulesList := make([]rules.Rule, len(inputs))
	for i, input := range inputs {
		if err := validateTransformRuleInput(input); err != nil {
			return err
		}
		rulesList[i] = toTransformRule(input)
	}

	if err := pipeline.SetRules(rulesList); err != nil {
		return err
	}
	return nil
}
