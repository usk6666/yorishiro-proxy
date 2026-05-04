package mcp

import (
	"fmt"
	"strings"

	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// transformRuleInput is the JSON representation of an auto-transform rule
// for MCP tool input. The shape mirrors httprules.TransformRule.
type transformRuleInput struct {
	// ID is the unique identifier for this rule.
	ID string `json:"id" jsonschema:"unique rule identifier"`

	// Enabled indicates whether this rule is active.
	Enabled bool `json:"enabled" jsonschema:"whether the rule is active"`

	// Priority determines the order in which rules are applied (lower values first).
	Priority int `json:"priority" jsonschema:"rule priority (lower values applied first)"`

	// Direction specifies whether the rule applies to requests, responses, or both.
	Direction string `json:"direction" jsonschema:"request, response, or both"`

	// HostPattern is a regex matched against the request hostname.
	HostPattern string `json:"host_pattern,omitempty" jsonschema:"regex matched against the request hostname"`

	// PathPattern is a regex matched against the URL path.
	PathPattern string `json:"path_pattern,omitempty" jsonschema:"regex matched against the URL path"`

	// Methods is a whitelist of HTTP methods (case-insensitive).
	Methods []string `json:"methods,omitempty" jsonschema:"HTTP method whitelist (case-insensitive)"`

	// BodyPattern is the search pattern (regex) for replace_body actions.
	BodyPattern string `json:"body_pattern,omitempty" jsonschema:"search pattern (regex) for replace_body action"`

	// ActionType is the action type: add_header, set_header, remove_header, or replace_body.
	ActionType string `json:"action_type" jsonschema:"action type: add_header, set_header, remove_header, or replace_body"`

	// HeaderName is the header name (for add_header, set_header, remove_header).
	HeaderName string `json:"header_name,omitempty" jsonschema:"header name for header actions"`

	// HeaderValue is the header value (for add_header, set_header).
	HeaderValue string `json:"header_value,omitempty" jsonschema:"header value for add_header / set_header"`

	// BodyReplace is the replacement string for replace_body (supports $1, $2 capture groups).
	BodyReplace string `json:"body_replace,omitempty" jsonschema:"replacement for replace_body (supports $1, $2 capture groups)"`
}

// transformRuleOutput is the JSON representation of an auto-transform rule for MCP tool output.
type transformRuleOutput struct {
	ID          string   `json:"id"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
	Direction   string   `json:"direction"`
	HostPattern string   `json:"host_pattern,omitempty"`
	PathPattern string   `json:"path_pattern,omitempty"`
	Methods     []string `json:"methods,omitempty"`
	BodyPattern string   `json:"body_pattern,omitempty"`
	ActionType  string   `json:"action_type"`
	HeaderName  string   `json:"header_name,omitempty"`
	HeaderValue string   `json:"header_value,omitempty"`
	BodyReplace string   `json:"body_replace,omitempty"`
}

// compileTransformRule compiles a transformRuleInput into an
// httprules.TransformRule. Validation includes CWE-113 CRLF rejection on
// header name/value, action-type enum decoding, and pattern compilation.
func compileTransformRule(input transformRuleInput) (*httprules.TransformRule, error) {
	if err := validateTransformRuleInput(input); err != nil {
		return nil, err
	}
	dir, err := normalizeHTTPDirection(input.Direction)
	if err != nil {
		return nil, err
	}
	action, err := transformActionFromName(input.ActionType)
	if err != nil {
		return nil, err
	}
	rule, err := httprules.CompileTransformRule(
		input.ID,
		input.Priority,
		dir,
		input.HostPattern,
		input.PathPattern,
		input.Methods,
		action,
		input.HeaderName,
		input.HeaderValue,
		input.BodyPattern,
		input.BodyReplace,
	)
	if err != nil {
		return nil, err
	}
	rule.Enabled = input.Enabled
	return rule, nil
}

// fromTransformRule converts an httprules.TransformRule into the JSON
// output shape used by MCP tools.
func fromTransformRule(r httprules.TransformRule) transformRuleOutput {
	out := transformRuleOutput{
		ID:          r.ID,
		Enabled:     r.Enabled,
		Priority:    r.Priority,
		Direction:   string(r.Direction),
		Methods:     r.Methods,
		ActionType:  transformActionName(r.ActionType),
		HeaderName:  r.HeaderName,
		HeaderValue: r.HeaderValue,
		BodyReplace: r.BodyReplace,
	}
	if r.HostPattern != nil {
		out.HostPattern = r.HostPattern.String()
	}
	if r.PathPattern != nil {
		out.PathPattern = r.PathPattern.String()
	}
	if r.BodyPattern != nil {
		out.BodyPattern = r.BodyPattern.String()
	}
	return out
}

// transformActionFromName decodes the JSON action_type string into the
// httprules.TransformActionType enum.
func transformActionFromName(name string) (httprules.TransformActionType, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "add_header":
		return httprules.TransformAddHeader, nil
	case "set_header":
		return httprules.TransformSetHeader, nil
	case "remove_header":
		return httprules.TransformRemoveHeader, nil
	case "replace_body":
		return httprules.TransformReplaceBody, nil
	default:
		return 0, fmt.Errorf("action_type: unknown value %q (expected add_header|set_header|remove_header|replace_body)", name)
	}
}

// transformActionName encodes the httprules.TransformActionType enum to
// its JSON action_type string.
func transformActionName(t httprules.TransformActionType) string {
	switch t {
	case httprules.TransformAddHeader:
		return "add_header"
	case httprules.TransformSetHeader:
		return "set_header"
	case httprules.TransformRemoveHeader:
		return "remove_header"
	case httprules.TransformReplaceBody:
		return "replace_body"
	default:
		return ""
	}
}

// validateTransformRuleInput checks a transform rule for CRLF injection in
// header names and values (CWE-113).
func validateTransformRuleInput(input transformRuleInput) error {
	switch strings.ToLower(strings.TrimSpace(input.ActionType)) {
	case "add_header", "set_header":
		if strings.ContainsAny(input.HeaderName, "\r\n") {
			return fmt.Errorf("rule %q: header_name contains CR/LF characters", input.ID)
		}
		if strings.ContainsAny(input.HeaderValue, "\r\n") {
			return fmt.Errorf("rule %q: header_value contains CR/LF characters", input.ID)
		}
	case "remove_header":
		if strings.ContainsAny(input.HeaderName, "\r\n") {
			return fmt.Errorf("rule %q: header_name contains CR/LF characters", input.ID)
		}
	}
	return nil
}

// applyTransformRules validates and sets auto-transform rules from the input.
func (s *Server) applyTransformRules(inputs []transformRuleInput) error {
	return applyTransformRulesHelper(s.pipeline.transformHTTPEngine, inputs)
}

// applyTransformRulesHelper validates and sets auto-transform rules on the
// given engine. Standalone for use by handler structs that don't carry
// the full Server.
func applyTransformRulesHelper(engine *httprules.TransformEngine, inputs []transformRuleInput) error {
	if engine == nil {
		return fmt.Errorf("transform engine is not initialized")
	}
	rulesList := make([]httprules.TransformRule, len(inputs))
	for i, input := range inputs {
		r, err := compileTransformRule(input)
		if err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		rulesList[i] = *r
	}
	engine.SetRules(rulesList)
	return nil
}
