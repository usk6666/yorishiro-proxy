package mcp

import (
	"fmt"
	"strings"

	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// transformRuleInput is the JSON representation of an auto-transform rule for MCP tool input.
//
// The schema currently surfaces HTTP-only conditions (URLPattern, Methods,
// HeaderMatch). The configure_tool dispatches to the per-protocol HTTP
// TransformEngine (internal/rules/http). WS / gRPC auto-transform are
// expected to land in a follow-up Issue mirroring the intercept_rules
// per-protocol dispatch in configure_tool.go.
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
	// URLPattern is a regular expression matched against the request URL path.
	// (Mapped onto httprules.TransformRule.PathPattern.)
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"regex pattern for URL path matching"`

	// Methods is a whitelist of HTTP methods (case-insensitive).
	Methods []string `json:"methods,omitempty" jsonschema:"HTTP method whitelist (e.g. POST, PUT, DELETE)"`

	// HeaderMatch is reserved; the per-protocol engine does not currently
	// match by headers in conditions. Values are accepted for schema
	// compatibility and ignored.
	HeaderMatch map[string]string `json:"header_match,omitempty" jsonschema:"header name to regex pattern mapping (currently ignored, retained for schema compatibility)"`
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

// transformActionTypeFromString converts the MCP-string action type to the
// per-protocol httprules.TransformActionType enum.
func transformActionTypeFromString(s string) (httprules.TransformActionType, error) {
	switch s {
	case "add_header":
		return httprules.TransformAddHeader, nil
	case "set_header":
		return httprules.TransformSetHeader, nil
	case "remove_header":
		return httprules.TransformRemoveHeader, nil
	case "replace_body":
		return httprules.TransformReplaceBody, nil
	default:
		return 0, fmt.Errorf("unknown action type %q", s)
	}
}

// transformActionTypeToString reverses transformActionTypeFromString for
// the rule output struct.
func transformActionTypeToString(t httprules.TransformActionType) string {
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

// toTransformRule compiles an MCP input rule into a per-protocol HTTP
// TransformRule. URLPattern is mapped to PathPattern; HeaderMatch is
// accepted but ignored (see transformConditionsInput).
func toTransformRule(input transformRuleInput) (httprules.TransformRule, error) {
	actionType, err := transformActionTypeFromString(input.Action.Type)
	if err != nil {
		return httprules.TransformRule{}, fmt.Errorf("rule %q: %w", input.ID, err)
	}
	dir := httprules.RuleDirection(input.Direction)
	switch dir {
	case httprules.DirectionRequest, httprules.DirectionResponse, httprules.DirectionBoth:
		// ok
	case "":
		return httprules.TransformRule{}, fmt.Errorf("rule %q: direction is required", input.ID)
	default:
		return httprules.TransformRule{}, fmt.Errorf("rule %q: invalid direction %q", input.ID, input.Direction)
	}
	rulePtr, err := httprules.CompileTransformRule(
		input.ID,
		input.Priority,
		dir,
		"", // hostPattern (no MCP surface)
		input.Conditions.URLPattern,
		input.Conditions.Methods,
		actionType,
		input.Action.Header,
		input.Action.Value,
		input.Action.Pattern,
		input.Action.Value,
	)
	if err != nil {
		return httprules.TransformRule{}, fmt.Errorf("rule %q: %w", input.ID, err)
	}
	rulePtr.Enabled = input.Enabled
	return *rulePtr, nil
}

// fromTransformRule converts a per-protocol httprules.TransformRule back to
// the MCP wire-format output shape.
func fromTransformRule(r httprules.TransformRule) transformRuleOutput {
	out := transformRuleOutput{
		ID:        r.ID,
		Enabled:   r.Enabled,
		Priority:  r.Priority,
		Direction: string(r.Direction),
		Conditions: transformConditionsOutput{
			Methods: r.Methods,
		},
		Action: transformActionOutput{
			Type:   transformActionTypeToString(r.ActionType),
			Header: r.HeaderName,
			Value:  r.HeaderValue,
		},
	}
	if r.PathPattern != nil {
		out.Conditions.URLPattern = r.PathPattern.String()
	}
	if r.BodyPattern != nil {
		out.Action.Pattern = r.BodyPattern.String()
	}
	if r.ActionType == httprules.TransformReplaceBody {
		out.Action.Value = r.BodyReplace
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
// All rules are routed to the HTTP per-protocol engine (current schema is
// HTTP-only).
func (s *Server) applyTransformRules(inputs []transformRuleInput) error {
	return applyTransformRulesHelper(s.pipeline.transformHTTPEngine, inputs)
}

// applyTransformRulesHelper validates and sets auto-transform rules on the
// given engine. Standalone form for callers without a Server pointer.
func applyTransformRulesHelper(engine *httprules.TransformEngine, inputs []transformRuleInput) error {
	if engine == nil {
		return fmt.Errorf("transform engine is not initialized")
	}

	rulesList := make([]httprules.TransformRule, 0, len(inputs))
	seen := make(map[string]bool)
	for _, input := range inputs {
		if err := validateTransformRuleInput(input); err != nil {
			return err
		}
		if input.ID != "" {
			if seen[input.ID] {
				return fmt.Errorf("duplicate rule ID %q", input.ID)
			}
			seen[input.ID] = true
		}
		r, err := toTransformRule(input)
		if err != nil {
			return err
		}
		rulesList = append(rulesList, r)
	}

	engine.SetRules(rulesList)
	return nil
}
