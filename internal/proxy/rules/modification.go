// Package rules provides auto-transform rules for modifying HTTP requests
// and responses as they pass through the proxy. Rules define pattern-based
// matching conditions and actions (header add/remove/set, body replace) that
// are applied automatically to all matching traffic.
package rules

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// maxRegexPatternLen is the maximum allowed length (in bytes) for regex
// patterns in auto-transform rules. This prevents ReDoS (CWE-1333) by
// limiting the complexity of user-supplied patterns. Consistent with the
// limits in the macro, body_patch, and fuzzer packages.
const maxRegexPatternLen = 1024

// Direction specifies whether a rule applies to requests, responses, or both.
type Direction string

const (
	// DirectionRequest applies the rule only to outgoing requests.
	DirectionRequest Direction = "request"
	// DirectionResponse applies the rule only to incoming responses.
	DirectionResponse Direction = "response"
	// DirectionBoth applies the rule to both requests and responses.
	DirectionBoth Direction = "both"
)

// validDirections contains all valid Direction values for validation.
var validDirections = map[Direction]bool{
	DirectionRequest:  true,
	DirectionResponse: true,
	DirectionBoth:     true,
}

// ActionType specifies the type of transformation to apply.
type ActionType string

const (
	// ActionAddHeader adds a header to the request/response.
	// If the header already exists, the new value is appended.
	ActionAddHeader ActionType = "add_header"

	// ActionSetHeader sets a header value, replacing any existing values.
	ActionSetHeader ActionType = "set_header"

	// ActionRemoveHeader removes a header from the request/response.
	ActionRemoveHeader ActionType = "remove_header"

	// ActionReplaceBody performs a string replacement in the body.
	ActionReplaceBody ActionType = "replace_body"
)

// validActionTypes contains all valid ActionType values.
var validActionTypes = map[ActionType]bool{
	ActionAddHeader:    true,
	ActionSetHeader:    true,
	ActionRemoveHeader: true,
	ActionReplaceBody:  true,
}

// Conditions defines the matching criteria for an auto-transform rule.
// All non-empty fields must match for the conditions to be satisfied (AND logic).
// These are compatible with the intercept package's Conditions structure.
type Conditions struct {
	// URLPattern is a regular expression matched against the request URL path.
	// An empty string matches all URLs.
	URLPattern string `json:"url_pattern,omitempty"`

	// Methods is a whitelist of HTTP methods (case-insensitive).
	// An empty slice matches all methods.
	Methods []string `json:"methods,omitempty"`

	// HeaderMatch maps header names to regular expressions.
	// All specified headers must match (AND logic).
	// Header names are matched case-insensitively.
	// An empty map matches all headers.
	HeaderMatch map[string]string `json:"header_match,omitempty"`
}

// Action defines the transformation to apply when conditions match.
type Action struct {
	// Type is the type of transformation.
	Type ActionType `json:"type"`

	// Header is the header name for add_header, set_header, and remove_header actions.
	Header string `json:"header,omitempty"`

	// Value is the value for add_header and set_header actions,
	// or the replacement string for replace_body.
	Value string `json:"value,omitempty"`

	// Pattern is the search string (or regex) for replace_body actions.
	Pattern string `json:"pattern,omitempty"`
}

// Rule defines a single auto-transform rule with an ID, priority, enabled state,
// direction, matching conditions, and transformation action.
type Rule struct {
	// ID is the unique identifier for this rule.
	ID string `json:"id"`

	// Enabled indicates whether this rule is active.
	Enabled bool `json:"enabled"`

	// Priority determines the order in which rules are applied.
	// Lower values are applied first. Rules with equal priority
	// are applied in the order they were added.
	Priority int `json:"priority"`

	// Direction specifies whether the rule applies to requests, responses, or both.
	Direction Direction `json:"direction"`

	// Conditions defines the matching criteria.
	Conditions Conditions `json:"conditions"`

	// Action defines the transformation to apply.
	Action Action `json:"action"`
}

// compiledRule holds a Rule along with its pre-compiled regular expressions
// for efficient matching and body replacement.
type compiledRule struct {
	rule           Rule
	urlPatternRe   *regexp.Regexp
	headerMatchRes map[string]*regexp.Regexp // canonical header name -> compiled regex
	bodyPatternRe  *regexp.Regexp            // compiled body replacement pattern
}

// compileRule validates and compiles a Rule's patterns into a compiledRule.
// It returns an error if any pattern is invalid.
func compileRule(r Rule) (*compiledRule, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("rule ID must not be empty")
	}

	if !validDirections[r.Direction] {
		return nil, fmt.Errorf("invalid direction %q: must be %q, %q, or %q",
			r.Direction, DirectionRequest, DirectionResponse, DirectionBoth)
	}

	if !validActionTypes[r.Action.Type] {
		return nil, fmt.Errorf("invalid action type %q", r.Action.Type)
	}

	// Validate action fields based on type.
	if err := validateAction(r.Action); err != nil {
		return nil, err
	}

	cr := &compiledRule{rule: r}

	// Compile URL pattern.
	if r.Conditions.URLPattern != "" {
		if len(r.Conditions.URLPattern) > maxRegexPatternLen {
			return nil, fmt.Errorf("url_pattern too long: %d > %d", len(r.Conditions.URLPattern), maxRegexPatternLen)
		}
		re, err := regexp.Compile(r.Conditions.URLPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid url_pattern %q: %w", r.Conditions.URLPattern, err)
		}
		cr.urlPatternRe = re
	}

	// Compile header match patterns.
	if len(r.Conditions.HeaderMatch) > 0 {
		cr.headerMatchRes = make(map[string]*regexp.Regexp, len(r.Conditions.HeaderMatch))
		for name, pattern := range r.Conditions.HeaderMatch {
			if len(pattern) > maxRegexPatternLen {
				return nil, fmt.Errorf("header_match pattern for %q too long: %d > %d", name, len(pattern), maxRegexPatternLen)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid header_match pattern for %q: %w", name, err)
			}
			// Store with canonical header name for consistent lookup.
			cr.headerMatchRes[http.CanonicalHeaderKey(name)] = re
		}
	}

	// Compile body replacement pattern.
	if r.Action.Type == ActionReplaceBody && r.Action.Pattern != "" {
		if len(r.Action.Pattern) > maxRegexPatternLen {
			return nil, fmt.Errorf("body replacement pattern too long: %d > %d", len(r.Action.Pattern), maxRegexPatternLen)
		}
		re, err := regexp.Compile(r.Action.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid body replacement pattern %q: %w", r.Action.Pattern, err)
		}
		cr.bodyPatternRe = re
	}

	return cr, nil
}

// containsCRLF reports whether s contains any CR (\r) or LF (\n) characters.
// This is used to prevent HTTP header injection (CWE-113) by rejecting header
// names and values that contain line terminators.
func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// validateAction checks that the action fields are valid for the given action type.
func validateAction(a Action) error {
	switch a.Type {
	case ActionAddHeader, ActionSetHeader:
		if a.Header == "" {
			return fmt.Errorf("action %q requires header name", a.Type)
		}
		if containsCRLF(a.Header) {
			return fmt.Errorf("action %q: header name contains invalid CR/LF characters", a.Type)
		}
		if containsCRLF(a.Value) {
			return fmt.Errorf("action %q: header value contains invalid CR/LF characters", a.Type)
		}
	case ActionRemoveHeader:
		if a.Header == "" {
			return fmt.Errorf("action %q requires header name", a.Type)
		}
		if containsCRLF(a.Header) {
			return fmt.Errorf("action %q: header name contains invalid CR/LF characters", a.Type)
		}
	case ActionReplaceBody:
		if a.Pattern == "" {
			return fmt.Errorf("action %q requires pattern", a.Type)
		}
	}
	return nil
}

// matchesRequest evaluates whether the compiled rule matches the given
// HTTP method, URL, and headers.
func (cr *compiledRule) matchesRequest(method string, u *url.URL, headers http.Header) bool {
	// Check URL pattern.
	if cr.urlPatternRe != nil {
		path := ""
		if u != nil {
			path = u.Path
		}
		if !cr.urlPatternRe.MatchString(path) {
			return false
		}
	}

	// Check method whitelist.
	if len(cr.rule.Conditions.Methods) > 0 {
		found := false
		for _, m := range cr.rule.Conditions.Methods {
			if strings.EqualFold(m, method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check header matches.
	if len(cr.headerMatchRes) > 0 {
		if headers == nil {
			return false
		}
		for canonicalName, re := range cr.headerMatchRes {
			val := headers.Get(canonicalName)
			if !re.MatchString(val) {
				return false
			}
		}
	}

	return true
}

// matchesResponse evaluates whether the compiled rule matches the given
// response status code and headers.
func (cr *compiledRule) matchesResponse(statusCode int, headers http.Header) bool {
	// For response matching, url_pattern and methods are not applicable.
	// Only header_match applies.
	if len(cr.headerMatchRes) > 0 {
		if headers == nil {
			return false
		}
		for canonicalName, re := range cr.headerMatchRes {
			val := headers.Get(canonicalName)
			if !re.MatchString(val) {
				return false
			}
		}
	}

	_ = statusCode // reserved for future use
	return true
}

// cloneRule returns a deep copy of a Rule.
func cloneRule(r Rule) Rule {
	out := Rule{
		ID:        r.ID,
		Enabled:   r.Enabled,
		Priority:  r.Priority,
		Direction: r.Direction,
		Conditions: Conditions{
			URLPattern: r.Conditions.URLPattern,
		},
		Action: Action{
			Type:    r.Action.Type,
			Header:  r.Action.Header,
			Value:   r.Action.Value,
			Pattern: r.Action.Pattern,
		},
	}
	if len(r.Conditions.Methods) > 0 {
		out.Conditions.Methods = make([]string, len(r.Conditions.Methods))
		copy(out.Conditions.Methods, r.Conditions.Methods)
	}
	if len(r.Conditions.HeaderMatch) > 0 {
		out.Conditions.HeaderMatch = make(map[string]string, len(r.Conditions.HeaderMatch))
		for k, v := range r.Conditions.HeaderMatch {
			out.Conditions.HeaderMatch[k] = v
		}
	}
	return out
}
