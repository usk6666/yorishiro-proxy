// Package rules provides auto-transform rules for modifying HTTP requests
// and responses as they pass through the proxy. Rules define pattern-based
// matching conditions and actions (header add/remove/set, body replace) that
// are applied automatically to all matching traffic.
package rules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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
	// URLPattern is a regular expression matched against the full request URL
	// (e.g. "http://example.com/path"). An empty string matches all URLs.
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
		return nil, fmt.Errorf("invalid action type %q: valid types are %q, %q, %q, %q",
			r.Action.Type, ActionAddHeader, ActionSetHeader, ActionRemoveHeader, ActionReplaceBody)
	}

	if err := validateAction(r.Action); err != nil {
		return nil, err
	}

	cr := &compiledRule{rule: r}

	if err := compileConditionPatterns(r.Conditions, cr); err != nil {
		return nil, err
	}

	if err := compileBodyPattern(r.Action, cr); err != nil {
		return nil, err
	}

	return cr, nil
}

// compileConditionPatterns compiles URL and header match patterns from conditions.
func compileConditionPatterns(cond Conditions, cr *compiledRule) error {
	if cond.URLPattern != "" {
		re, err := compileRegexWithLimit(cond.URLPattern, "url_pattern")
		if err != nil {
			return err
		}
		cr.urlPatternRe = re
	}

	if len(cond.HeaderMatch) > 0 {
		cr.headerMatchRes = make(map[string]*regexp.Regexp, len(cond.HeaderMatch))
		for name, pattern := range cond.HeaderMatch {
			re, err := compileRegexWithLimit(pattern, fmt.Sprintf("header_match pattern for %q", name))
			if err != nil {
				return err
			}
			cr.headerMatchRes[strings.ToLower(name)] = re
		}
	}

	return nil
}

// compileBodyPattern compiles the body replacement pattern for replace_body actions.
func compileBodyPattern(action Action, cr *compiledRule) error {
	if action.Type != ActionReplaceBody || action.Pattern == "" {
		return nil
	}
	re, err := compileRegexWithLimit(action.Pattern, "body replacement pattern")
	if err != nil {
		return err
	}
	cr.bodyPatternRe = re
	return nil
}

// compileRegexWithLimit validates length and compiles a regex pattern.
func compileRegexWithLimit(pattern, label string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("%s too long: %d > %d", label, len(pattern), maxRegexPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: %w", label, pattern, err)
	}
	return re, nil
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
func (cr *compiledRule) matchesRequest(method string, u *url.URL, headers parser.RawHeaders) bool {
	// Check URL pattern against the full URL (scheme + host + path + query).
	if cr.urlPatternRe != nil {
		fullURL := ""
		if u != nil {
			fullURL = u.String()
		}
		if !cr.urlPatternRe.MatchString(fullURL) {
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
func (cr *compiledRule) matchesResponse(statusCode int, headers parser.RawHeaders) bool {
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
