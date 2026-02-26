// Package intercept provides a rule engine for intercepting HTTP requests
// and responses based on configurable matching conditions. Rules support
// URL pattern (regex), HTTP method whitelist, and header matching (regex).
package intercept

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Direction specifies whether a rule applies to requests, responses, or both.
type Direction string

const (
	// DirectionRequest matches only outgoing requests.
	DirectionRequest Direction = "request"
	// DirectionResponse matches only incoming responses.
	DirectionResponse Direction = "response"
	// DirectionBoth matches both requests and responses.
	DirectionBoth Direction = "both"
)

// validDirections contains all valid Direction values for validation.
var validDirections = map[Direction]bool{
	DirectionRequest:  true,
	DirectionResponse: true,
	DirectionBoth:     true,
}

// Conditions defines the matching criteria for an intercept rule.
// All non-empty fields must match for the conditions to be satisfied (AND logic).
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

// Rule defines a single intercept rule with an ID, enabled state,
// direction, and matching conditions.
type Rule struct {
	// ID is the unique identifier for this rule.
	ID string `json:"id"`

	// Enabled indicates whether this rule is active.
	Enabled bool `json:"enabled"`

	// Direction specifies whether the rule applies to requests, responses, or both.
	Direction Direction `json:"direction"`

	// Conditions defines the matching criteria.
	Conditions Conditions `json:"conditions"`
}

// compiledRule holds a Rule along with its pre-compiled regular expressions
// for efficient matching.
type compiledRule struct {
	rule           Rule
	urlPatternRe   *regexp.Regexp
	headerMatchRes map[string]*regexp.Regexp // canonical header name -> compiled regex
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

	cr := &compiledRule{rule: r}

	// Compile URL pattern.
	if r.Conditions.URLPattern != "" {
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
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid header_match pattern for %q: %w", name, err)
			}
			// Store with canonical header name for consistent lookup.
			cr.headerMatchRes[http.CanonicalHeaderKey(name)] = re
		}
	}

	return cr, nil
}

// matchesRequest evaluates whether the compiled rule matches the given
// HTTP method, URL, and headers. Only applicable conditions are checked;
// empty conditions match everything.
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
// response status code and headers. URL pattern and method conditions
// are not applicable to responses and are ignored.
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
