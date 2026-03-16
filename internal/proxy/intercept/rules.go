// Package intercept provides a rule engine for intercepting HTTP requests
// and responses based on configurable matching conditions. Rules support
// host pattern (regex), path pattern (regex), HTTP method whitelist, and
// header matching (regex).
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

// maxRegexPatternLen is the maximum allowed length (in bytes) for regex
// patterns in intercept rules. This prevents excessive memory consumption
// during regex compilation and CPU consumption during matching. Consistent
// with the limits in the auto-transform, macro, body_patch, and fuzzer packages.
const maxRegexPatternLen = 1024

// maxFlowIDLen is the maximum allowed length (in bytes) for FlowID values.
const maxFlowIDLen = 256

// validDirections contains all valid Direction values for validation.
var validDirections = map[Direction]bool{
	DirectionRequest:  true,
	DirectionResponse: true,
	DirectionBoth:     true,
}

// Conditions defines the matching criteria for an intercept rule.
// All non-empty fields must match for the conditions to be satisfied (AND logic).
type Conditions struct {
	// HostPattern is a regular expression matched against the request hostname
	// (port excluded). An empty string matches all hosts.
	HostPattern string `json:"host_pattern,omitempty"`

	// PathPattern is a regular expression matched against the request URL path.
	// An empty string matches all paths.
	PathPattern string `json:"path_pattern,omitempty"`

	// Methods is a whitelist of HTTP methods (case-insensitive).
	// An empty slice matches all methods.
	Methods []string `json:"methods,omitempty"`

	// HeaderMatch maps header names to regular expressions.
	// All specified headers must match (AND logic).
	// Header names are matched case-insensitively.
	// An empty map matches all headers.
	HeaderMatch map[string]string `json:"header_match,omitempty"`

	// UpgradeURLPattern is a regular expression matched against the WebSocket
	// upgrade request URL. This field is exclusive to WebSocket intercept rules
	// and must not be combined with HTTP-only conditions (HostPattern, PathPattern,
	// Methods, HeaderMatch). An empty string matches all WebSocket URLs.
	UpgradeURLPattern string `json:"upgrade_url_pattern,omitempty"`

	// FlowID specifies a particular WebSocket flow ID to intercept.
	// This field is exclusive to WebSocket intercept rules. An empty string
	// matches all flows.
	FlowID string `json:"flow_id,omitempty"`
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
	rule                Rule
	hostPatternRe       *regexp.Regexp
	pathPatternRe       *regexp.Regexp
	headerMatchRes      map[string]*regexp.Regexp // canonical header name -> compiled regex
	upgradeURLPatternRe *regexp.Regexp
}

// compileRegexPattern validates the length and compiles a regex pattern.
// fieldName is used in error messages. Returns nil regex for empty patterns.
func compileRegexPattern(pattern string, fieldName string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("%s too long: %d > %d", fieldName, len(pattern), maxRegexPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: %w", fieldName, pattern, err)
	}
	return re, nil
}

// validateConditionExclusivity checks that WebSocket and HTTP conditions are not mixed.
func validateConditionExclusivity(c Conditions) error {
	hasWSCondition := c.UpgradeURLPattern != "" || c.FlowID != ""
	hasHTTPCondition := c.HostPattern != "" || c.PathPattern != "" ||
		len(c.Methods) > 0 || len(c.HeaderMatch) > 0
	if hasWSCondition && hasHTTPCondition {
		return fmt.Errorf("WebSocket conditions (upgrade_url_pattern, flow_id) and HTTP conditions (host_pattern, path_pattern, methods, header_match) are mutually exclusive")
	}
	return nil
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

	if err := validateConditionExclusivity(r.Conditions); err != nil {
		return nil, err
	}

	if len(r.Conditions.FlowID) > maxFlowIDLen {
		return nil, fmt.Errorf("flow_id too long: %d > %d", len(r.Conditions.FlowID), maxFlowIDLen)
	}

	cr := &compiledRule{rule: r}
	var err error

	if cr.upgradeURLPatternRe, err = compileRegexPattern(r.Conditions.UpgradeURLPattern, "upgrade_url_pattern"); err != nil {
		return nil, err
	}
	if cr.hostPatternRe, err = compileRegexPattern(r.Conditions.HostPattern, "host_pattern"); err != nil {
		return nil, err
	}
	if cr.pathPatternRe, err = compileRegexPattern(r.Conditions.PathPattern, "path_pattern"); err != nil {
		return nil, err
	}

	// Compile header match patterns.
	if len(r.Conditions.HeaderMatch) > 0 {
		cr.headerMatchRes = make(map[string]*regexp.Regexp, len(r.Conditions.HeaderMatch))
		for name, pattern := range r.Conditions.HeaderMatch {
			re, err := compileRegexPattern(pattern, fmt.Sprintf("header_match pattern for %q", name))
			if err != nil {
				return nil, err
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
	if !cr.matchesHost(u, headers) {
		return false
	}
	if !cr.matchesPath(u) {
		return false
	}
	if !cr.matchesMethod(method) {
		return false
	}
	if !cr.matchesHeaders(headers) {
		return false
	}
	return true
}

// matchesHost checks whether the request host matches the compiled host pattern.
// For HTTPS MITM (CONNECT tunnel), u.Host may be empty; falls back to the Host header.
func (cr *compiledRule) matchesHost(u *url.URL, headers http.Header) bool {
	if cr.hostPatternRe == nil {
		return true
	}
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	if host == "" && headers != nil {
		host = extractHostname(headers.Get("Host"))
	}
	return cr.hostPatternRe.MatchString(host)
}

// matchesPath checks whether the request path matches the compiled path pattern.
func (cr *compiledRule) matchesPath(u *url.URL) bool {
	if cr.pathPatternRe == nil {
		return true
	}
	path := ""
	if u != nil {
		path = u.Path
	}
	return cr.pathPatternRe.MatchString(path)
}

// matchesMethod checks whether the HTTP method is in the configured whitelist.
func (cr *compiledRule) matchesMethod(method string) bool {
	if len(cr.rule.Conditions.Methods) == 0 {
		return true
	}
	for _, m := range cr.rule.Conditions.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// matchesHeaders checks whether the request headers match all compiled header patterns.
func (cr *compiledRule) matchesHeaders(headers http.Header) bool {
	if len(cr.headerMatchRes) == 0 {
		return true
	}
	if headers == nil {
		return false
	}
	for canonicalName, re := range cr.headerMatchRes {
		val := headers.Get(canonicalName)
		if !re.MatchString(val) {
			return false
		}
	}
	return true
}

// matchesResponse evaluates whether the compiled rule matches the given
// response status code and headers. Host pattern, path pattern, and method
// conditions are not applicable to responses and are ignored.
func (cr *compiledRule) matchesResponse(statusCode int, headers http.Header) bool {
	// For response matching, host_pattern, path_pattern, and methods are not applicable.
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

// isWebSocketRule returns true if the rule has any WebSocket-specific conditions.
func (cr *compiledRule) isWebSocketRule() bool {
	return cr.upgradeURLPatternRe != nil || cr.rule.Conditions.FlowID != ""
}

// matchesWebSocketFrame evaluates whether the compiled rule matches the given
// WebSocket frame parameters. upgradeURL is the URL of the original WebSocket
// upgrade request, direction is "client_to_server" or "server_to_client",
// and flowID is the identifier of the WebSocket flow.
func (cr *compiledRule) matchesWebSocketFrame(upgradeURL string, flowID string) bool {
	if cr.upgradeURLPatternRe != nil {
		if !cr.upgradeURLPatternRe.MatchString(upgradeURL) {
			return false
		}
	}
	if cr.rule.Conditions.FlowID != "" {
		if cr.rule.Conditions.FlowID != flowID {
			return false
		}
	}
	return true
}

// extractHostname extracts the hostname from a host string, stripping the
// port if present. For example, "example.com:8080" returns "example.com".
func extractHostname(hostport string) string {
	if hostport == "" {
		return ""
	}
	// Handle IPv6 addresses like "[::1]:8080".
	if strings.HasPrefix(hostport, "[") {
		if i := strings.LastIndex(hostport, "]"); i >= 0 {
			return hostport[1:i]
		}
		return hostport
	}
	// Strip port.
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i]
	}
	return hostport
}
