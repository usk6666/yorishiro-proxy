package http

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// RuleDirection specifies which envelope direction a rule applies to.
type RuleDirection string

const (
	DirectionRequest  RuleDirection = "request"
	DirectionResponse RuleDirection = "response"
	DirectionBoth     RuleDirection = "both"
)

// InterceptRule defines conditions for intercepting HTTP messages.
// All non-empty conditions are AND-combined. Empty conditions match all.
type InterceptRule struct {
	ID          string
	Enabled     bool
	Direction   RuleDirection
	HostPattern *regexp.Regexp            // matches EnvelopeContext.TargetHost
	PathPattern *regexp.Regexp            // matches HTTPMessage.Path
	Methods     []string                  // whitelist of allowed methods
	HeaderMatch map[string]*regexp.Regexp // lowercased key → value pattern
}

// InterceptEngine matches HTTP requests/responses against intercept rules.
// Thread-safe via RWMutex.
type InterceptEngine struct {
	mu    sync.RWMutex
	rules []InterceptRule
}

// NewInterceptEngine creates an empty InterceptEngine.
func NewInterceptEngine() *InterceptEngine {
	return &InterceptEngine{}
}

// SetRules replaces all rules atomically.
func (e *InterceptEngine) SetRules(rules []InterceptRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// AddRule adds a rule to the engine.
func (e *InterceptEngine) AddRule(rule InterceptRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RemoveRule removes a rule by ID.
func (e *InterceptEngine) RemoveRule(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return
		}
	}
}

// Rules returns a defensive copy of the current rule slice.
// The HoldQueue + per-protocol-engine architecture (RFC-001 N8/N9) leaves
// rule listing as the only stable source of truth for tools that report
// rule counts and enabled state (configure_tool's intercept_rules result).
func (e *InterceptEngine) Rules() []InterceptRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]InterceptRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// EnableRule toggles the Enabled flag on the rule with the given ID.
// Returns false if no such rule is present.
func (e *InterceptEngine) EnableRule(id string, enabled bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules[i].Enabled = enabled
			return true
		}
	}
	return false
}

// MatchRequest checks if an HTTP request matches any intercept rules.
// Returns matched rule IDs. Empty/nil means no match.
func (e *InterceptEngine) MatchRequest(env *envelope.Envelope, msg *envelope.HTTPMessage) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Direction != DirectionRequest && rule.Direction != DirectionBoth {
			continue
		}
		if e.matchesRule(&rule, env, msg) {
			matched = append(matched, rule.ID)
		}
	}
	return matched
}

// MatchResponse checks if an HTTP response matches any intercept rules.
func (e *InterceptEngine) MatchResponse(env *envelope.Envelope, msg *envelope.HTTPMessage) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Direction != DirectionResponse && rule.Direction != DirectionBoth {
			continue
		}
		if e.matchesRule(&rule, env, msg) {
			matched = append(matched, rule.ID)
		}
	}
	return matched
}

func (e *InterceptEngine) matchesRule(rule *InterceptRule, env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	// Host pattern check.
	if rule.HostPattern != nil {
		host := extractHostname(env.Context.TargetHost)
		if !rule.HostPattern.MatchString(host) {
			return false
		}
	}

	// Path pattern check.
	if rule.PathPattern != nil {
		if !rule.PathPattern.MatchString(msg.Path) {
			return false
		}
	}

	// Method whitelist check.
	if len(rule.Methods) > 0 {
		found := false
		for _, m := range rule.Methods {
			if strings.EqualFold(m, msg.Method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Header match check (case-insensitive name lookup).
	if len(rule.HeaderMatch) > 0 {
		for name, pattern := range rule.HeaderMatch {
			value := headerGet(msg.Headers, name)
			if !pattern.MatchString(value) {
				return false
			}
		}
	}

	return true
}

// CompileInterceptRule compiles a rule from config values.
func CompileInterceptRule(id string, direction RuleDirection, hostPattern, pathPattern string, methods []string, headerMatch map[string]string) (*InterceptRule, error) {
	rule := &InterceptRule{
		ID:        id,
		Enabled:   true,
		Direction: direction,
	}

	if hostPattern != "" {
		re, err := common.CompilePattern(hostPattern)
		if err != nil {
			return nil, err
		}
		rule.HostPattern = re
	}

	if pathPattern != "" {
		re, err := common.CompilePattern(pathPattern)
		if err != nil {
			return nil, err
		}
		rule.PathPattern = re
	}

	if len(methods) > 0 {
		rule.Methods = methods
	}

	if len(headerMatch) > 0 {
		// Lowercase keys for HTTP case-insensitive matching.
		lowered := make(map[string]string, len(headerMatch))
		for k, v := range headerMatch {
			lowered[strings.ToLower(k)] = v
		}
		compiled, err := common.CompileHeaderMatch(lowered)
		if err != nil {
			return nil, err
		}
		rule.HeaderMatch = compiled
	}

	return rule, nil
}

// extractHostname strips port from a host:port string.
func extractHostname(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // no port, return as-is
	}
	return host
}
