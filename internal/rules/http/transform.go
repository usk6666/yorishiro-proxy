package http

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// TransformActionType specifies the kind of transformation.
type TransformActionType int

const (
	TransformAddHeader    TransformActionType = iota // append header (allows duplicates)
	TransformSetHeader                               // delete all matching, then add
	TransformRemoveHeader                            // delete all matching
	TransformReplaceBody                             // regex replace on body bytes
)

// TransformRule defines a single transformation with match conditions and action.
type TransformRule struct {
	ID       string
	Enabled  bool
	Priority int // lower values applied first

	// Match conditions (AND-combined, empty = match all).
	Direction   RuleDirection
	HostPattern *regexp.Regexp
	PathPattern *regexp.Regexp
	Methods     []string

	// Action.
	ActionType  TransformActionType
	HeaderName  string // for Add/Set/Remove
	HeaderValue string // for Add/Set
	BodyPattern *regexp.Regexp
	BodyReplace string // replacement (supports $1, $2 capture groups)
}

// TransformEngine applies transform rules to HTTP messages. Thread-safe.
type TransformEngine struct {
	mu    sync.RWMutex
	rules []TransformRule
}

// NewTransformEngine creates an empty TransformEngine.
func NewTransformEngine() *TransformEngine {
	return &TransformEngine{}
}

// SetRules replaces all rules atomically. Rules are sorted by priority.
func (e *TransformEngine) SetRules(rules []TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority < e.rules[j].Priority
	})
}

// AddRule adds a rule and re-sorts by priority.
func (e *TransformEngine) AddRule(rule TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority < e.rules[j].Priority
	})
}

// TransformRequest applies matching rules to an HTTP request.
// Modifies msg in-place. Returns true if any modification was applied.
func (e *TransformEngine) TransformRequest(env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	modified := false
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Direction != DirectionRequest && rule.Direction != DirectionBoth {
			continue
		}
		if !e.matchesConditions(&rule, env, msg) {
			continue
		}
		if e.applyAction(&rule, msg) {
			modified = true
		}
	}
	return modified
}

// TransformResponse applies matching rules to an HTTP response.
// Modifies msg in-place. Returns true if any modification was applied.
func (e *TransformEngine) TransformResponse(env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	modified := false
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Direction != DirectionResponse && rule.Direction != DirectionBoth {
			continue
		}
		if !e.matchesConditions(&rule, env, msg) {
			continue
		}
		if e.applyAction(&rule, msg) {
			modified = true
		}
	}
	return modified
}

func (e *TransformEngine) matchesConditions(rule *TransformRule, env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	if rule.HostPattern != nil {
		host := extractHostname(env.Context.TargetHost)
		if !rule.HostPattern.MatchString(host) {
			return false
		}
	}
	if rule.PathPattern != nil {
		if !rule.PathPattern.MatchString(msg.Path) {
			return false
		}
	}
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
	return true
}

func (e *TransformEngine) applyAction(rule *TransformRule, msg *envelope.HTTPMessage) bool {
	switch rule.ActionType {
	case TransformAddHeader:
		if containsCRLF(rule.HeaderName) || containsCRLF(rule.HeaderValue) {
			return false // CWE-113: reject CRLF in headers
		}
		msg.Headers = headerAdd(msg.Headers, rule.HeaderName, rule.HeaderValue)
		return true

	case TransformSetHeader:
		if containsCRLF(rule.HeaderName) || containsCRLF(rule.HeaderValue) {
			return false
		}
		msg.Headers = headerDel(msg.Headers, rule.HeaderName)
		msg.Headers = headerAdd(msg.Headers, rule.HeaderName, rule.HeaderValue)
		return true

	case TransformRemoveHeader:
		before := len(msg.Headers)
		msg.Headers = headerDel(msg.Headers, rule.HeaderName)
		return len(msg.Headers) != before

	case TransformReplaceBody:
		if msg.Body == nil {
			return false // passthrough mode: skip body transform
		}
		if rule.BodyPattern == nil {
			return false
		}
		replaced := rule.BodyPattern.ReplaceAll(msg.Body, []byte(rule.BodyReplace))
		if string(replaced) == string(msg.Body) {
			return false
		}
		msg.Body = replaced
		return true

	default:
		return false
	}
}

// CompileTransformRule compiles a transform rule from config values.
func CompileTransformRule(id string, priority int, direction RuleDirection, hostPattern, pathPattern string, methods []string, actionType TransformActionType, headerName, headerValue, bodyPattern, bodyReplace string) (*TransformRule, error) {
	rule := &TransformRule{
		ID:          id,
		Enabled:     true,
		Priority:    priority,
		Direction:   direction,
		ActionType:  actionType,
		HeaderName:  headerName,
		HeaderValue: headerValue,
		BodyReplace: bodyReplace,
	}

	if hostPattern != "" {
		re, err := common.CompilePattern(hostPattern)
		if err != nil {
			return nil, fmt.Errorf("host pattern: %w", err)
		}
		rule.HostPattern = re
	}
	if pathPattern != "" {
		re, err := common.CompilePattern(pathPattern)
		if err != nil {
			return nil, fmt.Errorf("path pattern: %w", err)
		}
		rule.PathPattern = re
	}
	if len(methods) > 0 {
		rule.Methods = methods
	}
	if bodyPattern != "" {
		re, err := common.CompilePattern(bodyPattern)
		if err != nil {
			return nil, fmt.Errorf("body pattern: %w", err)
		}
		rule.BodyPattern = re
	}

	return rule, nil
}
