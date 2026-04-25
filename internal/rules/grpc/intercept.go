package grpc

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// RuleDirection specifies which envelope direction a rule applies to.
//
// gRPC has no "request"/"response" symmetry; client sends headers and N
// data messages, server sends headers, N data messages and a trailer.
// The engine matches on envelope direction (send / receive) instead.
// "both" matches either direction.
type RuleDirection string

const (
	DirectionSend    RuleDirection = "send"
	DirectionReceive RuleDirection = "receive"
	DirectionBoth    RuleDirection = "both"
)

// InterceptRule defines conditions for intercepting gRPC messages.
//
// All non-empty conditions are AND-combined; empty conditions match
// any. Per the design review:
//   - Service / Method patterns are evaluated on every event
//     (Start/Data/End). GRPCDataMessage carries a denormalized,
//     read-only Service / Method copy populated by GRPCLayer.
//   - HeaderMatch applies ONLY on Start events (HEADERS frame). On
//     Data and End it is a no-op. Cross-event correlation is YAGNI.
//   - PayloadPattern applies ONLY on Data events. On Start and End it
//     is a no-op.
type InterceptRule struct {
	ID      string
	Enabled bool

	Direction RuleDirection

	ServicePattern *regexp.Regexp
	MethodPattern  *regexp.Regexp

	// HeaderMatch matches against GRPCStartMessage.Metadata. Keys are
	// lowercased at compile time (HTTP/2 wire form per RFC 9113 §8.2.2);
	// lookups against the envelope perform case-insensitive name
	// matching to tolerate non-conforming peers.
	HeaderMatch map[string]*regexp.Regexp

	// PayloadPattern matches against GRPCDataMessage.Payload (always
	// the decompressed bytes). Compiled once; nil disables payload
	// matching.
	PayloadPattern *regexp.Regexp
}

// InterceptEngine matches gRPC events against intercept rules.
// Thread-safe via RWMutex (mirrors rules/http precedent).
type InterceptEngine struct {
	mu    sync.RWMutex
	rules []InterceptRule
}

// NewInterceptEngine creates an empty engine.
func NewInterceptEngine() *InterceptEngine {
	return &InterceptEngine{}
}

// SetRules replaces all rules atomically.
func (e *InterceptEngine) SetRules(rules []InterceptRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// AddRule appends a rule to the engine.
func (e *InterceptEngine) AddRule(rule InterceptRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RemoveRule removes the rule with the given ID, if present.
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

// MatchStart evaluates rules against a GRPCStartMessage envelope.
// Returns the matched rule IDs.
func (e *InterceptEngine) MatchStart(env *envelope.Envelope, msg *envelope.GRPCStartMessage) []string {
	if env == nil || msg == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllowed(rule.Direction, env.Direction) {
			continue
		}
		if !matchServiceMethod(rule, msg.Service, msg.Method) {
			continue
		}
		if !matchHeaders(rule, msg.Metadata) {
			continue
		}
		matched = append(matched, rule.ID)
	}
	return matched
}

// MatchData evaluates rules against a GRPCDataMessage envelope.
// HeaderMatch is ignored on Data (Start-only); PayloadPattern, if set,
// must match.
func (e *InterceptEngine) MatchData(env *envelope.Envelope, msg *envelope.GRPCDataMessage) []string {
	if env == nil || msg == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllowed(rule.Direction, env.Direction) {
			continue
		}
		if !matchServiceMethod(rule, msg.Service, msg.Method) {
			continue
		}
		if rule.PayloadPattern != nil {
			if !rule.PayloadPattern.Match(msg.Payload) {
				continue
			}
		}
		matched = append(matched, rule.ID)
	}
	return matched
}

// MatchEnd evaluates rules against a GRPCEndMessage envelope.
// HeaderMatch and PayloadPattern are no-ops on End; only direction +
// service/method gates apply. Service / Method are not on
// GRPCEndMessage, so per the design review the engine evaluates only
// the direction + Enabled gates here. To match a specific RPC's End
// event, leave Service/Method patterns empty (they would be no-ops
// anyway since GRPCEndMessage carries no service/method fields).
func (e *InterceptEngine) MatchEnd(env *envelope.Envelope, msg *envelope.GRPCEndMessage) []string {
	if env == nil || msg == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllowed(rule.Direction, env.Direction) {
			continue
		}
		matched = append(matched, rule.ID)
	}
	return matched
}

// matchServiceMethod returns true when rule's Service/Method patterns
// (if any) match the supplied values.
func matchServiceMethod(rule *InterceptRule, service, method string) bool {
	if rule.ServicePattern != nil && !rule.ServicePattern.MatchString(service) {
		return false
	}
	if rule.MethodPattern != nil && !rule.MethodPattern.MatchString(method) {
		return false
	}
	return true
}

// matchHeaders evaluates HeaderMatch against the metadata slice.
// Returns true when all configured (lowercased) keys match.
func matchHeaders(rule *InterceptRule, metadata []envelope.KeyValue) bool {
	if len(rule.HeaderMatch) == 0 {
		return true
	}
	for name, pattern := range rule.HeaderMatch {
		value := metadataGet(metadata, name)
		if !pattern.MatchString(value) {
			return false
		}
	}
	return true
}

// CompileInterceptRule compiles raw config values into an InterceptRule.
//
// Bad regexes wrap the underlying compile error with the field name.
// HeaderMatch keys are lowercased at compile time; lookups remain
// case-insensitive against the envelope.
func CompileInterceptRule(id string, direction RuleDirection, servicePattern, methodPattern string, headerMatch map[string]string, payloadPattern string) (*InterceptRule, error) {
	rule := &InterceptRule{
		ID:        id,
		Enabled:   true,
		Direction: direction,
	}

	if servicePattern != "" {
		re, err := common.CompilePattern(servicePattern)
		if err != nil {
			return nil, fmt.Errorf("service pattern: %w", err)
		}
		rule.ServicePattern = re
	}
	if methodPattern != "" {
		re, err := common.CompilePattern(methodPattern)
		if err != nil {
			return nil, fmt.Errorf("method pattern: %w", err)
		}
		rule.MethodPattern = re
	}
	if len(headerMatch) > 0 {
		lowered := make(map[string]string, len(headerMatch))
		for k, v := range headerMatch {
			lowered[strings.ToLower(k)] = v
		}
		compiled, err := common.CompileHeaderMatch(lowered)
		if err != nil {
			return nil, fmt.Errorf("header match: %w", err)
		}
		rule.HeaderMatch = compiled
	}
	if payloadPattern != "" {
		re, err := common.CompilePattern(payloadPattern)
		if err != nil {
			return nil, fmt.Errorf("payload pattern: %w", err)
		}
		rule.PayloadPattern = re
	}

	return rule, nil
}
