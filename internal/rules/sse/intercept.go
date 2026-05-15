package sse

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// InterceptRule defines conditions for intercepting an SSE event.
// All non-empty conditions are AND-combined; empty conditions match all.
//
// Direction is "receive" by default on the live wire; "both" is accepted
// for cross-protocol schema parity. "send" is rejected at compile time —
// CompileInterceptRule returns an error rather than silently producing a
// never-matching rule.
type InterceptRule struct {
	ID        string
	Enabled   bool
	Direction RuleDirection

	// EventPattern matches SSEMessage.Event (the `event:` field).
	EventPattern *regexp.Regexp
	// IDPattern matches SSEMessage.ID.
	IDPattern *regexp.Regexp
	// DataPattern matches SSEMessage.Data — the joined multi-line data
	// body. Operators wanting per-line matching need the `(?m)` flag in
	// their regex.
	DataPattern *regexp.Regexp

	// RetryMinMs / RetryMaxMs match SSEMessage.Retry as integer ms in the
	// inclusive [min, max] window. nil bounds are unbounded on that side;
	// events with Retry == 0 (unset on the wire) are skipped whenever
	// either bound is set.
	RetryMinMs *int64
	RetryMaxMs *int64

	// Anomalies is OR / any-of: the rule matches when any envelope
	// anomaly's Type equals any entry. Empty list matches all events.
	Anomalies []string
}

// InterceptEngine matches SSE events against intercept rules.
// Thread-safe via RWMutex (mirrors rules/{http,ws,grpc}).
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

// AddRule appends a rule.
func (e *InterceptEngine) AddRule(rule InterceptRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RemoveRule removes the first rule with the given ID. Returns true when
// a rule was removed.
func (e *InterceptEngine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// EnableRule toggles the Enabled flag on the rule with the given ID.
// Returns true when a rule was updated.
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

// Rules returns a defensive copy of the current rule slice.
func (e *InterceptEngine) Rules() []InterceptRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]InterceptRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Match evaluates rules against an SSE event envelope. Returns matched
// rule IDs in slice order (which mirrors registration order).
func (e *InterceptEngine) Match(env *envelope.Envelope, msg *envelope.SSEMessage) []string {
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
		if !e.matchesConditions(rule, msg) {
			continue
		}
		matched = append(matched, rule.ID)
	}
	return matched
}

// matchesConditions evaluates the per-field rule predicates.
func (e *InterceptEngine) matchesConditions(rule *InterceptRule, msg *envelope.SSEMessage) bool {
	if rule.EventPattern != nil && !rule.EventPattern.MatchString(msg.Event) {
		return false
	}
	if rule.IDPattern != nil && !rule.IDPattern.MatchString(msg.ID) {
		return false
	}
	if rule.DataPattern != nil && !rule.DataPattern.MatchString(msg.Data) {
		return false
	}
	if !matchRetryRange(msg.Retry.Milliseconds(), rule.RetryMinMs, rule.RetryMaxMs) {
		return false
	}
	if !matchAnomalies(rule.Anomalies, msg.Anomalies) {
		return false
	}
	return true
}

// CompileInterceptRule compiles raw config values into an InterceptRule.
// Bad regexes wrap the underlying error with the offending field name;
// direction == "send" is rejected because SSE-on-the-wire is Receive-only.
func CompileInterceptRule(
	id string,
	direction RuleDirection,
	eventPattern, idPattern, dataPattern string,
	retryMinMs, retryMaxMs *int64,
	anomalies []string,
) (*InterceptRule, error) {
	if err := validateSSEDirection(direction); err != nil {
		return nil, err
	}
	rule := &InterceptRule{
		ID:         id,
		Enabled:    true,
		Direction:  direction,
		RetryMinMs: retryMinMs,
		RetryMaxMs: retryMaxMs,
		Anomalies:  append([]string(nil), anomalies...),
	}
	if eventPattern != "" {
		re, err := common.CompilePattern(eventPattern)
		if err != nil {
			return nil, fmt.Errorf("event pattern: %w", err)
		}
		rule.EventPattern = re
	}
	if idPattern != "" {
		re, err := common.CompilePattern(idPattern)
		if err != nil {
			return nil, fmt.Errorf("id pattern: %w", err)
		}
		rule.IDPattern = re
	}
	if dataPattern != "" {
		re, err := common.CompilePattern(dataPattern)
		if err != nil {
			return nil, fmt.Errorf("data pattern: %w", err)
		}
		rule.DataPattern = re
	}
	if retryMinMs != nil && retryMaxMs != nil && *retryMinMs > *retryMaxMs {
		return nil, fmt.Errorf("retry range: min %d > max %d", *retryMinMs, *retryMaxMs)
	}
	return rule, nil
}

// validateSSEDirection enforces SSE's Receive-only wire reality at
// compile time. Empty / "both" / "receive" are accepted; "send" is
// rejected with an explicit error so a misconfigured rule surfaces at
// configure-tool time rather than silently never matching.
func validateSSEDirection(d RuleDirection) error {
	switch d {
	case "", DirectionReceive, DirectionBoth:
		return nil
	default:
		return fmt.Errorf("direction: %q is not valid for SSE (expected receive|both)", d)
	}
}
