package http

import (
	"context"
	"log/slog"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// Violation records a safety rule match on an HTTP request.
type Violation struct {
	RuleID   string
	RuleName string
	Target   string // "body", "url", "query", "header:Name", "headers"
	Match    string // matched fragment
}

// SafetyEngine checks HTTP requests against input safety rules.
// Thread-safe via RWMutex.
type SafetyEngine struct {
	mu    sync.RWMutex
	rules []common.CompiledRule
}

// NewSafetyEngine creates an empty SafetyEngine.
func NewSafetyEngine() *SafetyEngine {
	return &SafetyEngine{}
}

// LoadPreset compiles and adds all rules from a named preset.
func (e *SafetyEngine) LoadPreset(name string) error {
	preset, err := common.LookupPreset(name)
	if err != nil {
		return err
	}
	compiled, err := common.CompilePreset(preset)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, compiled...)
	return nil
}

// AddRule adds a compiled rule to the engine.
func (e *SafetyEngine) AddRule(rule common.CompiledRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// SetRules replaces all rules atomically.
func (e *SafetyEngine) SetRules(rules []common.CompiledRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// CheckInput checks an HTTP request against all safety rules.
// Returns nil if safe, *Violation if a rule was triggered.
// Only the first match is returned (fail-fast).
//
// ctx is threaded down to BodyBuffer.Bytes(ctx) so that materializing a
// disk-backed body honors cancellation. On materialization error (e.g. ctx
// cancelled mid-read), the body target is skipped silently (logged at Debug);
// other targets still evaluate.
func (e *SafetyEngine) CheckInput(ctx context.Context, msg *envelope.HTTPMessage) *Violation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if v := e.checkRule(ctx, &rule, msg); v != nil {
			return v
		}
	}
	return nil
}

// CheckInputAll returns all violations (not just the first).
func (e *SafetyEngine) CheckInputAll(ctx context.Context, msg *envelope.HTTPMessage) []*Violation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var violations []*Violation
	for _, rule := range e.rules {
		if v := e.checkRule(ctx, &rule, msg); v != nil {
			violations = append(violations, v)
		}
	}
	return violations
}

func (e *SafetyEngine) checkRule(ctx context.Context, rule *common.CompiledRule, msg *envelope.HTTPMessage) *Violation {
	for _, target := range rule.Targets {
		data, targetName := e.extractTarget(ctx, target, msg)
		if data == "" {
			continue
		}
		match := rule.Pattern.Find([]byte(data))
		if match == nil {
			continue
		}
		// Apply optional validator (e.g. Luhn check).
		if rule.Validator != nil && !rule.Validator(match) {
			continue
		}
		return &Violation{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Target:   targetName,
			Match:    string(match),
		}
	}
	return nil
}

func (e *SafetyEngine) extractTarget(ctx context.Context, target common.Target, msg *envelope.HTTPMessage) (data, targetName string) {
	switch target {
	case common.TargetBody:
		body, err := materializeBody(ctx, msg)
		if err != nil {
			// Client-controlled input (e.g. ctx cancelled mid-read of a
			// disk-backed body) is not a proxy anomaly. Skip the body target
			// and continue with other targets.
			slog.DebugContext(ctx, "safety: materialize body failed", "err", err)
			return "", ""
		}
		if body == nil {
			return "", ""
		}
		return string(body), "body"

	case common.TargetURL:
		return reconstructURL(msg), "url"

	case common.TargetQuery:
		return msg.RawQuery, "query"

	case common.TargetHeaders:
		return allHeadersString(msg.Headers), "headers"

	default:
		// TargetHeader with specific name — handled by caller if needed.
		// For preset rules, TargetHeader isn't used (only body/url/query).
		return "", ""
	}
}

// CheckHeaderTarget checks a specific header against a rule pattern.
// Used when a custom rule targets "header:Name".
func (e *SafetyEngine) CheckHeaderTarget(msg *envelope.HTTPMessage, headerName string, rule *common.CompiledRule) *Violation {
	value := headerGet(msg.Headers, headerName)
	if value == "" {
		return nil
	}
	match := rule.Pattern.Find([]byte(value))
	if match == nil {
		return nil
	}
	if rule.Validator != nil && !rule.Validator(match) {
		return nil
	}
	return &Violation{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Target:   "header:" + headerName,
		Match:    string(match),
	}
}

// RuleCount returns the number of loaded rules.
func (e *SafetyEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}
