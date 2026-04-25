package ws

import (
	"context"
	"fmt"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// WS-local safety targets. Declared as common.Target-typed constants
// inside the rules/ws package so that common does not need to grow new
// targets for every per-protocol engine. Operators wire these in via
// preset.PresetRuleConfig.Targets or common.CompiledRule.Targets directly.
const (
	// TargetPayload selects the decompressed WSMessage.Payload bytes.
	TargetPayload common.Target = "payload"

	// TargetOpcode selects the numeric opcode rendered as a hex string
	// (e.g. "0x1" for WSText, "0x8" for WSClose). The string form lets
	// regex-based rules match opcode classes (e.g. ^0x[89A]$ for
	// control frames).
	TargetOpcode common.Target = "opcode"
)

// Violation records a safety rule match on a WS frame.
type Violation struct {
	RuleID   string
	RuleName string
	Target   string // "payload" or "opcode"
	Match    string // matched fragment (raw payload bytes for TargetPayload)
}

// SafetyEngine checks WS frames against input safety rules.
// Thread-safe via RWMutex.
//
// HTTP presets are NOT auto-loaded into the WS SafetyEngine. Operators
// who want payload regex rules should add them with explicit
// Targets: []common.Target{TargetPayload}.
type SafetyEngine struct {
	mu    sync.RWMutex
	rules []common.CompiledRule
}

// NewSafetyEngine creates an empty SafetyEngine. No presets are loaded.
func NewSafetyEngine() *SafetyEngine {
	return &SafetyEngine{}
}

// LoadPreset compiles and adds all rules from a named preset. Operators
// must ensure the preset's targets are WS-local (TargetPayload /
// TargetOpcode) — non-WS targets are silently skipped at evaluation.
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

// CheckInput evaluates all safety rules against a WS frame. Returns nil if
// safe, *Violation on the first matching rule (fail-fast).
//
// ctx is accepted for symmetry with rules/http; the current implementation
// does not block on ctx (WS payloads are bounded by WSLayer's
// maxFramePayloadSize=16 MiB and held in memory, not disk-backed).
func (e *SafetyEngine) CheckInput(ctx context.Context, msg *envelope.WSMessage) *Violation {
	if msg == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.rules {
		if v := e.checkRule(ctx, &e.rules[i], msg); v != nil {
			return v
		}
	}
	return nil
}

// CheckInputAll evaluates all safety rules and returns every violation.
func (e *SafetyEngine) CheckInputAll(ctx context.Context, msg *envelope.WSMessage) []*Violation {
	if msg == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var out []*Violation
	for i := range e.rules {
		if v := e.checkRule(ctx, &e.rules[i], msg); v != nil {
			out = append(out, v)
		}
	}
	return out
}

func (e *SafetyEngine) checkRule(_ context.Context, rule *common.CompiledRule, msg *envelope.WSMessage) *Violation {
	for _, target := range rule.Targets {
		data, targetName := e.extractTarget(target, msg)
		if data == "" && target != TargetPayload {
			// Empty payload still legitimately runs through the regex
			// (some patterns may match the empty string); other targets
			// short-circuit on empty.
			continue
		}
		match := rule.Pattern.Find([]byte(data))
		if match == nil {
			continue
		}
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

func (e *SafetyEngine) extractTarget(target common.Target, msg *envelope.WSMessage) (data, targetName string) {
	switch target {
	case TargetPayload:
		return string(msg.Payload), string(TargetPayload)
	case TargetOpcode:
		return fmt.Sprintf("0x%X", uint8(msg.Opcode)), string(TargetOpcode)
	default:
		// Unknown / non-WS targets are silently skipped.
		return "", ""
	}
}

// RuleCount returns the number of loaded rules.
func (e *SafetyEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}
