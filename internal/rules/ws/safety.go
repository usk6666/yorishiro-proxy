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

// SafetyEngine in this package is the live-path WebSocket safety filter.
// It is invoked by internal/pipeline/safety_step.go on every Send-direction
// WS frame and MAY only return a Violation that drives a block / drop
// decision.
//
// Per RFC-001 Principle 1 (Wire fidelity), this engine MUST NOT mutate
// Envelope.Raw, WSMessage.Payload, opcode, or any other message field.
// Output masking (PII redaction) is the exclusive responsibility of
// internal/safety, which is invoked at MCP response time — never before
// recording.

// Violation records a safety rule match on a WS frame.
type Violation struct {
	RuleID   string
	RuleName string
	Target   string // "payload" (also for common.TargetBody matches) or "opcode"
	Match    string // matched fragment (raw payload bytes for TargetPayload)
}

// SafetyEngine checks WS frames against input safety rules.
// Thread-safe via RWMutex.
//
// Presets are NOT auto-loaded; NewSafetyEngine starts empty. When a
// preset is loaded (LoadPreset) or a rule targets common.TargetBody, the
// body target is evaluated against the frame payload. url / query /
// headers targets are skipped per frame — they are evaluated on the
// WebSocket Upgrade request by the HTTP engine.
type SafetyEngine struct {
	mu    sync.RWMutex
	rules []common.CompiledRule
}

// NewSafetyEngine creates an empty SafetyEngine. No presets are loaded.
func NewSafetyEngine() *SafetyEngine {
	return &SafetyEngine{}
}

// LoadPreset compiles and adds all rules from a named preset verbatim.
// The built-in presets target {body, url, query}: body is evaluated
// against the frame payload (common.TargetBody aliases TargetPayload);
// url / query are skipped per frame because the HTTP engine already
// evaluates them on the WebSocket Upgrade request.
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
		if (target == TargetPayload || target == common.TargetBody) && payloadTruncated(msg) {
			// USK-1321: the WS Layer truncated this compressed message at
			// its decompression cap, so Payload is only a prefix of what
			// reaches the upstream verbatim. A payload rule cannot clear
			// bytes it cannot see: fail closed as if it matched.
			return &Violation{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Target:   string(TargetPayload),
				Match:    truncatedPayloadMatch,
			}
		}
		data, targetName := e.extractTarget(target, msg)
		if data == "" && target != TargetPayload && target != common.TargetBody {
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
	case TargetPayload, common.TargetBody:
		// common.TargetBody is an alias for the frame payload so the
		// built-in presets (which target the HTTP-canonical body / url /
		// query triple) and custom `body` rules gate WS frames. Mirrors
		// the gRPC engine's TargetBody → payload alias.
		return string(msg.Payload), string(TargetPayload)
	case TargetOpcode:
		return fmt.Sprintf("0x%X", uint8(msg.Opcode)), string(TargetOpcode)
	default:
		// url / query / headers have no frame-level meaning: they are
		// evaluated on the WebSocket Upgrade request by the HTTP engine
		// (SafetyStep's HTTP arm runs before the WS layer swap). Other
		// unknown targets are likewise skipped.
		return "", ""
	}
}

// truncatedPayloadMatch is the Violation.Match reported for a payload the
// engine refused to clear because it was truncated (USK-1321).
const truncatedPayloadMatch = "payload exceeds safety scan window (decompressed message truncated at the WebSocket decompression cap)"

// payloadTruncated reports whether msg.Payload is only a prefix of the
// message the WS Layer forwards (envelope.AnomalyWSDecompressedTooLarge).
func payloadTruncated(msg *envelope.WSMessage) bool {
	for _, a := range msg.Anomalies {
		if a.Type == envelope.AnomalyWSDecompressedTooLarge {
			return true
		}
	}
	return false
}

// RuleCount returns the number of loaded rules.
func (e *SafetyEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}
