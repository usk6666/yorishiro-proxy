package grpc

import (
	"context"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// gRPC-local Targets. These are kept in this package (NOT in
// internal/rules/common) per the design review: common is stable and
// shouldn't be polluted with protocol-specific values. common.Target is
// a string type so common.CompiledRule can carry these values directly.
const (
	TargetMetadata common.Target = "metadata"
	TargetPayload  common.Target = "payload"
	TargetService  common.Target = "service"
	TargetMethod   common.Target = "method"
)

// Violation records a safety rule match on a gRPC event. Per the
// design review the type is per-protocol (rules/grpc.Violation), not
// promoted to common.
type Violation struct {
	RuleID   string
	RuleName string
	Target   string // "metadata", "payload", "service", "method"
	Match    string // matched fragment (verbatim from regex)
}

// SafetyEngine checks gRPC events against safety rules. Thread-safe.
type SafetyEngine struct {
	mu    sync.RWMutex
	rules []common.CompiledRule
}

// NewSafetyEngine returns an empty engine.
func NewSafetyEngine() *SafetyEngine {
	return &SafetyEngine{}
}

// LoadPreset compiles and adds all rules from a named preset.
//
// When a preset rule's Targets contains common.TargetBody (the HTTP
// body target from the existing presets), the gRPC engine treats it
// as TargetPayload. This is the closest analogue and lets the existing
// destructive-sql / destructive-os-command presets work unchanged
// against gRPC payloads.
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

// AddRule appends a single compiled rule.
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

// RuleCount returns the number of loaded rules.
func (e *SafetyEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// CheckInput runs the loaded rules against env.Message and returns the
// first matching violation. Returns nil when no rule matches.
//
// CheckInput is symmetric with rules/http.CheckInput: ctx is threaded
// for parity (gRPC payloads don't currently spill to disk so the ctx
// is unused, but the signature matches the HTTP variant for caller
// convenience). The caller passes the typed message explicitly to
// avoid repeating the type-switch on every call site.
func (e *SafetyEngine) CheckInput(ctx context.Context, env *envelope.Envelope, msg envelope.Message) *Violation {
	if env == nil || msg == nil {
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

// CheckInputAll returns all violations (not just the first).
func (e *SafetyEngine) CheckInputAll(ctx context.Context, env *envelope.Envelope, msg envelope.Message) []*Violation {
	if env == nil || msg == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var violations []*Violation
	for i := range e.rules {
		if v := e.checkRule(ctx, &e.rules[i], msg); v != nil {
			violations = append(violations, v)
		}
	}
	return violations
}

func (e *SafetyEngine) checkRule(ctx context.Context, rule *common.CompiledRule, msg envelope.Message) *Violation {
	for _, target := range rule.Targets {
		data, name := extractTarget(ctx, target, msg)
		if data == "" {
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
			Target:   name,
			Match:    string(match),
		}
	}
	return nil
}

// extractTarget pulls the target data out of a gRPC message. Returns
// "" when the target is not applicable to this message type (so the
// caller's loop simply continues).
//
// common.TargetBody is an alias for the gRPC payload target when the
// message is GRPCDataMessage (preset reuse contract).
func extractTarget(ctx context.Context, target common.Target, msg envelope.Message) (data, name string) {
	switch m := msg.(type) {
	case *envelope.GRPCStartMessage:
		switch target {
		case TargetMetadata:
			return allMetadataString(m.Metadata), "metadata"
		case TargetService:
			return m.Service, "service"
		case TargetMethod:
			return m.Method, "method"
		}

	case *envelope.GRPCDataMessage:
		switch target {
		case TargetPayload, common.TargetBody:
			payload := materializePayload(ctx, m)
			if payload == nil {
				return "", ""
			}
			return string(payload), "payload"
		case TargetService:
			return m.Service, "service"
		case TargetMethod:
			return m.Method, "method"
		}

	case *envelope.GRPCEndMessage:
		switch target {
		case TargetMetadata:
			return allMetadataString(m.Trailers), "metadata"
		}
	}
	return "", ""
}

// CheckMetadataTarget evaluates a custom rule against a specific
// metadata entry by name. Mirrors rules/http.CheckHeaderTarget for the
// single-header lookup case.
func (e *SafetyEngine) CheckMetadataTarget(metadata []envelope.KeyValue, name string, rule *common.CompiledRule) *Violation {
	value := metadataGet(metadata, name)
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
		Target:   "metadata:" + name,
		Match:    string(match),
	}
}

// allMetadataString concatenates metadata in wire order for
// TargetMetadata matching. No normalization — wire casing and order
// preserved.
func allMetadataString(metadata []envelope.KeyValue) string {
	var b strings.Builder
	for _, kv := range metadata {
		b.WriteString(kv.Name)
		b.WriteString(": ")
		b.WriteString(kv.Value)
		b.WriteByte('\n')
	}
	return b.String()
}
