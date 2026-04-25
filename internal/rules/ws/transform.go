package ws

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// TransformActionType specifies the kind of transformation applied to a
// WS frame. All actions are intentionally low-level: they mutate the
// envelope.WSMessage fields directly without any semantic validation.
//
// MITM principles:
//
//   - SetOpcode/SetFin/SetClose perform NO semantic validation. Arbitrary
//     opcodes / Fin bools / close codes are allowed (attacker knob).
//   - SetClose forces Opcode=WSClose if the frame is not already a Close
//     frame. SetClose is the structured-edit path for Close frames.
//   - ReplacePayload mutates msg.Payload verbatim and does NOT touch the
//     Compressed flag. WSLayer.Send (USK-642) re-compresses if Compressed
//     is set on the frame. After payload modification, per-message-deflate
//     context-takeover desync is an accepted MITM consequence.
//   - ReplacePayload on a Close frame stomps the encoded
//     CloseCode/CloseReason bytes — use SetClose for structured Close
//     edits.
//   - Mask/Masked are NEVER touched by the action surface. WSLayer
//     regenerates Mask on Send.
type TransformActionType int

const (
	// TransformReplacePayload runs a regex replacement over the
	// decompressed Payload bytes.
	TransformReplacePayload TransformActionType = iota

	// TransformSetOpcode replaces WSMessage.Opcode with NewOpcode.
	TransformSetOpcode

	// TransformSetFin replaces WSMessage.Fin with NewFin.
	TransformSetFin

	// TransformSetClose sets CloseCode/CloseReason and forces
	// Opcode=WSClose if the frame is not already a Close frame.
	TransformSetClose
)

// TransformRule defines a single WS transformation with match conditions
// and an action.
type TransformRule struct {
	ID       string
	Enabled  bool
	Priority int // lower values applied first

	// Match conditions (AND-combined, empty = match all).
	Direction    RuleDirection
	HostPattern  *regexp.Regexp
	PathPattern  *regexp.Regexp
	OpcodeFilter []envelope.WSOpcode

	// Action.
	ActionType     TransformActionType
	PayloadPattern *regexp.Regexp    // for ReplacePayload
	PayloadReplace []byte            // for ReplacePayload (supports $1, $2 capture groups)
	NewOpcode      envelope.WSOpcode // for SetOpcode
	NewFin         bool              // for SetFin
	NewCloseCode   uint16            // for SetClose
	NewCloseReason string            // for SetClose
}

// TransformEngine applies WS transform rules in priority order. Thread-safe
// via RWMutex.
type TransformEngine struct {
	mu    sync.RWMutex
	rules []TransformRule
}

// NewTransformEngine creates an empty TransformEngine.
func NewTransformEngine() *TransformEngine {
	return &TransformEngine{}
}

// SetRules replaces all rules atomically and re-sorts by priority.
func (e *TransformEngine) SetRules(rules []TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	sortTransformRules(e.rules)
}

// AddRule adds a rule and re-sorts by priority.
func (e *TransformEngine) AddRule(rule TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	sortTransformRules(e.rules)
}

func sortTransformRules(rules []TransformRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
}

// Transform applies all matching rules to a WS frame in priority order.
// Modifies msg in-place. Returns true if any rule modified the frame.
//
// ctx is accepted for symmetry with rules/http and to allow future async
// extensions (e.g. external transform plugins). The current implementation
// does not block on ctx, but applyAction may consult it for cancellation
// in future revisions.
func (e *TransformEngine) Transform(ctx context.Context, env *envelope.Envelope, msg *envelope.WSMessage) bool {
	if env == nil || msg == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	frameDir := convertDirection(env.Direction)

	modified := false
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllows(rule.Direction, frameDir) {
			continue
		}
		if !e.matchesConditions(rule, env, msg) {
			continue
		}
		if e.applyAction(ctx, rule, msg) {
			modified = true
		}
	}
	return modified
}

func (e *TransformEngine) matchesConditions(rule *TransformRule, env *envelope.Envelope, msg *envelope.WSMessage) bool {
	// Opcode pre-bail (mirror InterceptEngine).
	if len(rule.OpcodeFilter) > 0 {
		ok := false
		for _, op := range rule.OpcodeFilter {
			if op == msg.Opcode {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if rule.HostPattern != nil {
		host := extractHostname(env.Context.TargetHost)
		if !rule.HostPattern.MatchString(host) {
			return false
		}
	}
	if rule.PathPattern != nil {
		if !rule.PathPattern.MatchString(env.Context.UpgradePath) {
			return false
		}
	}
	return true
}

func (e *TransformEngine) applyAction(_ context.Context, rule *TransformRule, msg *envelope.WSMessage) bool {
	switch rule.ActionType {
	case TransformReplacePayload:
		if rule.PayloadPattern == nil {
			return false
		}
		// On a Close frame this stomps the encoded CloseCode/CloseReason
		// bytes — that is the documented raw-edit semantic.
		replaced := rule.PayloadPattern.ReplaceAll(msg.Payload, rule.PayloadReplace)
		if bytes.Equal(replaced, msg.Payload) {
			return false
		}
		msg.Payload = replaced
		return true

	case TransformSetOpcode:
		if msg.Opcode == rule.NewOpcode {
			return false
		}
		msg.Opcode = rule.NewOpcode
		return true

	case TransformSetFin:
		if msg.Fin == rule.NewFin {
			return false
		}
		msg.Fin = rule.NewFin
		return true

	case TransformSetClose:
		// Action implies opcode flip: if the frame is not already a Close
		// frame, SetClose makes it one. Documented attacker knob.
		modified := false
		if msg.Opcode != envelope.WSClose {
			msg.Opcode = envelope.WSClose
			modified = true
		}
		if msg.CloseCode != rule.NewCloseCode {
			msg.CloseCode = rule.NewCloseCode
			modified = true
		}
		if msg.CloseReason != rule.NewCloseReason {
			msg.CloseReason = rule.NewCloseReason
			modified = true
		}
		return modified

	default:
		return false
	}
}

// CompileTransformRule compiles a transform rule from config values.
// payloadPattern may be empty for non-ReplacePayload actions.
func CompileTransformRule(id string, priority int, direction RuleDirection, hostPattern, pathPattern string, opcodes []envelope.WSOpcode, actionType TransformActionType, payloadPattern, payloadReplace string, newOpcode envelope.WSOpcode, newFin bool, newCloseCode uint16, newCloseReason string) (*TransformRule, error) {
	rule := &TransformRule{
		ID:             id,
		Enabled:        true,
		Priority:       priority,
		Direction:      direction,
		OpcodeFilter:   opcodes,
		ActionType:     actionType,
		PayloadReplace: []byte(payloadReplace),
		NewOpcode:      newOpcode,
		NewFin:         newFin,
		NewCloseCode:   newCloseCode,
		NewCloseReason: newCloseReason,
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
	if payloadPattern != "" {
		re, err := common.CompilePattern(payloadPattern)
		if err != nil {
			return nil, fmt.Errorf("payload pattern: %w", err)
		}
		rule.PayloadPattern = re
	}

	return rule, nil
}
