package ws

import (
	"regexp"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// RuleDirection specifies which envelope direction a rule applies to.
// WS streams are bidirectional but each frame still has a single direction
// (Send=client->server, Receive=server->client). "both" allows a single
// rule to match in either direction.
type RuleDirection string

const (
	// DirectionSend matches client-to-server frames.
	DirectionSend RuleDirection = "send"
	// DirectionReceive matches server-to-client frames.
	DirectionReceive RuleDirection = "receive"
	// DirectionBoth matches frames in either direction.
	DirectionBoth RuleDirection = "both"
)

// InterceptRule defines conditions for intercepting WebSocket frames.
// All non-empty conditions are AND-combined. Empty conditions match all.
//
// PathPattern matches EnvelopeContext.UpgradePath (populated by WSLayer at
// construction time, USK-642). Until that lands UpgradePath is empty and
// PathPattern-bearing rules will only match if the regex accepts the empty
// string.
type InterceptRule struct {
	ID             string
	Enabled        bool
	Direction      RuleDirection
	HostPattern    *regexp.Regexp
	PathPattern    *regexp.Regexp
	OpcodeFilter   []envelope.WSOpcode // empty = match all opcodes
	PayloadPattern *regexp.Regexp
}

// InterceptEngine matches WebSocket frames against intercept rules.
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

// AddRule appends a rule to the engine.
func (e *InterceptEngine) AddRule(rule InterceptRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RemoveRule removes the first rule with the given ID.
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

// Match checks if a WS frame matches any intercept rules.
// Returns matched rule IDs. Empty/nil means no match.
//
// WS has no Send/Receive asymmetry like HTTP request/response, so a single
// Match method covers both directions; the rule's Direction field gates
// evaluation.
//
// Evaluation order is fixed:
//
//	Direction → Enabled → Opcode → Host → Path → Payload
//
// The Opcode pre-bail short-circuits BEFORE any regex evaluation so that
// a Text-only rule with a heavy PayloadPattern does not pay regex cost on
// every Binary frame.
func (e *InterceptEngine) Match(env *envelope.Envelope, msg *envelope.WSMessage) []string {
	if env == nil || msg == nil {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	frameDir := convertDirection(env.Direction)

	var matched []string
	for i := range e.rules {
		rule := &e.rules[i]

		// Direction first — cheapest possible reject.
		if !directionAllows(rule.Direction, frameDir) {
			continue
		}
		if !rule.Enabled {
			continue
		}
		if e.matchesRule(rule, env, msg) {
			matched = append(matched, rule.ID)
		}
	}
	return matched
}

// directionAllows reports whether a rule with the given Direction setting
// matches a frame observed in frameDir.
func directionAllows(rule RuleDirection, frameDir RuleDirection) bool {
	if rule == DirectionBoth || rule == "" {
		return true
	}
	return rule == frameDir
}

// matchesRule evaluates the per-rule match conditions in the documented
// order. Opcode is checked BEFORE any regex evaluation.
func (e *InterceptEngine) matchesRule(rule *InterceptRule, env *envelope.Envelope, msg *envelope.WSMessage) bool {
	// Opcode pre-bail. Empty filter matches all opcodes; otherwise the
	// frame's opcode must appear literally in the filter list. The engine
	// does NOT resolve continuation frames to their stream's first-fragment
	// opcode — operators must list WSContinuation explicitly to inspect
	// continuations.
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

	// Host pattern check — port-stripped TargetHost.
	if rule.HostPattern != nil {
		host := extractHostname(env.Context.TargetHost)
		if !rule.HostPattern.MatchString(host) {
			return false
		}
	}

	// Path pattern check — EnvelopeContext.UpgradePath (set by WSLayer at
	// construction; empty until USK-642 lands).
	if rule.PathPattern != nil {
		if !rule.PathPattern.MatchString(env.Context.UpgradePath) {
			return false
		}
	}

	// Payload pattern check — decompressed bytes.
	if rule.PayloadPattern != nil {
		if !rule.PayloadPattern.Match(msg.Payload) {
			return false
		}
	}

	return true
}

// CompileInterceptRule compiles a rule from config string values.
func CompileInterceptRule(id string, direction RuleDirection, hostPattern, pathPattern string, opcodes []envelope.WSOpcode, payloadPattern string) (*InterceptRule, error) {
	rule := &InterceptRule{
		ID:           id,
		Enabled:      true,
		Direction:    direction,
		OpcodeFilter: opcodes,
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

	if payloadPattern != "" {
		re, err := common.CompilePattern(payloadPattern)
		if err != nil {
			return nil, err
		}
		rule.PayloadPattern = re
	}

	return rule, nil
}
