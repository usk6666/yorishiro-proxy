package intercept

import (
	"fmt"
	"log/slog"
	"net/url"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// Engine manages intercept rules and evaluates them against HTTP requests
// and responses. It is safe for concurrent use.
type Engine struct {
	mu    sync.RWMutex
	rules []*compiledRule
}

// NewEngine creates a new empty Engine with no rules.
func NewEngine() *Engine {
	return &Engine{}
}

// AddRule validates, compiles, and adds a new intercept rule.
// Returns an error if the rule is invalid or a rule with the same ID already exists.
func (e *Engine) AddRule(r Rule) error {
	cr, err := compileRule(r)
	if err != nil {
		return fmt.Errorf("add rule: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, existing := range e.rules {
		if existing.rule.ID == r.ID {
			return fmt.Errorf("add rule: duplicate rule ID %q", r.ID)
		}
	}

	e.rules = append(e.rules, cr)
	return nil
}

// RemoveRule removes the rule with the given ID.
// Returns an error if no rule with that ID exists.
func (e *Engine) RemoveRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, cr := range e.rules {
		if cr.rule.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("remove rule: rule %q not found", id)
}

// EnableRule sets the enabled state of the rule with the given ID.
// Returns an error if no rule with that ID exists.
func (e *Engine) EnableRule(id string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, cr := range e.rules {
		if cr.rule.ID == id {
			cr.rule.Enabled = enabled
			return nil
		}
	}

	return fmt.Errorf("enable rule: rule %q not found", id)
}

// GetRule returns a copy of the rule with the given ID.
// Returns an error if no rule with that ID exists.
func (e *Engine) GetRule(id string) (Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, cr := range e.rules {
		if cr.rule.ID == id {
			return cloneRule(cr.rule), nil
		}
	}

	return Rule{}, fmt.Errorf("get rule: rule %q not found", id)
}

// Rules returns a copy of all rules in their current order.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.rules) == 0 {
		return nil
	}

	result := make([]Rule, len(e.rules))
	for i, cr := range e.rules {
		result[i] = cloneRule(cr.rule)
	}
	return result
}

// SetRules replaces all rules atomically. Each rule is validated and compiled;
// if any rule is invalid, the entire operation is rejected and existing rules
// are preserved.
func (e *Engine) SetRules(rules []Rule) error {
	compiled := make([]*compiledRule, len(rules))
	seen := make(map[string]bool, len(rules))

	for i, r := range rules {
		if seen[r.ID] {
			return fmt.Errorf("set rules: duplicate rule ID %q at index %d", r.ID, i)
		}
		seen[r.ID] = true

		cr, err := compileRule(r)
		if err != nil {
			return fmt.Errorf("set rules: rule at index %d: %w", i, err)
		}
		compiled[i] = cr
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = compiled
	return nil
}

// MatchesRequest evaluates all enabled rules against the given request parameters.
// Returns true if any enabled rule with direction "request" or "both" matches
// (OR logic across rules).
func (e *Engine) MatchesRequest(method string, u *url.URL, headers []exchange.KeyValue) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, cr := range e.rules {
		if !cr.rule.Enabled {
			continue
		}
		if cr.isWebSocketRule() {
			continue
		}
		if cr.rule.Direction != DirectionRequest && cr.rule.Direction != DirectionBoth {
			continue
		}
		if cr.matchesRequest(method, u, headers) {
			slog.Debug("intercept rule matched request",
				slog.String("rule_id", cr.rule.ID),
				slog.String("method", method),
				slog.String("url", urlString(u)),
			)
			return true
		}
	}
	return false
}

// MatchesResponse evaluates all enabled rules against the given response parameters.
// Returns true if any enabled rule with direction "response" or "both" matches
// (OR logic across rules).
func (e *Engine) MatchesResponse(statusCode int, headers []exchange.KeyValue) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, cr := range e.rules {
		if !cr.rule.Enabled {
			continue
		}
		if cr.isWebSocketRule() {
			continue
		}
		if cr.rule.Direction != DirectionResponse && cr.rule.Direction != DirectionBoth {
			continue
		}
		if cr.matchesResponse(statusCode, headers) {
			slog.Debug("intercept rule matched response",
				slog.String("rule_id", cr.rule.ID),
				slog.Int("status_code", statusCode),
			)
			return true
		}
	}
	return false
}

// MatchRequestRules returns the IDs of all enabled rules that match the given request.
// This is useful for identifying which specific rules triggered an intercept.
func (e *Engine) MatchRequestRules(method string, u *url.URL, headers []exchange.KeyValue) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for _, cr := range e.rules {
		if !cr.rule.Enabled {
			continue
		}
		if cr.isWebSocketRule() {
			continue
		}
		if cr.rule.Direction != DirectionRequest && cr.rule.Direction != DirectionBoth {
			continue
		}
		if cr.matchesRequest(method, u, headers) {
			matched = append(matched, cr.rule.ID)
		}
	}
	if len(matched) > 0 {
		slog.Debug("intercept request rules evaluated",
			slog.String("method", method),
			slog.String("url", urlString(u)),
			slog.Any("matched_rules", matched),
		)
	}
	return matched
}

// MatchResponseRules returns the IDs of all enabled rules that match the given response.
func (e *Engine) MatchResponseRules(statusCode int, headers []exchange.KeyValue) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for _, cr := range e.rules {
		if !cr.rule.Enabled {
			continue
		}
		if cr.isWebSocketRule() {
			continue
		}
		if cr.rule.Direction != DirectionResponse && cr.rule.Direction != DirectionBoth {
			continue
		}
		if cr.matchesResponse(statusCode, headers) {
			matched = append(matched, cr.rule.ID)
		}
	}
	if len(matched) > 0 {
		slog.Debug("intercept response rules evaluated",
			slog.Int("status_code", statusCode),
			slog.Any("matched_rules", matched),
		)
	}
	return matched
}

// MatchesWebSocketFrame evaluates all enabled WebSocket rules against the given
// frame parameters. direction should be "client_to_server" or "server_to_client".
// The existing Direction field is mapped: "request" -> client_to_server,
// "response" -> server_to_client, "both" -> matches either direction.
// Returns true if any enabled WebSocket rule matches (OR logic across rules).
func (e *Engine) MatchesWebSocketFrame(upgradeURL string, direction string, flowID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, cr := range e.rules {
		if !cr.rule.Enabled {
			continue
		}
		if !cr.isWebSocketRule() {
			continue
		}
		if !matchesWSDirection(cr.rule.Direction, direction) {
			continue
		}
		if cr.matchesWebSocketFrame(upgradeURL, flowID) {
			slog.Debug("intercept rule matched websocket frame",
				slog.String("rule_id", cr.rule.ID),
				slog.String("direction", direction),
				slog.String("flow_id", flowID),
			)
			return true
		}
	}
	return false
}

// MatchWebSocketFrameRules returns the IDs of all enabled WebSocket rules
// that match the given frame parameters.
func (e *Engine) MatchWebSocketFrameRules(upgradeURL string, direction string, flowID string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []string
	for _, cr := range e.rules {
		if !cr.rule.Enabled {
			continue
		}
		if !cr.isWebSocketRule() {
			continue
		}
		if !matchesWSDirection(cr.rule.Direction, direction) {
			continue
		}
		if cr.matchesWebSocketFrame(upgradeURL, flowID) {
			matched = append(matched, cr.rule.ID)
		}
	}
	if len(matched) > 0 {
		slog.Debug("intercept websocket frame rules evaluated",
			slog.String("direction", direction),
			slog.String("flow_id", flowID),
			slog.Any("matched_rules", matched),
		)
	}
	return matched
}

// urlString returns the string representation of a URL, or an empty string if nil.
func urlString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Redacted()
}

// matchesWSDirection maps the rule's Direction to WebSocket direction strings.
// "request" maps to "client_to_server", "response" maps to "server_to_client",
// "both" matches either valid direction. An unrecognized frameDir always
// returns false (fail-closed) to avoid accidentally matching unknown values.
func matchesWSDirection(ruleDir Direction, frameDir string) bool {
	if frameDir != "client_to_server" && frameDir != "server_to_client" {
		return false
	}
	switch ruleDir {
	case DirectionBoth:
		return true
	case DirectionRequest:
		return frameDir == "client_to_server"
	case DirectionResponse:
		return frameDir == "server_to_client"
	default:
		return false
	}
}

// Len returns the number of rules in the engine.
func (e *Engine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// Clear removes all rules from the engine.
func (e *Engine) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = nil
}

// cloneRule returns a deep copy of a Rule.
func cloneRule(r Rule) Rule {
	out := Rule{
		ID:        r.ID,
		Enabled:   r.Enabled,
		Direction: r.Direction,
		Conditions: Conditions{
			HostPattern:       r.Conditions.HostPattern,
			PathPattern:       r.Conditions.PathPattern,
			UpgradeURLPattern: r.Conditions.UpgradeURLPattern,
			FlowID:            r.Conditions.FlowID,
		},
	}
	if len(r.Conditions.Methods) > 0 {
		out.Conditions.Methods = make([]string, len(r.Conditions.Methods))
		copy(out.Conditions.Methods, r.Conditions.Methods)
	}
	if len(r.Conditions.HeaderMatch) > 0 {
		out.Conditions.HeaderMatch = make(map[string]string, len(r.Conditions.HeaderMatch))
		for k, v := range r.Conditions.HeaderMatch {
			out.Conditions.HeaderMatch[k] = v
		}
	}
	return out
}
