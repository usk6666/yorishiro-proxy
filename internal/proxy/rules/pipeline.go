package rules

import (
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// Pipeline manages auto-transform rules and applies them to HTTP requests
// and responses in priority order. It is safe for concurrent use.
type Pipeline struct {
	mu    sync.RWMutex
	rules []*compiledRule
}

// NewPipeline creates a new empty Pipeline with no rules.
func NewPipeline() *Pipeline {
	return &Pipeline{}
}

// AddRule validates, compiles, and adds a new auto-transform rule.
// Returns an error if the rule is invalid or a rule with the same ID already exists.
func (p *Pipeline) AddRule(r Rule) error {
	cr, err := compileRule(r)
	if err != nil {
		return fmt.Errorf("add rule: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, existing := range p.rules {
		if existing.rule.ID == r.ID {
			return fmt.Errorf("add rule: duplicate rule ID %q", r.ID)
		}
	}

	p.rules = append(p.rules, cr)
	p.sortRulesLocked()
	return nil
}

// RemoveRule removes the rule with the given ID.
// Returns an error if no rule with that ID exists.
func (p *Pipeline) RemoveRule(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, cr := range p.rules {
		if cr.rule.ID == id {
			p.rules = append(p.rules[:i], p.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("remove rule: rule %q not found", id)
}

// EnableRule sets the enabled state of the rule with the given ID.
// Returns an error if no rule with that ID exists.
func (p *Pipeline) EnableRule(id string, enabled bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, cr := range p.rules {
		if cr.rule.ID == id {
			cr.rule.Enabled = enabled
			return nil
		}
	}

	return fmt.Errorf("enable rule: rule %q not found", id)
}

// GetRule returns a copy of the rule with the given ID.
// Returns an error if no rule with that ID exists.
func (p *Pipeline) GetRule(id string) (Rule, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, cr := range p.rules {
		if cr.rule.ID == id {
			return cloneRule(cr.rule), nil
		}
	}

	return Rule{}, fmt.Errorf("get rule: rule %q not found", id)
}

// Rules returns a copy of all rules in their current priority order.
func (p *Pipeline) Rules() []Rule {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.rules) == 0 {
		return nil
	}

	result := make([]Rule, len(p.rules))
	for i, cr := range p.rules {
		result[i] = cloneRule(cr.rule)
	}
	return result
}

// SetRules replaces all rules atomically. Each rule is validated and compiled;
// if any rule is invalid, the entire operation is rejected and existing rules
// are preserved.
func (p *Pipeline) SetRules(rules []Rule) error {
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

	// Sort by priority.
	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].rule.Priority < compiled[j].rule.Priority
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = compiled
	return nil
}

// Len returns the number of rules in the pipeline.
func (p *Pipeline) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.rules)
}

// Clear removes all rules from the pipeline.
func (p *Pipeline) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = nil
}

// TransformRequest applies all matching enabled request rules to the given
// request headers and body, returning the potentially modified headers and body.
// Rules are applied in priority order (lower priority values first).
func (p *Pipeline) TransformRequest(method string, u *url.URL, headers parser.RawHeaders, body []byte) (parser.RawHeaders, []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, cr := range p.rules {
		if !cr.rule.Enabled {
			continue
		}
		if cr.rule.Direction != DirectionRequest && cr.rule.Direction != DirectionBoth {
			continue
		}
		if !cr.matchesRequest(method, u, headers) {
			continue
		}
		slog.Debug("auto-transform rule matched request",
			slog.String("rule_id", cr.rule.ID),
			slog.String("action_type", string(cr.rule.Action.Type)),
			slog.Int("priority", cr.rule.Priority),
			slog.String("method", method),
		)
		headers, body = applyAction(cr, headers, body)
	}

	return headers, body
}

// TransformResponse applies all matching enabled response rules to the given
// response headers and body, returning the potentially modified headers and body.
// Rules are applied in priority order (lower priority values first).
func (p *Pipeline) TransformResponse(statusCode int, headers parser.RawHeaders, body []byte) (parser.RawHeaders, []byte) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, cr := range p.rules {
		if !cr.rule.Enabled {
			continue
		}
		if cr.rule.Direction != DirectionResponse && cr.rule.Direction != DirectionBoth {
			continue
		}
		if !cr.matchesResponse(statusCode, headers) {
			continue
		}
		slog.Debug("auto-transform rule matched response",
			slog.String("rule_id", cr.rule.ID),
			slog.String("action_type", string(cr.rule.Action.Type)),
			slog.Int("priority", cr.rule.Priority),
			slog.Int("status_code", statusCode),
		)
		headers, body = applyAction(cr, headers, body)
	}

	return headers, body
}

// applyAction applies a single rule's action to the headers and body.
func applyAction(cr *compiledRule, headers parser.RawHeaders, body []byte) (parser.RawHeaders, []byte) {
	switch cr.rule.Action.Type {
	case ActionAddHeader:
		headers = append(headers, parser.RawHeader{Name: cr.rule.Action.Header, Value: cr.rule.Action.Value})
	case ActionSetHeader:
		headers.Set(cr.rule.Action.Header, cr.rule.Action.Value)
	case ActionRemoveHeader:
		headers.Del(cr.rule.Action.Header)
	case ActionReplaceBody:
		if cr.bodyPatternRe != nil && len(body) > 0 {
			body = cr.bodyPatternRe.ReplaceAll(body, []byte(cr.rule.Action.Value))
		}
	}
	return headers, body
}

// sortRulesLocked sorts rules by priority. Must be called with mu held.
func (p *Pipeline) sortRulesLocked() {
	sort.SliceStable(p.rules, func(i, j int) bool {
		return p.rules[i].rule.Priority < p.rules[j].rule.Priority
	})
}
