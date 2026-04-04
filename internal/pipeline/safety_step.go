package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// SafetyStep enforces the safety engine's input filter rules on Send-direction
// Exchanges. Receive-direction Exchanges pass through unchanged.
//
// OutputFilter (PII masking) is NOT handled here — it stays in the MCP layer
// and is applied when returning data to the client.
type SafetyStep struct {
	engine *safety.Engine
}

// NewSafetyStep creates a SafetyStep with the given safety engine.
// A nil engine is permitted; Process will return Continue for all Exchanges.
func NewSafetyStep(engine *safety.Engine) *SafetyStep {
	return &SafetyStep{engine: engine}
}

// Process checks the Exchange against the safety engine's input rules.
// Only Send-direction Exchanges are inspected. If a blocking violation is
// found, the Exchange is dropped. If the engine is nil or the direction is
// Receive, Continue is returned.
func (s *SafetyStep) Process(_ context.Context, ex *exchange.Exchange) Result {
	if s.engine == nil {
		return Result{}
	}
	if ex.Direction != exchange.Send {
		return Result{}
	}

	var rawURL string
	if ex.URL != nil {
		rawURL = ex.URL.String()
	}

	// Body nil (passthrough mode): skip body check, check URL + headers only.
	var body []byte
	if ex.Body != nil {
		body = ex.Body
	}

	violation := s.engine.CheckInput(body, rawURL, ex.Headers)
	if violation == nil {
		return Result{}
	}

	action := lookupInputAction(s.engine, violation.RuleID)

	slog.Info("SafetyStep matched input filter",
		slog.String("rule_id", violation.RuleID),
		slog.String("rule_name", violation.RuleName),
		slog.String("target", violation.Target.String()),
		slog.String("action", action.String()),
	)

	if action == safety.ActionBlock {
		return Result{Action: Drop}
	}

	return Result{}
}

// lookupInputAction finds the action for the given rule ID from the engine's
// input rules. Returns ActionBlock if the rule is not found (fail-safe).
func lookupInputAction(engine *safety.Engine, ruleID string) safety.Action {
	for _, r := range engine.InputRules() {
		if r.ID == ruleID {
			return r.Action
		}
	}
	return safety.ActionBlock
}
