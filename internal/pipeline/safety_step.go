package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// SafetyStep is a Message-typed Pipeline Step that checks Send-direction
// messages against input safety rules. If a violation is detected, the
// envelope is dropped. Receive-direction messages always pass through
// (Input Filter is Send-only).
//
// HTTP messages are dispatched to the httprules.SafetyEngine; unknown
// Message types pass through.
type SafetyStep struct {
	http   *httprules.SafetyEngine
	logger *slog.Logger
}

// NewSafetyStep creates a SafetyStep. If httpEngine is nil, all messages
// pass through.
func NewSafetyStep(httpEngine *httprules.SafetyEngine, logger *slog.Logger) *SafetyStep {
	return &SafetyStep{http: httpEngine, logger: logger}
}

// Process checks Send-direction envelopes against safety rules. Receive
// direction always passes through. HTTPMessage is dispatched to the
// SafetyEngine; all other Message types pass through.
func (s *SafetyStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if env.Direction != envelope.Send {
		return Result{}
	}

	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(ctx, msg)
	default:
		return Result{}
	}
}

func (s *SafetyStep) processHTTP(ctx context.Context, msg *envelope.HTTPMessage) Result {
	if s.http == nil {
		return Result{}
	}

	violation := s.http.CheckInput(ctx, msg)
	if violation != nil {
		if s.logger != nil {
			s.logger.InfoContext(ctx, "safety: request blocked",
				slog.String("rule_id", violation.RuleID),
				slog.String("rule_name", violation.RuleName),
				slog.String("target", violation.Target),
				slog.String("match", violation.Match),
			)
		}
		return Result{Action: Drop}
	}

	return Result{}
}
