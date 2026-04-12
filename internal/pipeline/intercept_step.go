package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// InterceptStep is a Message-typed Pipeline Step that holds envelopes matching
// intercept rules and waits for an external action (release, drop, or modify).
// HTTP messages are dispatched to the httprules.InterceptEngine; unknown
// Message types pass through.
type InterceptStep struct {
	http   *httprules.InterceptEngine
	queue  *common.HoldQueue
	logger *slog.Logger
}

// NewInterceptStep creates an InterceptStep. If httpEngine, queue, or logger
// is nil, the step gracefully degrades (HTTP messages pass through).
func NewInterceptStep(httpEngine *httprules.InterceptEngine, queue *common.HoldQueue, logger *slog.Logger) *InterceptStep {
	return &InterceptStep{http: httpEngine, queue: queue, logger: logger}
}

// Process type-switches on env.Message. HTTPMessage is dispatched to the
// InterceptEngine; all other Message types pass through.
func (s *InterceptStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(ctx, env, msg)
	default:
		return Result{}
	}
}

func (s *InterceptStep) processHTTP(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) Result {
	if s.http == nil || s.queue == nil {
		return Result{}
	}

	var matchedRules []string
	switch env.Direction {
	case envelope.Send:
		matchedRules = s.http.MatchRequest(env, msg)
	case envelope.Receive:
		matchedRules = s.http.MatchResponse(env, msg)
	}

	if len(matchedRules) == 0 {
		return Result{}
	}

	if s.logger != nil {
		s.logger.DebugContext(ctx, "intercept: envelope held",
			slog.String("flow_id", env.FlowID),
			slog.String("direction", env.Direction.String()),
			slog.Any("matched_rules", matchedRules),
		)
	}

	action, err := s.queue.Hold(ctx, env, matchedRules)
	if err != nil {
		// Context cancelled while waiting.
		return Result{Action: Drop}
	}

	switch action.Type {
	case common.ActionRelease:
		return Result{}
	case common.ActionDrop:
		return Result{Action: Drop}
	case common.ActionModifyAndForward:
		return Result{Envelope: action.Modified}
	default:
		return Result{}
	}
}
