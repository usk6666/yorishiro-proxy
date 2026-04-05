package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
)

// TransformStep applies auto-transform rules as a Pipeline Step.
// When rules match, it modifies Exchange Headers and Body in place.
// Body nil (passthrough) skips body rules; only header rules are applied.
// Content-Length update is the Codec's responsibility, not TransformStep's.
type TransformStep struct {
	pipeline *rules.Pipeline
}

// NewTransformStep creates a TransformStep with the given rules.Pipeline.
// If pipeline is nil, Process always returns Continue with no modifications.
func NewTransformStep(pipeline *rules.Pipeline) *TransformStep {
	return &TransformStep{pipeline: pipeline}
}

// Process applies matching auto-transform rules to the Exchange.
// For Send direction, request-side rules are applied using Method, URL,
// Headers, and Body. For Receive direction, response-side rules are applied
// using Status, Headers, and Body.
func (s *TransformStep) Process(_ context.Context, ex *exchange.Exchange) Result {
	if s.pipeline == nil {
		return Result{}
	}

	switch ex.Direction {
	case exchange.Send:
		headers, body := s.pipeline.TransformRequest(ex.Method, ex.URL, ex.Headers, ex.Body)
		ex.Headers = headers
		if ex.Body != nil {
			ex.Body = body
		}
	case exchange.Receive:
		headers, body := s.pipeline.TransformResponse(ex.Status, ex.Headers, ex.Body)
		ex.Headers = headers
		if ex.Body != nil {
			ex.Body = body
		}
	}

	return Result{}
}
