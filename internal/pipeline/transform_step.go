package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// TransformStep is a Message-typed Pipeline Step that applies transformation
// rules to messages in-place. HTTP messages are dispatched to the
// httprules.TransformEngine; unknown Message types pass through.
type TransformStep struct {
	http *httprules.TransformEngine
}

// NewTransformStep creates a TransformStep. If httpEngine is nil, all
// messages pass through unmodified.
func NewTransformStep(httpEngine *httprules.TransformEngine) *TransformStep {
	return &TransformStep{http: httpEngine}
}

// Process type-switches on env.Message. HTTPMessage is dispatched to the
// TransformEngine for in-place mutation; all other Message types pass through.
// Returns Result{} always — mutations are in-place on the same Message
// pointer, so subsequent Steps see the modifications without envelope
// replacement.
func (s *TransformStep) Process(_ context.Context, env *envelope.Envelope) Result {
	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(env, msg)
	default:
		return Result{}
	}
}

func (s *TransformStep) processHTTP(env *envelope.Envelope, msg *envelope.HTTPMessage) Result {
	if s.http == nil {
		return Result{}
	}

	switch env.Direction {
	case envelope.Send:
		s.http.TransformRequest(env, msg)
	case envelope.Receive:
		s.http.TransformResponse(env, msg)
	}

	// In-place mutation — no Result.Envelope replacement needed.
	return Result{}
}
