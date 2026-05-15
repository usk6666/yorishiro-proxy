package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// TransformStep is a Message-typed Pipeline Step that applies transformation
// rules to messages in-place. HTTP / WebSocket / gRPC / SSE messages are
// dispatched to their respective per-protocol TransformEngines. Unknown
// Message types pass through.
type TransformStep struct {
	http *httprules.TransformEngine
	ws   *wsrules.TransformEngine
	grpc *grpcrules.TransformEngine
	sse  *sserules.TransformEngine
}

// NewTransformStep creates a TransformStep. Any nil engine causes the
// corresponding protocol arm to pass through unchanged. Engine arguments are
// positional in protocol order: http, ws, grpc, sse.
func NewTransformStep(
	httpEngine *httprules.TransformEngine,
	wsEngine *wsrules.TransformEngine,
	grpcEngine *grpcrules.TransformEngine,
	sseEngine *sserules.TransformEngine,
) *TransformStep {
	return &TransformStep{
		http: httpEngine,
		ws:   wsEngine,
		grpc: grpcEngine,
		sse:  sseEngine,
	}
}

// Process type-switches on env.Message and dispatches to the per-protocol
// TransformEngine arm. Mutations are in-place on the same Message pointer,
// so subsequent Steps see the modifications without envelope replacement;
// Result.Envelope is always nil.
//
// Each per-protocol engine is responsible for clearing env.Raw on commit
// when a wire-encoded snapshot is invalidated by the mutation. The Step
// itself never touches env.Raw.
//
// ctx is forwarded to engines so future async transform paths (e.g. disk-
// backed body materialization, plugin transforms) can honour cancellation.
func (s *TransformStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(ctx, env, msg)
	case *envelope.WSMessage:
		return s.processWS(ctx, env, msg)
	case *envelope.GRPCStartMessage:
		return s.processGRPCStart(ctx, env, msg)
	case *envelope.GRPCDataMessage:
		return s.processGRPCData(ctx, env, msg)
	case *envelope.GRPCEndMessage:
		return s.processGRPCEnd(ctx, env, msg)
	case *envelope.SSEMessage:
		return s.processSSE(ctx, env, msg)
	default:
		return Result{}
	}
}

func (s *TransformStep) processHTTP(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) Result {
	if s.http == nil {
		return Result{}
	}

	switch env.Direction {
	case envelope.Send:
		s.http.TransformRequest(ctx, env, msg)
	case envelope.Receive:
		s.http.TransformResponse(ctx, env, msg)
	}

	// In-place mutation — no Result.Envelope replacement needed.
	return Result{}
}

func (s *TransformStep) processWS(ctx context.Context, env *envelope.Envelope, msg *envelope.WSMessage) Result {
	if s.ws == nil {
		return Result{}
	}
	s.ws.Transform(ctx, env, msg)
	return Result{}
}

func (s *TransformStep) processGRPCStart(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCStartMessage) Result {
	if s.grpc == nil {
		return Result{}
	}
	s.grpc.TransformStart(ctx, env, msg)
	return Result{}
}

func (s *TransformStep) processGRPCData(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCDataMessage) Result {
	if s.grpc == nil {
		return Result{}
	}
	s.grpc.TransformData(ctx, env, msg)
	return Result{}
}

func (s *TransformStep) processGRPCEnd(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCEndMessage) Result {
	if s.grpc == nil {
		return Result{}
	}
	// Mirror the InterceptStep Send-side End guard for consistency: grpc-web
	// flushes a Send-side End sentinel (empty trailers, Status=0) which
	// carries no actionable status to mutate. Native gRPC End is always
	// Receive. Skip on Send so transform passes can't accidentally fabricate
	// a status on the request flush sentinel.
	if env.Direction == envelope.Send {
		return Result{}
	}
	s.grpc.TransformEnd(ctx, env, msg)
	return Result{}
}

// processSSE dispatches an SSE event envelope to the per-protocol
// TransformEngine. A matching Drop rule converts to
// Result{Action: Drop, BlockedBy: BlockedByInterceptDrop} — same pattern
// as WS / gRPC mid-stream drops. Engines do NOT clear env.Raw; the
// session-side `sseMessageMutated` field-diff is the authoritative
// re-encode signal (USK-892 wire-fidelity invariant).
func (s *TransformStep) processSSE(ctx context.Context, env *envelope.Envelope, msg *envelope.SSEMessage) Result {
	if s.sse == nil {
		return Result{}
	}
	res := s.sse.Transform(ctx, env, msg)
	if res.Drop {
		return Result{Action: Drop, BlockedBy: BlockedByInterceptDrop}
	}
	return Result{}
}
