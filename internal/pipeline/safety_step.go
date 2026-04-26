package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// SafetyStep is a Message-typed Pipeline Step that checks Send-direction
// messages against input safety rules. If a violation is detected, the
// envelope is dropped. Receive-direction messages always pass through
// (Input Filter is Send-only).
//
// HTTP / WebSocket / gRPC messages are dispatched to their respective
// per-protocol SafetyEngines. SSE has no per-protocol engine (N7 scope-out:
// half-duplex Receive-only). gRPC End events are skipped — End carries no
// Send-side user content (grpc-web sentinel has empty trailers/Status=0;
// native gRPC End is always Receive). Unknown Message types pass through.
type SafetyStep struct {
	http   *httprules.SafetyEngine
	ws     *wsrules.SafetyEngine
	grpc   *grpcrules.SafetyEngine
	logger *slog.Logger
}

// NewSafetyStep creates a SafetyStep. Any nil engine causes the corresponding
// protocol arm to pass through. Engine arguments are positional in protocol
// order: http, ws, grpc.
func NewSafetyStep(httpEngine *httprules.SafetyEngine, wsEngine *wsrules.SafetyEngine, grpcEngine *grpcrules.SafetyEngine, logger *slog.Logger) *SafetyStep {
	return &SafetyStep{
		http:   httpEngine,
		ws:     wsEngine,
		grpc:   grpcEngine,
		logger: logger,
	}
}

// Process checks Send-direction envelopes against safety rules. Receive
// direction always passes through.
func (s *SafetyStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if env.Direction != envelope.Send {
		return Result{}
	}

	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(ctx, msg)
	case *envelope.WSMessage:
		return s.processWS(ctx, msg)
	case *envelope.GRPCStartMessage:
		return s.processGRPC(ctx, env, msg)
	case *envelope.GRPCDataMessage:
		return s.processGRPC(ctx, env, msg)
	case *envelope.GRPCEndMessage:
		// End carries no Send-side user content (grpc-web sentinel has
		// empty trailers/Status=0; native gRPC End is always Receive).
		// gRPC SafetyEngine has no End-target rules — skip.
		_ = msg
		return Result{}
	case *envelope.SSEMessage:
		// N7 scope-out: SSE has no Send-side data — half-duplex Receive-only.
		_ = msg
		return Result{}
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

func (s *SafetyStep) processWS(ctx context.Context, msg *envelope.WSMessage) Result {
	if s.ws == nil {
		return Result{}
	}

	// WS SafetyEngine.CheckInput takes (ctx, msg) — no env. Surface
	// asymmetry vs gRPC is preserved.
	violation := s.ws.CheckInput(ctx, msg)
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

// processGRPC is a single helper shared by GRPCStart and GRPCData arms.
// gRPC SafetyEngine.CheckInput takes (ctx, env, msg envelope.Message); the
// caller passes the typed message verbatim and the engine type-switches
// internally to extract per-target data.
func (s *SafetyStep) processGRPC(ctx context.Context, env *envelope.Envelope, msg envelope.Message) Result {
	if s.grpc == nil {
		return Result{}
	}

	violation := s.grpc.CheckInput(ctx, env, msg)
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
