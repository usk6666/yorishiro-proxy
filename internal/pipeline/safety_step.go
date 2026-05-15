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
//
// Wire fidelity invariant (RFC-001 Principle 1): SafetyStep.Process MUST
// NOT mutate env, env.Message, env.Raw, or any field reachable from them.
// Result is restricted to {} (pass) or {Action: Drop} (block). PII / body
// masking belongs to internal/safety on the MCP response path, never here.
//
// SafetyStep is the live-wire Input Filter half of SafetyFilter — it
// protects the upstream server from destructive AI-agent payloads. The
// Output Filter half (sensitive-bytes masking on AI return) lives in
// internal/safety and is invoked from internal/mcp/safety_helper.go at
// the MCP transport boundary. The two filters serve different threat
// models and must not be conflated. See RFC-001 §3.7
// (docs/rfc/envelope.md) for the full role split (USK-702 / USK-894).
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
//
// USK-854: proxy-synthesized envelopes (Context.Synthetic=true) bypass
// safety matching. Synthetic frames carry no attacker-influenced payload
// — they are proxy-originated keepalive Pings with empty payload (RFC
// 6455 §5.5.2 permits zero-byte Ping).
func (s *SafetyStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if env.Direction != envelope.Send {
		return Result{}
	}
	if env.Context.Synthetic {
		return Result{}
	}

	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(ctx, env, msg)
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

func (s *SafetyStep) processHTTP(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) Result {
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
		// USK-829: emit a 403 terminator on the wire for HTTP requests
		// so the client closes cleanly. Surface the matched safety rule
		// ID via matched_rules so the body is consistent with the
		// intercept drop body shape.
		matched := []string{violation.RuleID}
		return Result{
			Action:    Respond,
			Response:  buildPolicyDropResponse(env, BlockedBySafetyFilter, matched),
			BlockedBy: BlockedBySafetyFilter,
		}
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
		// USK-829: mid-stream WS frame Drop. The protocol-correct
		// terminator is a Close control frame, which HTTPMessage cannot
		// express through the WS Send dispatch. Deferred to follow-up
		// Issue D2; keep Drop until that lands.
		return Result{Action: Drop, BlockedBy: BlockedBySafetyFilter}
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
		// USK-829: mid-stream gRPC Drop. The protocol-correct terminator
		// is a gRPC trailers frame (Status: 7 / PERMISSION_DENIED, or
		// similar), which HTTPMessage cannot express through the gRPC
		// Send dispatch. Deferred to follow-up Issue D3; keep Drop
		// until that lands.
		return Result{Action: Drop, BlockedBy: BlockedBySafetyFilter}
	}

	return Result{}
}
