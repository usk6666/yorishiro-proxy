package pipeline

import (
	"context"
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// InterceptStep is a Message-typed Pipeline Step that holds envelopes matching
// intercept rules and waits for an external action (release, drop, or modify).
// HTTP / WebSocket / gRPC messages are dispatched to their respective per-
// protocol InterceptEngines (rules/http, rules/ws, rules/grpc). SSE has no
// per-protocol engine (N7 scope-out: half-duplex Receive-only) and passes
// through unchanged. Unknown Message types pass through.
//
// On ActionModifyAndForward, the user-supplied modified envelope is re-checked
// against the SafetyStep before being released downstream — defense-in-depth
// for the case where SafetyStep already gated the original held envelope but
// the modify_and_forward payload re-introduces a destructive pattern (USK-702).
type InterceptStep struct {
	http        *httprules.InterceptEngine
	ws          *wsrules.InterceptEngine
	grpc        *grpcrules.InterceptEngine
	queue       *common.HoldQueue
	safety      *SafetyStep
	holdTracker *common.HoldTracker
	logger      *slog.Logger
}

// NewInterceptStep creates an InterceptStep. Any nil engine causes the
// corresponding protocol arm to gracefully degrade (pass-through). A nil
// queue causes all matching arms to pass through (no hold without queue).
// A nil safety disables the modify_and_forward re-check (callers without a
// SafetyStep — e.g. tests not exercising safety — pass nil).
//
// Engine arguments are positional in protocol order: http, ws, grpc.
//
// The optional HoldTracker is wired via WithHoldTracker. When non-nil,
// InterceptStep stamps the (StreamID, Direction) tuple on hold-enter and
// un-stamps it on hold-exit so the session keepalive goroutine (USK-854)
// can observe in-flight holds. A nil tracker is a graceful no-op.
func NewInterceptStep(httpEngine *httprules.InterceptEngine, wsEngine *wsrules.InterceptEngine, grpcEngine *grpcrules.InterceptEngine, queue *common.HoldQueue, safety *SafetyStep, logger *slog.Logger) *InterceptStep {
	return &InterceptStep{
		http:   httpEngine,
		ws:     wsEngine,
		grpc:   grpcEngine,
		queue:  queue,
		safety: safety,
		logger: logger,
	}
}

// WithHoldTracker wires the optional HoldTracker. A nil tracker is a
// graceful no-op so test stacks that do not construct one continue to
// work unchanged. Returns the receiver for fluent construction.
func (s *InterceptStep) WithHoldTracker(t *common.HoldTracker) *InterceptStep {
	s.holdTracker = t
	return s
}

// Process type-switches on env.Message and dispatches to the per-protocol
// InterceptEngine arm. Unknown Message types pass through.
//
// USK-854: proxy-synthesized envelopes (Context.Synthetic=true) bypass
// intercept matching entirely. A synthetic WS Ping injected during a hold
// must not itself trigger another hold (infinite-loop guard); and it
// carries no operator-supplied data worth matching against intercept
// rules.
func (s *InterceptStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if env != nil && env.Context.Synthetic {
		return Result{}
	}
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
		// N7 scope-out: SSE has no per-protocol intercept engine; pass
		// through. Half-duplex Receive-only — no Send-side rules to apply.
		_ = msg
		return Result{}
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

	return s.holdAndDispatch(ctx, env, matchedRules)
}

func (s *InterceptStep) processWS(ctx context.Context, env *envelope.Envelope, msg *envelope.WSMessage) Result {
	if s.ws == nil || s.queue == nil {
		return Result{}
	}
	// WS has no Send/Receive asymmetry like HTTP request/response, so a
	// single Match call covers both directions; the rule's Direction field
	// gates evaluation inside the engine.
	matchedRules := s.ws.Match(env, msg)
	return s.holdAndDispatch(ctx, env, matchedRules)
}

func (s *InterceptStep) processGRPCStart(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCStartMessage) Result {
	if s.grpc == nil || s.queue == nil {
		return Result{}
	}
	matchedRules := s.grpc.MatchStart(env, msg)
	return s.holdAndDispatch(ctx, env, matchedRules)
}

func (s *InterceptStep) processGRPCData(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCDataMessage) Result {
	if s.grpc == nil || s.queue == nil {
		return Result{}
	}
	matchedRules := s.grpc.MatchData(env, msg)
	return s.holdAndDispatch(ctx, env, matchedRules)
}

func (s *InterceptStep) processGRPCEnd(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCEndMessage) Result {
	if s.grpc == nil || s.queue == nil {
		return Result{}
	}
	// grpc-web flushes a Send-side End sentinel (empty trailers, Status=0)
	// at the close of the request body; native gRPC End is always Receive.
	// MatchEnd only filters by direction + Enabled, so a catch-all rule
	// with Direction=both/send would block the request flush. Skip MatchEnd
	// on Send to keep grpc-web flushes flowing.
	if env.Direction == envelope.Send {
		return Result{}
	}
	matchedRules := s.grpc.MatchEnd(env, msg)
	return s.holdAndDispatch(ctx, env, matchedRules)
}

// holdAndDispatch holds the envelope on a non-empty match and translates the
// resulting HoldAction into a Pipeline Result. Shared across all protocol arms
// so that hold/release/drop/modify behaviour is identical regardless of the
// matching engine.
func (s *InterceptStep) holdAndDispatch(ctx context.Context, env *envelope.Envelope, matchedRules []string) Result {
	if len(matchedRules) == 0 {
		return Result{}
	}

	if s.logger != nil {
		s.logger.DebugContext(ctx, "intercept: envelope held",
			slog.String("flow_id", env.FlowID),
			slog.String("direction", env.Direction.String()),
			slog.String("protocol", string(env.Protocol)),
			slog.Any("matched_rules", matchedRules),
		)
	}

	// USK-854: stamp the (StreamID, Direction) tuple on the shared
	// HoldTracker before HoldQueue.Hold blocks so the session keepalive
	// goroutine can observe the in-flight hold and inject WS Pings if
	// (and only if) the operator opted in via the web_socket.hold_keepalive_*
	// config knob. ForgetHold runs unconditionally after Hold returns so a
	// release / drop / modify all clear the entry — the keepalive goroutine
	// observes IsHeld=false on its next tick and terminates cleanly.
	// nil tracker is a no-op (test stacks).
	if s.holdTracker != nil {
		s.holdTracker.MarkHold(env.StreamID, env.Direction, time.Now())
		defer s.holdTracker.ForgetHold(env.StreamID, env.Direction)
	}

	action, err := s.queue.Hold(ctx, env, matchedRules)
	if err != nil {
		// Context cancelled while waiting. No user action ever resolved
		// the hold; do not attribute this to intercept_drop because no
		// drop decision was made — the surrounding session is being
		// torn down.
		return Result{Action: Drop}
	}

	switch action.Type {
	case common.ActionRelease:
		return Result{}
	case common.ActionDrop:
		// USK-829: when the held envelope is an HTTPMessage (Send or
		// Receive direction), synthesize a 403 response so the client
		// sees a clean close instead of hanging until its own read
		// timeout. The session loop dispatches Respond via client.Send
		// (dispatchClientAction / wsRelayDirection). Mid-stream WS / gRPC
		// data drops keep Action=Drop — protocol-correct terminators
		// (Close frame, trailers) are deferred to follow-up Issues
		// (D2 / D3).
		if _, ok := env.Message.(*envelope.HTTPMessage); ok {
			return Result{
				Action:    Respond,
				Response:  buildPolicyDropResponse(env, BlockedByInterceptDrop, matchedRules),
				BlockedBy: BlockedByInterceptDrop,
			}
		}
		return Result{Action: Drop, BlockedBy: BlockedByInterceptDrop}
	case common.ActionModifyAndForward:
		// Defense-in-depth: re-check the user-supplied modified envelope
		// against SafetyStep. The original held envelope already passed
		// SafetyStep at hold time (Pipeline order: Safety → Intercept), but
		// modify_and_forward lets the operator/AI agent inject content that
		// bypasses that gate. Mirroring SafetyStep ensures the same Send-
		// only / per-protocol coverage as the inline check (USK-702).
		if s.safety != nil {
			recheck := s.safety.Process(ctx, action.Modified)
			// USK-829: SafetyStep now returns Respond (with a synthetic
			// 403 envelope) for HTTPMessage blocks instead of Drop. The
			// recheck must forward both Action shapes — Drop for mid-
			// stream WS / gRPC paths, Respond for HTTPMessage paths —
			// so the modify_and_forward bypass is rejected with the same
			// wire behaviour as a direct SafetyStep block.
			if recheck.Action == Drop || recheck.Action == Respond {
				if s.logger != nil {
					s.logger.DebugContext(ctx, "intercept: modify_and_forward blocked by safety re-check",
						slog.String("flow_id", env.FlowID),
						slog.String("direction", env.Direction.String()),
						slog.String("protocol", string(env.Protocol)),
						slog.String("action", recheck.Action.String()),
					)
				}
				// Forward the recheck Result verbatim. The Response (if
				// any) was constructed by SafetyStep against the modified
				// envelope, which is the appropriate target for wire
				// attribution — the original held envelope was safe.
				return Result{
					Action:    recheck.Action,
					Response:  recheck.Response,
					BlockedBy: recheck.BlockedBy,
				}
			}
		}
		return Result{Envelope: action.Modified}
	default:
		return Result{}
	}
}
