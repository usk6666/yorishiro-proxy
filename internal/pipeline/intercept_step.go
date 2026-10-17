package pipeline

import (
	"context"
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// InterceptStep is a Message-typed Pipeline Step that holds envelopes matching
// intercept rules and waits for an external action (release, drop, or modify).
// HTTP / WebSocket / gRPC / SSE messages are dispatched to their respective
// per-protocol InterceptEngines. Unknown Message types pass through.
//
// When a hold is released to be forwarded — manual release, timeout
// auto-release, or modify_and_forward — the envelope about to be forwarded
// is first re-checked against HostScopeStep / HTTPScopeStep (USK-1159, wired
// via WithScopeRecheck): the scope may have narrowed while the envelope was
// held (operator policy reload, agent `security` tool), and
// modify_and_forward can rewrite the request target.
//
// On ActionModifyAndForward, the user-supplied modified envelope is then
// re-checked against the SafetyStep before being released downstream —
// defense-in-depth for the case where SafetyStep already gated the original
// held envelope but the modify_and_forward payload re-introduces a
// destructive pattern (USK-702).
type InterceptStep struct {
	http        *httprules.InterceptEngine
	ws          *wsrules.InterceptEngine
	grpc        *grpcrules.InterceptEngine
	sse         *sserules.InterceptEngine
	queue       *common.HoldQueue
	safety      *SafetyStep
	holdTracker *common.HoldTracker
	hostScope   *HostScopeStep
	httpScope   *HTTPScopeStep
	logger      *slog.Logger
}

// NewInterceptStep creates an InterceptStep. Any nil engine causes the
// corresponding protocol arm to gracefully degrade (pass-through). A nil
// queue causes all matching arms to pass through (no hold without queue).
// A nil safety disables the modify_and_forward re-check (callers without a
// SafetyStep — e.g. tests not exercising safety — pass nil).
//
// Engine arguments are positional in protocol order: http, ws, grpc, sse.
//
// The optional HoldTracker is wired via WithHoldTracker. When non-nil,
// InterceptStep stamps the (StreamID, Direction) tuple on hold-enter and
// un-stamps it on hold-exit so the session keepalive goroutine (USK-854)
// can observe in-flight holds. A nil tracker is a graceful no-op.
func NewInterceptStep(
	httpEngine *httprules.InterceptEngine,
	wsEngine *wsrules.InterceptEngine,
	grpcEngine *grpcrules.InterceptEngine,
	sseEngine *sserules.InterceptEngine,
	queue *common.HoldQueue,
	safety *SafetyStep,
	logger *slog.Logger,
) *InterceptStep {
	return &InterceptStep{
		http:   httpEngine,
		ws:     wsEngine,
		grpc:   grpcEngine,
		sse:    sseEngine,
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

// WithScopeRecheck wires the scope Steps that are re-run against the
// envelope about to be forwarded when a hold is released (USK-1159). Pass
// the same instances the Pipeline runs at its head so the re-check consults
// the same live TargetScope. Either Step may be nil (that half of the
// re-check is skipped); without this option a release is not re-checked.
// Returns the receiver for fluent construction.
func (s *InterceptStep) WithScopeRecheck(host *HostScopeStep, http *HTTPScopeStep) *InterceptStep {
	s.hostScope = host
	s.httpScope = http
	return s
}

// recheckScope re-runs the scope Steps, in Pipeline order (HostScopeStep
// then HTTPScopeStep), against env and returns the first non-Continue
// Result verbatim — Respond with a synthetic 403 and
// BlockedBy=target_scope for an HTTP request, Drop with
// BlockedBy=target_scope otherwise. It returns the zero Result when both
// allow env or are nil. Both Steps are Send-only, so a Receive envelope
// always passes.
//
// It exists for code that forwards an envelope after the head of the
// Pipeline already scope-checked an earlier form of it: an intercept
// release (scope may have narrowed during the hold, or modify_and_forward
// rewrote the target) and, later, plugin rewrites (USK-1150).
func recheckScope(ctx context.Context, host *HostScopeStep, httpStep *HTTPScopeStep, env *envelope.Envelope) Result {
	if host != nil {
		if r := host.Process(ctx, env); r.Action != Continue {
			return r
		}
	}
	if httpStep != nil {
		if r := httpStep.Process(ctx, env); r.Action != Continue {
			return r
		}
	}
	return Result{}
}

// recheckReleaseScope runs recheckScope for an envelope released from a
// hold, logging a block. The returned Result is forwarded verbatim by
// holdAndDispatch so the session emits the same 403 / Drop and the same
// OnPipelineDrop audit record as a head-of-pipeline scope deny.
//
// The block log carries the denied target of the forward envelope
// (connection TargetHost, plus scheme / authority / path for an HTTP
// request). The recorded flow holds the original held envelope, so for a
// modify_and_forward that rewrote the target this log line is the only
// trace of the attempted out-of-scope target. The query string, headers
// and body are deliberately not logged.
func (s *InterceptStep) recheckReleaseScope(ctx context.Context, held, forward *envelope.Envelope, action common.ActionType) Result {
	r := recheckScope(ctx, s.hostScope, s.httpScope, forward)
	if r.Action != Continue && s.logger != nil {
		attrs := []any{
			slog.String("flow_id", held.FlowID),
			slog.String("direction", held.Direction.String()),
			slog.String("protocol", string(held.Protocol)),
			slog.String("hold_action", action.String()),
			slog.String("action", r.Action.String()),
			slog.String("target_host", forward.Context.TargetHost),
		}
		if m, ok := forward.Message.(*envelope.HTTPMessage); ok {
			attrs = append(attrs,
				slog.String("scheme", m.Scheme),
				slog.String("authority", m.Authority),
				slog.String("path", m.Path),
			)
		}
		s.logger.InfoContext(ctx, "intercept: release blocked by target scope re-check", attrs...)
	}
	return r
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
		return s.processSSE(ctx, env, msg)
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

// processSSE dispatches an SSE event envelope to the per-protocol
// InterceptEngine. SSE on the live wire is Receive-only (single
// direction), so a single Match call suffices.
func (s *InterceptStep) processSSE(ctx context.Context, env *envelope.Envelope, msg *envelope.SSEMessage) Result {
	if s.sse == nil || s.queue == nil {
		return Result{}
	}
	matchedRules := s.sse.Match(env, msg)
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

	action, blocked, ok := s.hold(ctx, env, matchedRules)
	if !ok {
		return blocked
	}

	switch action.Type {
	case common.ActionRelease:
		// Covers manual release and timeout auto-release (HoldQueue
		// returns ActionRelease on expiry under auto_release). The held
		// envelope is forwarded unchanged; re-check its scope against the
		// current rules (USK-1159).
		return s.recheckReleaseScope(ctx, env, env, action.Type)
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
		// USK-1159: re-check scope on the envelope that will actually be
		// forwarded — the modified one, whose authority / path the
		// operator or agent may have rewritten — before the safety
		// re-check (Pipeline order: Scope → Safety). A nil Modified is
		// forwarded as the held envelope (Result.Envelope nil keeps env).
		forward := action.Modified
		if forward == nil {
			forward = env
		}
		if r := s.recheckReleaseScope(ctx, env, forward, action.Type); r.Action != Continue {
			return r
		}
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
		// An unknown action forwards the held envelope like a release, so
		// it is scope-checked like one.
		return s.recheckReleaseScope(ctx, env, env, action.Type)
	}
}

// pinLiveConnForHold pins the live connection carried by ctx for the
// duration of a hold (USK-1192), so a policy change that revokes it
// defers the cut instead of cancelling ctx under the hold — which would
// drop the held envelope with no answer and no record. The session
// settles the cut after it dispatched the hold's Result. The caller must
// Unpin the returned handle (nil-safe) when the hold resolves.
//
// ok=false means the connection was already cut or is revoke-pending (a
// new hold must not extend a deferred cut): the caller must not hold
// and returns blocked instead — a synthetic 403 for a Send HTTP request, a
// Drop otherwise (the Receive relay forwards the envelope on any non-Drop
// action), both attributed to target_scope. A ctx without a live-conn
// handle (no gate registered the connection) always pins.
func pinLiveConnForHold(ctx context.Context, env *envelope.Envelope) (lc *connector.LiveConnHandle, blocked Result, ok bool) {
	lc = connector.LiveConnFromContext(ctx)
	if lc.Pin() {
		return lc, Result{}, true
	}
	if env.Direction == envelope.Send {
		return nil, targetScopeBlock(env), false
	}
	return nil, Result{Action: Drop, BlockedBy: BlockedByTargetScope}, false
}

// hold blocks env on the HoldQueue until an action resolves it, with the
// session-facing bookkeeping around the wait (HoldTracker stamp, live
// connection pin). ok=false means no action resolved the hold and the
// caller returns blocked verbatim.
func (s *InterceptStep) hold(ctx context.Context, env *envelope.Envelope, matchedRules []string) (action *common.HoldAction, blocked Result, ok bool) {
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

	// USK-1192: pin the live connection for the duration of the hold.
	lc, blocked, ok := pinLiveConnForHold(ctx, env)
	if !ok {
		return nil, blocked, false
	}
	defer lc.Unpin()

	action, err := s.queue.Hold(ctx, env, matchedRules)
	if err != nil {
		// Context cancelled while waiting. No user action ever resolved
		// the hold; do not attribute this to intercept_drop because no
		// drop decision was made — the surrounding session is being
		// torn down.
		return nil, Result{Action: Drop}, false
	}
	return action, Result{}, true
}
