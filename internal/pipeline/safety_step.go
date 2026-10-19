package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// SafetyStep is a Message-typed Pipeline Step that checks Send-direction
// messages against input safety rules. If a violation is detected, the
// envelope is not forwarded and, where the protocol has a terminator the
// client understands, the client is answered with one: HTTP gets a synthetic
// 403, native gRPC gets grpc-status 7 PERMISSION_DENIED (USK-1202).
// WebSocket and gRPC-Web are dropped without a terminator for now.
// Receive-direction messages always pass through (Input Filter is
// Send-only).
//
// HTTP / WebSocket / gRPC messages are dispatched to their respective
// per-protocol SafetyEngines. SSE has no per-protocol engine (N7 scope-out:
// half-duplex Receive-only). gRPC End events are skipped — End carries no
// Send-side user content (grpc-web sentinel has empty trailers/Status=0;
// native gRPC End is always Receive). Unknown Message types pass through.
//
// Wire fidelity invariant (RFC-001 Principle 1): SafetyStep.Process MUST
// NOT mutate env, env.Message, env.Raw, or any field reachable from them.
// Result is {} (pass), {Action: Drop} (block), or {Action: Respond} (block
// with a terminator carried in a NEW Response envelope; the blocked envelope
// itself is left untouched). PII / body masking belongs to internal/safety on
// the MCP response path, never here.
//
// SafetyStep is the live-wire Input Filter half of SafetyFilter — it
// protects the upstream server from destructive AI-agent payloads. The
// Output Filter half (sensitive-bytes masking on AI return) lives in
// internal/safety and is invoked from internal/mcp/safety_helper.go at
// the MCP transport boundary. The two filters serve different threat
// models and must not be conflated. See RFC-001 §3.7
// (docs/rfc/envelope.md) for the full role split (USK-702 / USK-894).
//
// log_only mode (USK-1109, safety_filter.input.action "log_only"): a
// violation is logged and the envelope continues untouched; the Result
// carries Annotations {"safety_log_only:<rule_id>": <target>} so RecordStep
// tags the Stream. Block mode (the default) is unchanged.
type SafetyStep struct {
	http    *httprules.SafetyEngine
	ws      *wsrules.SafetyEngine
	grpc    *grpcrules.SafetyEngine
	logger  *slog.Logger
	logOnly bool
}

// SafetyLogOnlyTagPrefix prefixes the Stream tag key SafetyStep emits (via
// Result.Annotations) for a log_only match. The full key is the prefix plus
// the matched rule ID; the value is the matched target name (USK-1109).
const SafetyLogOnlyTagPrefix = "safety_log_only:"

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

// WithLogOnly sets log_only mode (USK-1109): violations are logged and
// annotated but never block. Returns s for chaining, mirroring the
// InterceptStep With* options. Boot-time only — call before the step is
// shared with a Pipeline.
func (s *SafetyStep) WithLogOnly(logOnly bool) *SafetyStep {
	s.logOnly = logOnly
	return s
}

// safetyMatch is the protocol-neutral view of a per-protocol Violation.
type safetyMatch struct {
	ruleID, ruleName, target, fragment string
}

// logMatch emits the Info record for one match. The matched fragment is
// never logged raw (CWE-312).
func (s *SafetyStep) logMatch(ctx context.Context, msg string, m safetyMatch) {
	if s.logger == nil {
		return
	}
	s.logger.InfoContext(ctx, msg,
		slog.String("filter", BlockedBySafetyFilter),
		slog.String("rule_id", m.ruleID),
		slog.String("rule_name", m.ruleName),
		slog.String("target", m.target),
		slog.String("match", safety.RedactFragment(m.fragment)),
	)
}

// logBlock logs the single (first) match that blocks the envelope.
func (s *SafetyStep) logBlock(ctx context.Context, m safetyMatch) {
	s.logMatch(ctx, "safety: request blocked", m)
}

// observeAll is the log_only arm: it logs every match (the per-protocol
// CheckInputAll result, so a noisy early rule cannot hide later ones) and
// returns the pass Result (Continue, env untouched) annotated with one
// "safety_log_only:<rule_id>" tag per matched rule. No matches → empty
// Result.
func (s *SafetyStep) observeAll(ctx context.Context, matches []safetyMatch) Result {
	if len(matches) == 0 {
		return Result{}
	}
	tags := make(map[string]string, len(matches))
	for _, m := range matches {
		s.logMatch(ctx, safety.LogOnlyMessage, m)
		tags[SafetyLogOnlyTagPrefix+m.ruleID] = m.target
	}
	return Result{Annotations: tags}
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

	if s.logOnly {
		vs := s.http.CheckInputAll(ctx, msg)
		matches := make([]safetyMatch, 0, len(vs))
		for _, v := range vs {
			matches = append(matches, safetyMatch{v.RuleID, v.RuleName, v.Target, v.Match})
		}
		return s.observeAll(ctx, matches)
	}

	violation := s.http.CheckInput(ctx, msg)
	if violation != nil {
		s.logBlock(ctx, safetyMatch{violation.RuleID, violation.RuleName, violation.Target, violation.Match})
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
	if s.logOnly {
		vs := s.ws.CheckInputAll(ctx, msg)
		matches := make([]safetyMatch, 0, len(vs))
		for _, v := range vs {
			matches = append(matches, safetyMatch{v.RuleID, v.RuleName, v.Target, v.Match})
		}
		return s.observeAll(ctx, matches)
	}

	violation := s.ws.CheckInput(ctx, msg)
	if violation != nil {
		s.logBlock(ctx, safetyMatch{violation.RuleID, violation.RuleName, violation.Target, violation.Match})
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

	if s.logOnly {
		vs := s.grpc.CheckInputAll(ctx, env, msg)
		matches := make([]safetyMatch, 0, len(vs))
		for _, v := range vs {
			matches = append(matches, safetyMatch{v.RuleID, v.RuleName, v.Target, v.Match})
		}
		return s.observeAll(ctx, matches)
	}

	violation := s.grpc.CheckInput(ctx, env, msg)
	if violation != nil {
		s.logBlock(ctx, safetyMatch{violation.RuleID, violation.RuleName, violation.Target, violation.Match})
		// USK-1202: native gRPC answers the client with grpc-status 7
		// PERMISSION_DENIED (Trailers-Only, or trailers once response
		// HEADERS were relayed) and the session then ends the RPC, so the
		// client does not hang until its own deadline. gRPC-Web keeps
		// Drop (USK-1220).
		return grpcPolicyDropResult(env, BlockedBySafetyFilter, []string{violation.RuleID})
	}

	return Result{}
}
