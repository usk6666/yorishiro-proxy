package pipeline

import (
	"context"
	"net"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// HostScopeStep is an Envelope-only Pipeline Step that validates the
// connection's target host against the TargetScope policy. It uses
// Envelope.Context.TargetHost (populated from CONNECT or SOCKS5 target)
// and Envelope.Context.TLS, and never type-asserts on Message to reach
// the scope decision.
//
// This is the host-level scope check. Path-based HTTP scope is a separate
// Step added in N3 (HTTPScopeStep).
type HostScopeStep struct {
	scope *connector.TargetScope
}

// NewHostScopeStep creates a HostScopeStep with the given TargetScope.
// If scope is nil, Process always continues (no filtering).
func NewHostScopeStep(scope *connector.TargetScope) *HostScopeStep {
	return &HostScopeStep{scope: scope}
}

// Process checks whether the envelope's target host is allowed by the
// TargetScope policy. Returns Drop if the target is blocked, Continue
// otherwise. Envelopes without a TargetHost are always allowed.
//
// Only Send-direction envelopes are checked, mirroring HTTPScopeStep.
// This is a connection-level gate, and a connection-level gate must reach
// exactly one verdict per connection. Since USK-1081 the scheme comes
// from Envelope.Context.TLS, which is per-Layer and not per-stack
// (RFC-001 §3.1): a tcp_forward entry with `tls` and no `upstream_tls`
// stamps a snapshot on the client Layer's EnvelopeContext and nil on the
// upstream Layer's (connector/stack_builder_target_override.go), so
// without this gate the Send leg would derive "https", the Receive leg
// "http", and a Schemes-bearing rule could reach opposite verdicts on the
// two halves of one exchange.
//
// Gating loses no coverage. Both legs are stamped with the same
// Context.TargetHost, so the Receive-leg check was already redundant on
// hostname and port; the only axis it added was the scheme — exactly the
// axis that diverges. The client-facing Layer is the one that emits Send
// (connector/stack_builder.go), so the surviving check reads the
// confidentiality of the leg the client is actually speaking on.
//
// The scheme handed to CheckTarget is derived from Envelope.Context.TLS
// (see transportScopeScheme).
//
// A Send envelope on a live connection that a policy change revoked but
// whose cut is deferred for in-flight intercept holds (USK-1192,
// connector.LiveConnHandle.RevokePending) is blocked regardless of
// CheckTarget: the gate that admitted the connection already decided it
// may carry nothing more to its target, and this Step's own verdict can
// differ from the gate's (the gate scopes a SOCKS5 tunnel with a blank
// scheme, a CONNECT tunnel as "https"; this Step derives the scheme from
// TLS state). The intercept release re-check reuses this Step and so
// inherits the block.
//
// USK-1130: the check is TargetScope.CheckHost, not CheckTarget with an
// empty path, so a path-scoped allow ({hostname: X, path_prefix: "/api/"})
// admits X here *conditionally* (pathPending). The connection gates admit
// such a host provisionally on every route that reaches the Pipeline, and
// this Step is where the condition is enforced, per envelope and
// statelessly (so the intercept release re-check and the USK-1192 revoke
// path need no extra state): an HTTP envelope continues to HTTPScopeStep,
// which checks the request path; a WebSocket envelope continues because
// its frames ride an upgrade request HTTPScopeStep already path-checked;
// every other protocol — raw bytes, gRPC and gRPC-Web, whose requests
// HTTPScopeStep does not path-check (USK-1236) — is blocked, failing
// closed.
func (s *HostScopeStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if env.Direction != envelope.Send {
		return Result{}
	}
	if connector.LiveConnFromContext(ctx).RevokePending() {
		return targetScopeBlock(env)
	}
	if s.scope == nil || env.Context.TargetHost == "" {
		return Result{}
	}

	host, portStr, err := net.SplitHostPort(env.Context.TargetHost)
	if err != nil {
		// TargetHost might be a bare hostname without port.
		host = env.Context.TargetHost
		portStr = ""
	}

	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}

	// No path is passed: this is a connection-level check and no request
	// path is known here (CheckHost). The scheme, however, IS known — it
	// is the connection's transport confidentiality — and must be passed,
	// because matchTargetRule is AND logic: a rule carrying a Schemes
	// condition silently stops matching when the scheme is blank
	// (USK-1081).
	allowed, pathPending, _ := s.scope.CheckHost(transportScopeScheme(env), host, port)
	if !allowed {
		return targetScopeBlock(env)
	}
	if pathPending && !requestPathChecked(env.Protocol) {
		return targetScopeBlock(env)
	}
	return Result{}
}

// AdmitsRawRelay reports whether the Pipeline's HostScopeStep would let
// the first client-sent raw chunk of a connection whose client Layer
// stamps envCtx through. The raw relay asks it before relaying anything
// (USK-1130 review S-1): HostScopeStep checks only Send envelopes, so on
// a server-first protocol with a silent client its verdict — in
// particular the pathPending block for a path-scoped allow — would
// otherwise never fire while upstream bytes reach the client. The probe
// carries no payload and runs no other Step. A Pipeline without a
// HostScopeStep admits.
func (p *Pipeline) AdmitsRawRelay(ctx context.Context, envCtx envelope.EnvelopeContext) bool {
	if p == nil {
		return true
	}
	probe := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Context:   envCtx,
		Message:   &envelope.RawMessage{},
	}
	for _, step := range p.steps {
		if hs, ok := step.(*HostScopeStep); ok && hs.Process(ctx, probe).Action != Continue {
			return false
		}
	}
	return true
}

// requestPathChecked reports whether every Send envelope of protocol p is
// covered by an HTTPScopeStep request-path check (USK-1130): HTTP requests
// directly, WebSocket frames through the upgrade request. Raw bytes carry
// no path, and gRPC / gRPC-Web requests are not path-checked by
// HTTPScopeStep (USK-1236), so a path-scoped allow must not admit them.
func requestPathChecked(p envelope.Protocol) bool {
	switch p {
	case envelope.ProtocolHTTP, envelope.ProtocolWebSocket:
		return true
	default:
		return false
	}
}

// targetScopeBlock is the Result of a target scope deny for env.
//
// USK-829: when the envelope is an HTTP message, synthesize a 403
// terminator so the client sees a clean close instead of hanging on its
// read timeout. Non-HTTP envelopes keep the legacy silent Drop —
// protocol-correct terminators for raw/ws/gRPC are deferred (D2-D5).
func targetScopeBlock(env *envelope.Envelope) Result {
	if _, ok := env.Message.(*envelope.HTTPMessage); ok {
		return Result{
			Action:    Respond,
			Response:  buildPolicyDropResponse(env, BlockedByTargetScope, nil),
			BlockedBy: BlockedByTargetScope,
		}
	}
	return Result{Action: Drop, BlockedBy: BlockedByTargetScope}
}

// transportScopeScheme derives the TargetScope scheme token from the
// envelope's TLS state. It is the single source of the scheme both scope
// Steps hand CheckTarget: HostScopeStep (connection level) and
// HTTPScopeStep (request level).
//
// TargetRule.Schemes describes transport confidentiality — plaintext
// versus TLS — spelled with the "http" / "https" tokens, not the L7
// application protocol. That is the meaning the connection-level handler
// gates already encode with their literals: connectPolicyReject scopes a
// CONNECT tunnel as "https" even though the tunnel may carry any protocol,
// and the plain HTTP forward handler scopes as "http" "so scope rules can
// disambiguate http vs https traffic for the same host". Envelope.Context.TLS
// is non-nil exactly when a TLS layer is in the stack, so it answers the
// same question without inspecting Message — which is what lets
// HostScopeStep stay protocol-agnostic.
//
// HTTPScopeStep uses it instead of HTTPMessage.Scheme (USK-1086). The
// declared scheme is client-controlled — HTTP/2 records `:scheme`
// verbatim, so an absent pseudo-header leaves it empty and a client may
// declare "http" over TLS; an intercept modify_and_forward can set it to
// anything — and because matchTargetRule is AND logic, a declared scheme
// that disagrees with the transport silently steers a Schemes-bearing
// rule. HTTPMessage.Scheme is still recorded and forwarded verbatim; only
// the policy decision reads the transport.
//
// Because TLS is per-Layer and not per-stack (RFC-001 §3.1), the two legs
// of a connection with independent TLS axes (a tcp_forward entry with
// `tls` but no `upstream_tls`, say) carry different snapshots and would
// derive different schemes. Callers therefore use this only on
// Send-direction envelopes, which come from the client-facing Layer, so
// the scope decision reads the client-facing leg's wire reality.
func transportScopeScheme(env *envelope.Envelope) string {
	if env.Context.TLS != nil {
		return "https"
	}
	return "http"
}
