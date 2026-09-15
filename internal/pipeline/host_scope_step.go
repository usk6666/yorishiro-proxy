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
// The scheme handed to CheckTarget is derived from Envelope.Context.TLS
// (see hostScopeScheme).
func (s *HostScopeStep) Process(_ context.Context, env *envelope.Envelope) Result {
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

	// Path is passed empty: this is a connection-level check and no
	// request path is known yet. The scheme, however, IS known — it is
	// the connection's transport confidentiality — and must be passed,
	// because matchTargetRule is AND logic: a rule carrying a Schemes
	// condition silently stops matching when the scheme is blank
	// (USK-1081).
	allowed, _ := s.scope.CheckTarget(hostScopeScheme(env), host, port, "")
	if !allowed {
		// USK-829: when the connection's first envelope is an HTTP
		// request, synthesize a 403 terminator so the client sees a
		// clean close instead of hanging on its read timeout. Non-HTTP
		// envelopes keep the legacy silent Drop — protocol-correct
		// terminators for raw/ws/gRPC are deferred (D2-D5).
		if _, ok := env.Message.(*envelope.HTTPMessage); ok {
			return Result{
				Action:    Respond,
				Response:  buildPolicyDropResponse(env, BlockedByTargetScope, nil),
				BlockedBy: BlockedByTargetScope,
			}
		}
		return Result{Action: Drop, BlockedBy: BlockedByTargetScope}
	}
	return Result{}
}

// hostScopeScheme derives the TargetScope scheme token for a connection-
// level check from the envelope's TLS state.
//
// TargetRule.Schemes describes transport confidentiality — plaintext
// versus TLS — spelled with the "http" / "https" tokens, not the L7
// application protocol. That is the meaning the connection-level handler
// gates already encode with their literals: connectPolicyAllow scopes a
// CONNECT tunnel as "https" even though the tunnel may carry any protocol,
// and the plain HTTP forward handler scopes as "http" "so scope rules can
// disambiguate http vs https traffic for the same host". Envelope.Context.TLS
// is non-nil exactly when a TLS layer is in the stack, so it answers the
// same question without inspecting Message — which is what lets
// HostScopeStep stay protocol-agnostic.
//
// Because TLS is per-Layer and not per-stack (RFC-001 §3.1), the two legs
// of a connection with independent TLS axes (a tcp_forward entry with
// `tls` but no `upstream_tls`, say) derive different schemes. That is the
// wire reality of each leg, and it is what a Schemes rule is asking about.
func hostScopeScheme(env *envelope.Envelope) string {
	if env.Context.TLS != nil {
		return "https"
	}
	return "http"
}
