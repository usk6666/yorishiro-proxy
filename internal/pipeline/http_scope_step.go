package pipeline

import (
	"context"
	"net"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// HTTPScopeStep is a Message-typed Pipeline Step that validates HTTP
// request targets against the TargetScope policy at the request level
// (scheme + authority + path). This complements HostScopeStep, which
// operates at the connection level using TargetHost.
//
// The scheme is the transport confidentiality of the client's connection,
// derived from Envelope.Context.TLS exactly as HostScopeStep derives it —
// not HTTPMessage.Scheme (USK-1086, see transportScopeScheme).
//
// The request is checked twice when Envelope.Context.TargetHost is set:
// against the client-written authority (Host / :authority) and against the
// connection's actual dial target, both with the request path (USK-1130).
// The authority is client-controlled and the upstream leg is bound to the
// target the gate admitted, so checking the authority alone let a request
// carry a path to a host whose path rules it never matched — a path-scoped
// deny on the dial target was bypassed by naming another host, and a host
// admitted provisionally for a path-scoped allow could be reached on any
// path. Both checks must pass. For rules without path_prefix the
// dial-target check is the one HostScopeStep already made.
//
// Only Send-direction HTTPMessage envelopes are checked. Receive and
// non-HTTP messages always pass through.
type HTTPScopeStep struct {
	scope *connector.TargetScope
}

// NewHTTPScopeStep creates an HTTPScopeStep. If scope is nil, all
// messages pass through.
func NewHTTPScopeStep(scope *connector.TargetScope) *HTTPScopeStep {
	return &HTTPScopeStep{scope: scope}
}

// Process checks Send-direction HTTPMessage envelopes against the
// TargetScope. Returns Drop if the target is blocked, Continue otherwise.
func (s *HTTPScopeStep) Process(_ context.Context, env *envelope.Envelope) Result {
	if env.Direction != envelope.Send {
		return Result{}
	}

	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(env, msg)
	default:
		return Result{}
	}
}

func (s *HTTPScopeStep) processHTTP(env *envelope.Envelope, msg *envelope.HTTPMessage) Result {
	if s.scope == nil || !s.scope.HasRules() {
		return Result{}
	}

	// The scheme is the client connection's transport, never msg.Scheme:
	// the declared scheme is client-controlled and a blank or mismatched
	// one silently stops Schemes-bearing rules from matching and breaks
	// default-port inference (USK-1086, see transportScopeScheme).
	// msg.Scheme itself is left untouched — it is recorded and forwarded
	// as the wire declared it.
	scheme := transportScopeScheme(env)
	path := msg.Path

	allowed := s.checkHostPort(scheme, msg.Authority, path)
	if allowed && env.Context.TargetHost != "" {
		allowed = s.checkHostPort(scheme, env.Context.TargetHost, path)
	}
	if !allowed {
		// USK-829: emit a 403 terminator on the wire. HTTPScopeStep is
		// HTTPMessage-typed by construction so the synthetic Respond
		// envelope is always appropriate here.
		return Result{
			Action:    Respond,
			Response:  buildPolicyDropResponse(env, BlockedByTargetScope, nil),
			BlockedBy: BlockedByTargetScope,
		}
	}
	return Result{}
}

// checkHostPort checks scheme, the host and port of hostPort (a port-less
// value takes the scheme's default port) and path against the scope.
func (s *HTTPScopeStep) checkHostPort(scheme, hostPort, path string) bool {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port (e.g., "example.com").
		host = hostPort
		portStr = ""
	}

	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}
	if port == 0 {
		port = defaultPortForScheme(scheme)
	}

	allowed, _ := s.scope.CheckTarget(scheme, host, port, path)
	return allowed
}

// defaultPortForScheme returns the well-known default port for HTTP schemes.
func defaultPortForScheme(scheme string) int {
	switch scheme {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}
