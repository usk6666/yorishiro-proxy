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
// Every Host header value is checked as well (USK-1167): the HTTP/1
// serializer writes the Host line from Headers, never from Authority, so
// a Host rewritten by intercept or Transform, or a duplicate Host on the
// wire, would otherwise name a vhost no check saw. HTTP/2 forwards a
// regular "host" header next to :authority, so it is checked there too.
// The authority and the Host values are name legs
// (connector.TargetScope.CheckAuthority / CheckHostHeader): deny rules
// always apply — matched on the name's port or the dial port, and to
// every comma-separated part of the value (USK-1304, USK-1306) — but an
// allow layer that admitted the dial target through an IP-literal rule
// does not require them to be allow-listed — same-IP different-vhost and
// Host-injection testing stay possible while a denied name is refused.
//
// The authority of an HTTP/1.x absolute-form request-target
// (Envelope.Context.AbsoluteFormAuthority) is a name leg too (USK-1274):
// the request-target is forwarded verbatim and a server that receives
// absolute-form routes on its authority and ignores Host (RFC 9112
// §3.2.2), so `GET http://denied.example/` behind an allowed Host — in a
// CONNECT / SOCKS5 MITM tunnel, or on a later request of a plain forward
// keep-alive connection — would otherwise reach a name no check saw.
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

	dialTarget := env.Context.TargetHost
	allowed := s.checkNameLeg(scheme, msg.Authority, path, dialTarget)
	if allowed && dialTarget != "" {
		allowed = s.checkHostPort(scheme, dialTarget, path)
	}
	if allowed {
		allowed = s.checkHostHeaders(scheme, msg.Headers, path, dialTarget)
	}
	if allowed && env.Context.AbsoluteFormAuthority != "" {
		// USK-1274: an HTTP/1.x absolute-form request-target goes out
		// verbatim, and a server routes on its authority, not on Host
		// (RFC 9112 §3.2.2).
		allowed, _ = s.scope.CheckAbsoluteFormAuthority(scheme, env.Context.AbsoluteFormAuthority, path, dialTarget)
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
	host, port := splitScopeHostPort(scheme, hostPort)
	allowed, _ := s.scope.CheckTarget(scheme, host, port, path)
	return allowed
}

// checkNameLeg checks the request authority as a name leg against the
// connection's dial target (TargetScope.CheckAuthority, USK-1167): denies
// always apply — on the authority's port or the dial port (USK-1306), and
// to every comma-separated part (USK-1304) — and an allow layer that
// admitted the dial target through an IP-literal rule does not require
// the authority to be allow-listed. With no dial target it is the full
// check. The whole authority is split exactly as before (lenient port
// parse, default port inference).
func (s *HTTPScopeStep) checkNameLeg(scheme, authority, path, dialTarget string) bool {
	allowed, _ := s.scope.CheckAuthority(scheme, authority, path, dialTarget)
	return allowed
}

// checkHostHeaders checks every Host header value as a name leg
// (TargetScope.CheckHostHeader, USK-1167). The HTTP/1 serializer writes
// the Host line from msg.Headers and never from msg.Authority, so a Host
// rewritten after parsing (intercept, Transform) or a second Host header
// on the wire would otherwise reach a vhost no check saw; HTTP/2 forwards
// a regular "host" header next to :authority. Every value must pass.
// headers is only read.
func (s *HTTPScopeStep) checkHostHeaders(scheme string, headers []envelope.KeyValue, path, dialTarget string) bool {
	for _, v := range envelope.HostHeaderValues(headers) {
		if ok, _ := s.scope.CheckHostHeader(scheme, v, path, dialTarget); !ok {
			return false
		}
	}
	return true
}

// splitScopeHostPort splits hostPort for a scope check: a value without a
// port, or whose port does not parse as a positive number, takes the
// scheme's default port.
func splitScopeHostPort(scheme, hostPort string) (string, int) {
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
	return host, port
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
