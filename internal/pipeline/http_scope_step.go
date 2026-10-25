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
// gRPC and gRPC-Web requests are checked the same way (USK-1376,
// USK-1236). They reach the Pipeline as a Send GRPCStartMessage, never as
// an HTTPMessage, so the Start is judged through the same request view:
// its Authority (the :authority, or the first Host of an HTTP/1.x
// gRPC-Web request), every "host" value in its Metadata, the connection's
// absolute-form authority, and the path the Layers actually write
// (envelope.GRPCStartWirePath — the derived Service / Method win over an
// overridden parseable :path). The judgement — legs, Option B, the
// transparent DNS binding, the scheme from the transport — is identical;
// only the extraction differs. A native gRPC block answers grpc-status 7
// PERMISSION_DENIED, a gRPC-Web block is a Drop (targetScopeBlock).
//
// Only Send-direction HTTPMessage and GRPCStartMessage envelopes are
// checked. Receive envelopes, gRPC Data / End and every other message
// always pass through.
type HTTPScopeStep struct {
	scope *connector.TargetScope
}

// NewHTTPScopeStep creates an HTTPScopeStep. If scope is nil, all
// messages pass through.
func NewHTTPScopeStep(scope *connector.TargetScope) *HTTPScopeStep {
	return &HTTPScopeStep{scope: scope}
}

// Process checks Send-direction HTTPMessage and GRPCStartMessage envelopes
// against the TargetScope. A blocked request gets targetScopeBlock's
// Result (a synthetic 403 for HTTP, grpc-status 7 for native gRPC, Drop
// for gRPC-Web); everything else continues.
func (s *HTTPScopeStep) Process(ctx context.Context, env *envelope.Envelope) Result {
	if env.Direction != envelope.Send {
		return Result{}
	}

	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processRequest(ctx, env, scopeRequest{
			authority: msg.Authority,
			path:      msg.Path,
			headers:   msg.Headers,
		})
	case *envelope.GRPCStartMessage:
		if msg == nil {
			return Result{}
		}
		// USK-1376 / USK-1236: the wire path, not msg.Path alone — the
		// Layers rebuild a parseable :path from Service / Method, so an
		// overridden Service / Method is what the upstream receives.
		return s.processRequest(ctx, env, scopeRequest{
			authority: msg.Authority,
			path:      envelope.GRPCStartWirePath(msg),
			headers:   msg.Metadata,
		})
	default:
		return Result{}
	}
}

// scopeRequest is the protocol-neutral, read-only view of a request that
// HTTPScopeStep judges: the client-written authority, the request path
// (without the query) and the header list whose "host" values are name
// legs. Each protocol maps its own Message onto it; headers is the
// Message's own slice, never copied or modified (MITM Principle 1).
type scopeRequest struct {
	authority string
	path      string
	headers   []envelope.KeyValue
}

func (s *HTTPScopeStep) processRequest(ctx context.Context, env *envelope.Envelope, req scopeRequest) Result {
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
	path := req.path

	dialTarget := env.Context.TargetHost
	allowed := s.checkNameLeg(scheme, req.authority, path, dialTarget)
	var bindTo *connector.TransparentScope
	if allowed && dialTarget != "" {
		if ts := connector.TransparentScopeFromContext(ctx); ts != nil {
			var needBinding bool
			allowed, needBinding = s.checkTransparentDial(scheme, dialTarget, path)
			if needBinding {
				bindTo = ts
			}
		} else {
			allowed = s.checkHostPort(scheme, dialTarget, path)
		}
	}
	if allowed {
		allowed = s.checkHostHeaders(scheme, req.headers, path, dialTarget)
	}
	if allowed && env.Context.AbsoluteFormAuthority != "" {
		// USK-1274: an HTTP/1.x absolute-form request-target goes out
		// verbatim, and a server routes on its authority, not on Host
		// (RFC 9112 §3.2.2).
		allowed, _ = s.scope.CheckAbsoluteFormAuthority(scheme, env.Context.AbsoluteFormAuthority, path, dialTarget)
	}
	if allowed && bindTo != nil {
		// The DNS binding runs last, on names every allow / deny check
		// above already admitted: a refused name is never resolved.
		allowed = bindTo.NamesBound(ctx, transparentRequestNames(req, env))
	}
	if !allowed {
		// USK-829: a 403 terminator for HTTP; grpc-status 7 for native
		// gRPC and Drop for gRPC-Web (USK-1376).
		return targetScopeBlock(env)
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

// checkTransparentDial is the dial-target check of a transparent
// connection (USK-1316, decision U3 amended; ts on ctx). When an allow
// rule admits the original destination (with the request path) it is
// the ordinary check, and the names stay deny-only legs. Otherwise the
// destination must not be denied, and needBinding is set: every name the
// request carries — the authority, each Host value, the absolute-form
// authority — must then resolve to it by DNS. The name legs (checked by
// the caller) had to match an allow rule, and the binding stops a client
// from writing an allowed name to reach an arbitrary IP. The caller runs
// the binding only after every name check passed, so a refused name is
// never looked up. Explicit-proxy, CONNECT and tcp_forward connections
// carry no TransparentScope and never get here.
func (s *HTTPScopeStep) checkTransparentDial(scheme, dialTarget, path string) (allowed, needBinding bool) {
	if s.checkHostPort(scheme, dialTarget, path) {
		return true, false
	}
	host, port := splitScopeHostPort(scheme, dialTarget)
	if ok, _ := s.scope.CheckDenyOnly(scheme, host, port, path); !ok {
		return false, false
	}
	return true, true
}

// transparentRequestNames is every name a request carries: the
// authority, each Host value and the absolute-form authority.
func transparentRequestNames(req scopeRequest, env *envelope.Envelope) []string {
	var names []string
	if req.authority != "" {
		names = append(names, req.authority)
	}
	names = append(names, envelope.HostHeaderValues(req.headers)...)
	if env.Context.AbsoluteFormAuthority != "" {
		names = append(names, env.Context.AbsoluteFormAuthority)
	}
	return names
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
