package proxybuild

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TCP forward TargetScope gate (USK-1161).
//
// CONNECT, SOCKS5 and the plain-HTTP forward gate check TargetScope when a
// client names its target. A tcp_forwards entry has a fixed target, so it
// is checked twice:
//
//   - at listener start (startTCPForwardListener) — advisory: an agent
//     cannot start a forward whose target the scope denies right now, and
//     proxy_start reports why;
//   - at every accept (admitTCPForwardConn) — authoritative: the scope can
//     change at runtime (policy reload, the agent's security tool), so each
//     new connection is checked before client TLS termination and before
//     the upstream dial. No byte, SYN, ClientHello or h2 preface reaches a
//     denied target.
//
// An admitted connection is registered in the live-connection registry
// (USK-1160) with the same predicate, so a policy change that no longer
// admits the target closes it. The forward listener itself stays bound.
//
// The scheme is the upstream (dial) leg's: "https" iff upstream_tls,
// whatever the client-facing leg is (user decision U1). The Policy Layer
// protects egress; deriving it from the client leg would let a tls=true
// forward carry plaintext egress past an http-only deny. HostScopeStep
// keeps checking each envelope with the client leg's scheme (RFC-001
// §3.5.1), so a deny fires if either leg matches it.

// tcpForwardScopeVia is the LiveConn.Via label of tcp_forwards connections.
const tcpForwardScopeVia = "tcp-forward"

// tcpForwardDenyDrainTimeout bounds how long a denied plaintext HTTP
// connection is drained after the canned 403, so the client's unread
// request bytes do not turn the close into a RST that discards the 403.
const tcpForwardDenyDrainTimeout = 2 * time.Second

// tcpForwardDenyDrainLimit caps the bytes drained from a denied client.
const tcpForwardDenyDrainLimit = 64 << 10

// tcpForwardDenyResponse is the canned answer to a denied plaintext
// http / websocket / sse forward connection. It mirrors the plain-HTTP
// forward gate's 403 (connector.writeForwardErrorResponse).
var tcpForwardDenyResponse = []byte("HTTP/1.1 403 Forbidden\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: 40\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"yorishiro-proxy: target blocked by scope")

// tcpForwardScheme returns the scheme of a forward's upstream (dial) leg.
func tcpForwardScheme(upstreamTLS bool) string {
	if upstreamTLS {
		return "https"
	}
	return "http"
}

// tcpForwardScopeCheck is the TCP forward gate's scope check: the dial
// leg's scheme, the literal target host (no DNS resolution; TargetScope
// compares it in canonical form) and port, no path. It is the start-time
// check, the accept-time check and the live-connection predicate, so a
// connection survives a policy change iff an identical new one would be
// admitted. A nil or rule-less scope allows everything. With rules, a
// target that tcpForwardTargetHostPort rejects fails closed: net.Dial
// resolves a service-name port ("postgresql" → 5432), so checking it as
// port 0 would slip past a port-scoped deny (USK-1161 review S-1).
//
// protocol is the entry's declared arm ("" = auto). A path-scoped allow
// admits the target provisionally on the arms whose requests the Pipeline
// path-checks — http, http2, websocket, sse, grpc (each RPC's Start is
// judged by HTTPScopeStep, USK-1236) and auto (an auto raw fallback is
// then blocked per envelope by HostScopeStep) — and not on raw, which
// never yields a checked path (USK-1130).
func tcpForwardScopeCheck(scope *connector.TargetScope, target string, upstreamTLS bool, protocol string) (allowed bool, reason string) {
	if scope == nil || !scope.HasRules() {
		return true, ""
	}
	host, port, err := tcpForwardTargetHostPort(target)
	if err != nil {
		return false, err.Error()
	}
	scheme := tcpForwardScheme(upstreamTLS)
	if tcpForwardOpaqueProtocol(protocol) {
		return scope.CheckOpaqueTarget(scheme, host, port)
	}
	allowed, _, reason = scope.CheckHost(scheme, host, port)
	return allowed, reason
}

// tcpForwardOpaqueProtocol reports whether a forward arm never yields a
// request path that HTTPScopeStep checks: raw is a byte relay. The grpc
// arm is not opaque — HTTPScopeStep judges every RPC's :authority and
// path (USK-1236).
func tcpForwardOpaqueProtocol(protocol string) bool {
	return protocol == "raw"
}

// tcpForwardTargetHostPort splits a forward target into host and a port
// that must be a decimal integer in 1..65535 (connector.SplitTargetHostPort).
// Service names ("https", "postgresql"), signs and out-of-range values are
// rejected, so the port the scope checks is the port the dialer connects to.
func tcpForwardTargetHostPort(target string) (string, int, error) {
	return connector.SplitTargetHostPort(target)
}

// tcpForwardProtocol returns the forward's declared protocol ("" = auto).
func tcpForwardProtocol(fc *config.ForwardConfig) string {
	if fc == nil {
		return ""
	}
	return fc.Protocol
}

// tcpForwardUpstreamTLS reports the forward's upstream_tls axis.
func tcpForwardUpstreamTLS(fc *config.ForwardConfig) bool {
	return fc != nil && fc.UpstreamTLS
}

// admitTCPForwardConn runs the accept-time gate for one accepted forward
// connection. On admission it returns a context derived from ctx that the
// live-connection registry cancels when a policy change no longer admits
// the target, and a release function the caller must defer. On rejection
// it has answered and closed conn, and returns ok=false.
func (m *Manager) admitTCPForwardConn(ctx context.Context, parentListenerName string, entry *tcpForwardEntry, conn net.Conn) (context.Context, func(), bool) {
	stack := m.Stack(parentListenerName)
	if stack == nil {
		// The handlers drop the connection themselves when the parent
		// listener is gone.
		return ctx, func() {}, true
	}
	upstreamTLS := tcpForwardUpstreamTLS(entry.fc)
	scope := stack.Scope
	logger := m.logger.With(
		"name", parentListenerName,
		"port", entry.port,
		"target", entry.target,
		"remote_addr", conn.RemoteAddr().String(),
		"via", tcpForwardScopeVia,
	)

	if allowed, reason := tcpForwardScopeCheck(scope, entry.target, upstreamTLS, tcpForwardProtocol(entry.fc)); !allowed {
		logger.Info("tcp forward target blocked by scope", "reason", reason)
		rejectTCPForwardConn(entry, conn, tcpForwardDenyResponse, logger)
		return ctx, func() {}, false
	}

	// Mint the conn ID here and carry it on ctx so the live-connection
	// registry's close / revoke logs, the handlers' logs, recorded flows
	// and a rate-limit refusal's Stream share one conn_id
	// (tcpForwardConnID reuses it).
	connID := connector.GenerateConnID()
	ctx = connector.ContextWithConnID(ctx, connID)

	if tcpForwardRateLimited(ctx, stack, entry, conn, logger) {
		return ctx, func() {}, false
	}
	rctx, release, err := stack.LiveConns.Register(ctx, connector.LiveConn{
		ConnID:   connID,
		Listener: parentListenerName,
		Via:      tcpForwardScopeVia,
		Target:   entry.target,
		Admit: func() (bool, string) {
			return tcpForwardScopeCheck(scope, entry.target, upstreamTLS, tcpForwardProtocol(entry.fc))
		},
		// USK-1130 review S-1: an auto arm that falls back to Raw is
		// re-checked as the raw arm would be before any byte is relayed.
		AdmitOpaque: func() (bool, string) {
			return tcpForwardScopeCheck(scope, entry.target, upstreamTLS, "raw")
		},
	})
	if err != nil {
		logger.Info("tcp forward target blocked by scope (policy changed during admission)", "error", err)
		release()
		rejectTCPForwardConn(entry, conn, tcpForwardDenyResponse, logger)
		return ctx, func() {}, false
	}
	return rctx, release, true
}

// tcpForwardConnID returns the conn ID admitTCPForwardConn put on ctx,
// or a fresh one when there is none (the parent listener was gone at
// admission, or a caller outside the accept loop).
func tcpForwardConnID(ctx context.Context) string {
	if id := connector.ConnIDFromContext(ctx); id != "" {
		return id
	}
	return connector.GenerateConnID()
}

// rejectTCPForwardConn answers a refused forward connection and closes
// it. A plaintext http / websocket / sse forward gets resp — the scope
// gate's canned 403 or the rate-limit gate's 429 — written without reading
// the request; every other arm — raw, auto, http2, grpc and every tls=true
// entry, whose client TLS is not terminated — is closed with no byte
// written (a FIN, not a RST).
func rejectTCPForwardConn(entry *tcpForwardEntry, conn net.Conn, resp []byte, logger *slog.Logger) {
	defer conn.Close()
	if entry.fc == nil || entry.fc.TLS {
		return
	}
	switch entry.fc.Protocol {
	case "http", "websocket", "sse":
	default:
		return
	}
	_ = conn.SetDeadline(time.Now().Add(tcpForwardDenyDrainTimeout))
	if _, err := conn.Write(resp); err != nil {
		logger.Debug("tcp forward refusal write failed", "error", err)
		return
	}
	// Half-close and drain what the client already sent, so the close is
	// a FIN rather than a RST that would discard the response at the
	// client.
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_, _ = io.CopyN(io.Discard, conn, tcpForwardDenyDrainLimit)
}
