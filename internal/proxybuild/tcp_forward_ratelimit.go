package proxybuild

import (
	"context"
	"log/slog"
	"net"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// TCP forward rate-limit gate (USK-1380).
//
// The Policy / Agent rate limit (connector.RateLimiter, the instance the
// MCP security tool mutates) is checked once per accepted tcp_forwards
// connection — not per request inside a kept-alive connection, like the
// CONNECT / forward / SOCKS5 / transparent gates. It runs in
// admitTCPForwardConn after the scope verdict (a scope refusal spends no
// token) and before the live-connection registration, client TLS
// termination and the upstream dial, so a refused connection never
// reaches the target. The bucket key is the forward target's literal host
// as written in the config; the limiter folds it (hostcanon.Fold), so the
// per-host bucket is shared with the other gates. No DNS lookup.
//
// Over the limit, a plaintext http / websocket / sse forward answers the
// CONNECT gate's 429 (connector.RateLimitRefusalResponse); every other arm
// and every tls=true entry is closed with no byte written. Each refusal is
// logged at Info and recorded as one State="error",
// BlockedBy="rate_limit" Stream with the denial's rate_limit_* tags.

// tcpForwardRateLimited runs the rate-limit gate for one admitted forward
// connection. It returns true when the connection was refused — conn is
// then answered, closed and recorded. A nil Stack.RateLimiter, or one with
// no limits, admits everything and spends nothing.
func tcpForwardRateLimited(ctx context.Context, stack *Stack, entry *tcpForwardEntry, conn net.Conn, logger *slog.Logger) bool {
	if stack.RateLimiter == nil {
		return false
	}
	host, _, err := tcpForwardTargetHostPort(entry.target)
	if err != nil {
		// startTCPForwardListener rejects such targets; key on the
		// literal target rather than skip the limit.
		host = entry.target
	}
	denial := stack.RateLimiter.Check(host)
	if denial == nil {
		return false
	}
	logger.Info("tcp forward target blocked by rate limit",
		"conn_id", connector.ConnIDFromContext(ctx),
		"limit_type", denial.LimitType,
		"effective_rps", denial.EffectiveRPS)
	clientAddr := conn.RemoteAddr().String()
	rejectTCPForwardConn(entry, conn, connector.RateLimitRefusalResponse(), logger)

	tags := map[string]string{
		"via":              tcpForwardScopeVia,
		"target":           entry.target,
		"forward_port":     entry.port,
		"forward_protocol": tcpForwardDeclaredProtocol(entry.fc),
		"reason":           denial.LimitType + " limit " + strconv.FormatFloat(denial.EffectiveRPS, 'g', -1, 64) + " rps",
	}
	for k, v := range denial.Tags() {
		tags[k] = v
	}
	stack.blockedRecorder.record(ctx, blockedConn{
		Protocol:      tcpForwardRefusalProtocol(entry.fc),
		Scheme:        tcpForwardClientScheme(entry.fc),
		ClientAddr:    clientAddr,
		ScopeHost:     host,
		BlockedBy:     pipeline.BlockedByRateLimit,
		FailureReason: pipeline.BlockedByRateLimit,
		Tags:          tags,
	})
	return true
}

// tcpForwardDeclaredProtocol is the forward's declared arm, "auto" when
// unset.
func tcpForwardDeclaredProtocol(fc *config.ForwardConfig) string {
	if p := tcpForwardProtocol(fc); p != "" {
		return p
	}
	return "auto"
}

// tcpForwardRefusalProtocol is the Stream protocol of a connection refused
// before any byte was read: the protocol family of the declared arm — grpc
// for grpc, http for the HTTP arms (http, http2, websocket and sse all
// start as an HTTP exchange), raw for raw and auto.
func tcpForwardRefusalProtocol(fc *config.ForwardConfig) string {
	switch tcpForwardProtocol(fc) {
	case "grpc":
		return string(envelope.ProtocolGRPC)
	case "http", "http2", "websocket", "sse":
		return string(envelope.ProtocolHTTP)
	default:
		return string(envelope.ProtocolRaw)
	}
}

// tcpForwardClientScheme is the scheme of the forward's client-facing
// leg — the one recorded on its Streams: "https" iff tls.
func tcpForwardClientScheme(fc *config.ForwardConfig) string {
	if fc != nil && fc.TLS {
		return "https"
	}
	return "http"
}
