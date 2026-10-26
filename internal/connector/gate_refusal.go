package connector

import (
	"context"
	"net"
	"strconv"
)

// GateRefusalBlockedByRateLimit is the GateRefusal.BlockedBy value of a
// rate-limit refusal. It equals pipeline.BlockedByRateLimit (connector
// does not import pipeline).
const GateRefusalBlockedByRateLimit = "rate_limit"

// GateRefusal describes a connection a connector-level gate (CONNECT,
// plain-HTTP forward, SOCKS5) refused before any Layer or Envelope
// existed (USK-1381). The refusal bytes have already been written to the
// client when the callback runs.
type GateRefusal struct {
	// Via names the gate: "connect", "http1-forward" or "socks5" (the
	// LiveConns labels of the same handlers).
	Via string
	// Target is the dial target host:port the gate checked, verbatim.
	Target string
	// Host is the host the gate keyed its check on (Target's host).
	Host string
	// ClientAddr is the client's remote address.
	ClientAddr string
	// BlockedBy is the refusal attribution. Only
	// GateRefusalBlockedByRateLimit is emitted today; scope refusals on
	// these gates stay log-only.
	BlockedBy string
	// Tags are the audit tags: via, target, reason and the denial's
	// rate_limit_* tags.
	Tags map[string]string
}

// OnGateRefusalFunc is invoked once per connection a connector-level gate
// refused (USK-1381). Nil disables — the refusal is only logged.
type OnGateRefusalFunc func(ctx context.Context, r GateRefusal)

// reportRateLimitRefusal hands a rate-limit denial to fn. It is a no-op
// when fn or d is nil. clientAddr falls back to remote when ctx carries
// none.
func reportRateLimitRefusal(ctx context.Context, fn OnGateRefusalFunc, via, target string, remote net.Addr, d *RateLimitDenial) {
	if fn == nil || d == nil {
		return
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	clientAddr := ClientAddrFromContext(ctx)
	if clientAddr == "" && remote != nil {
		clientAddr = remote.String()
	}
	tags := map[string]string{
		"via":    via,
		"target": target,
		"reason": d.LimitType + " limit " + strconv.FormatFloat(d.EffectiveRPS, 'g', -1, 64) + " rps",
	}
	for k, v := range d.Tags() {
		tags[k] = v
	}
	fn(ctx, GateRefusal{
		Via:        via,
		Target:     target,
		Host:       host,
		ClientAddr: clientAddr,
		BlockedBy:  GateRefusalBlockedByRateLimit,
		Tags:       tags,
	})
}
