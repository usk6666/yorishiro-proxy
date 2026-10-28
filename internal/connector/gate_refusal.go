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

// GateRefusalBlockedByTargetScope is the GateRefusal.BlockedBy value of a
// scope refusal (USK-1403). It equals pipeline.BlockedByTargetScope.
const GateRefusalBlockedByTargetScope = "target_scope"

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
	// BlockedBy is the refusal attribution:
	// GateRefusalBlockedByRateLimit or GateRefusalBlockedByTargetScope.
	BlockedBy string
	// Tags are the audit tags: via, target, reason and, for a rate-limit
	// refusal, the denial's rate_limit_* tags.
	Tags map[string]string
}

// OnGateRefusalFunc is invoked once per connection a connector-level gate
// refused (USK-1381; scope refusals since USK-1403). Nil disables — the
// refusal is only logged.
type OnGateRefusalFunc func(ctx context.Context, r GateRefusal)

// reportRateLimitRefusal hands a rate-limit denial to fn. It is a no-op
// when fn or d is nil. clientAddr falls back to remote when ctx carries
// none.
func reportRateLimitRefusal(ctx context.Context, fn OnGateRefusalFunc, via, target string, remote net.Addr, d *RateLimitDenial) {
	if fn == nil || d == nil {
		return
	}
	r := newGateRefusal(ctx, via, target, remote, GateRefusalBlockedByRateLimit,
		d.LimitType+" limit "+strconv.FormatFloat(d.EffectiveRPS, 'g', -1, 64)+" rps")
	for k, v := range d.Tags() {
		r.Tags[k] = v
	}
	fn(ctx, r)
}

// reportScopeRefusal hands a scope refusal to fn (USK-1403). reason is the
// scope check's reason, or AdmissionRaceReason's for a refusal decided by
// LiveConns.Register's re-check. It is a no-op when fn is nil. clientAddr
// falls back to remote when ctx carries none.
func reportScopeRefusal(ctx context.Context, fn OnGateRefusalFunc, via, target string, remote net.Addr, reason string) {
	if fn == nil {
		return
	}
	fn(ctx, newGateRefusal(ctx, via, target, remote, GateRefusalBlockedByTargetScope, reason))
}

// newGateRefusal builds the GateRefusal common to both attributions:
// Host is target's host (the literal target when it has no port) and the
// tags are via, target and reason.
func newGateRefusal(ctx context.Context, via, target string, remote net.Addr, blockedBy, reason string) GateRefusal {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	clientAddr := ClientAddrFromContext(ctx)
	if clientAddr == "" && remote != nil {
		clientAddr = remote.String()
	}
	return GateRefusal{
		Via:        via,
		Target:     target,
		Host:       host,
		ClientAddr: clientAddr,
		BlockedBy:  blockedBy,
		Tags: map[string]string{
			"via":    via,
			"target": target,
			"reason": reason,
		},
	}
}

// fallbackScopeReason is the reason recorded for a scope refusal whose
// check returned none.
const fallbackScopeReason = "blocked by target scope"

// nonEmptyScopeReason returns reason, or fallbackScopeReason when it is
// empty, so a scope refusal always carries a reason.
func nonEmptyScopeReason(reason string) string {
	if reason == "" {
		return fallbackScopeReason
	}
	return reason
}
