package pipeline

import (
	"context"
	"net/netip"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1317 (owner decision U4): on a transparent TLS MITM connection
// whose original destination no allow rule admits, a ClientHello SNI that
// is allow-listed, not denied and bound to the destination by DNS admits
// the connection's non-HTTP / non-WebSocket envelopes, which would
// otherwise fail closed (no request path is ever checked on them).
func TestHostScopeStep_TransparentSNIAdmission(t *testing.T) {
	const target = "192.0.2.10:993"
	dst := netip.MustParseAddrPort(target)
	resolver := &recordingNameResolver{answers: map[string][]netip.Addr{
		"mail.example.com":    {dst.Addr()},
		"unbound.example.com": {netip.MustParseAddr("198.51.100.1")},
	}}
	binder := connector.NewNameBindingCache(resolver, connector.NameBindingConfig{})
	allowNames := []connector.TargetRule{{Hostname: "mail.example.com"}, {Hostname: "unbound.example.com"}}

	tlsCtx := envelope.EnvelopeContext{TargetHost: target, TLS: &envelope.TLSSnapshot{SNI: "mail.example.com"}}
	rawEnv := func(c envelope.EnvelopeContext) *envelope.Envelope {
		return &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolRaw, Context: c, Message: &envelope.RawMessage{Bytes: []byte("a1 LOGIN")}}
	}
	grpcEnv := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolGRPC, Context: tlsCtx, Message: &envelope.GRPCDataMessage{}}

	transparent := func(sni string) context.Context {
		return connector.ContextWithTransparentScope(context.Background(), &connector.TransparentScope{
			Dst: dst, Binder: binder, AdmittedBySNI: sni,
		})
	}

	tests := []struct {
		name   string
		ctx    context.Context
		scope  *connector.TargetScope
		env    *envelope.Envelope
		wantOK bool
	}{
		{"SNI-admitted raw bytes relayed", transparent("mail.example.com"), hostLegScope(allowNames, nil), rawEnv(tlsCtx), true},
		{"SNI-admitted gRPC relayed", transparent("mail.example.com"), hostLegScope(allowNames, nil), grpcEnv, true},
		{"no SNI admission: raw bytes fail closed", transparent(""), hostLegScope(allowNames, nil), rawEnv(tlsCtx), false},
		{"admitting SNI now denied", transparent("mail.example.com"),
			hostLegScope(allowNames, []connector.TargetRule{{Hostname: "mail.example.com"}}), rawEnv(tlsCtx), false},
		{"admitting SNI no longer allowed", transparent("mail.example.com"),
			hostLegScope([]connector.TargetRule{{Hostname: "other.example.com"}}, nil), rawEnv(tlsCtx), false},
		{"admitting SNI not bound", transparent("unbound.example.com"), hostLegScope(allowNames, nil), rawEnv(tlsCtx), false},
		{"original destination denied", transparent("mail.example.com"),
			hostLegScope(allowNames, []connector.TargetRule{{Hostname: "192.0.2.10"}}), rawEnv(tlsCtx), false},
		{"CONNECT ctx (no TransparentScope): path-scoped allow still fails closed", context.Background(),
			hostLegScope([]connector.TargetRule{{Hostname: "192.0.2.10", PathPrefix: "/api/"}}, nil), rawEnv(tlsCtx), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := NewHostScopeStep(tc.scope).Process(tc.ctx, tc.env)
			if got := res.Action == Continue; got != tc.wantOK {
				t.Errorf("Action = %v (BlockedBy %q), want continue=%v", res.Action, res.BlockedBy, tc.wantOK)
			}
		})
	}
}
