package pipeline

import (
	"context"
	"net/netip"
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
)

// USK-1376 / USK-1236: gRPC and gRPC-Web requests reach the Pipeline as a
// Send GRPCStartMessage, never as an HTTPMessage, so HTTPScopeStep must
// judge the Start's :authority / Host metadata / wire path exactly as it
// judges an HTTP request: the same name legs (Option B), the same
// transparent DNS binding, the same path rules.

const grpcScopeTarget = "127.0.0.1:8443"

var grpcScopeProtocols = []envelope.Protocol{envelope.ProtocolGRPC, envelope.ProtocolGRPCWeb}

// grpcStartEnv is a Send Start in the shape both gRPC Layers produce on a
// CONNECT MITM connection: the connection's TargetHost and TLS snapshot
// copied from the inner envelope.
func grpcStartEnv(proto envelope.Protocol, envCtx envelope.EnvelopeContext, m *envelope.GRPCStartMessage) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "s-grpc",
		FlowID:    "f-grpc",
		Direction: envelope.Send,
		Protocol:  proto,
		Context:   envCtx,
		Message:   m,
	}
}

func grpcTLSCtx() envelope.EnvelopeContext {
	return envelope.EnvelopeContext{TargetHost: grpcScopeTarget, TLS: &envelope.TLSSnapshot{}}
}

// assertGRPCTargetScopeBlock asserts the target_scope block shape for env:
// native gRPC and gRPC-Web (USK-1220) both get the grpc-status 7
// PERMISSION_DENIED terminator, on the blocked envelope's own protocol.
func assertGRPCTargetScopeBlock(t *testing.T, env *envelope.Envelope, r Result) {
	t.Helper()
	if r.BlockedBy != BlockedByTargetScope {
		t.Fatalf("Action=%v BlockedBy=%q, want a %q block", r.Action, r.BlockedBy, BlockedByTargetScope)
	}
	if r.Action != Respond || r.Response == nil {
		t.Fatalf("%s block Action = %v (Response %v), want Respond with a gRPC End", env.Protocol, r.Action, r.Response)
	}
	end, ok := r.Response.Message.(*envelope.GRPCEndMessage)
	if !ok {
		t.Fatalf("Response.Message = %T, want *GRPCEndMessage", r.Response.Message)
	}
	if end.Status != grpcStatusPermissionDenied || end.Message != "blocked by "+BlockedByTargetScope {
		t.Errorf("End = status %d %q, want %d %q", end.Status, end.Message, grpcStatusPermissionDenied, "blocked by "+BlockedByTargetScope)
	}
	if r.Response.Direction != envelope.Receive || r.Response.Protocol != env.Protocol {
		t.Errorf("Response direction/protocol = %v/%v, want Receive/%v", r.Response.Direction, r.Response.Protocol, env.Protocol)
	}
}

// U1: authority, every Host metadata value, the absolute-form authority
// and the path are judged; Option B keeps an allowed-by-IP target open to
// any non-denied name.
func TestHTTPScopeStep_GRPCStart_Legs(t *testing.T) {
	scope := hostLegScope(
		[]connector.TargetRule{{Hostname: "127.0.0.1"}},
		[]connector.TargetRule{
			{Hostname: "denied.example"},
			{Hostname: "127.0.0.1", PathPrefix: "/admin.AdminService/"},
		},
	)
	echo := func() *envelope.GRPCStartMessage {
		return &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say", Path: "/pkg.Echo/Say", Authority: grpcScopeTarget}
	}
	tests := []struct {
		name      string
		build     func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext)
		wantBlock bool
	}{
		{"allowed authority passes", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			return echo(), grpcTLSCtx()
		}, false},
		{"non-denied vhost passes under an IP allow (Option B)", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			m := echo()
			m.Authority = "vhost.example:8443"
			return m, grpcTLSCtx()
		}, false},
		{"denied :authority blocked", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			m := echo()
			m.Authority = "denied.example:8443"
			return m, grpcTLSCtx()
		}, true},
		{"denied port-less :authority blocked", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			m := echo()
			m.Authority = "denied.example"
			return m, grpcTLSCtx()
		}, true},
		{"denied host metadata blocked", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			m := echo()
			m.Metadata = []envelope.KeyValue{{Name: "host", Value: "denied.example"}}
			return m, grpcTLSCtx()
		}, true},
		{"second (duplicate) Host value denied blocked", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			m := echo()
			m.Metadata = []envelope.KeyValue{{Name: "Host", Value: "vhost.example"}, {Name: "x-trace", Value: "1"}, {Name: "host", Value: "denied.example"}}
			return m, grpcTLSCtx()
		}, true},
		{"absolute-form authority denied blocked", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			c := grpcTLSCtx()
			c.AbsoluteFormAuthority = "denied.example"
			return echo(), c
		}, true},
		{"path_prefix deny on the dial target blocked", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			m := &envelope.GRPCStartMessage{Service: "admin.AdminService", Method: "Delete", Path: "/admin.AdminService/Delete", Authority: grpcScopeTarget}
			return m, grpcTLSCtx()
		}, true},
		{"path_prefix deny fires behind a spoofed authority", func() (*envelope.GRPCStartMessage, envelope.EnvelopeContext) {
			m := &envelope.GRPCStartMessage{Service: "admin.AdminService", Method: "Delete", Path: "/admin.AdminService/Delete", Authority: "vhost.example"}
			return m, grpcTLSCtx()
		}, true},
	}
	step := NewHTTPScopeStep(scope)
	for _, proto := range grpcScopeProtocols {
		for _, tc := range tests {
			t.Run(string(proto)+"/"+tc.name, func(t *testing.T) {
				m, c := tc.build()
				env := grpcStartEnv(proto, c, m)
				r := step.Process(context.Background(), env)
				if !tc.wantBlock {
					if r.Action != Continue {
						t.Fatalf("Action = %v (BlockedBy %q), want Continue", r.Action, r.BlockedBy)
					}
					return
				}
				assertGRPCTargetScopeBlock(t, env, r)
			})
		}
	}
}

// U2: the judged path is the path the Layers write
// (envelope.GRPCStartWirePath), not GRPCStartMessage.Path alone.
func TestHTTPScopeStep_GRPCStart_WirePath(t *testing.T) {
	scope := hostLegScope(nil, []connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin.AdminService/"}})
	tests := []struct {
		name      string
		msg       *envelope.GRPCStartMessage
		wantBlock bool
	}{
		{"service/method override of a parseable path is what goes out",
			&envelope.GRPCStartMessage{Path: "/ok.Svc/M", Service: "admin.AdminService", Method: "Delete"}, true},
		{"overridden away from the denied prefix passes",
			&envelope.GRPCStartMessage{Path: "/admin.AdminService/Delete", Service: "ok.Svc", Method: "M"}, false},
		{"unparseable path judged verbatim",
			&envelope.GRPCStartMessage{Path: "/admin.AdminService/"}, true},
		{"synthetic Start without Path judged on the rebuild",
			&envelope.GRPCStartMessage{Service: "admin.AdminService", Method: "Delete"}, true},
	}
	step := NewHTTPScopeStep(scope)
	for _, proto := range grpcScopeProtocols {
		for _, tc := range tests {
			t.Run(string(proto)+"/"+tc.name, func(t *testing.T) {
				m := tc.msg.CloneMessage().(*envelope.GRPCStartMessage)
				m.Authority = grpcScopeTarget
				env := grpcStartEnv(proto, grpcTLSCtx(), m)
				r := step.Process(context.Background(), env)
				if !tc.wantBlock {
					if r.Action != Continue {
						t.Fatalf("Action = %v (BlockedBy %q), want Continue (wire path %q)", r.Action, r.BlockedBy, envelope.GRPCStartWirePath(m))
					}
					return
				}
				assertGRPCTargetScopeBlock(t, env, r)
			})
		}
	}
}

// U3: the scheme is the client connection's transport, never the
// client-declared :scheme.
func TestHTTPScopeStep_GRPCStart_SchemeFromTransport(t *testing.T) {
	scope := hostLegScope(nil, []connector.TargetRule{{Hostname: "denied.example", Schemes: []string{"https"}}})
	step := NewHTTPScopeStep(scope)
	for _, proto := range grpcScopeProtocols {
		t.Run(string(proto), func(t *testing.T) {
			m := &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say", Scheme: "http", Authority: "denied.example"}
			env := grpcStartEnv(proto, grpcTLSCtx(), m)
			assertGRPCTargetScopeBlock(t, env, step.Process(context.Background(), env))

			plain := grpcStartEnv(proto, envelope.EnvelopeContext{TargetHost: grpcScopeTarget},
				&envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say", Scheme: "https", Authority: "denied.example"})
			if r := step.Process(context.Background(), plain); r.Action != Continue {
				t.Errorf("plaintext connection declaring :scheme https: Action = %v, want Continue", r.Action)
			}
		})
	}
}

// U4: on a transparent connection the gRPC :authority must be allowed and
// bound to the original destination by DNS; a denied name is never
// resolved.
func TestHTTPScopeStep_GRPCStart_Transparent(t *testing.T) {
	const target = "192.0.2.10:443"
	dst := netip.MustParseAddrPort(target)
	r := &recordingNameResolver{answers: map[string][]netip.Addr{
		"allowed.example": {dst.Addr()},
		"unbound.example": {netip.MustParseAddr("198.51.100.1")},
		"denied.example":  {dst.Addr()},
	}}
	ctx := connector.ContextWithTransparentScope(context.Background(), &connector.TransparentScope{
		Dst:           dst,
		Binder:        connector.NewNameBindingCache(r, connector.NameBindingConfig{}),
		AdmittedBySNI: "allowed.example",
	})
	scope := hostLegScope(
		[]connector.TargetRule{{Hostname: "allowed.example"}, {Hostname: "unbound.example"}},
		[]connector.TargetRule{{Hostname: "denied.example"}},
	)
	tlsCtx := envelope.EnvelopeContext{TargetHost: target, TLS: &envelope.TLSSnapshot{SNI: "allowed.example"}}
	tests := []struct {
		name      string
		authority string
		wantBlock bool
	}{
		{"allowed and bound passes", "allowed.example", false},
		{"allowed but unbound blocked", "unbound.example", true},
		{"denied blocked", "denied.example", true},
		{"no :authority under a name allow blocked", "", true},
	}
	step := NewHTTPScopeStep(scope)
	for _, proto := range grpcScopeProtocols {
		for _, tc := range tests {
			t.Run(string(proto)+"/"+tc.name, func(t *testing.T) {
				env := grpcStartEnv(proto, tlsCtx, &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say", Authority: tc.authority})
				res := step.Process(ctx, env)
				if !tc.wantBlock {
					if res.Action != Continue {
						t.Fatalf("Action = %v (BlockedBy %q), want Continue", res.Action, res.BlockedBy)
					}
					return
				}
				assertGRPCTargetScopeBlock(t, env, res)
			})
		}
	}
	for _, n := range r.lookedUp() {
		if n == "denied.example" {
			t.Errorf("denied name was resolved (lookups %q)", r.lookedUp())
		}
	}
}

// U6: only the Send Start is judged; Receive Start, Data and End pass, and
// a typed-nil Start does not panic.
func TestHTTPScopeStep_GRPC_NonStartPasses(t *testing.T) {
	scope := hostLegScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
	step := NewHTTPScopeStep(scope)
	for _, proto := range grpcScopeProtocols {
		cases := []struct {
			name string
			env  *envelope.Envelope
		}{
			{"receive start", &envelope.Envelope{Direction: envelope.Receive, Protocol: proto, Context: grpcTLSCtx(),
				Message: &envelope.GRPCStartMessage{Authority: "denied.example"}}},
			{"send data", &envelope.Envelope{Direction: envelope.Send, Protocol: proto, Context: grpcTLSCtx(),
				Message: &envelope.GRPCDataMessage{Payload: []byte("x")}}},
			{"send end", &envelope.Envelope{Direction: envelope.Send, Protocol: proto, Context: grpcTLSCtx(),
				Message: &envelope.GRPCEndMessage{}}},
			{"typed-nil start", &envelope.Envelope{Direction: envelope.Send, Protocol: proto, Context: grpcTLSCtx(),
				Message: (*envelope.GRPCStartMessage)(nil)}},
		}
		for _, tc := range cases {
			t.Run(string(proto)+"/"+tc.name, func(t *testing.T) {
				if r := step.Process(context.Background(), tc.env); r.Action != Continue {
					t.Errorf("Action = %v (BlockedBy %q), want Continue", r.Action, r.BlockedBy)
				}
			})
		}
	}
}

// U5: a path-scoped allow admits gRPC / gRPC-Web at HostScopeStep (the
// request path is now checked by HTTPScopeStep); raw still fails closed.
// The chain then admits an in-prefix RPC and blocks an out-of-prefix one.
func TestScopeChain_PathScopedAllow_GRPC(t *testing.T) {
	scope := pathScopedAllowScope(connector.TargetRule{Hostname: "x.test", PathPrefix: "/pkg.Allowed/"})
	tlsCtx := envelope.EnvelopeContext{TargetHost: "x.test:443", TLS: &envelope.TLSSnapshot{}}
	host := NewHostScopeStep(scope)
	for _, proto := range grpcScopeProtocols {
		t.Run(string(proto), func(t *testing.T) {
			in := grpcStartEnv(proto, tlsCtx, &envelope.GRPCStartMessage{Service: "pkg.Allowed", Method: "Do", Authority: "x.test"})
			if r := host.Process(context.Background(), in); r.Action != Continue {
				t.Fatalf("HostScopeStep on a path-scoped allow: Action = %v, want Continue", r.Action)
			}
			data := &envelope.Envelope{Direction: envelope.Send, Protocol: proto, Context: tlsCtx, Message: &envelope.GRPCDataMessage{}}
			if r := host.Process(context.Background(), data); r.Action != Continue {
				t.Fatalf("HostScopeStep on a Data envelope under a path-scoped allow: Action = %v, want Continue", r.Action)
			}
			if _, action, _ := scopeChain(scope).Run(context.Background(), in); action != Continue {
				t.Errorf("in-prefix RPC: chain action = %v, want Continue", action)
			}
			out := grpcStartEnv(proto, tlsCtx, &envelope.GRPCStartMessage{Service: "pkg.Other", Method: "Do", Authority: "x.test"})
			assertGRPCTargetScopeBlock(t, out, recheckScope(context.Background(), host, NewHTTPScopeStep(scope), out))
		})
	}
	raw := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolRaw, Context: tlsCtx, Message: &envelope.RawMessage{Bytes: []byte{0}}}
	if r := host.Process(context.Background(), raw); r.Action == Continue {
		t.Error("raw under a path-scoped allow continued; want fail closed")
	}
}

// U10: a target_scope block of a Send native gRPC envelope answers
// grpc-status 7 (unified with the Safety / intercept drop shape); so does
// a gRPC-Web one since USK-1220.
func TestHostScopeStep_GRPCBlockShape(t *testing.T) {
	scope := hostLegScope(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}})
	step := NewHostScopeStep(scope)
	for _, proto := range grpcScopeProtocols {
		for name, msg := range map[string]envelope.Message{
			"start": &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say"},
			"data":  &envelope.GRPCDataMessage{Payload: []byte("x")},
		} {
			t.Run(string(proto)+"/"+name, func(t *testing.T) {
				env := &envelope.Envelope{Direction: envelope.Send, Protocol: proto, Context: grpcTLSCtx(), Message: msg}
				assertGRPCTargetScopeBlock(t, env, step.Process(context.Background(), env))
			})
		}
	}
}

// U7: a Transform rule that rewrites the Host metadata of a Send Start to
// a denied name is re-judged and blocked.
func TestTransformStep_GRPCStart_ScopeRecheck(t *testing.T) {
	scope := hostLegScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
	engine := grpcrules.NewTransformEngine()
	engine.SetRules([]grpcrules.TransformRule{{
		ID: "set-host", Enabled: true, Direction: grpcrules.DirectionSend,
		ServicePattern: regexp.MustCompile(".*"),
		ActionType:     grpcrules.TransformSetMetadata, MetadataName: "host", MetadataValue: "denied.example",
	}})
	step := NewTransformStep(nil, nil, engine, nil).WithScopeRecheck(NewHostScopeStep(scope), NewHTTPScopeStep(scope))
	for _, proto := range grpcScopeProtocols {
		t.Run(string(proto), func(t *testing.T) {
			env := grpcStartEnv(proto, grpcTLSCtx(), &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say", Authority: grpcScopeTarget})
			assertGRPCTargetScopeBlock(t, env, step.Process(context.Background(), env))
		})
	}
}

// U8: an intercept modify_and_forward that rewrites a held gRPC Start's
// :authority to a denied name is blocked on release.
func TestInterceptStep_GRPCStart_ModifyAuthorityRecheck(t *testing.T) {
	scope := hostLegScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
	for _, proto := range grpcScopeProtocols {
		t.Run(string(proto), func(t *testing.T) {
			queue := common.NewHoldQueue()
			step := NewInterceptStep(nil, nil, newTestGRPCInterceptEngine(newCatchAllGRPCRule()), nil, queue, nil, nil).
				WithScopeRecheck(NewHostScopeStep(scope), NewHTTPScopeStep(scope))
			held := grpcStartEnv(proto, grpcTLSCtx(), &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say", Authority: grpcScopeTarget})
			modified := held.Clone()
			modified.Message.(*envelope.GRPCStartMessage).Authority = "denied.example"
			whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified})
			assertGRPCTargetScopeBlock(t, held, step.Process(context.Background(), held))
		})
	}
}
