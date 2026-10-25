package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1130: HostScopeStep and HTTPScopeStep under a path-scoped allow
// ({hostname: X, path_prefix: "/api/"}). The connection-level step cannot
// see a path; it lets HTTP / WebSocket / gRPC / gRPC-Web envelopes through
// to HTTPScopeStep, which is authoritative for the path (gRPC since
// USK-1236), and blocks raw, on which no request path is ever checked
// (fail closed).

func pathScopedAllowScope(rules ...connector.TargetRule) *connector.TargetScope {
	s := connector.NewTargetScope()
	s.SetPolicyRules(rules, nil)
	return s
}

// scopeChain is the production order of the two scope Steps
// (proxybuild/builder.go: HostScope → HTTPScope → ...).
func scopeChain(scope *connector.TargetScope) *Pipeline {
	return New(NewHostScopeStep(scope), NewHTTPScopeStep(scope))
}

// T7: HostScopeStep with a path-pending admission, per env.Protocol.
func TestHostScopeStep_PathPending_ByProtocol(t *testing.T) {
	scope := pathScopedAllowScope(connector.TargetRule{Hostname: "x.test", PathPrefix: "/api/"})
	tlsCtx := envelope.EnvelopeContext{TargetHost: "x.test:443", TLS: &envelope.TLSSnapshot{}}

	tests := []struct {
		name      string
		env       *envelope.Envelope
		wantBlock bool
	}{
		{"http continues to HTTPScopeStep", &envelope.Envelope{
			Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Context: tlsCtx,
			Message: &envelope.HTTPMessage{Method: "GET", Authority: "x.test", Path: "/api/x"},
		}, false},
		{"ws continues (frames ride the path-checked upgrade)", &envelope.Envelope{
			Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket, Context: tlsCtx,
			Message: &envelope.WSMessage{Payload: []byte("hi")},
		}, false},
		{"raw is blocked (no path is ever seen)", &envelope.Envelope{
			Direction: envelope.Send, Protocol: envelope.ProtocolRaw, Context: tlsCtx,
			Message: &envelope.RawMessage{Bytes: []byte{0x00, 0x01}},
		}, true},
		{"grpc continues (HTTPScopeStep path-checks the RPC Start, USK-1236)", &envelope.Envelope{
			Direction: envelope.Send, Protocol: envelope.ProtocolGRPC, Context: tlsCtx,
			Message: &envelope.GRPCStartMessage{Service: "pkg.Svc", Method: "Do"},
		}, false},
		{"grpc-web continues", &envelope.Envelope{
			Direction: envelope.Send, Protocol: envelope.ProtocolGRPCWeb, Context: tlsCtx,
			Message: &envelope.GRPCStartMessage{Service: "pkg.Svc", Method: "Do"},
		}, false},
	}
	step := NewHostScopeStep(scope)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := step.Process(context.Background(), tc.env)
			blocked := r.Action != Continue
			if blocked != tc.wantBlock {
				t.Fatalf("Process action = %v (blocked_by %q), want blocked=%v", r.Action, r.BlockedBy, tc.wantBlock)
			}
			if blocked && r.BlockedBy != BlockedByTargetScope {
				t.Errorf("BlockedBy = %q, want %q", r.BlockedBy, BlockedByTargetScope)
			}
		})
	}
}

// A host-only allow is not path-pending: raw still passes (control for the
// raw row above).
func TestHostScopeStep_HostOnlyAllow_RawContinues(t *testing.T) {
	step := NewHostScopeStep(pathScopedAllowScope(connector.TargetRule{Hostname: "x.test"}))
	env := &envelope.Envelope{
		Direction: envelope.Send, Protocol: envelope.ProtocolRaw,
		Context: envelope.EnvelopeContext{TargetHost: "x.test:443"},
		Message: &envelope.RawMessage{Bytes: []byte{0x00}},
	}
	if r := step.Process(context.Background(), env); r.Action != Continue {
		t.Errorf("raw under host-only allow: action %v, want Continue", r.Action)
	}
}

// T7: the scope chain admits an in-prefix request and 403s an out-of-prefix
// one, with the request parsed by the real HTTP/1.x Layer.
func TestScopeChain_PathScopedAllow_HTTP(t *testing.T) {
	scope := pathScopedAllowScope(connector.TargetRule{Hostname: "x.test", PathPrefix: "/api/"})
	tests := []struct {
		name      string
		raw       string
		wantBlock bool
	}{
		{"in-prefix request reaches upstream", "GET /api/x HTTP/1.1\r\nHost: x.test\r\n\r\n", false},
		{"percent-encoded in-prefix request (USK-1139)", "GET /%61pi/x HTTP/1.1\r\nHost: x.test\r\n\r\n", false},
		{"out-of-prefix request is answered 403", "GET /other HTTP/1.1\r\nHost: x.test\r\n\r\n", true},
		{"prefix without its trailing slash is out of prefix", "GET /api HTTP/1.1\r\nHost: x.test\r\n\r\n", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := parseH1Request(t, tc.raw)
			env.Context.TargetHost = "x.test:80"
			_, action, resp := scopeChain(scope).Run(context.Background(), env)
			if tc.wantBlock {
				if action != Respond || resp == nil {
					t.Fatalf("action = %v, want Respond (403)", action)
				}
				if m, ok := resp.Message.(*envelope.HTTPMessage); !ok || m.Status != 403 {
					t.Errorf("response = %#v, want a 403 HTTPMessage", resp.Message)
				}
				return
			}
			if action != Continue {
				t.Fatalf("action = %v, want Continue", action)
			}
		})
	}
}

// T5 / U2: HTTPScopeStep also checks the actual dial target (TargetHost)
// with the request path, so the client-written Host / :authority cannot
// steer the verdict away from the host the request really reaches.
func TestScopeChain_TargetHostCheckedWithPath(t *testing.T) {
	tests := []struct {
		name       string
		allows     []connector.TargetRule
		denies     []connector.TargetRule
		targetHost string
		raw        string
		wantBlock  bool
	}{
		{
			// Live bypass on main: neither step matched the deny.
			name:       "path deny on the dial target fires despite a spoofed Host",
			denies:     []connector.TargetRule{{Hostname: "x.test", PathPrefix: "/admin"}},
			targetHost: "x.test:443",
			raw:        "GET /admin HTTP/1.1\r\nHost: y.test\r\n\r\n",
			wantBlock:  true,
		},
		{
			name:       "path deny on the dial target leaves other paths alone",
			denies:     []connector.TargetRule{{Hostname: "x.test", PathPrefix: "/admin"}},
			targetHost: "x.test:443",
			raw:        "GET /public HTTP/1.1\r\nHost: y.test\r\n\r\n",
			wantBlock:  false,
		},
		{
			// CONNECT x.test is admitted provisionally; a Host naming a
			// host-only-allowed z.test must not carry /admin to x.test.
			name: "provisional dial target plus host-only-allowed Host is still path-checked",
			allows: []connector.TargetRule{
				{Hostname: "x.test", PathPrefix: "/api/"},
				{Hostname: "z.test"},
			},
			targetHost: "x.test:443",
			raw:        "GET /admin HTTP/1.1\r\nHost: z.test\r\n\r\n",
			wantBlock:  true,
		},
		{
			name: "provisional dial target with an in-prefix path passes",
			allows: []connector.TargetRule{
				{Hostname: "x.test", PathPrefix: "/api/"},
			},
			targetHost: "x.test:443",
			raw:        "GET /api/ok HTTP/1.1\r\nHost: x.test\r\n\r\n",
			wantBlock:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(tc.allows, tc.denies)
			env := parseH1Request(t, tc.raw)
			env.Context.TargetHost = tc.targetHost
			env.Context.TLS = &envelope.TLSSnapshot{}
			_, action, _ := scopeChain(scope).Run(context.Background(), env)
			if blocked := action != Continue; blocked != tc.wantBlock {
				t.Errorf("action = %v, want blocked=%v", action, tc.wantBlock)
			}
		})
	}
}
