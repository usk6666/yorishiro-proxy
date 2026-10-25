package proxybuild

import (
	"context"
	"errors"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1130: a path-scoped allow at the tcp_forwards gate. Arms whose
// Pipeline path-checks every request (http, http2, websocket, sse, grpc —
// each RPC's Start since USK-1236 — and auto, whose raw fallback
// HostScopeStep blocks) admit the target provisionally; raw never yields
// a checked path and stays strict. Start-time, accept-time and
// live-connection checks share the predicate.
func TestTCPForwardScopeCheck_PathScopedAllow(t *testing.T) {
	const target = "127.0.0.1:4444"
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/api/"}}, nil)

	cases := []struct {
		protocol    string
		wantAllowed bool
	}{
		{"", true},
		{"auto", true},
		{"http", true},
		{"http2", true},
		{"websocket", true},
		{"sse", true},
		{"raw", false},
		{"grpc", true},
	}
	for _, tc := range cases {
		t.Run("protocol="+tc.protocol, func(t *testing.T) {
			allowed, reason := tcpForwardScopeCheck(scope, target, false, tc.protocol)
			if allowed != tc.wantAllowed {
				t.Fatalf("tcpForwardScopeCheck(protocol %q) = %v (%q), want %v", tc.protocol, allowed, reason, tc.wantAllowed)
			}
			if !allowed && reason == "" {
				t.Errorf("denied without a reason")
			}
		})
	}
}

// A path-scoped deny never blocks at the gate (R3): it is enforced per
// request, on every arm.
func TestTCPForwardScopeCheck_PathScopedDenyNotAtGate(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin"}})
	for _, p := range []string{"raw", "http", "grpc", "auto"} {
		if ok, reason := tcpForwardScopeCheck(scope, "127.0.0.1:4444", false, p); !ok {
			t.Errorf("protocol %q denied by a path-scoped deny at the gate: %s", p, reason)
		}
	}
}

// T8 at the Manager seam: under a path-scoped allow, StartTCPForwards
// refuses a raw forward and starts an http forward.
func TestStartTCPForwards_PathScopedAllow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/api/"}}, nil)
	mgr := newScopedTestManager(t, scope)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	err := mgr.StartTCPForwards(ctx, TCPForwardParams{Forwards: map[string]*config.ForwardConfig{
		freePortKey(t): {Target: "127.0.0.1:4444", Protocol: "raw"},
	}})
	if !errors.Is(err, ErrTCPForwardTargetBlocked) {
		t.Errorf("raw forward under a path-scoped allow: err = %v, want ErrTCPForwardTargetBlocked", err)
	}
	if err := mgr.StartTCPForwards(ctx, TCPForwardParams{Forwards: map[string]*config.ForwardConfig{
		freePortKey(t): {Target: "127.0.0.1:4444", Protocol: "http"},
	}}); err != nil {
		t.Errorf("http forward under a path-scoped allow refused: %v", err)
	}
}

// USK-1236: the grpc arm's RPCs are path-checked per request by
// HTTPScopeStep, so a path-scoped allow admits the target provisionally on
// it, as on the other L7 arms; raw stays strict.
func TestTCPForwardScopeCheck_PathScopedAllow_GRPCArmProvisional(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/pkg.Svc/"}}, nil)
	if ok, reason := tcpForwardScopeCheck(scope, "127.0.0.1:4444", false, "grpc"); !ok {
		t.Errorf("grpc arm under a path-scoped allow refused at the gate: %s", reason)
	}
	if ok, _ := tcpForwardScopeCheck(scope, "127.0.0.1:4444", false, "raw"); ok {
		t.Error("raw arm under a path-scoped allow admitted; want strict")
	}
}
