package proxybuild

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// newScopedTestManager is newTestManager with scope wired into every
// Stack it builds.
func newScopedTestManager(t *testing.T, scope *connector.TargetScope) *Manager {
	t.Helper()
	depsTpl := newTestDeps(t)
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			d.Scope = scope
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

// TestTCPForwardScopeCheck_SchemeIsDialLeg pins user decision U1 of
// USK-1161: the gate checks the scheme of the upstream (dial) leg —
// "https" iff upstream_tls — whatever the client-facing leg is.
func TestTCPForwardScopeCheck_SchemeIsDialLeg(t *testing.T) {
	const target = "127.0.0.1:4444"
	cases := []struct {
		name        string
		denyScheme  string
		upstreamTLS bool
		wantAllowed bool
	}{
		{"deny http, plaintext dial", "http", false, false},
		{"deny http, tls dial", "http", true, true},
		{"deny https, plaintext dial", "https", false, true},
		{"deny https, tls dial", "https", true, false},
		{"deny all schemes, plaintext dial", "", false, false},
		{"deny all schemes, tls dial", "", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			rule := connector.TargetRule{Hostname: "127.0.0.1", Ports: []int{4444}}
			if tc.denyScheme != "" {
				rule.Schemes = []string{tc.denyScheme}
			}
			scope.SetPolicyRules(nil, []connector.TargetRule{rule})
			allowed, reason := tcpForwardScopeCheck(scope, target, tc.upstreamTLS)
			if allowed != tc.wantAllowed {
				t.Fatalf("tcpForwardScopeCheck(upstreamTLS=%v) = %v (%q), want %v", tc.upstreamTLS, allowed, reason, tc.wantAllowed)
			}
			if !allowed && reason == "" {
				t.Errorf("denied without a reason")
			}
		})
	}
}

// TestTCPForwardScopeCheck_OtherPortAndNilScope: a deny on another port,
// a nil scope and a rule-less scope all admit.
func TestTCPForwardScopeCheck_OtherPortAndNilScope(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{1}}})
	if ok, reason := tcpForwardScopeCheck(scope, "127.0.0.1:4444", false); !ok {
		t.Errorf("deny on port 1 blocked port 4444: %s", reason)
	}
	if ok, _ := tcpForwardScopeCheck(nil, "127.0.0.1:4444", false); !ok {
		t.Error("nil scope blocked")
	}
	if ok, _ := tcpForwardScopeCheck(connector.NewTargetScope(), "127.0.0.1:4444", false); !ok {
		t.Error("rule-less scope blocked")
	}
}

// TestTCPForwardScopeCheck_HostCanonicalized: the literal target host is
// matched in TargetScope's canonical form (case, IPv6 brackets), with no
// DNS resolution.
func TestTCPForwardScopeCheck_HostCanonicalized(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "denied.example"}, {Hostname: "::1"}})
	for _, target := range []string{"DENIED.example:80", "[::1]:8080"} {
		if ok, _ := tcpForwardScopeCheck(scope, target, false); ok {
			t.Errorf("target %q admitted, want denied", target)
		}
	}
}

// TestStartTCPForwards_DeniedTargetRejected is test-plan 1 at the Manager
// seam: StartTCPForwards refuses a forward whose target the scope denies,
// with ErrTCPForwardTargetBlocked naming the port, and binds nothing.
func TestStartTCPForwards_DeniedTargetRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{4444}}})
	mgr := newScopedTestManager(t, scope)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	// A fixed free port, so the test can prove nothing was bound on it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	_ = l.Close()

	startErr := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			port: {Target: "127.0.0.1:4444", Protocol: "raw"},
		},
	})
	if !errors.Is(startErr, ErrTCPForwardTargetBlocked) {
		t.Fatalf("StartTCPForwards error = %v, want ErrTCPForwardTargetBlocked", startErr)
	}
	if msg := startErr.Error(); !strings.Contains(msg, port) || !strings.Contains(msg, "scope") {
		t.Errorf("error %q does not name the port %s and the scope", msg, port)
	}
	if addrs := mgr.TCPForwardAddrs(); len(addrs) != 0 {
		t.Errorf("TCPForwardAddrs = %v after rejected start, want none", addrs)
	}
	if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port)); err == nil {
		_ = c.Close()
		t.Errorf("forward port %s is bound after a rejected start", port)
	}
}

// TestStartTCPForwards_SchemeSpecificDenyFollowsDialLeg: with a deny on
// schemes ["https"], a plaintext-dial forward starts and an
// upstream_tls forward is rejected (U1).
func TestStartTCPForwards_SchemeSpecificDenyFollowsDialLeg(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{4444}, Schemes: []string{"https"}}})
	mgr := newScopedTestManager(t, scope)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	if err := mgr.StartTCPForwards(ctx, TCPForwardParams{Forwards: map[string]*config.ForwardConfig{
		freePortKey(t): {Target: "127.0.0.1:4444", Protocol: "raw"},
	}}); err != nil {
		t.Fatalf("plaintext-dial forward rejected under an https-only deny: %v", err)
	}
	err := mgr.StartTCPForwards(ctx, TCPForwardParams{Forwards: map[string]*config.ForwardConfig{
		freePortKey(t): {Target: "127.0.0.1:4444", Protocol: "raw", UpstreamTLS: true},
	}})
	if !errors.Is(err, ErrTCPForwardTargetBlocked) {
		t.Fatalf("upstream_tls forward under an https deny: err = %v, want ErrTCPForwardTargetBlocked", err)
	}
}

func freePortKey(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}
