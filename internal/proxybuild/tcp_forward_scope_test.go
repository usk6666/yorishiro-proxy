package proxybuild

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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

// TestTCPForwardScopeCheck_NonNumericPortFailsClosed (USK-1161 review
// S-1): net.Dial resolves a service name as the port ("postgresql" →
// 5432), so a target whose port is not a decimal 1..65535 must not be
// checked as port 0 — that would slip past a port-scoped deny while the
// dialer still reaches the denied port. With rules present the gate
// fails closed; a rule-less scope still admits.
func TestTCPForwardScopeCheck_NonNumericPortFailsClosed(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "db.internal", Ports: []int{5432}}})
	for _, target := range []string{
		"db.internal:postgresql",
		"db.internal:https",
		"db.internal:+5432",
		"db.internal:0",
		"db.internal:65536",
		"db.internal:",
		"db.internal",
	} {
		allowed, reason := tcpForwardScopeCheck(scope, target, false)
		if allowed {
			t.Errorf("tcpForwardScopeCheck(%q) admitted under a port-scoped deny, want fail-closed", target)
			continue
		}
		if reason == "" {
			t.Errorf("tcpForwardScopeCheck(%q) denied without a reason", target)
		}
	}
	if ok, reason := tcpForwardScopeCheck(scope, "db.internal:05433", false); !ok {
		t.Errorf("decimal port 05433 (=5433) denied by a port-5432 rule: %s", reason)
	}
	if ok, _ := tcpForwardScopeCheck(connector.NewTargetScope(), "db.internal:postgresql", false); !ok {
		t.Error("rule-less scope blocked a service-name target")
	}
}

// TestAdmitTCPForwardConn_ConnIDSharedWithRegistry (USK-1161 review
// F-1): the conn ID admitTCPForwardConn registers in the live-connection
// registry is the one it puts on the returned ctx (which the handlers
// reuse via tcpForwardConnID), so the registry's revoke log carries the
// same conn_id as the handler's logs and the recorded flow.
func TestAdmitTCPForwardConn_ConnIDSharedWithRegistry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logBuf bytes.Buffer
	live := connector.NewLiveConns(slog.New(slog.NewTextHandler(&logBuf, nil)))
	scope := connector.NewTargetScope()
	depsTpl := newTestDeps(t)
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			d.Scope = scope
			d.LiveConns = live
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	entry := &tcpForwardEntry{port: "1", target: "127.0.0.1:4444", fc: &config.ForwardConfig{Target: "127.0.0.1:4444", Protocol: "raw"}}
	rctx, release, ok := mgr.admitTCPForwardConn(ctx, DefaultListenerName, entry, server)
	if !ok {
		t.Fatal("admitTCPForwardConn rejected under an empty scope")
	}
	defer release()

	connID := connector.ConnIDFromContext(rctx)
	if connID == "" {
		t.Fatal("admitted ctx carries no conn ID")
	}
	if got := tcpForwardConnID(rctx); got != connID {
		t.Errorf("tcpForwardConnID(admitted ctx) = %q, want %q", got, connID)
	}

	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{4444}}})
	if n := live.Reconcile("test"); n != 1 {
		t.Fatalf("Reconcile revoked %d connections, want 1", n)
	}
	if logs := logBuf.String(); !strings.Contains(logs, "conn_id="+connID) {
		t.Errorf("registry revoke log does not carry conn_id=%s:\n%s", connID, logs)
	}
}

// TestStartTCPForwards_NonNumericTargetPortRejected (USK-1161 review
// S-1): a forward whose target port is not a decimal 1..65535 is refused
// at start — under a port-scoped deny and with no scope at all — and
// binds nothing, so the dialer never resolves a service-name port.
func TestStartTCPForwards_NonNumericTargetPortRejected(t *testing.T) {
	scoped := connector.NewTargetScope()
	scoped.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{5432}}})
	for _, tc := range []struct {
		name  string
		scope *connector.TargetScope
	}{
		{"port-scoped deny", scoped},
		{"no scope", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mgr := newScopedTestManager(t, tc.scope)
			if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer mgr.StopAll(context.Background())

			const target = "127.0.0.1:postgresql"
			port := freePortKey(t)
			err := mgr.StartTCPForwards(ctx, TCPForwardParams{Forwards: map[string]*config.ForwardConfig{
				port: {Target: target, Protocol: "raw"},
			}})
			if err == nil {
				t.Fatalf("StartTCPForwards(target %q) = nil, want an error", target)
			}
			if msg := err.Error(); !strings.Contains(msg, target) || !strings.Contains(msg, port) {
				t.Errorf("error %q does not name the target %q and the port %s", msg, target, port)
			}
			if addrs := mgr.TCPForwardAddrs(); len(addrs) != 0 {
				t.Errorf("TCPForwardAddrs = %v after rejected start, want none", addrs)
			}
		})
	}
}
