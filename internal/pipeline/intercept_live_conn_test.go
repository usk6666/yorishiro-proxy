package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1192: a host-denying policy change must not silently drop an
// intercept-held request along with its connection. The live connection is
// revoked but kept until the hold resolves; the release re-check then
// answers 403 target_scope, and only SettleLiveConn (after the Result was
// dispatched) cuts the connection.

// registerLiveConn registers a plain-forward live connection to
// recheckTarget, admitted by the same predicate the forward gate stores.
func registerLiveConn(t *testing.T, scope *connector.TargetScope, scheme string) (context.Context, *connector.LiveConns) {
	t.Helper()
	reg := connector.NewLiveConns(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, rel, err := reg.Register(context.Background(), connector.LiveConn{
		ConnID: "c1", Via: "http1-forward", Target: recheckTarget,
		Admit: func() (bool, string) { return scope.CheckTarget(scheme, "127.0.0.1", 8080, "") },
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(rel)
	return ctx, reg
}

func TestInterceptStep_LiveConn_HoldSurvivesDenyReconcile(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)
	ctx, reg := registerLiveConn(t, scope, "http")

	whileHeld(t, queue, func() {
		denyLoopback(scope)
		reg.Reconcile("test")
		if n := queue.Len(); n != 1 {
			t.Errorf("queue.Len after deny Reconcile = %d, want 1 (held entry vanished)", n)
		}
		if ctx.Err() != nil {
			t.Errorf("held connection ctx cancelled at Reconcile: %v", context.Cause(ctx))
		}
	}, &common.HoldAction{Type: common.ActionRelease})

	assertTargetScope403(t, step.Process(ctx, recheckHTTPRequest("/")))
	if ctx.Err() != nil {
		t.Fatalf("ctx cancelled before SettleLiveConn: %v", context.Cause(ctx))
	}
	connector.SettleLiveConn(ctx)
	if !errors.Is(context.Cause(ctx), connector.ErrTargetScopeRevoked) {
		t.Errorf("cause after SettleLiveConn = %v, want ErrTargetScopeRevoked", context.Cause(ctx))
	}
}

func TestInterceptStep_LiveConn_TimeoutAutoReleaseAfterDeny(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	queue.SetTimeout(100 * time.Millisecond)
	step := newRecheckStep(t, scope, queue, nil)
	ctx, reg := registerLiveConn(t, scope, "http")

	whileHeld(t, queue, func() {
		denyLoopback(scope)
		reg.Reconcile("test")
	}, nil)

	assertTargetScope403(t, step.Process(ctx, recheckHTTPRequest("/")))
}

// A hold attempted on a connection that was already cut is answered with
// the target_scope block instead of an unattributed Drop.
func TestInterceptStep_LiveConn_HoldOnCutConnBlocked(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)
	ctx, reg := registerLiveConn(t, scope, "http")

	denyLoopback(scope)
	reg.Reconcile("test")
	if ctx.Err() == nil {
		t.Fatal("precondition: hold-free connection not cut")
	}
	// The receive-direction arm reaches holdAndDispatch without a
	// HostScopeStep verdict.
	env := recheckHTTPRequest("/")
	env.Direction = envelope.Receive
	env.Message = &envelope.HTTPMessage{Status: 200}
	r := step.Process(ctx, env)
	if r.Action != Drop || r.BlockedBy != BlockedByTargetScope {
		t.Errorf("Result = (%v, %q), want (Drop, %q)", r.Action, r.BlockedBy, BlockedByTargetScope)
	}
	if n := queue.Len(); n != 0 {
		t.Errorf("queue.Len = %d, want 0 (nothing held on a cut connection)", n)
	}
}

// HostScopeStep blocks a Send envelope on a revoke-pending connection even
// when its own CheckTarget would allow it — here the SOCKS5-style gate
// scopes with a blank scheme while HostScopeStep derives "https" from TLS.
func TestHostScopeStep_BlocksRevokePendingConnection(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	ctx, reg := registerLiveConn(t, scope, "")
	h := connector.LiveConnFromContext(ctx)
	if !h.Pin() {
		t.Fatal("Pin = false")
	}
	defer h.Unpin()

	scope.ReplacePolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", Schemes: []string{"https"}}}, nil, connector.PolicyOrigin{})
	reg.Reconcile("test")
	if ok, _ := scope.CheckTarget("https", "127.0.0.1", 8080, ""); !ok {
		t.Fatal("precondition: HostScopeStep's own check must allow")
	}

	step := NewHostScopeStep(scope)
	env := recheckHTTPRequest("/")
	env.Context.TLS = &envelope.TLSSnapshot{}
	r := step.Process(ctx, env)
	if r.Action != Respond || r.BlockedBy != BlockedByTargetScope {
		t.Errorf("Result = (%v, %q), want (Respond, %q) on a revoke-pending connection", r.Action, r.BlockedBy, BlockedByTargetScope)
	}

	ws := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
		Context: env.Context, Message: &envelope.WSMessage{Opcode: envelope.WSText}}
	if r := step.Process(ctx, ws); r.Action != Drop || r.BlockedBy != BlockedByTargetScope {
		t.Errorf("WS Result = (%v, %q), want (Drop, %q)", r.Action, r.BlockedBy, BlockedByTargetScope)
	}
	// Receive envelopes are not gated (Send-only Step).
	recv := recheckHTTPRequest("/")
	recv.Direction = envelope.Receive
	if r := step.Process(ctx, recv); r.Action != Continue {
		t.Errorf("Receive Result = %v, want Continue", r.Action)
	}
}
