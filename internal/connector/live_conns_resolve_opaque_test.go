package connector

import (
	"context"
	"errors"
	"testing"
)

// USK-1283: once a raw relay resolved a provisionally admitted connection
// to raw bytes (LiveConnHandle.ResolveOpaque), every later re-evaluation —
// Reconcile, ReconcileWithDeferred, Settle — must run the gate's strict
// check, so narrowing a host-only allow to a path-scoped one cuts the
// relay exactly as it refuses an identical new one.

// registerProvisional registers target the way the CONNECT gate does for a
// non-opaque route: Admit is the provisional CheckHost verdict, AdmitOpaque
// the strict CheckOpaqueTarget one (connect_handler.go).
func registerProvisional(t *testing.T, reg *LiveConns, scope *TargetScope, target string) (context.Context, *LiveConnHandle) {
	t.Helper()
	ctx, rel, err := reg.Register(context.Background(), LiveConn{
		ConnID: target, Via: "connect", Target: target,
		Admit: func() (bool, string) {
			allowed, reason, _ := connectScopeCheck(scope, target, false)
			return allowed, reason
		},
		AdmitOpaque: func() (bool, string) {
			allowed, reason, _ := connectScopeCheck(scope, target, true)
			return allowed, reason
		},
	})
	if err != nil {
		t.Fatalf("Register %s: %v", target, err)
	}
	t.Cleanup(rel)
	h := LiveConnFromContext(ctx)
	if h == nil {
		t.Fatalf("LiveConnFromContext(%s) = nil", target)
	}
	return ctx, h
}

func narrowToPathOnly(scope *TargetScope, host string) {
	scope.ReplacePolicyRules([]TargetRule{{Hostname: host, PathPrefix: "/api/"}}, nil, PolicyOrigin{Source: "test"})
}

func TestLiveConns_ResolvedOpaqueReconcileUsesStrictCheck(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	rawCtx, rawH := registerProvisional(t, reg, scope, "a.test:443")
	httpCtx, _ := registerProvisional(t, reg, scope, "a.test:8443")

	if allowed, reason := rawH.ResolveOpaque(); !allowed {
		t.Fatalf("ResolveOpaque under a host-only allow = denied (%s), want allowed", reason)
	}
	narrowToPathOnly(scope, "a.test")

	if got := reg.Reconcile("test"); got != 1 {
		t.Errorf("Reconcile after narrowing to a path-only allow = %d revoked, want 1 (the resolved raw relay)", got)
	}
	if !errors.Is(context.Cause(rawCtx), ErrTargetScopeRevoked) {
		t.Errorf("resolved raw relay ctx cause = %v, want ErrTargetScopeRevoked", context.Cause(rawCtx))
	}
	// Control: a connection whose route still carries HTTP stays admitted
	// provisionally; HTTPScopeStep judges its next request path.
	if err := httpCtx.Err(); err != nil {
		t.Errorf("unresolved (HTTP) connection was cut: %v", context.Cause(httpCtx))
	}
	if got := reg.Reconcile("test"); got != 0 {
		t.Errorf("second Reconcile = %d revoked, want 0", got)
	}
}

func TestLiveConns_ResolvedOpaqueSettleUsesStrictCheck(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerProvisional(t, reg, scope, "a.test:443")

	if !h.Pin() {
		t.Fatal("Pin = false on a live connection")
	}
	if allowed, reason := h.ResolveOpaque(); !allowed {
		t.Fatalf("ResolveOpaque = denied (%s), want allowed", reason)
	}
	narrowToPathOnly(scope, "a.test")

	revoked, deferred := reg.ReconcileWithDeferred("test")
	if revoked != 1 || deferred != 1 {
		t.Fatalf("ReconcileWithDeferred = (%d, %d), want (1, 1) for a pinned resolved raw relay", revoked, deferred)
	}
	h.Unpin()
	h.Settle()
	if !errors.Is(context.Cause(ctx), ErrTargetScopeRevoked) {
		t.Errorf("Settle left the resolved raw relay open (cause %v), want it cut", context.Cause(ctx))
	}
}

func TestLiveConns_ResolveOpaqueReportsStrictVerdict(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules([]TargetRule{{Hostname: "a.test", PathPrefix: "/api/"}}, nil)
	reg := NewLiveConns(newTestLogger())
	_, h := registerProvisional(t, reg, scope, "a.test:443")

	if allowed, reason := h.ResolveOpaque(); allowed || reason != ReasonPathRequired {
		t.Errorf("ResolveOpaque under a path-only allow = (%v, %q), want (false, %q)", allowed, reason, ReasonPathRequired)
	}
	var nilH *LiveConnHandle
	if allowed, _ := nilH.ResolveOpaque(); !allowed {
		t.Error("nil handle ResolveOpaque = denied, want allowed")
	}
}
