package connector

import (
	"context"
	"errors"
	"testing"
)

// T14 (USK-1410): a plain-HTTP forward connection that switched its
// upstream from a.test to b.test is judged by b.test from then on — the
// same check an identical new connection to b.test would pass.
func TestLiveConnHandle_Retarget_ReconcileJudgesNewTarget(t *testing.T) {
	both := []TargetRule{{Hostname: "a.test"}, {Hostname: "b.test"}}
	cases := []struct {
		name    string
		narrow  []TargetRule // allows after the policy change
		wantCut bool
	}{
		{name: "denying the new target cuts", narrow: allowOnly("a.test"), wantCut: true},
		{name: "denying only the old target does not cut", narrow: allowOnly("b.test"), wantCut: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope := NewTargetScope()
			scope.SetPolicyRules(both, nil)
			reg := NewLiveConns(newTestLogger())
			ctx, release, err := reg.Register(context.Background(), LiveConn{
				ConnID: "c1", Via: "http1-forward", Target: "a.test:80",
				Admit: scopeAdmit(scope, "http", "a.test", 80),
			})
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			defer release()

			h := LiveConnFromContext(ctx)
			if err := h.Retarget("b.test:80", scopeAdmit(scope, "http", "b.test", 80), nil); err != nil {
				t.Fatalf("Retarget: %v", err)
			}

			scope.ReplacePolicyRules(c.narrow, nil, PolicyOrigin{Source: "test"})
			reg.Reconcile("test")
			cut := errors.Is(context.Cause(ctx), ErrTargetScopeRevoked)
			if cut != c.wantCut {
				t.Errorf("connection cut = %v (cause %v), want %v", cut, context.Cause(ctx), c.wantCut)
			}
		})
	}
}

// T14: Retarget re-runs the new target's check like Register does, so a
// target the scope does not admit is refused and the registration keeps
// judging the old target.
func TestLiveConnHandle_Retarget_RefusesUnadmittedTarget(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, release, err := reg.Register(context.Background(), LiveConn{
		ConnID: "c1", Via: "http1-forward", Target: "a.test:80",
		Admit: scopeAdmit(scope, "http", "a.test", 80),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer release()

	err = LiveConnFromContext(ctx).Retarget("b.test:80", scopeAdmit(scope, "http", "b.test", 80), nil)
	var se *ScopeAdmissionError
	if !errors.As(err, &se) || !errors.Is(err, ErrTargetScopeRevoked) {
		t.Fatalf("Retarget err = %v, want *ScopeAdmissionError wrapping ErrTargetScopeRevoked", err)
	}
	if n := reg.Reconcile("test"); n != 0 {
		t.Errorf("Reconcile cut %d after a refused Retarget, want 0 (a.test is still admitted)", n)
	}
	if ctx.Err() != nil {
		t.Errorf("refused Retarget cancelled the connection: %v", context.Cause(ctx))
	}
}

// A nil handle (no registry) allows every retarget.
func TestLiveConnHandle_Retarget_NilHandle(t *testing.T) {
	var h *LiveConnHandle
	if err := h.Retarget("b.test:80", func() (bool, string) { return false, "denied" }, nil); err != nil {
		t.Errorf("nil handle Retarget = %v, want nil", err)
	}
}
