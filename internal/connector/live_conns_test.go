package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// scopeAdmit builds the predicate a CONNECT gate stores: the exact
// admission check against the live engine.
func scopeAdmit(scope *TargetScope, scheme, host string, port int) LiveConnAdmitFunc {
	return func() (bool, string) { return scope.CheckTarget(scheme, host, port, "") }
}

func allowOnly(host string) []TargetRule { return []TargetRule{{Hostname: host}} }

func TestLiveConns_RegisterTracksUntilRelease(t *testing.T) {
	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())

	ctx, release, err := reg.Register(context.Background(), LiveConn{
		ConnID: "c1", Via: "connect", Target: "a.test:443",
		Admit: scopeAdmit(scope, "https", "a.test", 443),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := reg.Len(); got != 1 {
		t.Fatalf("Len after Register = %d, want 1", got)
	}
	if ctx.Err() != nil {
		t.Fatalf("registered ctx already done: %v", ctx.Err())
	}
	release()
	if got := reg.Len(); got != 0 {
		t.Errorf("Len after release = %d, want 0 (entry leaked)", got)
	}
	release() // idempotent
	if got := reg.Len(); got != 0 {
		t.Errorf("Len after second release = %d, want 0", got)
	}
}

// T5: the register/reload race. The gate admitted the target against the
// old policy, the policy changed before Register ran, so Register must
// reject the connection and leave no entry behind.
func TestLiveConns_RegisterRejectsWhenAlreadyDenied(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	if ok, _ := scope.CheckTarget("https", "a.test", 443, ""); !ok {
		t.Fatal("precondition: a.test must be admitted by the boot policy")
	}
	// Reload lands between the gate's admission check and Register.
	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{Source: "test"})

	reg := NewLiveConns(newTestLogger())
	ctx, release, err := reg.Register(context.Background(), LiveConn{
		ConnID: "c1", Via: "connect", Target: "a.test:443",
		Admit: scopeAdmit(scope, "https", "a.test", 443),
	})
	defer release()
	if !errors.Is(err, ErrTargetScopeRevoked) {
		t.Fatalf("Register err = %v, want ErrTargetScopeRevoked", err)
	}
	if ctx.Err() == nil {
		t.Errorf("rejected registration returned a live ctx")
	}
	if got := reg.Len(); got != 0 {
		t.Errorf("Len after rejected Register = %d, want 0 (entry leaked)", got)
	}
}

func TestLiveConns_ReconcileCutsOnlyDenied(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules([]TargetRule{{Hostname: "a.test"}, {Hostname: "b.test"}}, nil)
	reg := NewLiveConns(newTestLogger())

	ctxA, relA, err := reg.Register(context.Background(), LiveConn{
		ConnID: "a", Via: "connect", Target: "a.test:443", Admit: scopeAdmit(scope, "https", "a.test", 443),
	})
	if err != nil {
		t.Fatalf("Register a: %v", err)
	}
	defer relA()
	ctxB, relB, err := reg.Register(context.Background(), LiveConn{
		ConnID: "b", Via: "socks5", Target: "b.test:443", Admit: scopeAdmit(scope, "", "b.test", 443),
	})
	if err != nil {
		t.Fatalf("Register b: %v", err)
	}
	defer relB()

	scope.ReplacePolicyRules(allowOnly("a.test"), nil, PolicyOrigin{Source: "test"})
	if n := reg.Reconcile("test"); n != 1 {
		t.Errorf("Reconcile closed %d, want 1", n)
	}
	if ctxA.Err() != nil {
		t.Errorf("a.test still admitted but its ctx was cancelled: %v", context.Cause(ctxA))
	}
	if !errors.Is(context.Cause(ctxB), ErrTargetScopeRevoked) {
		t.Errorf("b.test cause = %v, want ErrTargetScopeRevoked", context.Cause(ctxB))
	}

	// A second reconcile does not count the already-cut entry again.
	if n := reg.Reconcile("test"); n != 0 {
		t.Errorf("second Reconcile closed %d, want 0", n)
	}
	relB()
	if got := reg.Len(); got != 1 {
		t.Errorf("Len after b released = %d, want 1", got)
	}
}

// T4 at the registry seam: widening or unchanged rules cut nothing.
func TestLiveConns_ReconcileWideningCutsNothing(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, rel, err := reg.Register(context.Background(), LiveConn{
		ConnID: "a", Via: "connect", Target: "a.test:443", Admit: scopeAdmit(scope, "https", "a.test", 443),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer rel()

	if n := reg.Reconcile("unchanged"); n != 0 {
		t.Errorf("unchanged Reconcile closed %d, want 0", n)
	}
	scope.ReplacePolicyRules([]TargetRule{{Hostname: "a.test"}, {Hostname: "c.test"}}, nil, PolicyOrigin{})
	if n := reg.Reconcile("widen"); n != 0 {
		t.Errorf("widening Reconcile closed %d, want 0", n)
	}
	// A path_prefix-only deny never cuts a connection: the gate checks
	// path "" so the rule cannot match it.
	scope.ReplacePolicyRules(nil, []TargetRule{{Hostname: "a.test", PathPrefix: "/admin"}}, PolicyOrigin{})
	if n := reg.Reconcile("path-deny"); n != 0 {
		t.Errorf("path_prefix-only deny closed %d, want 0", n)
	}
	if ctx.Err() != nil {
		t.Errorf("ctx cancelled by a non-narrowing reconcile: %v", context.Cause(ctx))
	}
}

// Agent-layer writes go through the same predicate as policy reloads.
func TestLiveConns_ReconcileAfterAgentDeny(t *testing.T) {
	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())
	ctx, rel, err := reg.Register(context.Background(), LiveConn{
		ConnID: "a", Via: "http1-forward", Target: "a.test:80", Admit: scopeAdmit(scope, "http", "a.test", 80),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer rel()
	if err := scope.MergeAgentRules(nil, nil, allowOnly("a.test"), nil); err != nil {
		t.Fatalf("MergeAgentRules: %v", err)
	}
	if n := reg.Reconcile("security_tool"); n != 1 {
		t.Errorf("Reconcile closed %d, want 1", n)
	}
	if !errors.Is(context.Cause(ctx), ErrTargetScopeRevoked) {
		t.Errorf("cause = %v, want ErrTargetScopeRevoked", context.Cause(ctx))
	}
}

func TestLiveConns_NilRegistryIsInert(t *testing.T) {
	var reg *LiveConns
	parent := context.Background()
	ctx, rel, err := reg.Register(parent, LiveConn{Target: "a.test:443"})
	if err != nil || ctx != parent {
		t.Fatalf("nil Register = (%v, %v), want parent ctx and nil", ctx, err)
	}
	rel()
	if n := reg.Reconcile("x"); n != 0 {
		t.Errorf("nil Reconcile = %d", n)
	}
	if n := reg.Len(); n != 0 {
		t.Errorf("nil Len = %d", n)
	}
}

// Register / release / Reconcile / scope writes from many goroutines; run
// under -race. Every entry must be gone at the end.
func TestLiveConns_ConcurrentUse(t *testing.T) {
	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				host := fmt.Sprintf("h%d.test", j%3)
				ctx, rel, err := reg.Register(context.Background(), LiveConn{
					ConnID: fmt.Sprintf("%d-%d", i, j), Via: "connect", Target: host + ":443",
					Admit: scopeAdmit(scope, "https", host, 443),
				})
				if err == nil {
					_ = ctx.Err()
				}
				rel()
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; ; j++ {
			select {
			case <-stop:
				return
			default:
			}
			scope.ReplacePolicyRules(nil, allowOnly(fmt.Sprintf("h%d.test", j%3)), PolicyOrigin{})
			reg.Reconcile("race")
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	if got := reg.Len(); got != 0 {
		t.Errorf("Len after all releases = %d, want 0", got)
	}
}
