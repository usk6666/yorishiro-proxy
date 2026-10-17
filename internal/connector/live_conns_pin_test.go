package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// USK-1192: a live connection with an in-flight intercept hold is revoked,
// not cut, by Reconcile; the cut is deferred until the last hold resolved
// and its Result was dispatched (Settle).

func registerPinTest(t *testing.T, reg *LiveConns, scope *TargetScope, host string) (context.Context, *LiveConnHandle) {
	t.Helper()
	ctx, rel, err := reg.Register(context.Background(), LiveConn{
		ConnID: host, Via: "http1-forward", Target: host + ":80",
		Admit: scopeAdmit(scope, "http", host, 80),
	})
	if err != nil {
		t.Fatalf("Register %s: %v", host, err)
	}
	t.Cleanup(rel)
	h := LiveConnFromContext(ctx)
	if h == nil {
		t.Fatalf("LiveConnFromContext(%s) = nil, want the registered handle", host)
	}
	return ctx, h
}

func TestLiveConns_PinnedEntryRevokedNotCut(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	if !h.Pin() {
		t.Fatal("Pin on a live entry = false, want true")
	}
	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{Source: "test"})
	revoked, deferred := reg.ReconcileWithDeferred("test")
	if revoked != 1 || deferred != 1 {
		t.Errorf("ReconcileWithDeferred = (%d, %d), want (1, 1)", revoked, deferred)
	}
	if ctx.Err() != nil {
		t.Fatalf("pinned entry cut at Reconcile: %v", context.Cause(ctx))
	}
	if !h.RevokePending() {
		t.Error("RevokePending = false after a deferring Reconcile, want true")
	}

	h.Unpin()
	if ctx.Err() != nil {
		t.Fatalf("Unpin cut the entry (%v); only Settle may cut", context.Cause(ctx))
	}
	h.Settle()
	if !errors.Is(context.Cause(ctx), ErrTargetScopeRevoked) {
		t.Errorf("cause after Settle = %v, want ErrTargetScopeRevoked", context.Cause(ctx))
	}
}

func TestLiveConns_SettleWhilePinnedDoesNotCut(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	h.Pin()
	h.Pin()
	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{})
	reg.Reconcile("test")
	h.Unpin()
	h.Settle()
	if ctx.Err() != nil {
		t.Fatalf("Settle cut the entry with one pin still held: %v", context.Cause(ctx))
	}
	h.Unpin()
	h.Settle()
	if !errors.Is(context.Cause(ctx), ErrTargetScopeRevoked) {
		t.Errorf("cause after the last Settle = %v, want ErrTargetScopeRevoked", context.Cause(ctx))
	}
}

// Guard (passes on red): an unpinned entry is still cut at Reconcile while
// another entry is pinned. Fails under a "defer every entry" mutation.
func TestLiveConns_UnpinnedEntryCutWhilePeerPinned(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	_, hPinned := registerPinTest(t, reg, scope, "a.test")
	ctxFree, _ := registerPinTest(t, reg, scope, "a.test")

	hPinned.Pin()
	defer hPinned.Unpin()
	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{})
	reg.Reconcile("test")
	if !errors.Is(context.Cause(ctxFree), ErrTargetScopeRevoked) {
		t.Errorf("hold-free entry cause = %v, want ErrTargetScopeRevoked (cut immediately)", context.Cause(ctxFree))
	}
}

func TestLiveConns_WideningBeforeSettleWithdrawsRevocation(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	h.Pin()
	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{})
	reg.Reconcile("narrow")
	if !h.RevokePending() {
		t.Fatal("precondition: RevokePending = false after a deferring Reconcile")
	}

	// Widened again before the hold resolves.
	scope.ReplacePolicyRules(allowOnly("a.test"), nil, PolicyOrigin{})
	h.Unpin()
	h.Settle()
	if ctx.Err() != nil {
		t.Errorf("Settle cut an entry the current scope admits: %v", context.Cause(ctx))
	}
	if h.RevokePending() {
		t.Error("RevokePending = true after the scope re-admitted the target")
	}
	if n := reg.Reconcile("again"); n != 0 {
		t.Errorf("Reconcile after widening revoked %d, want 0", n)
	}
	if ctx.Err() != nil {
		t.Errorf("entry cut after widening: %v", context.Cause(ctx))
	}
}

func TestLiveConns_ReconcileWideningWithdrawsRevocation(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	h.Pin()
	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{})
	reg.Reconcile("narrow")
	scope.ReplacePolicyRules(allowOnly("a.test"), nil, PolicyOrigin{})
	if n := reg.Reconcile("widen"); n != 0 {
		t.Errorf("widening Reconcile revoked %d, want 0", n)
	}
	if h.RevokePending() {
		t.Error("RevokePending = true after a widening Reconcile")
	}
	h.Unpin()
	h.Settle()
	if ctx.Err() != nil {
		t.Errorf("entry cut after widening: %v", context.Cause(ctx))
	}
}

func TestLiveConns_PinOnCutEntryFails(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{})
	reg.Reconcile("test")
	if ctx.Err() == nil {
		t.Fatal("precondition: hold-free entry not cut")
	}
	if h.Pin() {
		t.Error("Pin on a cut entry = true, want false")
	}
	if !h.RevokePending() {
		t.Error("RevokePending on a cut entry = false, want true")
	}
}

func TestLiveConns_PendingCountedOnce(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	h.Pin()
	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{})
	if n := reg.Reconcile("first"); n != 1 {
		t.Errorf("first Reconcile revoked %d, want 1", n)
	}
	if ctx.Err() != nil {
		t.Fatalf("pinned entry cut at Reconcile: %v", context.Cause(ctx))
	}
	if revoked, deferred := reg.ReconcileWithDeferred("second"); revoked != 0 || deferred != 0 {
		t.Errorf("second ReconcileWithDeferred = (%d, %d), want (0, 0) — pending entry counted again", revoked, deferred)
	}
	// Backstop: the hold resolved but Settle never ran; a later Reconcile
	// cuts it without counting it a second time.
	h.Unpin()
	if n := reg.Reconcile("backstop"); n != 0 {
		t.Errorf("backstop Reconcile revoked %d, want 0 (already counted)", n)
	}
	if !errors.Is(context.Cause(ctx), ErrTargetScopeRevoked) {
		t.Errorf("cause after backstop Reconcile = %v, want ErrTargetScopeRevoked", context.Cause(ctx))
	}
}

func TestLiveConns_NilHandleIsInert(t *testing.T) {
	var h *LiveConnHandle
	if !h.Pin() {
		t.Error("nil Pin = false, want true")
	}
	h.Unpin()
	h.Settle()
	if h.RevokePending() {
		t.Error("nil RevokePending = true")
	}
	if LiveConnFromContext(context.Background()) != nil {
		t.Error("LiveConnFromContext(Background) != nil")
	}
	SettleLiveConn(context.Background())
}

// Pin / Unpin / Settle / Reconcile / scope writes from many goroutines;
// run under -race. Every entry must be gone at the end and no pinned
// entry may ever be cancelled.
func TestLiveConns_ConcurrentPinReconcileSettle(t *testing.T) {
	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errCh := make(chan error, 16)

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
					h := LiveConnFromContext(ctx)
					if h.Pin() {
						for k := 0; k < 3; k++ {
							if ctx.Err() != nil {
								select {
								case errCh <- fmt.Errorf("pinned entry cancelled: %v", context.Cause(ctx)):
								default:
								}
								break
							}
							time.Sleep(time.Microsecond)
						}
						h.Unpin()
					}
					h.Settle()
					_ = h.RevokePending()
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
			reg.ReconcileWithDeferred("race")
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if got := reg.Len(); got != 0 {
		t.Errorf("Len after all releases = %d, want 0", got)
	}
}
