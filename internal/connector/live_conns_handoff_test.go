package connector

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// USK-1196: the pin of a resolved intercept hold is handed off to the
// session relay loop that ran the Pipeline pass, so the deferred cut waits
// until the hold's Result was dispatched — not merely until the hold
// resolved.

func TestHandOffHoldPin_NoCollectorOrNilHandle(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	if HandOffHoldPin(ctx, h) {
		t.Error("HandOffHoldPin without a collector in ctx = true, want false (the caller must Unpin)")
	}
	cctx, _ := WithHoldPinHandoff(ctx)
	if HandOffHoldPin(cctx, nil) {
		t.Error("HandOffHoldPin(nil handle) = true, want false")
	}
	if !h.Pin() {
		t.Fatal("Pin = false")
	}
	if !HandOffHoldPin(cctx, h) {
		t.Error("HandOffHoldPin with a collector in ctx = false, want true")
	}
	var nilColl *HoldPinHandoff
	nilColl.Release() // nil-safe
}

func TestHoldPinHandoff_ReleaseUnpinsExactlyTheAdoptedPins(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")
	cctx, pins := WithHoldPinHandoff(ctx)

	for i := 0; i < 3; i++ {
		if !h.Pin() {
			t.Fatalf("Pin #%d = false", i)
		}
	}
	// Two holds resolve inside the pass and hand their pins off; the third
	// is still in flight.
	for i := 0; i < 2; i++ {
		if !HandOffHoldPin(cctx, h) {
			t.Fatalf("HandOffHoldPin #%d = false", i)
		}
	}

	scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{Source: "test"})
	if revoked, deferred := reg.ReconcileWithDeferred("test"); revoked != 1 || deferred != 1 {
		t.Fatalf("ReconcileWithDeferred = (%d, %d), want (1, 1)", revoked, deferred)
	}

	h.Settle()
	if ctx.Err() != nil {
		t.Fatalf("cut while handed-off pins are unreleased: %v", context.Cause(ctx))
	}
	reg.Reconcile("second")
	if ctx.Err() != nil {
		t.Fatalf("second Reconcile cut while handed-off pins are unreleased: %v", context.Cause(ctx))
	}

	pins.Release()
	h.Settle()
	if ctx.Err() != nil {
		t.Fatalf("cut after Release while one un-handed hold is still in flight: %v", context.Cause(ctx))
	}
	pins.Release() // idempotent: must not unpin the in-flight hold
	h.Settle()
	if ctx.Err() != nil {
		t.Fatalf("second Release unpinned a pin it never adopted: %v", context.Cause(ctx))
	}

	h.Unpin() // the in-flight hold resolves outside any pass
	h.Settle()
	if !errors.Is(context.Cause(ctx), ErrTargetScopeRevoked) {
		t.Errorf("cause after the last pin went = %v, want ErrTargetScopeRevoked", context.Cause(ctx))
	}
}

// Race-clean under -race: hand-offs and Releases from one loop goroutine
// while other goroutines Reconcile and Settle the same connection.
func TestHoldPinHandoff_ConcurrentReconcileSettle(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("a.test"), nil)
	reg := NewLiveConns(newTestLogger())
	ctx, h := registerPinTest(t, reg, scope, "a.test")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				reg.Reconcile("race")
				h.Settle()
			}
		}()
	}
	cctx, pins := WithHoldPinHandoff(ctx)
	for i := 0; i < 500; i++ {
		if h.Pin() && !HandOffHoldPin(cctx, h) {
			h.Unpin()
		}
		if i == 250 {
			scope.ReplacePolicyRules(nil, allowOnly("a.test"), PolicyOrigin{Source: "test"})
		}
		pins.Release()
		h.Settle()
	}
	close(stop)
	wg.Wait()
	pins.Release()
	// The racing goroutines may not have run a Reconcile after the deny
	// landed (the loop is short); revoke deterministically now. With every
	// handed-off pin released there is no hold left, so it cuts.
	reg.Reconcile("final")
	h.Settle()
	if !errors.Is(context.Cause(ctx), ErrTargetScopeRevoked) {
		t.Errorf("cause = %v, want ErrTargetScopeRevoked once every handed-off pin was released", context.Cause(ctx))
	}
}
