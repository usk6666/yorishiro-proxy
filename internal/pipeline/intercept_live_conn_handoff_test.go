package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1196: when the Pipeline runs inside a session relay loop (a
// HoldPinHandoff in ctx), the pin of a resolved hold is handed off to the
// loop instead of being dropped at resolution, so the connection stays
// pinned until the loop dispatched the hold's Result. Without a collector
// (MCP resend / fuzz, record-only pipelines) the pin is dropped at
// resolution as before.

// A second Reconcile landing after the hold resolved but before the loop
// released the handed-off pin must not cut the connection (the "known
// window" of USK-1192).
func TestInterceptStep_LiveConn_SecondReconcileDuringDispatchDoesNotCut(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)
	ctx, reg := registerLiveConn(t, scope, "http")
	pctx, pins := connector.WithHoldPinHandoff(ctx)

	whileHeld(t, queue, func() {
		denyLoopback(scope)
		reg.Reconcile("first")
	}, &common.HoldAction{Type: common.ActionRelease})

	assertTargetScope403(t, step.Process(pctx, recheckHTTPRequest("/")))

	// The session is now dispatching the 403; a second policy write lands.
	reg.Reconcile("second")
	if ctx.Err() != nil {
		t.Fatalf("second Reconcile cut the connection while the hold's Result was undispatched: %v", context.Cause(ctx))
	}
	connector.SettleLiveConn(ctx)
	if ctx.Err() != nil {
		t.Fatalf("Settle cut the connection before the loop released the handed-off pin: %v", context.Cause(ctx))
	}

	pins.Release()
	connector.SettleLiveConn(ctx)
	if !errors.Is(context.Cause(ctx), connector.ErrTargetScopeRevoked) {
		t.Errorf("cause after Release + Settle = %v, want ErrTargetScopeRevoked", context.Cause(ctx))
	}
}

// Guard (no pin leak on the non-session path): without a collector in ctx
// the hold's pin is dropped when the hold resolves, so a Settle right after
// Process cuts the revoked connection — for every hold action.
func TestInterceptStep_LiveConn_NoCollectorUnpinsAtResolution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action *common.HoldAction
	}{
		{"release", &common.HoldAction{Type: common.ActionRelease}},
		{"drop", &common.HoldAction{Type: common.ActionDrop}},
		{"modify_and_forward", &common.HoldAction{Type: common.ActionModifyAndForward, Modified: recheckHTTPRequest("/m")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope := newAllowLoopbackScope()
			queue := common.NewHoldQueue()
			step := newRecheckStep(t, scope, queue, nil)
			ctx, reg := registerLiveConn(t, scope, "http")
			// A collector in an unrelated context must not adopt the pin.
			_, foreign := connector.WithHoldPinHandoff(context.Background())

			whileHeld(t, queue, func() {
				denyLoopback(scope)
				reg.Reconcile("test")
			}, tc.action)

			r := step.Process(ctx, recheckHTTPRequest("/"))
			if r.Action != Respond {
				t.Fatalf("Action = %v, want Respond", r.Action)
			}
			connector.SettleLiveConn(ctx)
			if !errors.Is(context.Cause(ctx), connector.ErrTargetScopeRevoked) {
				t.Errorf("cause after Settle = %v, want ErrTargetScopeRevoked (hold pin leaked)", context.Cause(ctx))
			}
			foreign.Release()
		})
	}
}
