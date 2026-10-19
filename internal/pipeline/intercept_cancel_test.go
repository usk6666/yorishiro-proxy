package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	ssrules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
)

// USK-1193: a hold whose ctx ends without an agent action (proxy_stop,
// session teardown, peer-direction failure) must be attributed to
// intercept_cancelled so the session's OnPipelineDrop records an audit
// Stream instead of letting the held envelope vanish with no record.

// cancelWhenHeld cancels once the queue holds an entry (the hold is
// waiting inside HoldQueue.Hold) and fails the test if none appears.
func cancelWhenHeld(t *testing.T, queue *common.HoldQueue, cancel context.CancelFunc) {
	t.Helper()
	go func() {
		defer cancel()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if queue.Len() == 1 {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Error("timed out waiting for held entry")
	}()
}

func newCatchAllSSEEngine(t *testing.T) *ssrules.InterceptEngine {
	t.Helper()
	r, err := ssrules.CompileInterceptRule("sse-catch-all", ssrules.DirectionReceive, "", "", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("CompileInterceptRule: %v", err)
	}
	e := ssrules.NewInterceptEngine()
	e.SetRules([]ssrules.InterceptRule{*r})
	return e
}

func TestInterceptStep_HoldCtxCancelled_AttributedInterceptCancelled(t *testing.T) {
	tests := []struct {
		name      string
		direction envelope.Direction
		protocol  envelope.Protocol
		msg       envelope.Message
	}{
		{"http send (Drop, not Respond)", envelope.Send, envelope.ProtocolHTTP, &envelope.HTTPMessage{Method: "GET", Path: "/"}},
		{"http receive", envelope.Receive, envelope.ProtocolHTTP, &envelope.HTTPMessage{Status: 200}},
		{"ws", envelope.Receive, envelope.ProtocolWebSocket, &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hi")}},
		{"grpc start", envelope.Send, envelope.ProtocolGRPC, &envelope.GRPCStartMessage{Service: "Greeter", Method: "SayHello"}},
		{"grpc data", envelope.Receive, envelope.ProtocolGRPC, &envelope.GRPCDataMessage{Service: "Greeter", Method: "SayHello", Payload: []byte("b")}},
		{"grpc end receive", envelope.Receive, envelope.ProtocolGRPC, &envelope.GRPCEndMessage{Status: 0}},
		{"sse", envelope.Receive, envelope.ProtocolSSE, &envelope.SSEMessage{Event: "msg", Data: "hello"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			queue := common.NewHoldQueue()
			step := NewInterceptStep(
				newTestInterceptEngine(newCatchAllRequestRule(), newCatchAllResponseRule()),
				newTestWSInterceptEngine(newCatchAllWSRule()),
				newTestGRPCInterceptEngine(newCatchAllGRPCRule()),
				newCatchAllSSEEngine(t),
				queue, nil, nil,
			)
			env := &envelope.Envelope{
				StreamID:  "s-1",
				FlowID:    "f-1",
				Direction: tc.direction,
				Protocol:  tc.protocol,
				Message:   tc.msg,
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancelWhenHeld(t, queue, cancel)

			r := step.Process(ctx, env)
			if r.Action != Drop {
				t.Errorf("Action = %v, want Drop (nobody to answer once the hold's ctx ended)", r.Action)
			}
			if r.BlockedBy != BlockedByInterceptCancelled {
				t.Errorf("BlockedBy = %q, want %q", r.BlockedBy, BlockedByInterceptCancelled)
			}
			if r.Response != nil {
				t.Errorf("Response = %v, want nil", r.Response)
			}
			if n := queue.Len(); n != 0 {
				t.Errorf("queue.Len = %d, want 0", n)
			}
		})
	}
}

// A hold whose ctx deadline expires is a ctx end too, not an agent drop.
func TestInterceptStep_HoldCtxDeadline_AttributedInterceptCancelled(t *testing.T) {
	queue := common.NewHoldQueue()
	step := NewInterceptStep(newTestInterceptEngine(newCatchAllRequestRule()), nil, nil, nil, queue, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	r := step.Process(ctx, &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: &envelope.HTTPMessage{Method: "GET", Path: "/"}})
	if r.Action != Drop || r.BlockedBy != BlockedByInterceptCancelled {
		t.Errorf("Result = (%v, %q), want (Drop, %q)", r.Action, r.BlockedBy, BlockedByInterceptCancelled)
	}
}

// Guard: a timeout auto_drop is the queue's policy acting for the agent,
// not a ctx end — it stays intercept_drop with the synthetic 403.
func TestInterceptStep_TimeoutAutoDrop_StaysInterceptDrop(t *testing.T) {
	queue := common.NewHoldQueue()
	queue.SetTimeout(20 * time.Millisecond)
	queue.SetTimeoutBehavior(common.TimeoutAutoDrop)
	step := NewInterceptStep(newTestInterceptEngine(newCatchAllRequestRule()), nil, nil, nil, queue, nil, nil)

	r := step.Process(context.Background(), &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: &envelope.HTTPMessage{Method: "GET", Path: "/"}})
	if r.Action != Respond || r.BlockedBy != BlockedByInterceptDrop {
		t.Errorf("Result = (%v, %q), want (Respond, %q)", r.Action, r.BlockedBy, BlockedByInterceptDrop)
	}
}

// Guard: an agent drop of a non-HTTP envelope stays intercept_drop.
func TestInterceptStep_AgentDropWS_StaysInterceptDrop(t *testing.T) {
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, newTestWSInterceptEngine(newCatchAllWSRule()), nil, nil, queue, nil, nil)
	releaseFirst(t, queue, &common.HoldAction{Type: common.ActionDrop})

	r := step.Process(context.Background(), &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolWebSocket, Message: &envelope.WSMessage{Opcode: envelope.WSText}})
	if r.Action != Drop || r.BlockedBy != BlockedByInterceptDrop {
		t.Errorf("Result = (%v, %q), want (Drop, %q)", r.Action, r.BlockedBy, BlockedByInterceptDrop)
	}
}

// The USK-1192 pin is still released when the hold ends by ctx: a revoke
// deferred by the pin is settled right after Process returns.
func TestInterceptStep_HoldCtxCancelled_ReleasesLiveConnPin(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)
	connCtx, reg := registerLiveConn(t, scope, "http")
	holdCtx, cancel := context.WithCancel(connCtx)

	go func() {
		defer cancel()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if queue.Len() == 1 {
				denyLoopback(scope)
				reg.Reconcile("test")
				if connCtx.Err() != nil {
					t.Errorf("pinned connection cut at Reconcile: %v", context.Cause(connCtx))
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Error("timed out waiting for held entry")
	}()

	r := step.Process(holdCtx, recheckHTTPRequest("/"))
	if r.Action != Drop || r.BlockedBy != BlockedByInterceptCancelled {
		t.Errorf("Result = (%v, %q), want (Drop, %q)", r.Action, r.BlockedBy, BlockedByInterceptCancelled)
	}
	connector.SettleLiveConn(connCtx)
	if !errors.Is(context.Cause(connCtx), connector.ErrTargetScopeRevoked) {
		t.Errorf("cause after Settle = %v, want ErrTargetScopeRevoked (hold pin leaked on ctx end)", context.Cause(connCtx))
	}
}
