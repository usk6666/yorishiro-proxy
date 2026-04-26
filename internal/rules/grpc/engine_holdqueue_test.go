package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// TestEngineToHoldQueue_Release wires InterceptEngine matches into a
// manually-constructed common.HoldQueue and verifies that an external
// "Release" decision unblocks the held envelope. This mirrors the
// flow that USK-648's InterceptStep will own.
func TestEngineToHoldQueue_Release(t *testing.T) {
	engine := NewInterceptEngine()
	rule, err := CompileInterceptRule("trace-rule", DirectionSend,
		`^example\.`, ``,
		map[string]string{"x-trace-id": `.+`},
		``,
	)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetRules([]InterceptRule{*rule})

	queue := common.NewHoldQueue()
	queue.SetTimeout(2 * time.Second)

	metadata := []envelope.KeyValue{{Name: "x-trace-id", Value: "trace-42"}}
	env, msg := makeStartEnv(envelope.Send, "example.Greeter", "SayHi", metadata)

	matched := engine.MatchStart(env, msg)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %v", matched)
	}

	// Hold blocks until Release; run it on a goroutine.
	type result struct {
		action *common.HoldAction
		err    error
	}
	done := make(chan result, 1)
	go func() {
		action, err := queue.Hold(context.Background(), env, matched)
		done <- result{action, err}
	}()

	// Find the held entry and release.
	deadline := time.After(time.Second)
	var held *common.HeldEntry
	for held == nil {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for queue to register held entry")
		default:
		}
		entries := queue.List()
		if len(entries) > 0 {
			held = entries[0]
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}

	if len(held.MatchedRules) != 1 || held.MatchedRules[0] != "trace-rule" {
		t.Errorf("MatchedRules = %v, want [trace-rule]", held.MatchedRules)
	}

	if err := queue.Release(held.ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hold returned error: %v", r.err)
		}
		if r.action == nil || r.action.Type != common.ActionRelease {
			t.Errorf("action = %+v, want Release", r.action)
		}
	case <-time.After(time.Second):
		t.Fatal("Hold did not unblock after Release")
	}
}

// TestEngineToHoldQueue_ModifyAndForward verifies that a
// ModifyAndForward decision propagates a modified envelope back to
// the Hold caller (the path InterceptStep will take when the rule
// engine-initiated hold is followed by an MCP-driven mutation).
func TestEngineToHoldQueue_ModifyAndForward(t *testing.T) {
	engine := NewInterceptEngine()
	rule, _ := CompileInterceptRule("payload-rule", DirectionSend,
		`^svc$`, ``, nil, `secret`)
	engine.SetRules([]InterceptRule{*rule})

	queue := common.NewHoldQueue()
	queue.SetTimeout(2 * time.Second)

	env, msg := makeDataEnv(envelope.Send, "svc", "Method", []byte("contains secret"))
	matched := engine.MatchData(env, msg)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %v", matched)
	}

	type result struct {
		action *common.HoldAction
		err    error
	}
	done := make(chan result, 1)
	go func() {
		action, err := queue.Hold(context.Background(), env, matched)
		done <- result{action, err}
	}()

	// Wait for the entry, then release with a modified envelope.
	deadline := time.After(time.Second)
	var heldID string
	for heldID == "" {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for queue to register held entry")
		default:
		}
		entries := queue.List()
		if len(entries) > 0 {
			heldID = entries[0].ID
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}

	modified := env.Clone()
	if dm, ok := modified.Message.(*envelope.GRPCDataMessage); ok {
		dm.Payload = []byte("contains [REDACTED]")
	}

	if err := queue.Release(heldID, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modified,
	}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Hold returned error: %v", r.err)
		}
		if r.action == nil || r.action.Type != common.ActionModifyAndForward {
			t.Fatalf("action = %+v, want ModifyAndForward", r.action)
		}
		if r.action.Modified == nil {
			t.Fatal("Modified envelope must be propagated")
		}
		dm, ok := r.action.Modified.Message.(*envelope.GRPCDataMessage)
		if !ok {
			t.Fatalf("Modified.Message type = %T", r.action.Modified.Message)
		}
		if string(dm.Payload) != "contains [REDACTED]" {
			t.Errorf("modified payload = %q", dm.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("Hold did not unblock after Release")
	}
}

// TestEngineToHoldQueue_Drop verifies the Drop path.
func TestEngineToHoldQueue_Drop(t *testing.T) {
	engine := NewInterceptEngine()
	rule, _ := CompileInterceptRule("drop-rule", DirectionBoth, ``, ``, nil, ``)
	engine.SetRules([]InterceptRule{*rule})

	queue := common.NewHoldQueue()
	queue.SetTimeout(2 * time.Second)

	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	matched := engine.MatchStart(env, msg)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match")
	}

	done := make(chan *common.HoldAction, 1)
	errs := make(chan error, 1)
	go func() {
		action, err := queue.Hold(context.Background(), env, matched)
		if err != nil {
			errs <- err
			return
		}
		done <- action
	}()

	// Wait for entry to appear.
	deadline := time.After(time.Second)
	var heldID string
	for heldID == "" {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for queue entry")
		default:
		}
		entries := queue.List()
		if len(entries) > 0 {
			heldID = entries[0].ID
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}

	if err := queue.Release(heldID, &common.HoldAction{Type: common.ActionDrop}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	select {
	case action := <-done:
		if action == nil || action.Type != common.ActionDrop {
			t.Errorf("action = %+v, want Drop", action)
		}
	case err := <-errs:
		t.Fatalf("Hold returned error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Hold did not unblock after Drop")
	}
}

// TestEngineToHoldQueue_NoMatchSkipsHold verifies the negative path:
// when the engine returns no matches, callers must skip Hold entirely
// (the contract InterceptStep will follow). The engine returns an
// empty slice — never holds.
func TestEngineToHoldQueue_NoMatchSkipsHold(t *testing.T) {
	engine := NewInterceptEngine()
	rule, _ := CompileInterceptRule("rule", DirectionReceive, ``, ``, nil, ``)
	engine.SetRules([]InterceptRule{*rule})

	// Send-direction event: receive-only rule must not match.
	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	matched := engine.MatchStart(env, msg)
	if len(matched) != 0 {
		t.Fatalf("expected no match, got %v", matched)
	}

	// Sanity: HoldQueue.Hold with no matches is the caller's responsibility
	// to skip. We don't call it here. The empty len(matched) is the contract.
}
