package common

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func testEnvelope() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/test",
		},
	}
}

func TestHoldQueue_HoldRelease(t *testing.T) {
	q := NewHoldQueue()

	env := testEnvelope()

	var action *HoldAction
	var holdErr error
	done := make(chan struct{})

	go func() {
		action, holdErr = q.Hold(context.Background(), env, []string{"rule-1"})
		close(done)
	}()

	// Wait for item to appear in queue.
	for q.Len() == 0 {
		time.Sleep(time.Millisecond)
	}

	// Release.
	entries := q.List()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if err := q.Release(entries[0].ID, &HoldAction{Type: ActionRelease}); err != nil {
		t.Fatal(err)
	}

	<-done
	if holdErr != nil {
		t.Fatalf("Hold returned error: %v", holdErr)
	}
	if action.Type != ActionRelease {
		t.Errorf("action type = %v, want Release", action.Type)
	}
}

func TestHoldQueue_HoldDrop(t *testing.T) {
	q := NewHoldQueue()
	env := testEnvelope()

	var action *HoldAction
	done := make(chan struct{})

	go func() {
		action, _ = q.Hold(context.Background(), env, nil)
		close(done)
	}()

	for q.Len() == 0 {
		time.Sleep(time.Millisecond)
	}

	entries := q.List()
	if err := q.Release(entries[0].ID, &HoldAction{Type: ActionDrop}); err != nil {
		t.Fatal(err)
	}

	<-done
	if action.Type != ActionDrop {
		t.Errorf("action type = %v, want Drop", action.Type)
	}
}

func TestHoldQueue_ModifyAndForward(t *testing.T) {
	q := NewHoldQueue()
	env := testEnvelope()

	var action *HoldAction
	done := make(chan struct{})

	go func() {
		action, _ = q.Hold(context.Background(), env, nil)
		close(done)
	}()

	for q.Len() == 0 {
		time.Sleep(time.Millisecond)
	}

	modified := testEnvelope()
	modified.Message.(*envelope.HTTPMessage).Method = "POST"

	entries := q.List()
	err := q.Release(entries[0].ID, &HoldAction{
		Type:     ActionModifyAndForward,
		Modified: modified,
	})
	if err != nil {
		t.Fatal(err)
	}

	<-done
	if action.Type != ActionModifyAndForward {
		t.Errorf("action type = %v, want ModifyAndForward", action.Type)
	}
	if action.Modified == nil {
		t.Fatal("Modified envelope is nil")
	}
	msg := action.Modified.Message.(*envelope.HTTPMessage)
	if msg.Method != "POST" {
		t.Errorf("modified method = %q, want POST", msg.Method)
	}
}

func TestHoldQueue_Timeout_AutoRelease(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(50 * time.Millisecond)

	env := testEnvelope()
	action, err := q.Hold(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if action.Type != ActionRelease {
		t.Errorf("timeout action = %v, want Release", action.Type)
	}
	if q.Len() != 0 {
		t.Error("queue should be empty after timeout")
	}
}

func TestHoldQueue_Timeout_AutoDrop(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(50 * time.Millisecond)
	q.SetTimeoutBehavior(TimeoutAutoDrop)

	env := testEnvelope()
	action, err := q.Hold(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if action.Type != ActionDrop {
		t.Errorf("timeout action = %v, want Drop", action.Type)
	}
}

func TestHoldQueue_ContextCancel(t *testing.T) {
	q := NewHoldQueue()

	ctx, cancel := context.WithCancel(context.Background())
	env := testEnvelope()

	done := make(chan struct{})
	var holdErr error

	go func() {
		_, holdErr = q.Hold(ctx, env, nil)
		close(done)
	}()

	for q.Len() == 0 {
		time.Sleep(time.Millisecond)
	}

	cancel()
	<-done

	if holdErr != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", holdErr)
	}
	if q.Len() != 0 {
		t.Error("queue should be empty after cancel")
	}
}

func TestHoldQueue_MaxItems_AutoRelease(t *testing.T) {
	q := NewHoldQueue()
	q.SetMaxItems(1)
	q.SetTimeout(time.Hour) // long timeout so we don't timeout

	env := testEnvelope()

	// Hold first item in background.
	go func() {
		q.Hold(context.Background(), env, nil) //nolint:errcheck
	}()

	for q.Len() == 0 {
		time.Sleep(time.Millisecond)
	}

	// Second item should be auto-released.
	action, err := q.Hold(context.Background(), env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if action.Type != ActionRelease {
		t.Errorf("overflow action = %v, want Release", action.Type)
	}
}

func TestHoldQueue_Concurrent(t *testing.T) {
	q := NewHoldQueue()
	q.SetMaxItems(50)

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			env := testEnvelope()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			q.Hold(ctx, env, nil) //nolint:errcheck
		}()
	}

	wg.Wait()
	// All should have either timed out or been released. Queue should be empty.
	if q.Len() != 0 {
		t.Errorf("queue not empty after all workers done: %d items", q.Len())
	}
}

func TestHoldQueue_ReleaseNotFound(t *testing.T) {
	q := NewHoldQueue()
	err := q.Release("nonexistent", &HoldAction{Type: ActionRelease})
	if err == nil {
		t.Error("expected error for nonexistent ID")
	}
}

func TestHoldQueue_Clear_UnblocksHeldGoroutines_AutoRelease(t *testing.T) {
	q := NewHoldQueue()
	// Long timeout so the test relies on Clear(), not the timer.
	q.SetTimeout(time.Hour)

	env := testEnvelope()

	const workers = 5
	type result struct {
		action *HoldAction
		err    error
	}
	results := make(chan result, workers)

	for i := 0; i < workers; i++ {
		go func() {
			a, err := q.Hold(context.Background(), env, nil)
			results <- result{action: a, err: err}
		}()
	}

	// Wait for all workers to enqueue.
	deadline := time.Now().Add(time.Second)
	for q.Len() < workers {
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d workers enqueued before deadline", q.Len(), workers)
		}
		time.Sleep(time.Millisecond)
	}

	q.Clear()

	// Each worker should observe a Release action within a deterministic short window.
	for i := 0; i < workers; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Errorf("worker %d returned error: %v", i, r.err)
				continue
			}
			if r.action == nil {
				t.Errorf("worker %d returned nil action", i)
				continue
			}
			if r.action.Type != ActionRelease {
				t.Errorf("worker %d action = %v, want Release", i, r.action.Type)
			}
		case <-time.After(time.Second):
			t.Fatalf("worker %d did not unblock within 1s after Clear()", i)
		}
	}

	if q.Len() != 0 {
		t.Errorf("queue not empty after Clear: %d items", q.Len())
	}
}

func TestHoldQueue_Clear_UnblocksHeldGoroutines_AutoDrop(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(time.Hour)
	q.SetTimeoutBehavior(TimeoutAutoDrop)

	env := testEnvelope()

	type result struct {
		action *HoldAction
		err    error
	}
	results := make(chan result, 1)

	go func() {
		a, err := q.Hold(context.Background(), env, nil)
		results <- result{action: a, err: err}
	}()

	for q.Len() == 0 {
		time.Sleep(time.Millisecond)
	}

	q.Clear()

	select {
	case r := <-results:
		if r.err != nil {
			t.Fatalf("worker returned error: %v", r.err)
		}
		if r.action == nil || r.action.Type != ActionDrop {
			t.Fatalf("worker action = %+v, want Drop", r.action)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not unblock within 1s after Clear()")
	}

	if q.Len() != 0 {
		t.Errorf("queue not empty after Clear: %d items", q.Len())
	}
}

func TestHoldQueue_List_ReturnsClones(t *testing.T) {
	q := NewHoldQueue()
	env := testEnvelope()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		q.Hold(ctx, env, []string{"r1"}) //nolint:errcheck
	}()

	for q.Len() == 0 {
		time.Sleep(time.Millisecond)
	}

	entries := q.List()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Verify it's a clone (different pointer).
	if entries[0].Envelope == env {
		t.Error("List() should return cloned envelopes")
	}

	// Verify matched rules.
	if len(entries[0].MatchedRules) != 1 || entries[0].MatchedRules[0] != "r1" {
		t.Errorf("MatchedRules = %v, want [r1]", entries[0].MatchedRules)
	}
}

// wsEnvelope returns a minimal Envelope tagged with ProtocolWebSocket so
// the HoldQueue's per-protocol override resolution path is exercised.
func wsEnvelope() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "s-ws",
		FlowID:    "f-ws",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   &envelope.WSMessage{},
	}
}

// TestHoldQueue_DefaultProtocolOverrides asserts that NewHoldQueue seeds
// the WS / SSE / gRPC entries with the documented defaults so the
// pre-config built-in behaviour matches the spec without any operator
// action.
func TestHoldQueue_DefaultProtocolOverrides(t *testing.T) {
	q := NewHoldQueue()
	got := q.ProtocolOverrides()
	cases := []struct {
		name  string
		proto envelope.Protocol
		want  time.Duration
	}{
		{"ws", envelope.ProtocolWebSocket, DefaultHoldTimeoutWS},
		{"sse", envelope.ProtocolSSE, DefaultHoldTimeoutSSE},
		{"grpc", envelope.ProtocolGRPC, DefaultHoldTimeoutGRPC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := got[tc.proto]
			if !ok {
				t.Fatalf("ProtocolOverrides missing %s", tc.proto)
			}
			if entry.Timeout == nil || *entry.Timeout != tc.want {
				t.Errorf("ProtocolOverrides[%s].Timeout = %v, want %v", tc.proto, entry.Timeout, tc.want)
			}
			if entry.Behavior != nil {
				t.Errorf("ProtocolOverrides[%s].Behavior = %v, want nil (inherit global)", tc.proto, *entry.Behavior)
			}
		})
	}
	if _, ok := got[envelope.ProtocolHTTP]; ok {
		t.Errorf("ProtocolOverrides unexpectedly contains http")
	}
}

// TestHoldQueue_Timeout_PerProtocol_Override pins the WS-specific timeout
// to a value distinct from the global and confirms the resolution path
// picks it up at Hold time. The global timeout is set high so the
// override is the only short-circuit.
func TestHoldQueue_Timeout_PerProtocol_Override(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(time.Hour) // global; long, so override must win
	q.SetProtocolTimeout(envelope.ProtocolWebSocket, 40*time.Millisecond)

	env := wsEnvelope()
	start := time.Now()
	action, err := q.Hold(context.Background(), env, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if action.Type != ActionRelease {
		t.Errorf("timeout action = %v, want Release", action.Type)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Hold elapsed %s; per-protocol override should have fired before global", elapsed)
	}
}

// TestHoldQueue_Timeout_PerProtocol_InheritGlobal asserts that an
// Envelope tagged with a Protocol that has NO override falls back to the
// global timeout. We use a short global and a long ws-only override and
// pass an HTTP envelope so the global fires first.
func TestHoldQueue_Timeout_PerProtocol_InheritGlobal(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(40 * time.Millisecond)
	q.SetProtocolTimeout(envelope.ProtocolWebSocket, time.Hour)

	env := testEnvelope() // HTTP
	start := time.Now()
	action, err := q.Hold(context.Background(), env, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if action.Type != ActionRelease {
		t.Errorf("timeout action = %v, want Release (global default)", action.Type)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Hold elapsed %s; HTTP envelope should use the short global timeout", elapsed)
	}
}

// TestHoldQueue_Behavior_PerProtocol_Override pins the WS-specific
// timeout-behavior to AutoDrop while the global stays at AutoRelease.
// An expired WS hold must surface ActionDrop.
func TestHoldQueue_Behavior_PerProtocol_Override(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(time.Hour)
	q.SetTimeoutBehavior(TimeoutAutoRelease)
	q.SetProtocolTimeout(envelope.ProtocolWebSocket, 40*time.Millisecond)
	q.SetProtocolBehavior(envelope.ProtocolWebSocket, TimeoutAutoDrop)

	env := wsEnvelope()
	action, err := q.Hold(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if action.Type != ActionDrop {
		t.Errorf("timeout action = %v, want Drop (per-protocol behavior override)", action.Type)
	}
}

// TestHoldQueue_PerProtocol_PartialOverride_TimeoutOnly confirms that a
// protocol entry with only Timeout set still inherits the global
// Behavior. This is the "inherit per-field" guarantee from the design.
func TestHoldQueue_PerProtocol_PartialOverride_TimeoutOnly(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(time.Hour)
	q.SetTimeoutBehavior(TimeoutAutoDrop) // global behavior = drop
	q.SetProtocolTimeout(envelope.ProtocolWebSocket, 40*time.Millisecond)

	env := wsEnvelope()
	action, err := q.Hold(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if action.Type != ActionDrop {
		t.Errorf("timeout action = %v, want Drop (inherits global behavior)", action.Type)
	}
}

// TestHoldQueue_PerProtocol_SetAndClear verifies that ClearProtocolOverride
// fully removes the per-protocol entry and the Envelope falls back to the
// global timeout afterwards.
func TestHoldQueue_PerProtocol_SetAndClear(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(40 * time.Millisecond)
	q.SetProtocolTimeout(envelope.ProtocolWebSocket, time.Hour)

	// Confirm override is in place.
	got := q.ProtocolOverrides()
	if entry, ok := got[envelope.ProtocolWebSocket]; !ok || entry.Timeout == nil || *entry.Timeout != time.Hour {
		t.Fatalf("ProtocolOverrides[ws] = %+v, want Timeout=1h", entry)
	}

	q.ClearProtocolOverride(envelope.ProtocolWebSocket)

	got = q.ProtocolOverrides()
	if _, ok := got[envelope.ProtocolWebSocket]; ok {
		t.Errorf("ProtocolOverrides[ws] should be cleared, got %+v", got[envelope.ProtocolWebSocket])
	}

	// After clear, a WS hold should pick up the short global timeout.
	env := wsEnvelope()
	start := time.Now()
	action, err := q.Hold(context.Background(), env, nil)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if action.Type != ActionRelease {
		t.Errorf("timeout action = %v, want Release", action.Type)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Hold elapsed %s; cleared WS override should fall back to short global", elapsed)
	}
}

// TestHoldQueue_PerProtocol_Concurrent stresses the per-protocol path
// under -race. Workers Hold and another goroutine concurrently mutates
// the override; the test must finish cleanly with the queue empty.
func TestHoldQueue_PerProtocol_Concurrent(t *testing.T) {
	q := NewHoldQueue()
	q.SetMaxItems(50)
	q.SetTimeout(time.Hour)
	q.SetProtocolTimeout(envelope.ProtocolWebSocket, 60*time.Millisecond)

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			env := wsEnvelope()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			q.Hold(ctx, env, nil) //nolint:errcheck
		}()
	}

	// Concurrent reconfigure.
	var rcfg sync.WaitGroup
	rcfg.Add(1)
	go func() {
		defer rcfg.Done()
		for i := 0; i < 50; i++ {
			q.SetProtocolTimeout(envelope.ProtocolWebSocket, 30*time.Millisecond+time.Duration(i)*time.Millisecond)
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()
	rcfg.Wait()
	if q.Len() != 0 {
		t.Errorf("queue not empty after all workers done: %d items", q.Len())
	}
}

// TestHoldQueue_ProtocolOverrideResolved verifies the read-side helper
// that resolves the effective (timeout, behavior) per Protocol with
// global fallback per-field.
func TestHoldQueue_ProtocolOverrideResolved(t *testing.T) {
	q := NewHoldQueue()
	q.SetTimeout(7 * time.Second)
	q.SetTimeoutBehavior(TimeoutAutoDrop)
	q.SetProtocolTimeout(envelope.ProtocolWebSocket, 3*time.Second)
	// WS inherits global behavior (auto_drop).

	timeout, behavior := q.ProtocolOverrideResolved(envelope.ProtocolWebSocket)
	if timeout != 3*time.Second {
		t.Errorf("WS timeout = %v, want 3s", timeout)
	}
	if behavior != TimeoutAutoDrop {
		t.Errorf("WS behavior = %v, want auto_drop (inherited)", behavior)
	}

	// HTTP has no override → both global.
	timeout, behavior = q.ProtocolOverrideResolved(envelope.ProtocolHTTP)
	if timeout != 7*time.Second {
		t.Errorf("HTTP timeout = %v, want 7s (global)", timeout)
	}
	if behavior != TimeoutAutoDrop {
		t.Errorf("HTTP behavior = %v, want auto_drop (global)", behavior)
	}
}
