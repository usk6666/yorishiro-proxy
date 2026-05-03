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
