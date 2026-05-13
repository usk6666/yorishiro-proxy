package common

import (
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestHoldTracker_MarkAndIsHeld(t *testing.T) {
	tr := NewHoldTracker()
	now := time.Now()
	tr.MarkHold("stream-1", envelope.Send, now)

	if !tr.IsHeld("stream-1", envelope.Send) {
		t.Errorf("IsHeld(Send) want true immediately after MarkHold")
	}
	// Distinct direction must not be observed as held.
	if tr.IsHeld("stream-1", envelope.Receive) {
		t.Errorf("IsHeld(Receive) want false; only Send was marked")
	}
	// Distinct stream must not be observed as held.
	if tr.IsHeld("stream-2", envelope.Send) {
		t.Errorf("IsHeld(stream-2, Send) want false; only stream-1 was marked")
	}
}

func TestHoldTracker_ForgetHold(t *testing.T) {
	tr := NewHoldTracker()
	now := time.Now()
	tr.MarkHold("stream-1", envelope.Send, now)
	tr.MarkHold("stream-1", envelope.Receive, now)
	tr.MarkHold("stream-2", envelope.Send, now)

	tr.ForgetHold("stream-1", envelope.Send)
	if tr.IsHeld("stream-1", envelope.Send) {
		t.Errorf("ForgetHold did not evict (stream-1, Send)")
	}
	// Sibling direction untouched.
	if !tr.IsHeld("stream-1", envelope.Receive) {
		t.Errorf("ForgetHold incorrectly evicted (stream-1, Receive)")
	}
	// Sibling stream untouched.
	if !tr.IsHeld("stream-2", envelope.Send) {
		t.Errorf("ForgetHold incorrectly evicted (stream-2, Send)")
	}
}

func TestHoldTracker_ForgetStream(t *testing.T) {
	tr := NewHoldTracker()
	now := time.Now()
	tr.MarkHold("stream-1", envelope.Send, now)
	tr.MarkHold("stream-1", envelope.Receive, now)
	tr.MarkHold("stream-2", envelope.Send, now)

	tr.ForgetStream("stream-1")

	if tr.IsHeld("stream-1", envelope.Send) {
		t.Errorf("ForgetStream did not evict (stream-1, Send)")
	}
	if tr.IsHeld("stream-1", envelope.Receive) {
		t.Errorf("ForgetStream did not evict (stream-1, Receive)")
	}
	if !tr.IsHeld("stream-2", envelope.Send) {
		t.Errorf("ForgetStream evicted stream-2 (should be untouched)")
	}
}

func TestHoldTracker_NilSafe(t *testing.T) {
	var tr *HoldTracker // nil receiver
	tr.MarkHold("stream-1", envelope.Send, time.Now())
	if tr.IsHeld("stream-1", envelope.Send) {
		t.Errorf("nil HoldTracker should return IsHeld=false")
	}
	tr.ForgetHold("stream-1", envelope.Send)
	tr.ForgetStream("stream-1")
	if n := tr.Len(); n != 0 {
		t.Errorf("nil Len = %d, want 0", n)
	}
}

func TestHoldTracker_EmptyStreamID(t *testing.T) {
	tr := NewHoldTracker()
	tr.MarkHold("", envelope.Send, time.Now())
	if n := tr.Len(); n != 0 {
		t.Errorf("empty StreamID should be a no-op, Len = %d", n)
	}
	if tr.IsHeld("", envelope.Send) {
		t.Errorf("empty StreamID lookup must miss")
	}
}

func TestHoldTracker_PruneRetainsRecent(t *testing.T) {
	tr := NewHoldTracker()
	// Older than the 1h retention window: should be pruned on the next
	// MarkHold call.
	old := time.Now().Add(-2 * time.Hour)
	tr.MarkHold("stale", envelope.Send, old)
	tr.MarkHold("fresh", envelope.Send, time.Now())
	if got, want := tr.Len(), 1; got != want {
		t.Errorf("after MarkHold prune, Len = %d, want %d", got, want)
	}
}

// TestHoldTracker_ConcurrentMarkAndPoll exercises the tracker under
// concurrent MarkHold / IsHeld / ForgetHold from many goroutines. The
// assertion is freedom from data race (verified by -race in CI) plus the
// final invariant: after every Mark is paired with a Forget, Len is 0.
func TestHoldTracker_ConcurrentMarkAndPoll(t *testing.T) {
	tr := NewHoldTracker()
	const goroutines = 32
	const iterations = 100

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			streamID := "stream-concurrent"
			direction := envelope.Send
			if id%2 == 0 {
				direction = envelope.Receive
			}
			for i := 0; i < iterations; i++ {
				tr.MarkHold(streamID, direction, time.Now())
				_ = tr.IsHeld(streamID, direction)
				tr.ForgetHold(streamID, direction)
			}
		}(g)
	}
	wg.Wait()
	if got := tr.Len(); got != 0 {
		t.Errorf("after paired Mark/Forget, Len = %d, want 0", got)
	}
}
