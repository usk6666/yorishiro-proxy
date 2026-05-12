package common

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestReleaseTracker_MarkAndLookupOpposite(t *testing.T) {
	tr := NewReleaseTracker()
	now := time.Now()
	tr.MarkRelease("stream-1", envelope.Send, now)

	// Same direction does NOT correlate — we only look at the opposite.
	if _, ok := tr.LookupOppositeRelease("stream-1", envelope.Send, now, 2*time.Second); ok {
		t.Errorf("LookupOppositeRelease(Send) should not match a Send-side release")
	}
	ts, ok := tr.LookupOppositeRelease("stream-1", envelope.Receive, now, 2*time.Second)
	if !ok {
		t.Fatalf("LookupOppositeRelease(Receive) want match within window, got none")
	}
	if !ts.Equal(now) {
		t.Errorf("LookupOppositeRelease ts = %v, want %v", ts, now)
	}
}

func TestReleaseTracker_WindowExpiry(t *testing.T) {
	tr := NewReleaseTracker()
	past := time.Now().Add(-3 * time.Second)
	tr.MarkRelease("stream-1", envelope.Send, past)
	now := past.Add(3 * time.Second)
	// Outside the 2s detection window.
	if _, ok := tr.LookupOppositeRelease("stream-1", envelope.Receive, now, 2*time.Second); ok {
		t.Errorf("LookupOppositeRelease should drop entries older than window")
	}
	// Inside a relaxed window.
	if _, ok := tr.LookupOppositeRelease("stream-1", envelope.Receive, now, 5*time.Second); !ok {
		t.Errorf("LookupOppositeRelease with 5s window should still see the entry")
	}
}

func TestReleaseTracker_ForgetStream(t *testing.T) {
	tr := NewReleaseTracker()
	now := time.Now()
	tr.MarkRelease("stream-1", envelope.Send, now)
	tr.MarkRelease("stream-1", envelope.Receive, now)
	tr.MarkRelease("stream-2", envelope.Send, now)

	tr.ForgetStream("stream-1")

	if _, ok := tr.LookupOppositeRelease("stream-1", envelope.Receive, now, time.Second); ok {
		t.Errorf("ForgetStream did not evict stream-1 Send entry")
	}
	if _, ok := tr.LookupOppositeRelease("stream-1", envelope.Send, now, time.Second); ok {
		t.Errorf("ForgetStream did not evict stream-1 Receive entry")
	}
	if _, ok := tr.LookupOppositeRelease("stream-2", envelope.Receive, now, time.Second); !ok {
		t.Errorf("ForgetStream evicted stream-2 (should be untouched)")
	}
}

func TestReleaseTracker_NilSafe(t *testing.T) {
	var tr *ReleaseTracker // nil receiver
	tr.MarkRelease("stream-1", envelope.Send, time.Now())
	if _, ok := tr.LookupOppositeRelease("stream-1", envelope.Receive, time.Now(), time.Second); ok {
		t.Errorf("nil ReleaseTracker should return ok=false")
	}
	tr.ForgetStream("stream-1")
	if n := tr.Len(); n != 0 {
		t.Errorf("nil Len = %d, want 0", n)
	}
}

func TestReleaseTracker_PruneRetainsRecent(t *testing.T) {
	tr := NewReleaseTracker()
	old := time.Now().Add(-20 * time.Second) // older than 10s retention
	tr.MarkRelease("stale", envelope.Send, old)
	tr.MarkRelease("fresh", envelope.Send, time.Now())
	if got, want := tr.Len(), 1; got != want {
		t.Errorf("after MarkRelease prune, Len = %d, want %d", got, want)
	}
}

func TestReleaseTracker_EmptyStreamID(t *testing.T) {
	tr := NewReleaseTracker()
	tr.MarkRelease("", envelope.Send, time.Now())
	if n := tr.Len(); n != 0 {
		t.Errorf("empty StreamID should be a no-op, Len = %d", n)
	}
}

func TestReleaseTracker_LookupAndForgetOpposite(t *testing.T) {
	tr := NewReleaseTracker()
	now := time.Now()
	tr.MarkRelease("stream-1", envelope.Send, now)

	// Same direction does not correlate.
	if _, ok := tr.LookupAndForgetOpposite("stream-1", envelope.Send, now, 2*time.Second); ok {
		t.Errorf("LookupAndForgetOpposite(Send) should not match a Send-side release")
	}
	// Opposite direction hits and atomically clears.
	ts, ok := tr.LookupAndForgetOpposite("stream-1", envelope.Receive, now, 2*time.Second)
	if !ok {
		t.Fatalf("LookupAndForgetOpposite(Receive) want match within window, got none")
	}
	if !ts.Equal(now) {
		t.Errorf("LookupAndForgetOpposite ts = %v, want %v", ts, now)
	}
	// Second call must miss because the first cleared the entry.
	if _, ok := tr.LookupAndForgetOpposite("stream-1", envelope.Receive, now, 2*time.Second); ok {
		t.Errorf("second LookupAndForgetOpposite(Receive) should miss after atomic clear")
	}
	// Both directions are wiped, so the symmetric direction also misses.
	if _, ok := tr.LookupAndForgetOpposite("stream-1", envelope.Send, now, 2*time.Second); ok {
		t.Errorf("LookupAndForgetOpposite(Send) should also miss after atomic clear")
	}
	if n := tr.Len(); n != 0 {
		t.Errorf("after atomic clear, Len = %d, want 0", n)
	}
}

func TestReleaseTracker_LookupAndForgetOpposite_WindowExpiry(t *testing.T) {
	tr := NewReleaseTracker()
	past := time.Now().Add(-3 * time.Second)
	tr.MarkRelease("stream-1", envelope.Send, past)
	now := past.Add(3 * time.Second)
	// Outside the 2s detection window: no hit, no clear.
	if _, ok := tr.LookupAndForgetOpposite("stream-1", envelope.Receive, now, 2*time.Second); ok {
		t.Errorf("LookupAndForgetOpposite should drop entries older than window")
	}
}

func TestReleaseTracker_LookupAndForgetOpposite_NilSafe(t *testing.T) {
	var tr *ReleaseTracker
	if _, ok := tr.LookupAndForgetOpposite("stream-1", envelope.Receive, time.Now(), time.Second); ok {
		t.Errorf("nil receiver should return ok=false")
	}
}

// TestReleaseTracker_LookupAndForgetOpposite_AtomicOnce verifies that two
// concurrent callers racing on the opposite direction of the same Stream
// observe the entry at most once. This is the at-most-once contract the
// session.checkInterceptReleaseEOF callback relies on.
func TestReleaseTracker_LookupAndForgetOpposite_AtomicOnce(t *testing.T) {
	const goroutines = 64
	for trial := 0; trial < 50; trial++ {
		tr := NewReleaseTracker()
		now := time.Now()
		tr.MarkRelease("stream-1", envelope.Send, now)

		var hits int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, ok := tr.LookupAndForgetOpposite("stream-1", envelope.Receive, now, 2*time.Second); ok {
					atomic.AddInt32(&hits, 1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := atomic.LoadInt32(&hits); got != 1 {
			t.Fatalf("trial %d: hits = %d, want exactly 1", trial, got)
		}
	}
}
