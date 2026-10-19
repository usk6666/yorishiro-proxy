//go:build e2e && !e2e_smoke

package proxybuild

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1213: the load-dependent stress twin of
// TestConnectionRejections_DrainerRecheckAfterRelease (USK-1142) runs in
// the exhaustive (nightly) tier. It spends a fixed 2 s budget per run and
// only hits the release/enqueue window when the scheduler cooperates, so
// it is not a per-PR signal; the deterministic seam test in
// connection_rejections_test.go stays in the fast tier.

// countingFlowStore counts SaveStream calls and closes all once want
// streams have been saved.
type countingFlowStore struct {
	n    atomic.Int64
	want int64
	all  chan struct{}
}

func (s *countingFlowStore) SaveStream(context.Context, *flow.Stream) error {
	if s.n.Add(1) == s.want {
		close(s.all)
	}
	return nil
}

func (s *countingFlowStore) UpdateStream(context.Context, string, flow.StreamUpdate) error {
	return nil
}
func (s *countingFlowStore) SaveFlow(context.Context, *flow.Flow) error { return nil }

// TestConnectionRejections_DrainerRecheckStress exercises the same
// release/enqueue window under the real scheduler: many short rounds of
// concurrent producers on several independent aggregators, with no rate
// cap and a queue large enough for every record, so every record must be
// written. Hitting the window needs the drainer to be descheduled between
// finding the queue empty and releasing ownership, so this test is
// load-dependent; DrainerRecheckAfterRelease is the deterministic guard.
func TestConnectionRejections_DrainerRecheckStress(t *testing.T) {
	const workers = 4
	budget := time.Now().Add(2 * time.Second)

	var failed atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for round := 0; !failed.Load() && time.Now().Before(budget); round++ {
				if err := drainerReleaseRound(); err != nil {
					failed.Store(true)
					t.Errorf("worker %d round %d: %v", w, round, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// drainerReleaseRound runs 8 concurrent producers of 6 rejections each
// against a fresh aggregator and returns an error unless every record is
// written.
func drainerReleaseRound() error {
	const producers, per = 8, 6
	const total = producers * per
	store := &countingFlowStore{want: total, all: make(chan struct{})}
	c := NewConnectionRejections(ConnectionRejectionsConfig{
		Store:       store,
		Logger:      silentLogger(),
		RecordRate:  rate.Inf,
		RecordBurst: total,
		QueueSize:   total,
	})
	defer c.Close()

	start := make(chan struct{})
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			<-start
			for i := 0; i < per; i++ {
				c.Record(connectReject(p*per+i, "race.example:443"))
				runtime.Gosched()
			}
		}(p)
	}
	close(start)
	wg.Wait()

	select {
	case <-store.all:
	case <-time.After(2 * time.Second):
		return fmt.Errorf("saved=%d want %d; queue len=%d (record stranded after drainer release)",
			store.n.Load(), total, len(c.queue))
	}
	if snap := c.Snapshot(); snap.Unrecorded != 0 {
		return fmt.Errorf("Unrecorded = %d, want 0 (nothing may be shed here)", snap.Unrecorded)
	}
	return nil
}
