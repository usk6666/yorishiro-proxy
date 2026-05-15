package http2

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWaitDone_ShutdownVsDoneRace is the regression test for USK-812.
//
// Before the fix, waitDone selected on done / ctx.Done / shutdown with no
// preference. When shutdown closed concurrently with a write that was
// queued (or already completed by the writer), Go's pseudo-random select
// could pick the shutdown branch and return ErrWriterClosed even though
// the writer's drain branch (writerLoop's `case <-l.shutdown:`) would
// still process the queued request and call deliverDone(nil).
//
// This surfaced as the
// TestE2E_LiveGRPCWeb_DispatchDeliversEnvelope/binary_proto flake on the
// CI smoke gate: the response HEADERS+DATA frames hit the wire (cli.Do
// returned matching bytes) but the proxy recorded the Stream as
// state=error because waitDone returned ErrWriterClosed for a write that
// had completed successfully.
//
// The fix: when shutdown fires, block on `<-done` so the writer's
// authoritative result wins. failWriteRequest writes done in the
// "request was never queued" path; the writer's drain loop writes done
// in the "request was queued" path. Either way done fires.
//
// This test directly exercises waitDone (not through the full Layer) by
// driving a buffered done channel and a shutdown chan in three timing
// patterns:
//
//   - shutdown closes BEFORE done has a value but writer eventually
//     delivers (the production flake pattern). waitDone must return the
//     delivered value, not ErrWriterClosed.
//   - shutdown closes AFTER done already has a value (the buffered
//     value sits waiting). waitDone must return the delivered value.
//   - both fire concurrently many times. waitDone must never return
//     ErrWriterClosed when done eventually has a value.
//
// Timing-sensitive; requires -race for the strongest signal but the test
// also asserts return values directly.
func TestWaitDone_ShutdownVsDoneRace(t *testing.T) {
	t.Run("shutdown_first_then_done", func(t *testing.T) {
		done := make(chan error, 1)
		shutdown := make(chan struct{})

		// Close shutdown immediately.
		close(shutdown)

		// Writer delivers AFTER shutdown closed (mimics the production
		// failure mode where the writerLoop's drain branch processes the
		// already-queued request after `<-l.shutdown`).
		go func() {
			time.Sleep(5 * time.Millisecond)
			done <- nil // simulate successful wire write
		}()

		err := waitDone(context.Background(), done, shutdown)
		if err != nil {
			t.Fatalf("waitDone returned err=%v after writer-delivered nil; want nil (the bug returned ErrWriterClosed)", err)
		}
	})

	t.Run("done_first_then_shutdown", func(t *testing.T) {
		done := make(chan error, 1)
		shutdown := make(chan struct{})

		// Writer delivers FIRST, then shutdown closes.
		done <- nil
		close(shutdown)

		err := waitDone(context.Background(), done, shutdown)
		if err != nil {
			t.Fatalf("waitDone returned err=%v with buffered done=nil and shutdown closed; want nil", err)
		}
	})

	t.Run("writer_returned_real_error_then_shutdown", func(t *testing.T) {
		// Sanity: real wire errors must still surface.
		done := make(chan error, 1)
		shutdown := make(chan struct{})

		realErr := errors.New("simulated wire error")
		done <- realErr
		close(shutdown)

		err := waitDone(context.Background(), done, shutdown)
		if !errors.Is(err, realErr) {
			t.Fatalf("waitDone returned err=%v; want wraps %v", err, realErr)
		}
	})

	t.Run("never_queued_then_shutdown", func(t *testing.T) {
		// Mirrors the enqueueWrite path where failWriteRequest writes
		// ErrWriterClosed onto done before close(shutdown).
		done := make(chan error, 1)
		shutdown := make(chan struct{})

		done <- ErrWriterClosed
		close(shutdown)

		err := waitDone(context.Background(), done, shutdown)
		if !errors.Is(err, ErrWriterClosed) {
			t.Fatalf("waitDone returned err=%v; want ErrWriterClosed", err)
		}
	})

	t.Run("ctx_cancelled_then_done", func(t *testing.T) {
		// ctx cancellation should surface promptly (not block on done) but
		// must still prefer a buffered done value if present.
		done := make(chan error, 1)
		shutdown := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())

		done <- nil // already delivered
		cancel()

		err := waitDone(ctx, done, shutdown)
		if err != nil {
			t.Fatalf("waitDone returned err=%v with buffered done=nil and ctx cancelled; want nil", err)
		}
	})

	t.Run("ctx_cancelled_no_done", func(t *testing.T) {
		// ctx cancellation with no done value should return ctx.Err().
		done := make(chan error, 1)
		shutdown := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())

		cancel()

		err := waitDone(ctx, done, shutdown)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waitDone returned err=%v; want context.Canceled", err)
		}
	})
}

// TestWaitDone_ShutdownVsDoneRace_Hammer hammers the close-vs-write race
// at the same scale as USK-798 / USK-614 close_race_test (N=32 × 50
// iterations). For each iteration: spawn N goroutines each running
// waitDone with its own done/shutdown pair, race the writer goroutine
// closing shutdown against delivering done. None of the waitDone returns
// may surface ErrWriterClosed when the writer DID call deliverDone(nil).
func TestWaitDone_ShutdownVsDoneRace_Hammer(t *testing.T) {
	const iterations = 50
	const concurrency = 32

	for iter := 0; iter < iterations; iter++ {
		runOneWaitDoneRace(t, iter, concurrency)
	}
}

func runOneWaitDoneRace(t *testing.T, iter, concurrency int) {
	t.Helper()

	var wg sync.WaitGroup
	var falsePositives int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			done := make(chan error, 1)
			shutdown := make(chan struct{})

			// Writer goroutine: simulate the production race by closing
			// shutdown and delivering done in rapid succession with
			// nondeterministic ordering. The writerLoop's drain branch
			// guarantees that for any queued request, deliverDone fires
			// regardless of when shutdown closed.
			go func() {
				close(shutdown)
				done <- nil
			}()

			err := waitDone(context.Background(), done, shutdown)
			if errors.Is(err, ErrWriterClosed) {
				atomic.AddInt64(&falsePositives, 1)
			}
		}()
	}

	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("iter %d: waitDone hammer did not finish within 5s (possible block on <-done)", iter)
	}

	if n := atomic.LoadInt64(&falsePositives); n > 0 {
		t.Fatalf("iter %d: %d/%d waitDone returns surfaced ErrWriterClosed despite writer delivering nil", iter, n, concurrency)
	}
}
