package http2

import (
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLayer_Close_EnqueueRaceRegression is the regression test for USK-614.
//
// Before the fix, Layer.Close() held writerMu, closed writerQueue, and set
// writerOpen=false, while enqueueWrite released writerMu between checking
// writerOpen and sending on writerQueue. That window allowed Close() to
// close writerQueue concurrently with an in-flight enqueueWrite send —
// panic("send on closed channel").
//
// The fix (shutdown-first, writer owns queue close) makes the writer
// goroutine the sole owner of writerQueue's lifecycle: Close only signals
// shutdown, the writer drains and exits, writerQueue is never explicitly
// closed. enqueueWrite selects on <-shutdown to fail gracefully.
//
// This test hammers the race: N goroutines concurrently call
// enqueueWrite while another goroutine calls Close. Repeated across many
// iterations, with -race, it reliably caught the old bug and must pass
// 0-failure now.
func TestLayer_Close_EnqueueRaceRegression(t *testing.T) {
	const iterations = 50
	const enqueuers = 32

	for iter := 0; iter < iterations; iter++ {
		runOneCloseRace(t, iter, enqueuers)
	}
}

func runOneCloseRace(t *testing.T, iter, enqueuers int) {
	t.Helper()

	cliConn, srvConn := net.Pipe()

	// Peer-side goroutine: consume the client preface, then drain and
	// discard everything. Exits when srvConn is closed.
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		// Read the 24-byte client preface.
		pf := make([]byte, 24)
		if _, err := io.ReadFull(srvConn, pf); err != nil {
			return
		}
		// Discard the rest forever.
		_, _ = io.Copy(io.Discard, srvConn)
	}()

	l, err := New(cliConn, "race-test", ClientRole)
	if err != nil {
		_ = cliConn.Close()
		_ = srvConn.Close()
		<-peerDone
		t.Fatalf("iter %d: New: %v", iter, err)
	}

	// Safety net: recover so a bug is reported as a test failure rather
	// than crashing the whole test binary. The primary signal is -race
	// flagging a data race; a panic here would indicate a regression.
	var panicCount int64
	var panicMu sync.Mutex
	var panicVals []interface{}

	safe := func(fn func()) {
		defer func() {
			if r := recover(); r != nil {
				atomic.AddInt64(&panicCount, 1)
				panicMu.Lock()
				panicVals = append(panicVals, r)
				panicMu.Unlock()
			}
		}()
		fn()
	}

	var wg sync.WaitGroup
	// Pre-gate all enqueue goroutines so they start together and maximize
	// contention with Close().
	start := make(chan struct{})

	for i := 0; i < enqueuers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			safe(func() {
				// Use a small, harmless write: RST_STREAM on a
				// never-existing stream. No done channel is
				// expected by the writer; failWriteRequest will
				// fail it silently if shutdown races in.
				l.enqueueWrite(writeRequest{rst: &writeRST{
					streamID: 99,
					code:     ErrCodeCancel,
				}})
			})
		}()
	}

	// Closer goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		safe(func() {
			_ = l.Close()
		})
	}()

	// Release all goroutines roughly simultaneously.
	close(start)

	// Bounded wait. If we deadlock we want the race test to fail loudly
	// rather than hang the whole package test.
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("iter %d: goroutines did not finish within 5s (possible deadlock)", iter)
	}

	// Always close both conn ends so peer goroutine exits.
	_ = cliConn.Close()
	_ = srvConn.Close()
	<-peerDone

	if n := atomic.LoadInt64(&panicCount); n > 0 {
		t.Fatalf("iter %d: %d panic(s) during concurrent enqueue+Close: %v", iter, n, panicVals)
	}
}

// TestLayer_Close_EnqueueAfterShutdownNoPanic confirms the post-shutdown
// contract: enqueueWrite after Close() must never panic, must never block
// indefinitely, and the writer goroutine has exited cleanly.
//
// Note: after shutdown, writerQueue may still have buffer capacity, so an
// individual enqueueWrite call's select may nondeterministically take
// either the queue-send branch (request silently orphaned — no done
// signal, since no writer is consuming) or the shutdown branch (done
// signaled with errWriterClosed). Real callers use waitDone() which also
// selects on <-shutdown, so either outcome is safe for them. This test
// just asserts the no-panic / no-block contract.
func TestLayer_Close_EnqueueAfterShutdownNoPanic(t *testing.T) {
	cliConn, srvConn := net.Pipe()

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		pf := make([]byte, 24)
		if _, err := io.ReadFull(srvConn, pf); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, srvConn)
	}()

	l, err := New(cliConn, "after-close", ClientRole)
	if err != nil {
		_ = cliConn.Close()
		_ = srvConn.Close()
		<-peerDone
		t.Fatalf("New: %v", err)
	}

	_ = l.Close()

	// Writer goroutine must have exited after Close (Close joins on it).
	select {
	case <-l.writerDone:
	default:
		t.Fatal("writerDone not closed after Close returned")
	}

	// Drive many post-shutdown enqueues to maximize chance of hitting
	// both select branches under -race. None may panic; all must return
	// (not block) in bounded time.
	const n = 128
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		defer func() {
			// If any enqueue panics, the deferred recover here
			// converts it into a nil return — the outer select
			// timeout path would then also not fire, so the test
			// passes. But we want to actually flag panic, so
			// re-raise.
			if r := recover(); r != nil {
				panic(r)
			}
		}()
		for i := 0; i < n; i++ {
			l.enqueueWrite(writeRequest{rst: &writeRST{
				streamID: uint32(i + 1),
				code:     ErrCodeCancel,
			}})
		}
	}()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("post-shutdown enqueueWrite batch blocked (possible regression)")
	}

	_ = srvConn.Close()
	<-peerDone
}

// TestLayer_Close_NoWriterGoroutineLeak verifies the writer goroutine
// terminates after Close, in a dedicated goroutine-leak check separate
// from TestLayer_Close_NoGoroutineLeak (which tests the full stack).
func TestLayer_Close_NoWriterGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	cliConn, srvConn := net.Pipe()
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		pf := make([]byte, 24)
		if _, err := io.ReadFull(srvConn, pf); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, srvConn)
	}()

	l, err := New(cliConn, "leak-check", ClientRole)
	if err != nil {
		_ = cliConn.Close()
		_ = srvConn.Close()
		<-peerDone
		t.Fatalf("New: %v", err)
	}
	_ = l.Close()
	_ = srvConn.Close()
	<-peerDone

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	if after > before+1 {
		t.Errorf("goroutine leak: before=%d after=%d", before, after)
	}
}
