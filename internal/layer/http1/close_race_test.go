package http1

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestChannel_Close_DeliverResponseRace is the regression test for USK-798.
//
// Before the fix, channel.responseReady was concurrently close()d (from
// channel.Close → closeResponseReady, e.g. via cascade-close in
// session.clientToUpstream's defer) and chansend-ed (from
// channel.deliverResponse running in Layer.spawnLoopReceive). The previous
// recover()-based suppression in deliverResponse caught the resulting panic
// but did not eliminate the underlying memory data race that -race detected
// reliably under load (CI smoke flake on TestHTTPSMITM_LargeBodyChunkedTrailers).
//
// The fix (responseReadyMu + responseReadyClosed atomic + closeOnce) makes
// close-vs-send mutually exclusive. Close() sequences markTerminated →
// closeResponseReady so a producer blocked in the send-select unblocks via
// termDone before the mutex acquisition.
//
// This test hammers the race: N goroutines concurrently call deliverResponse
// while another goroutine calls Close. Repeated across many iterations, with
// -race, it reliably caught the old bug and must pass 0-failure now.
func TestChannel_Close_DeliverResponseRace(t *testing.T) {
	const iterations = 50
	const senders = 32

	for iter := 0; iter < iterations; iter++ {
		runOneDeliverCloseRace(t, iter, senders)
	}
}

func runOneDeliverCloseRace(t *testing.T, iter, senders int) {
	t.Helper()

	// Build a channel with the same shape Layer.newChannelLocked uses, but
	// without a parent Layer — deliverResponse / closeResponseReady / Close
	// only touch responseReady, responseReadyMu, responseReadyClosed,
	// closeOnce, termDone, termOnce, termMu, emittedFlowIDs, releaseReader's
	// readerReleased — none of which require a Layer.
	ch := &channel{
		direction:      envelope.Receive,
		responseReady:  make(chan responseDelivery, 4),
		termDone:       make(chan struct{}),
		readerReleased: make(chan struct{}),
	}

	// Recover so a regression panic is reported as a test failure rather
	// than crashing the whole test binary. Primary signal is -race; a panic
	// here would indicate the structural guard regressed.
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
	start := make(chan struct{})

	// Senders: each calls deliverResponse with a 1xx envelope (no terminal
	// close), then a final-status envelope (which itself triggers a close).
	// Mixing both shapes exercises both the err-path and the env-path send
	// branches.
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			safe(func() {
				// 1xx informational — no terminal close on this path.
				env1xx := &envelope.Envelope{
					Direction: envelope.Receive,
					Protocol:  envelope.ProtocolHTTP,
					Message:   &envelope.HTTPMessage{Status: 100},
				}
				ch.deliverResponse(env1xx, nil)
				// Final 200 — triggers terminal close inside deliverResponse.
				env200 := &envelope.Envelope{
					Direction: envelope.Receive,
					Protocol:  envelope.ProtocolHTTP,
					Message:   &envelope.HTTPMessage{Status: 200},
				}
				ch.deliverResponse(env200, nil)
			})
		}(i)
	}

	// Closer: races against the senders.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		safe(func() {
			_ = ch.Close()
		})
	}()

	close(start)

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

	if n := atomic.LoadInt64(&panicCount); n > 0 {
		t.Fatalf("iter %d: %d panic(s) during concurrent deliverResponse+Close: %v", iter, n, panicVals)
	}
}

// TestChannel_Close_DeliverResponseError_Race exercises the err-path branch of
// deliverResponse (the early return before the env-path send-select) against
// a concurrent Close. The err-path takes a different code path inside
// deliverResponse, so it deserves its own race exercise.
func TestChannel_Close_DeliverResponseError_Race(t *testing.T) {
	const iterations = 50
	const senders = 32

	for iter := 0; iter < iterations; iter++ {
		ch := &channel{
			direction:      envelope.Receive,
			responseReady:  make(chan responseDelivery, 4),
			termDone:       make(chan struct{}),
			readerReleased: make(chan struct{}),
		}

		var wg sync.WaitGroup
		start := make(chan struct{})

		var panicCount int64
		safe := func(fn func()) {
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt64(&panicCount, 1)
				}
			}()
			fn()
		}

		for i := 0; i < senders; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				safe(func() {
					ch.deliverResponse(nil, errSimulatedTerminal)
				})
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			safe(func() {
				_ = ch.Close()
			})
		}()

		close(start)

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
		if n := atomic.LoadInt64(&panicCount); n > 0 {
			t.Fatalf("iter %d: %d panic(s) during concurrent deliverResponse(err)+Close", iter, n)
		}
	}
}

var errSimulatedTerminal = &simulatedErr{msg: "simulated terminal"}

type simulatedErr struct{ msg string }

func (e *simulatedErr) Error() string { return e.msg }
