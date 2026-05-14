//go:build e2e && !e2e_smoke

// USK-885 (exhaustive tier): additional SSE close-transition scenarios.
// These cover the client-initiated-close and forced-abort paths that
// the smoke-tier TestSSE_GracefulUpstreamClose_StateComplete does not.
//
// Tier rationale: graceful upstream close is the per-PR regression
// guard (smoke); client-initiated close and ctx-cancel paths are
// watched nightly to keep CI fast.
package sse_test

import (
	"fmt"
	"testing"
	"time"
)

// TestSSE_ClientCloseBeforeUpstream_StateComplete asserts that when the
// browser closes the TCP connection before the upstream's chunked
// terminator (e.g. user hits Ctrl-C on `curl -N` after the first event),
// runUpgradeSSE's client-side watcher fires, the centralised teardown
// closes the upstream body, the parser unblocks with a transport
// error, and the watcher's verdict — graceful client close — wins:
// state=complete, duration_ms > 0.
//
// Pre-USK-885 the SSE Stream stayed at state=active in this scenario;
// the parser was blocked inside body.Read and ctx cancellation never
// reached it because http1's body.Read does not honor ctx.
func TestSSE_ClientCloseBeforeUpstream_StateComplete(t *testing.T) {
	h := newSSECloseHarness(t)

	const event = "event: ping\ndata: %d\nid: %d\n\n"

	// Upstream streams indefinitely (one event per 50ms) so the only way
	// for runUpgradeSSE to terminate is via the client-side watcher.
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		buf := make([]byte, 4096)
		_, _ = h.upstreamB.Read(buf)
		_, _ = h.upstreamB.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"\r\n"))
		// Stream events until the upstream conn is closed by the proxy.
		for i := 1; ; i++ {
			if _, werr := fmt.Fprintf(h.upstreamB, event, i, i); werr != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			if i > 1000 {
				return // safety cap; the test should have aborted long before
			}
		}
	}()

	start := time.Now()
	h.run(t, 5*time.Second)

	// Phase 1: send GET + drain 200 OK headers + half-close write to fire
	// the SSE swap. driveBrowserPhase1 must run before waitForSwap because
	// the swap can only fire after the proxy parses a request.
	prior := h.driveBrowserPhase1(t)
	h.waitForSwap(t, 3*time.Second)

	// Drain at least one event so we know the swap is mid-stream.
	_ = h.drainBrowser(t, prior, 1, 2*time.Second)

	// Phase 2: full-close the client side. This must unblock the
	// runUpgradeSSE client-watcher, which then cascades the upstream
	// body close so the parser unblocks and runUpgradeSSE returns.
	_ = h.clientA.Close()

	h.waitDone(t, 3*time.Second)
	elapsed := time.Since(start)

	streams := h.store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	st := streams[0]
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want %q (client-initiated graceful close should transition to complete)", st.State, "complete")
	}
	if st.Duration <= 0 {
		t.Errorf("Stream.Duration = %v, want > 0 (duration_ms must be populated)", st.Duration)
	}
	if elapsed >= 4*time.Second {
		t.Errorf("RunStackSession took %v; client-watcher cascade is too slow or not firing", elapsed)
	}

	// Allow the upstream writer goroutine to terminate.
	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
		// The upstream writer exits when its conn write returns an
		// error; if the proxy closed the upstream side promptly, the
		// goroutine should be near-done. Don't fail the test on a
		// slow-cleanup goroutine — its terminal write would just
		// log-error in production.
	}
}

// TestSSE_ForcedAbort_StateError verifies that context cancellation
// mid-stream classifies as state=error. This is the regression guard for
// the existing forced-abort path (curl --max-time, OS signal, ctx
// timeout) — pre-USK-885 it correctly produced state=error; we want to
// confirm USK-885's close-watcher refactor preserves this behaviour.
func TestSSE_ForcedAbort_StateError(t *testing.T) {
	h := newSSECloseHarness(t)

	const event = "event: ping\ndata: %d\nid: %d\n\n"

	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		buf := make([]byte, 4096)
		_, _ = h.upstreamB.Read(buf)
		_, _ = h.upstreamB.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"\r\n"))
		for i := 1; ; i++ {
			if _, werr := fmt.Fprintf(h.upstreamB, event, i, i); werr != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			if i > 1000 {
				return
			}
		}
	}()

	h.run(t, 5*time.Second)

	prior := h.driveBrowserPhase1(t)
	h.waitForSwap(t, 3*time.Second)
	_ = h.drainBrowser(t, prior, 1, 2*time.Second)

	// Cancel the session context — this is the "curl --max-time"
	// equivalent. With USK-885 the ctx.Done() arm of the select in
	// runUpgradeSSE fires, abort cascades both closes, and the
	// returned error is ctx.Err() — which OnComplete classifies as
	// state=error.
	if h.cancel != nil {
		h.cancel()
	}

	h.waitDone(t, 3*time.Second)

	streams := h.store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	st := streams[0]
	if st.State != "error" {
		t.Errorf("Stream.State = %q, want %q (forced abort must remain state=error)", st.State, "error")
	}
	// Note: FailureReason intentionally not asserted. session.ClassifyError
	// returns "" for plain context.Canceled / DeadlineExceeded (only
	// *layer.StreamError wrappers get a canonical taxonomy label —
	// "canceled", "aborted", "internal_error", "refused",
	// "protocol_error"). The ctx-cancel error here is a session-level
	// control-flow signal, not a wire-observed protocol error, so
	// FailureReason="" is the documented behaviour. The state=error
	// projection on a non-EOF error is what matters for the Issue.

	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
	}
}

// Note on protocol-violation classification: USK-885's implementation
// approach is the clientWriteEOFSink in session.go, which converts any
// client-side write failure into io.EOF on the io.TeeReader read side
// driving the SSE parser. This is sufficient for the Issue acceptance
// gate ("client/upstream どちらが close しても state=complete") because
// SSE is half-duplex post-upgrade — the proxy's only observable signal
// for client disposition is the write path, and any failure there means
// the client is gone (graceful or otherwise). A dedicated client-bytes-
// post-upgrade test was considered but is unreachable in realistic TCP
// usage: the swap requires CloseWrite from the client (so the OS
// prevents subsequent writes), and a custom non-conforming transport
// would be required to exercise the half-duplex-violation branch.
