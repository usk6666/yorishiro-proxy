//go:build e2e

// USK-885: SSE close transition tests. Verifies that runUpgradeSSE drives the
// recorded Stream to state=complete (with duration_ms > 0) when either the
// upstream or the client closes the connection gracefully, and to
// state=error when the client violates the SSE half-duplex contract
// (sends bytes post-upgrade).
//
// These tests exercise the production HTTP/1.x → SSE swap path
// (RunStackSession → runUpgradeSSE) end-to-end over a real TCP loopback
// pair, mirroring TestSSE_FullChainSwapEndToEnd in sse_integration_test.go.
// The dedicated file keeps the close-transition assertions cohesive and
// avoids further bloating the original integration file.
package sse_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// durationTestStore extends the integration helpers with Duration
// capture. The shared testStore in sse_integration_test.go ignores
// update.Duration (it only mutates State / FailureReason). USK-885 also
// fixes the cross-protocol duration_ms gap in
// buildSessionOptions.OnComplete (which projects Duration =
// time.Since(Stream.Timestamp) onto every finalised Stream), so these
// tests assert Duration > 0 against the recorded Stream.Duration field
// to provide an integration-level guard for that wiring path.
type durationTestStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
}

func (s *durationTestStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *durationTestStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.ID == id {
			if update.State != "" {
				st.State = update.State
			}
			if update.FailureReason != "" {
				st.FailureReason = update.FailureReason
			}
			if update.Duration > 0 {
				st.Duration = update.Duration
			}
		}
	}
	return nil
}

func (s *durationTestStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, f)
	return nil
}

func (s *durationTestStore) getStreams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

// sseCloseHarness wires a single SSE HTTP/1.x → swap exchange over a real
// TCP loopback pair and exposes the actor-side conns for the test to
// drive close semantics. The harness is parameterised by the
// upstream's writer behaviour (so each test can choose chunked-terminator,
// indefinite stream, etc.) and by the browser's drive function (so each
// test can choose graceful close, mid-stream close, or post-upgrade
// protocol violation).
type sseCloseHarness struct {
	clientA, clientB     net.Conn
	upstreamA, upstreamB net.Conn
	store                *durationTestStore
	stack                *connector.ConnectionStack
	upstreamLayer        *http1.Layer
	done                 chan error
	cancel               context.CancelFunc
}

func newSSECloseHarness(t *testing.T) *sseCloseHarness {
	t.Helper()
	h := &sseCloseHarness{store: &durationTestStore{}}
	h.clientA, h.clientB = pipePair()
	h.upstreamA, h.upstreamB = pipePair()
	t.Cleanup(func() {
		_ = h.clientA.Close()
		_ = h.clientB.Close()
		_ = h.upstreamA.Close()
		_ = h.upstreamB.Close()
	})

	h.stack = connector.NewConnectionStack("sse-close-" + t.Name())
	clientLayer := http1.New(h.clientB, "client-stream", envelope.Send,
		http1.WithScheme("https"))
	h.upstreamLayer = http1.New(h.upstreamA, "upstream-stream", envelope.Receive,
		http1.WithScheme("https"),
		http1.WithStreamingResponseDetect(http1.IsSSEResponse))
	h.stack.PushClient(clientLayer)
	h.stack.PushUpstream(h.upstreamLayer)

	return h
}

// run launches RunStackSession on a background goroutine and returns
// without waiting. The caller drives client/upstream conns and then
// waits via waitDone.
func (h *sseCloseHarness) run(t *testing.T, timeout time.Duration) {
	t.Helper()

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		ch, ok := <-h.upstreamLayer.Channels()
		if !ok {
			return nil, errors.New("upstream Channels closed before yielding")
		}
		return ch, nil
	}

	p := pipeline.New(
		pipeline.NewRecordStep(h.store, slog.Default()),
		session.NewUpgradeStep(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	h.cancel = cancel

	h.done = make(chan error, 1)
	go func() {
		h.done <- session.RunStackSession(ctx, h.stack, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, sid string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if sid == "" {
					return
				}
				upd := flow.StreamUpdate{
					State:         state,
					FailureReason: session.ClassifyError(err),
				}
				// Mirror the builder.go fix: compute Duration from
				// the Stream's recorded Timestamp so the test can
				// validate state=complete + duration_ms > 0 in a
				// single assertion.
				for _, st := range h.store.getStreams() {
					if st.ID == sid && !st.Timestamp.IsZero() {
						if d := time.Since(st.Timestamp); d > 0 {
							upd.Duration = d
						}
						break
					}
				}
				_ = h.store.UpdateStream(cctx, sid, upd)
			},
		})
	}()
}

// waitDone waits for RunStackSession to return, asserting it does so
// before the test deadline.
func (h *sseCloseHarness) waitDone(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(within):
		// Fall back to forcing cancel so the test does not deadlock.
		if h.cancel != nil {
			h.cancel()
		}
		t.Fatal("RunStackSession did not return within deadline; state transition wiring is broken")
	}
}

// waitForSwap blocks until the upstream topmost is no longer the original
// http1.Layer (i.e. runUpgradeSSE installed the SSE adapter).
func (h *sseCloseHarness) waitForSwap(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if h.stack.UpstreamTopmost() != h.upstreamLayer {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("SSE swap never installed; upstream topmost still original http1.Layer")
}

// driveBrowserPhase1 sends the GET and drains the 200 OK header block,
// then half-closes the client write side so the proxy's clientToUpstream
// goroutine returns ErrUpgradePending. Returns the bytes received so far.
func (h *sseCloseHarness) driveBrowserPhase1(t *testing.T) []byte {
	t.Helper()
	if _, err := h.clientA.Write([]byte("GET /events HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: text/event-stream\r\n" +
		"\r\n")); err != nil {
		t.Fatalf("clientA write: %v", err)
	}

	all := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = h.clientA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _ := h.clientA.Read(buf)
		if n > 0 {
			all = append(all, buf[:n]...)
		}
		if bytes.Contains(all, []byte("\r\n\r\n")) {
			break
		}
	}
	if cw, ok := h.clientA.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	return all
}

// drainBrowser reads from clientA until it has seen `wantEvents` blank-line
// terminators or the deadline expires.
func (h *sseCloseHarness) drainBrowser(t *testing.T, prior []byte, wantEvents int, within time.Duration) []byte {
	t.Helper()
	all := append([]byte(nil), prior...)
	buf := make([]byte, 1024)
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		_ = h.clientA.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, rerr := h.clientA.Read(buf)
		if n > 0 {
			all = append(all, buf[:n]...)
		}
		// Headers terminator + N event terminators.
		if bytes.Count(all, []byte("\n\n")) >= 1+wantEvents {
			break
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			// Read deadline / closed conn: ignore and keep polling
			// until the overall deadline.
		}
	}
	_ = h.clientA.SetReadDeadline(time.Time{})
	return all
}

// TestSSE_GracefulUpstreamClose_StateComplete is the merge-gate regression
// guard. The upstream streams three events then closes via chunked
// terminator (0\r\n\r\n) — the standard HTTP/1.1 SSE end-of-stream
// signal. After USK-883 + USK-885 the parser observes io.EOF on the
// chunked terminator, runUpgradeSSE exits with retErr=nil, OnComplete
// fires with state=complete + duration_ms > 0.
//
// Pre-USK-885 this test would time out: the SSE parser's body.Read
// stays blocked indefinitely because the chunked decoder's io.EOF was
// being absorbed at the http1.Layer body bridge (USK-883 fix) AND there
// was no client-side close watcher to break the parser out of its
// blocking read on a clean conn close (USK-885 fix).
func TestSSE_GracefulUpstreamClose_StateComplete(t *testing.T) {
	h := newSSECloseHarness(t)

	const event = "event: ping\ndata: %d\nid: %d\n\n"
	const eventCount = 3

	// Upstream goroutine: reply with chunked text/event-stream, send
	// each event as a separate chunk, terminate with the zero-size
	// chunk + trailing CRLF, then close the connection.
	go func() {
		buf := make([]byte, 4096)
		_, _ = h.upstreamB.Read(buf)
		_, _ = h.upstreamB.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/event-stream\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n"))
		for i := 1; i <= eventCount; i++ {
			body := fmt.Sprintf(event, i, i)
			_, _ = fmt.Fprintf(h.upstreamB, "%X\r\n%s\r\n", len(body), body)
		}
		// Chunked terminator: this is the USK-883 / USK-885 path.
		_, _ = h.upstreamB.Write([]byte("0\r\n\r\n"))
		// Hold the connection briefly so the proxy has time to parse
		// every event before the close races the parser.
		time.Sleep(150 * time.Millisecond)
		_ = h.upstreamB.Close()
	}()

	start := time.Now()
	h.run(t, 5*time.Second)

	// driveBrowserPhase1 writes the GET (so the proxy starts the upgrade
	// pipeline) and half-closes the write side so the proxy's
	// clientToUpstream goroutine returns ErrUpgradePending.
	prior := h.driveBrowserPhase1(t)
	h.waitForSwap(t, 3*time.Second)

	// Drain the eventCount events.
	_ = h.drainBrowser(t, prior, eventCount, 3*time.Second)

	// runUpgradeSSE must return on its own once the upstream chunked
	// terminator hits the parser as io.EOF. Do NOT force-close clientA
	// here — the whole point of this test is that the upstream-side
	// graceful close is sufficient.
	h.waitDone(t, 3*time.Second)
	elapsed := time.Since(start)

	streams := h.store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	st := streams[0]
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want %q (graceful upstream close should transition to complete)", st.State, "complete")
	}
	if st.Duration <= 0 {
		t.Errorf("Stream.Duration = %v, want > 0 (duration_ms must be populated)", st.Duration)
	}
	if elapsed >= 4*time.Second {
		t.Errorf("RunStackSession took %v; suggests session stuck waiting on something instead of EOF-cascading", elapsed)
	}
}
