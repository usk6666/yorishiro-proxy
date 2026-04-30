package http2

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// recordingReleaser captures every ReleaseStream / ReleaseTransaction call
// so a test can assert which terminal path triggered which key. Safe for
// concurrent use — markTerminated may fire from the reader, the aggregator,
// or Close depending on the path under test.
type recordingReleaser struct {
	mu      sync.Mutex
	streams []releaseEvent
	txs     []releaseEvent
}

type releaseEvent struct {
	connID string
	id     string
}

func (r *recordingReleaser) ReleaseStream(connID, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams = append(r.streams, releaseEvent{connID: connID, id: id})
}

func (r *recordingReleaser) ReleaseTransaction(connID, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txs = append(r.txs, releaseEvent{connID: connID, id: id})
}

func (r *recordingReleaser) streamCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams)
}

func (r *recordingReleaser) lastStream() (releaseEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.streams) == 0 {
		return releaseEvent{}, false
	}
	return r.streams[len(r.streams)-1], true
}

// openOneStream sends a HEADERS frame from the peer and returns the
// emitted Channel + its first envelope (which the test usually discards).
func openOneStream(t *testing.T, l *Layer, peer *h2Peer, streamID uint32, endStream bool) layer.Channel {
	t.Helper()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/state-test"},
		{Name: ":authority", Value: "example.test"},
	}
	encoded := peer.encoder.Encode(headers)
	if err := peer.wr.WriteHeaders(streamID, true, endStream, encoded); err != nil {
		t.Fatalf("peer.WriteHeaders: %v", err)
	}

	var ch layer.Channel
	select {
	case ch = <-l.Channels():
	case <-time.After(time.Second):
		t.Fatal("did not receive Channel within 1s")
	}
	if ch == nil {
		t.Fatal("nil Channel")
	}

	// Drain the first envelope so the channel is in its post-HEADERS state
	// and the caller can drive whichever terminal path the test exercises.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("Channel.Next initial: %v", err)
	}
	return ch
}

// waitForStreamRelease polls the recorder for at least n release events.
// markTerminated fires from goroutines other than the test, so we need
// a short grace window.
func waitForStreamRelease(t *testing.T, r *recordingReleaser, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.streamCount() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waitForStreamRelease: got %d, want %d", r.streamCount(), n)
}

// TestStateReleaser_StreamCloseFiresRelease drives a stream to terminal
// via the channel.Close() path and asserts that exactly one ReleaseStream
// was issued with the channel's UUID-StreamID and the layer's ConnID.
func TestStateReleaser_StreamCloseFiresRelease(t *testing.T) {
	r := &recordingReleaser{}
	envCtx := envelope.EnvelopeContext{ConnID: "test-conn-close"}
	l, peer, cleanup := startServerLayer(t,
		WithEnvelopeContext(envCtx),
		WithStateReleaser(r),
	)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	ch := openOneStream(t, l, peer, 1, true)

	if err := ch.Close(); err != nil {
		t.Fatalf("Channel.Close: %v", err)
	}

	waitForStreamRelease(t, r, 1)

	ev, _ := r.lastStream()
	if ev.connID != "test-conn-close" {
		t.Fatalf("ReleaseStream connID = %q, want %q", ev.connID, "test-conn-close")
	}
	if ev.id != ch.StreamID() {
		t.Fatalf("ReleaseStream id = %q, want %q", ev.id, ch.StreamID())
	}
}

// TestStateReleaser_RSTFiresRelease drives a stream to terminal via the
// MarkTerminatedWithRST path (the same convergence the aggregator uses
// for MaxBodySize enforcement) and asserts ReleaseStream fires.
func TestStateReleaser_RSTFiresRelease(t *testing.T) {
	r := &recordingReleaser{}
	envCtx := envelope.EnvelopeContext{ConnID: "test-conn-rst"}
	l, peer, cleanup := startServerLayer(t,
		WithEnvelopeContext(envCtx),
		WithStateReleaser(r),
	)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	ch := openOneStream(t, l, peer, 3, true)

	c, ok := ch.(*channel)
	if !ok {
		t.Fatalf("type-assert *channel: got %T", ch)
	}
	c.MarkTerminatedWithRST(ErrCodeInternal, errors.New("test-rst"))

	waitForStreamRelease(t, r, 1)
	ev, _ := r.lastStream()
	if ev.id != ch.StreamID() {
		t.Fatalf("ReleaseStream id = %q, want %q", ev.id, ch.StreamID())
	}
}

// TestStateReleaser_LayerCloseReleasesAllStreams opens multiple streams,
// calls Layer.Close, and asserts ReleaseStream fired exactly once per
// stream. broadcastShutdown is the convergence path on Layer.Close.
func TestStateReleaser_LayerCloseReleasesAllStreams(t *testing.T) {
	r := &recordingReleaser{}
	envCtx := envelope.EnvelopeContext{ConnID: "test-conn-layer-close"}
	l, peer, cleanup := startServerLayer(t,
		WithEnvelopeContext(envCtx),
		WithStateReleaser(r),
	)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	chA := openOneStream(t, l, peer, 1, true)
	chB := openOneStream(t, l, peer, 3, true)

	_ = l.Close()

	// Layer.Close runs broadcastShutdown which markTerminated each
	// channel. Two streams → two ReleaseStream events, one per channel,
	// each carrying the right (ConnID, StreamID) pair.
	waitForStreamRelease(t, r, 2)

	r.mu.Lock()
	seen := make(map[string]int, len(r.streams))
	for _, ev := range r.streams {
		if ev.connID != "test-conn-layer-close" {
			t.Errorf("unexpected connID %q in event %+v", ev.connID, ev)
		}
		seen[ev.id]++
	}
	r.mu.Unlock()

	if seen[chA.StreamID()] != 1 {
		t.Errorf("ReleaseStream count for chA = %d, want 1", seen[chA.StreamID()])
	}
	if seen[chB.StreamID()] != 1 {
		t.Errorf("ReleaseStream count for chB = %d, want 1", seen[chB.StreamID()])
	}
}

// TestStateReleaser_NilReleaserNoOp asserts that a Layer constructed
// without WithStateReleaser does not crash and does not allocate work
// for the legacy path. (Implicitly: the Layer reaches markTerminated
// and finds nil, which short-circuits.)
func TestStateReleaser_NilReleaserNoOp(t *testing.T) {
	envCtx := envelope.EnvelopeContext{ConnID: "test-conn-nil"}
	l, peer, cleanup := startServerLayer(t, WithEnvelopeContext(envCtx))
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	ch := openOneStream(t, l, peer, 1, true)
	if err := ch.Close(); err != nil {
		t.Fatalf("Channel.Close: %v", err)
	}
	// No assertion beyond "did not panic"; nil releaser path must be safe.
}

// TestStateReleaser_EmptyConnIDIsNoOp asserts that a Layer whose
// EnvelopeContext lacks a ConnID does not issue release calls (the
// release would have an empty connID which the engine refuses anyway,
// so the Layer skips early).
func TestStateReleaser_EmptyConnIDIsNoOp(t *testing.T) {
	r := &recordingReleaser{}
	l, peer, cleanup := startServerLayer(t, WithStateReleaser(r))
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	ch := openOneStream(t, l, peer, 1, true)
	if err := ch.Close(); err != nil {
		t.Fatalf("Channel.Close: %v", err)
	}

	// Give the goroutine a moment to run markTerminated.
	time.Sleep(20 * time.Millisecond)
	if got := r.streamCount(); got != 0 {
		t.Fatalf("ReleaseStream fired %d times, want 0 (no ConnID configured)", got)
	}
}
