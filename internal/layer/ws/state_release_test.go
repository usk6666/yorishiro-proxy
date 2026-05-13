package ws

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// recordingReleaser captures every ReleaseTransaction / ReleaseStream call
// against the WS Layer so the USK-853 wiring tests can assert on the
// canonical (ConnID, StreamID) pair without booting the full pluginv2
// Engine.
type recordingReleaser struct {
	mu      sync.Mutex
	txs     []releaseEvent
	streams []releaseEvent
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

func (r *recordingReleaser) streamSnapshot() []releaseEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]releaseEvent, len(r.streams))
	copy(out, r.streams)
	return out
}

func (r *recordingReleaser) streamCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams)
}

func (r *recordingReleaser) txCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.txs)
}

// TestWSLayer_ReleaseStream_FiresOnTerminal asserts that the ws Layer
// fires pluginv2.StateReleaser.ReleaseStream(ConnID, StreamID) exactly
// once on Channel terminal — symmetric with the http2 Layer pattern.
// USK-853 plumbs this so the unified StreamID introduced by USK-848
// (handshake StreamID survives the protocol flip) does not leak
// ctx.stream_state for the process lifetime.
func TestWSLayer_ReleaseStream_FiresOnTerminal(t *testing.T) {
	t.Parallel()

	rec := &recordingReleaser{}
	envCtx := envelope.EnvelopeContext{ConnID: "test-conn"}
	rwc := newFakeRWC(nil) // empty input → pre-frame EOF drives markTerminated

	l := New(rwc, rwc, rwc, "stream-ws-1", RoleClient,
		WithEnvelopeContext(envCtx),
		WithStateReleaser(rec),
	)
	defer l.Close()

	ch := <-l.Channels()
	if _, err := ch.Next(context.Background()); err != io.EOF {
		t.Fatalf("Next: err = %v, want io.EOF", err)
	}

	if got := rec.streamCount(); got != 1 {
		t.Fatalf("ReleaseStream count = %d, want 1: %+v", got, rec.streamSnapshot())
	}
	ev := rec.streamSnapshot()[0]
	if ev.connID != "test-conn" {
		t.Errorf("ReleaseStream connID = %q, want test-conn", ev.connID)
	}
	if ev.id != "stream-ws-1" {
		t.Errorf("ReleaseStream id = %q, want stream-ws-1", ev.id)
	}
	// Transaction-scope release also fires (existing USK-682 wiring).
	if got := rec.txCount(); got != 1 {
		t.Errorf("ReleaseTransaction count = %d, want 1", got)
	}
}

// TestWSLayer_ReleaseStream_NilReleaserNoOp verifies that a Layer
// constructed without WithStateReleaser does not panic on terminal.
func TestWSLayer_ReleaseStream_NilReleaserNoOp(t *testing.T) {
	t.Parallel()

	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "stream-ws-1", RoleClient,
		WithEnvelopeContext(envelope.EnvelopeContext{ConnID: "test-conn"}),
	)
	defer l.Close()
	ch := <-l.Channels()
	if _, err := ch.Next(context.Background()); err != io.EOF {
		t.Fatalf("Next: err = %v, want io.EOF", err)
	}
}

// TestWSLayer_ReleaseStream_EmptyConnIDIsNoOp verifies the symmetric
// guard with the http2 Layer pattern: an empty ConnID short-circuits the
// release and no ReleaseStream call is issued.
func TestWSLayer_ReleaseStream_EmptyConnIDIsNoOp(t *testing.T) {
	t.Parallel()

	rec := &recordingReleaser{}
	rwc := newFakeRWC(nil)

	// No WithEnvelopeContext → ConnID is "".
	l := New(rwc, rwc, rwc, "stream-ws-1", RoleClient,
		WithStateReleaser(rec),
	)
	defer l.Close()
	ch := <-l.Channels()
	if _, err := ch.Next(context.Background()); err != io.EOF {
		t.Fatalf("Next: err = %v, want io.EOF", err)
	}

	if got := rec.streamCount(); got != 0 {
		t.Fatalf("ReleaseStream fired %d times with empty ConnID, want 0: %+v", got, rec.streamSnapshot())
	}
}

// TestWSLayer_ReleaseStream_FiresOnceUnderConcurrentTermination ensures
// the sync.Once on markTerminated keeps ReleaseStream to a single firing
// even when terminal is reached from both the Next-driven EOF path AND
// an explicit Layer.Close.
func TestWSLayer_ReleaseStream_FiresOnceUnderConcurrentTermination(t *testing.T) {
	t.Parallel()

	rec := &recordingReleaser{}
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "stream-ws-1", RoleClient,
		WithEnvelopeContext(envelope.EnvelopeContext{ConnID: "test-conn"}),
		WithStateReleaser(rec),
	)

	ch := <-l.Channels()
	_, _ = ch.Next(context.Background()) // → io.EOF → markTerminated
	_ = l.Close()                        // → markTerminated again (no-op via sync.Once)

	if got := rec.streamCount(); got != 1 {
		t.Errorf("ReleaseStream count = %d, want 1 (sync.Once gate)", got)
	}
}
