package bytechunk

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// nextWithWrite writes payload on w and returns the envelope ch.Next yields.
func nextWithWrite(t *testing.T, ch interface {
	Next(context.Context) (*envelope.Envelope, error)
}, w net.Conn, payload string) *envelope.Envelope {
	t.Helper()
	go func() { _, _ = w.Write([]byte(payload)) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return env
}

// TestWithEnvelopeContext_StampedOnEveryEnvelope is USK-1083 T11: the
// template's ConnID / TargetHost / TLS reach every envelope, ReceivedAt is
// fresh per envelope, and the caller's template is never mutated.
func TestWithEnvelopeContext_StampedOnEveryEnvelope(t *testing.T) {
	peer, proxySide := net.Pipe()
	defer peer.Close()
	defer proxySide.Close()

	snap := &envelope.TLSSnapshot{SNI: "example.test", ALPN: "x-custom"}
	tmpl := envelope.EnvelopeContext{
		ConnID:     "conn-1083",
		TargetHost: "example.test:4443",
		TLS:        snap,
	}
	l := New(proxySide, "conn-1083/client", envelope.Send, WithEnvelopeContext(tmpl))
	ch := <-l.Channels()

	before := time.Now()
	first := nextWithWrite(t, ch, peer, "one")
	second := nextWithWrite(t, ch, peer, "two")

	for i, env := range []*envelope.Envelope{first, second} {
		if env.Context.ConnID != "conn-1083" {
			t.Errorf("env[%d].Context.ConnID = %q, want conn-1083", i, env.Context.ConnID)
		}
		if env.Context.TargetHost != "example.test:4443" {
			t.Errorf("env[%d].Context.TargetHost = %q, want example.test:4443", i, env.Context.TargetHost)
		}
		if env.Context.TLS != snap {
			t.Errorf("env[%d].Context.TLS = %v, want the template snapshot", i, env.Context.TLS)
		}
		if env.Context.ReceivedAt.Before(before) {
			t.Errorf("env[%d].Context.ReceivedAt = %v, want >= %v", i, env.Context.ReceivedAt, before)
		}
	}
	if !tmpl.ReceivedAt.IsZero() {
		t.Errorf("template ReceivedAt mutated to %v", tmpl.ReceivedAt)
	}
	if second.Context.ReceivedAt.Before(first.Context.ReceivedAt) {
		t.Errorf("ReceivedAt not refreshed per envelope: first=%v second=%v", first.Context.ReceivedAt, second.Context.ReceivedAt)
	}
}

// TestNew_NoOptions_ContextOnlyReceivedAt pins the unchanged no-option
// behaviour (MCP resend_raw / fuzz_raw construct Layers without options).
func TestNew_NoOptions_ContextOnlyReceivedAt(t *testing.T) {
	peer, proxySide := net.Pipe()
	defer peer.Close()
	defer proxySide.Close()

	l := New(proxySide, "s", envelope.Receive)
	env := nextWithWrite(t, <-l.Channels(), peer, "x")
	if env.Context.ConnID != "" || env.Context.TargetHost != "" || env.Context.TLS != nil {
		t.Errorf("Context = %+v, want only ReceivedAt set", env.Context)
	}
	if env.Context.ReceivedAt.IsZero() {
		t.Error("ReceivedAt is zero")
	}
}

type recordingReleaser struct {
	mu      sync.Mutex
	txs     []string
	streams []string
}

func (r *recordingReleaser) ReleaseTransaction(connID, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txs = append(r.txs, connID+"|"+id)
}

func (r *recordingReleaser) ReleaseStream(connID, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams = append(r.streams, connID+"|"+id)
}

// TestWithStateReleaser_FiresOnceOnLayerClose is USK-1083 T11 / R12: the
// (ConnID, StreamID) transaction and stream scopes are released exactly
// once, from Layer.Close — not from the Channel's terminal state, because
// the session still runs Receive envelopes under the client StreamID after
// the client side reads EOF.
func TestWithStateReleaser_FiresOnceOnLayerClose(t *testing.T) {
	peer, proxySide := net.Pipe()
	defer peer.Close()

	rel := &recordingReleaser{}
	l := New(proxySide, "c1/client", envelope.Send,
		WithEnvelopeContext(envelope.EnvelopeContext{ConnID: "c1"}),
		WithStateReleaser(rel),
	)
	ch := <-l.Channels()

	// Channel terminal state alone must not release.
	_ = peer.Close()
	if _, err := ch.Next(context.Background()); err == nil {
		t.Fatal("Next after peer close: want an error")
	}
	rel.mu.Lock()
	early := len(rel.txs) + len(rel.streams)
	rel.mu.Unlock()
	if early != 0 {
		t.Fatalf("released %d scopes on Channel EOF; want 0 before Layer.Close", early)
	}

	_ = l.Close()
	_ = l.Close()

	rel.mu.Lock()
	defer rel.mu.Unlock()
	if len(rel.txs) != 1 || rel.txs[0] != "c1|c1/client" {
		t.Errorf("ReleaseTransaction calls = %v, want exactly [c1|c1/client]", rel.txs)
	}
	if len(rel.streams) != 1 || rel.streams[0] != "c1|c1/client" {
		t.Errorf("ReleaseStream calls = %v, want exactly [c1|c1/client]", rel.streams)
	}
}

// TestWithStateReleaser_NoConnID_NoRelease mirrors the sibling layers: an
// empty ConnID has no scope to release.
func TestWithStateReleaser_NoConnID_NoRelease(t *testing.T) {
	_, proxySide := net.Pipe()
	rel := &recordingReleaser{}
	l := New(proxySide, "s", envelope.Send, WithStateReleaser(rel))
	_ = l.Close()
	if len(rel.txs)+len(rel.streams) != 0 {
		t.Errorf("released %v / %v with empty ConnID; want none", rel.txs, rel.streams)
	}
}

// TestChannel_Abort_ClosesConnection pins the USK-1083 U1 teardown seam:
// Abort closes the underlying conn so a Next parked on Read returns and
// the peer reads EOF.
func TestChannel_Abort_ClosesConnection(t *testing.T) {
	peer, proxySide := net.Pipe()
	defer peer.Close()

	l := New(proxySide, "s", envelope.Receive)
	ch := (<-l.Channels()).(*Channel)

	done := make(chan error, 1)
	go func() {
		_, err := ch.Next(context.Background())
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := ch.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Next still parked 2s after Abort")
	}
	if _, err := peer.Write([]byte("x")); err == nil {
		t.Error("peer write after Abort succeeded; want closed pipe")
	}
}
