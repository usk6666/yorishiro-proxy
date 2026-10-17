package http2

import (
	"context"
	"testing"
	"time"
)

// USK-1179: InitiatedStreams is the client-side "this connection carried a
// stream" signal the proxybuild pre-warm worker uses to stop replacing a
// speculative upstream connection that went away unused. It must flip only
// when a request HEADERS is actually allocated a stream id — not on
// OpenStream alone, and not on an OpenStream refused after GOAWAY.

func TestLayer_InitiatedStreams_FalseUntilFirstHeaders(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	if l.InitiatedStreams() {
		t.Fatal("InitiatedStreams() = true on a fresh Layer, want false")
	}

	// An opened channel that has not sent HEADERS has no stream id yet.
	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if l.InitiatedStreams() {
		t.Fatal("InitiatedStreams() = true after OpenStream without HEADERS, want false")
	}
	_ = ch.Close()

	ch2, id := openClientGET(t, l, peer)
	defer ch2.Close()
	if id != 1 {
		t.Fatalf("first stream id = %d, want 1", id)
	}
	if !l.InitiatedStreams() {
		t.Error("InitiatedStreams() = false after the first request HEADERS was sent, want true")
	}
}

func TestLayer_InitiatedStreams_FalseWhenOpenStreamRefusedAfterGoAway(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !l.GoAwayClosed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !l.GoAwayClosed() {
		t.Fatal("GoAwayClosed() did not flip true within 2s of peer GOAWAY")
	}

	if _, err := l.OpenStream(context.Background()); err == nil {
		t.Fatal("OpenStream after peer GOAWAY succeeded, want refused")
	}
	if l.InitiatedStreams() {
		t.Error("InitiatedStreams() = true after a refused OpenStream, want false")
	}
}
