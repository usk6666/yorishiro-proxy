package http2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// USK-1175: a client-role channel obtained via OpenStream BEFORE the
// connection's GOAWAY, whose first HEADERS is sent AFTER it, must be refused
// without ever reaching the wire. RFC 9113 §6.8: after receiving (or
// sending) GOAWAY an endpoint MUST NOT open additional streams; the peer
// ignores a stream above its last_stream_id, so allocating an id and
// sending HEADERS would hang the stream until the peer closes the TCP
// connection.

// getHeadersEnvelope is the request-HEADERS envelope the first-Send tests
// drive through channel.Send.
func getHeadersEnvelope() *envelope.Envelope {
	return &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &H2HeadersEvent{
			Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
			EndStream: true,
		},
	}
}

// assertRefused fails unless err wraps *layer.StreamError{Code: ErrorRefused}.
func assertRefused(t *testing.T, what string, err error) {
	t.Helper()
	var se *layer.StreamError
	if !errors.As(err, &se) || se.Code != layer.ErrorRefused {
		t.Fatalf("%s = %v, want *layer.StreamError{Code: refused}", what, err)
	}
}

// TestChannel_FirstHeadersAfterGoAway_Refused drives real frames: the
// stream is opened, the connection then sees GOAWAY (received from the
// peer, or sent by the Layer after a connection error), and only then is
// the first HEADERS sent.
func TestChannel_FirstHeadersAfterGoAway_Refused(t *testing.T) {
	tests := []struct {
		name string
		// goAway makes the Layer record GOAWAY and returns only once the
		// Layer's reader has processed it.
		goAway func(t *testing.T, peer *h2Peer)
	}{
		{
			name: "GOAWAY received from upstream",
			goAway: func(t *testing.T, peer *h2Peer) {
				if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
					t.Fatalf("write GOAWAY: %v", err)
				}
				// The reader handles frames in order, so the PING ACK
				// proves failStreamsAfterGoAway has already run.
				syncPing(t, peer)
			},
		},
		{
			name: "GOAWAY sent after a connection error",
			goAway: func(t *testing.T, peer *h2Peer) {
				// A connection-level WINDOW_UPDATE with a zero increment
				// is a connection error of type PROTOCOL_ERROR (RFC 9113
				// §6.9); the Layer answers with GOAWAY. Seeing that
				// GOAWAY on the wire proves the writer has recorded
				// GoAwaySent.
				if err := peer.wr.WriteRawBytes([]byte{0, 0, 4, byte(frame.TypeWindowUpdate), 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
					t.Fatalf("write WINDOW_UPDATE(0): %v", err)
				}
				drainUntil(t, peer, frame.TypeGoAway)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, peer, cleanup := startClientLayer(t)
			defer cleanup()
			peer.consumePeerSettings(t)

			lc, err := l.OpenStream(context.Background())
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			ch := lc.(*channel)

			tt.goAway(t, peer)

			sendErr := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				sendErr <- ch.Send(ctx, getHeadersEnvelope())
			}()

			// No HEADERS may reach the peer: the stream must not be
			// opened on a connection that is going away.
			if err := peer.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			for {
				f, err := peer.rd.ReadFrame()
				if err != nil {
					break
				}
				if f.Header.Type == frame.TypeHeaders {
					t.Errorf("HEADERS on stream %d reached the peer after GOAWAY", f.Header.StreamID)
				}
			}
			_ = peer.conn.SetReadDeadline(time.Time{})

			select {
			case err := <-sendErr:
				assertRefused(t, "Send err", err)
			case <-time.After(3 * time.Second):
				t.Fatal("Send did not return")
			}
			if id := ch.H2StreamID(); id != 0 {
				t.Errorf("H2StreamID = %d after refused first HEADERS, want 0 (no id allocated)", id)
			}
			// The session reads the refusal from the channel's terminal
			// error (upstreamHolder.refused); Next must surface it too
			// instead of hanging.
			assertRefused(t, "Err()", ch.Err())
			assertRefused(t, "Next err", nextUntilError(t, ch))
		})
	}
}

// TestChannel_FirstHeadersRacingGoAway_NeverHangs races the first HEADERS
// Send against GOAWAY(0) processing. Whichever wins, the stream must end
// refused: either Send itself is refused (GOAWAY first) or the HEADERS went
// out and the GOAWAY scan refuses the allocated stream (Send first). It
// must never hang until a deadline.
//
// This is a probabilistic liveness and -race guard: whether a given run
// hits the losing interleaving depends on scheduling, so it does not fail
// deterministically without the fix. The deterministic tests above carry
// the acceptance criteria (refusal of a post-GOAWAY first HEADERS, no id
// allocated, refusal surfaced via Err/Next).
func TestChannel_FirstHeadersRacingGoAway_NeverHangs(t *testing.T) {
	const iterations = 200
	for i := 0; i < iterations; i++ {
		raceFirstHeadersAgainstGoAway(t, i)
		if t.Failed() {
			return
		}
	}
}

func raceFirstHeadersAgainstGoAway(t *testing.T, iter int) {
	t.Helper()
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	// Drain everything the Layer writes so the writer never blocks on the
	// pipe; stops when cleanup closes the conn.
	go func() {
		for {
			if _, err := peer.rd.ReadFrame(); err != nil {
				return
			}
		}
	}()

	lc, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("iter %d: OpenStream: %v", iter, err)
	}

	goAwayErr := make(chan error, 1)
	go func() { goAwayErr <- peer.wr.WriteGoAway(0, ErrCodeNo, nil) }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := lc.Send(ctx, getHeadersEnvelope()); err != nil {
		var se *layer.StreamError
		if !errors.As(err, &se) || se.Code != layer.ErrorRefused {
			t.Errorf("iter %d: Send err = %v, want nil or StreamError{refused}", iter, err)
		}
	}
	if err := <-goAwayErr; err != nil {
		t.Fatalf("iter %d: write GOAWAY: %v", iter, err)
	}

	nctx, ncancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer ncancel()
	_, err = lc.Next(nctx)
	var se *layer.StreamError
	if !errors.As(err, &se) || se.Code != layer.ErrorRefused {
		t.Errorf("iter %d: Next err = %v, want StreamError{refused}", iter, err)
	}
}
