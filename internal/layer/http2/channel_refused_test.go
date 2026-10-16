package http2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1157: RST_STREAM bookkeeping on the channel teardown paths.
//
// RFC 9113 §5.4.2: "an endpoint MUST NOT send a RST_STREAM in response to a
// RST_STREAM frame". RFC 9113 §6.8: streams above a GOAWAY's last_stream_id
// were never processed by the GOAWAY sender, which ignores further frames on
// them. RFC 9113 §8.7: REFUSED_STREAM tells the peer the stream was closed
// before any application processing, so the request can be retried.

// refusedCloser is the consumer-side optional interface the session uses to
// pick REFUSED_STREAM over CANCEL on teardown (USK-1157).
type refusedCloser interface {
	CloseRefused() error
}

// collectRSTs reads frames from peer for window and returns the RST_STREAM
// frames observed, as streamID → error codes (in arrival order). A read
// error (the deadline firing, or the pipe closing) ends the collection.
func collectRSTs(t *testing.T, peer *h2Peer, window time.Duration) map[uint32][]uint32 {
	t.Helper()
	if err := peer.conn.SetReadDeadline(time.Now().Add(window)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	defer func() { _ = peer.conn.SetReadDeadline(time.Time{}) }()
	out := make(map[uint32][]uint32)
	for {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			return out
		}
		if f.Header.Type != frame.TypeRSTStream {
			continue
		}
		code, cerr := f.RSTStreamErrorCode()
		if cerr != nil {
			t.Fatalf("RSTStreamErrorCode: %v", cerr)
		}
		out[f.Header.StreamID] = append(out[f.Header.StreamID], code)
	}
}

// openClientGET opens a client-role stream, sends a GET HEADERS with
// END_STREAM, and returns the channel and its wire stream id. The send half
// is closed; the receive half stays open, so a plain Close would be abnormal
// and (pre-USK-1157) emit RST_STREAM(CANCEL).
func openClientGET(t *testing.T, l *Layer, peer *h2Peer) (*channel, uint32) {
	t.Helper()
	lc, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	ch := lc.(*channel)
	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, &envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Message: &H2HeadersEvent{
				Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
				EndStream: true,
			},
		})
	}()
	f := drainUntil(t, peer, frame.TypeHeaders)
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
	return ch, f.Header.StreamID
}

// nextUntilError drains envelopes from ch until Next returns an error and
// returns that error.
func nextUntilError(t *testing.T, ch layer.Channel) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 8; i++ {
		if _, err := ch.Next(ctx); err != nil {
			return err
		}
	}
	t.Fatal("Next never returned an error")
	return nil
}

// TestChannel_Close_NoRSTAfterPeerRefusal pins that channel.Close does not
// answer a peer-side refusal with its own RST_STREAM. Before USK-1157 the
// abnormal-close branch unconditionally emitted RST_STREAM(CANCEL), which on
// the upstream leg violated RFC 9113 §5.4.2 (RST in response to RST).
func TestChannel_Close_NoRSTAfterPeerRefusal(t *testing.T) {
	tests := []struct {
		name   string
		refuse func(t *testing.T, peer *h2Peer, streamID uint32)
	}{
		{
			name: "peer RST_STREAM(REFUSED_STREAM)",
			refuse: func(t *testing.T, peer *h2Peer, streamID uint32) {
				if err := peer.wr.WriteRSTStream(streamID, ErrCodeRefusedStream); err != nil {
					t.Fatalf("write RST_STREAM: %v", err)
				}
			},
		},
		{
			name: "peer GOAWAY(NO_ERROR) below the stream id",
			refuse: func(t *testing.T, peer *h2Peer, _ uint32) {
				// last_stream_id=0: the (first, id=1) stream was never
				// processed.
				if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
					t.Fatalf("write GOAWAY: %v", err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, peer, cleanup := startClientLayer(t)
			defer cleanup()
			peer.consumePeerSettings(t)

			ch, id := openClientGET(t, l, peer)
			tt.refuse(t, peer, id)

			err := nextUntilError(t, ch)
			var se *layer.StreamError
			if !errors.As(err, &se) || se.Code != layer.ErrorRefused {
				t.Fatalf("Next err = %v, want StreamError{refused}", err)
			}

			if err := ch.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if got := collectRSTs(t, peer, 300*time.Millisecond)[id]; len(got) != 0 {
				t.Errorf("RST_STREAM codes sent on refused stream %d = %v, want none", id, got)
			}
		})
	}
}

// TestChannel_Close_AfterMarkTerminatedWithRST_SingleRST pins that Close
// after MarkTerminatedWithRST does not emit a second RST_STREAM. Before
// USK-1157 the MaxBodySize path sent INTERNAL_ERROR and then the session's
// deferred Close sent CANCEL on the same stream.
func TestChannel_Close_AfterMarkTerminatedWithRST_SingleRST(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "StreamError", err: &layer.StreamError{Code: layer.ErrorInternalError, Reason: "max body size"}},
		{name: "plain error", err: errors.New("aggregator: max body size exceeded")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, peer, cleanup := startClientLayer(t)
			defer cleanup()
			peer.consumePeerSettings(t)

			ch, id := openClientGET(t, l, peer)
			ch.MarkTerminatedWithRST(ErrCodeInternal, tt.err)
			if err := ch.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			got := collectRSTs(t, peer, 300*time.Millisecond)[id]
			if len(got) != 1 || got[0] != ErrCodeInternal {
				t.Errorf("RST_STREAM codes on stream %d = %v, want exactly [%d] (INTERNAL_ERROR)", id, got, ErrCodeInternal)
			}
		})
	}
}

// acceptServerStream drives a peer request HEADERS (GET, END_STREAM) on
// stream 1 of a ServerRole Layer and returns the emitted channel after
// draining its request envelope.
func acceptServerStream(t *testing.T, l *Layer, peer *h2Peer) layer.Channel {
	t.Helper()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	enc := peer.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
	})
	if err := peer.wr.WriteHeaders(1, true, true, enc); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
	var ch layer.Channel
	select {
	case ch = <-l.Channels():
	case <-time.After(2 * time.Second):
		t.Fatal("no channel emitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("Next (request HEADERS): %v", err)
	}
	return ch
}

// TestChannel_CloseRefused_ServerRole pins the client-facing half of
// USK-1157: when the upstream refused a stream, the session closes the
// client stream with CloseRefused, which resets it with REFUSED_STREAM so
// the client retries — unless a response HEADERS (including 1xx) already
// reached the client, in which case the stream is no longer "unprocessed"
// and CANCEL is the only honest code; and never when the client already
// reset the stream itself.
func TestChannel_CloseRefused_ServerRole(t *testing.T) {
	tests := []struct {
		name string
		// prepare runs against the accepted stream before CloseRefused.
		prepare func(t *testing.T, peer *h2Peer, ch layer.Channel)
		want    []uint32
	}{
		{
			name:    "no response HEADERS sent",
			prepare: func(*testing.T, *h2Peer, layer.Channel) {},
			want:    []uint32{ErrCodeRefusedStream},
		},
		{
			name: "1xx response HEADERS already sent",
			prepare: func(t *testing.T, peer *h2Peer, ch layer.Channel) {
				sendErr := make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					sendErr <- ch.Send(ctx, &envelope.Envelope{
						Direction: envelope.Receive,
						Protocol:  envelope.ProtocolHTTP,
						Message: &H2HeadersEvent{
							Status:  103,
							Headers: []envelope.KeyValue{{Name: "link", Value: "</a.css>; rel=preload"}},
						},
					})
				}()
				drainUntil(t, peer, frame.TypeHeaders)
				if err := <-sendErr; err != nil {
					t.Fatalf("Send(103): %v", err)
				}
			},
			want: []uint32{ErrCodeCancel},
		},
		{
			name: "client already reset the stream",
			prepare: func(t *testing.T, peer *h2Peer, ch layer.Channel) {
				if err := peer.wr.WriteRSTStream(1, ErrCodeRefusedStream); err != nil {
					t.Fatalf("write RST_STREAM: %v", err)
				}
				// The request carried END_STREAM, so the recv half is
				// already closed and Next would race the RST to io.EOF;
				// the terminal signal is the stable observation point.
				select {
				case <-ch.Closed():
				case <-time.After(2 * time.Second):
					t.Fatal("channel not terminated after client RST_STREAM")
				}
				var se *layer.StreamError
				if err := ch.Err(); !errors.As(err, &se) {
					t.Fatalf("Err = %v, want StreamError", err)
				}
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, peer, cleanup := startServerLayer(t)
			defer cleanup()
			ch := acceptServerStream(t, l, peer)
			tt.prepare(t, peer, ch)

			rc, ok := ch.(refusedCloser)
			if !ok {
				t.Fatalf("server-role channel %T does not implement CloseRefused", ch)
			}
			if err := rc.CloseRefused(); err != nil {
				t.Fatalf("CloseRefused: %v", err)
			}
			// A follow-up Close (the session's generic teardown, or a
			// wrapper cascade) must not add a second RST.
			if err := ch.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			got := collectRSTs(t, peer, 300*time.Millisecond)[1]
			if len(got) != len(tt.want) {
				t.Fatalf("RST_STREAM codes on stream 1 = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("RST_STREAM codes on stream 1 = %v, want %v", got, tt.want)
					break
				}
			}
			select {
			case <-ch.Closed():
			default:
				t.Error("channel not terminated after CloseRefused")
			}
		})
	}
}

// TestChannel_Close_ServerRole_ClientGoAwayKeepsCancel guards the exception
// in streamAlreadyReset: a client's GOAWAY last_stream_id only covers
// streams the proxy (its receiver) initiated, so the client-initiated
// streams the reader nevertheless fails as refused are still open on the
// client's side and must still be reset with CANCEL on teardown.
func TestChannel_Close_ServerRole_ClientGoAwayKeepsCancel(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	ch := acceptServerStream(t, l, peer)

	if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}
	select {
	case <-ch.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("channel not terminated after client GOAWAY")
	}
	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := collectRSTs(t, peer, 300*time.Millisecond)[1]
	if len(got) != 1 || got[0] != ErrCodeCancel {
		t.Errorf("RST_STREAM codes on stream 1 = %v, want [%d] (CANCEL)", got, ErrCodeCancel)
	}
}
