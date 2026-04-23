package http2

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// TestChannel_Close_SkipsRSTOnBilateralEndStream (USK-618 acceptance guard,
// ported to event-granular API): after both sides complete END_STREAM,
// channel.Close must NOT emit RST_STREAM. Emitting RST on a closed stream
// would violate RFC 9113 §5.1 and trigger peer PROTOCOL_ERROR + GOAWAY,
// cascading to other streams.
func TestChannel_Close_SkipsRSTOnBilateralEndStream(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Send HEADERS event with END_STREAM (no body).
	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, &envelope.Envelope{
			StreamID:  ch.StreamID(),
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Message: &H2HeadersEvent{
				Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
				EndStream: true,
			},
		})
	}()

	f := drainUntil(t, peer, frame.TypeHeaders)
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Fatalf("request HEADERS missing END_STREAM")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Peer sends response HEADERS with END_STREAM.
	resp := []hpack.HeaderField{{Name: ":status", Value: "200"}}
	enc := peer.encoder.Encode(resp)
	if err := peer.wr.WriteHeaders(f.Header.StreamID, true, true, enc); err != nil {
		t.Fatalf("write response HEADERS: %v", err)
	}

	// Drain the H2HeadersEvent on the channel (reader observed END_STREAM).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("ch.Next: %v", err)
	}
	if _, ok := env.Message.(*H2HeadersEvent); !ok {
		t.Fatalf("got %T, want *H2HeadersEvent", env.Message)
	}
	// Next read must be io.EOF (recv closed by reader on END_STREAM).
	_, err = ch.Next(ctx)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second Next = %v, want io.EOF", err)
	}

	// Close and assert NO RST_STREAM was emitted.
	if err := ch.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// Poll the wire briefly: if a RST comes through, the bilateral-close
	// gate is broken.
	if err := peer.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			// Timeout — good.
			return
		}
		if f.Header.Type == frame.TypeRSTStream {
			t.Fatalf("received unexpected RST_STREAM after bilateral close")
		}
		// Ignore other frames (e.g., a trailing WINDOW_UPDATE).
	}
}

// TestChannel_Close_EmitsRSTOnAbnormalClose verifies that Close DOES emit
// RST_STREAM when only one side has END_STREAM (client still open).
func TestChannel_Close_EmitsRSTOnAbnormalClose(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Send HEADERS without END_STREAM (request with body expected).
	go func() {
		_ = ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message: &H2HeadersEvent{
				Method: "POST", Scheme: "https", Authority: "x", Path: "/",
			},
		})
	}()
	drainUntil(t, peer, frame.TypeHeaders)

	// Close mid-request — must emit RST_STREAM.
	if err := ch.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := peer.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	sawRST := false
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			break
		}
		if f.Header.Type == frame.TypeRSTStream {
			sawRST = true
			break
		}
	}
	if !sawRST {
		t.Error("did not receive RST_STREAM after abnormal Close")
	}
}
