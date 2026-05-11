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

// TestReader_PingAck verifies a PING is replied with PING ACK.
func TestReader_PingAck(t *testing.T) {
	_, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	want := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := peer.wr.WritePing(false, want); err != nil {
		t.Fatalf("write PING: %v", err)
	}

	// Expect a PING ACK back with the same data.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.Header.Type == frame.TypePing && f.Header.Flags.Has(frame.FlagAck) {
			data, _ := f.PingData()
			if data != want {
				t.Errorf("PING ACK data = %v, want %v", data, want)
			}
			return
		}
	}
	t.Fatal("did not receive PING ACK")
}

func TestReader_SettingsAck(t *testing.T) {
	_, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	if err := peer.wr.WriteSettings([]frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 50},
	}); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.Header.Type == frame.TypeSettings && f.Header.Flags.Has(frame.FlagAck) {
			return
		}
	}
	t.Fatal("did not receive SETTINGS ACK")
}

func TestReader_GoAwayMarksStreams(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	// Open a peer-initiated stream (id=1) and grab the channel.
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
	}
	encoded := peer.encoder.Encode(headers)
	if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}

	var ch layer.Channel
	select {
	case ch = <-l.Channels():
	case <-time.After(time.Second):
		t.Fatal("no channel emitted")
	}

	// Drain the in-flight envelope (no body yet, but headers without
	// END_STREAM means we'll hold).
	// Actually with no END_STREAM, no envelope is yielded yet.

	// Send GOAWAY with last_stream_id=0 — this stream (1) is > 0, so it
	// should fail.
	if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// USK-637: post-split, the initial HEADERS emits an H2HeadersEvent
	// envelope even without END_STREAM. Drain it; the GOAWAY that follows
	// surfaces on the channel's error path.
	env, err := ch.Next(ctx)
	if err == nil {
		if _, ok := env.Message.(*H2HeadersEvent); !ok {
			t.Fatalf("first envelope Message = %T, want *H2HeadersEvent", env.Message)
		}
		_, err = ch.Next(ctx)
	}
	if err == nil {
		t.Fatal("Next: want error after GOAWAY, got nil")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: want *layer.StreamError, got %T (%v)", err, err)
	}
	if se.Code != layer.ErrorRefused {
		t.Errorf("StreamError code = %s, want refused", se.Code)
	}
}

func TestReader_RSTStreamTranslated(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	// Open a stream.
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
	}
	encoded := peer.encoder.Encode(headers)
	if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}

	var ch layer.Channel
	select {
	case ch = <-l.Channels():
	case <-time.After(time.Second):
		t.Fatal("no channel emitted")
	}

	if err := peer.wr.WriteRSTStream(1, ErrCodeCancel); err != nil {
		t.Fatalf("write RST_STREAM: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// USK-637: the initial HEADERS block (no END_STREAM) emits an
	// H2HeadersEvent envelope immediately post-split. Drain it; the RST
	// that follows should then surface on the channel's error path.
	env, err := ch.Next(ctx)
	if err == nil {
		if _, ok := env.Message.(*H2HeadersEvent); !ok {
			t.Fatalf("first envelope Message = %T, want *H2HeadersEvent", env.Message)
		}
		// Now expect the RST.
		_, err = ch.Next(ctx)
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: want *layer.StreamError, got %T (%v)", err, err)
	}
	if se.Code != layer.ErrorCanceled {
		t.Errorf("StreamError code = %s, want canceled", se.Code)
	}
}

// TestReader_PushPromise_RejectedWhenEnablePushZero verifies the residual
// RFC-compliance behavior left in place after USK-823 retired HTTP/2
// server-push recording. A ClientRole layer defaults SETTINGS_ENABLE_PUSH=0
// (RFC 9113 §6.5.2, USK-820). A peer that nonetheless sends PUSH_PROMISE
// is a protocol violation; the reader must treat it as a connection-level
// PROTOCOL_ERROR and the resulting GOAWAY must surface on subsequent reads.
//
// No push channel must appear on Channels() — the production wiring no
// longer drains them.
func TestReader_PushPromise_RejectedWhenEnablePushZero(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	// Anchor the stream by opening a client request stream and driving
	// its first HEADERS frame onto the wire. The peer needs a known
	// origin stream id to put on the PUSH_PROMISE frame.
	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	go func() {
		_ = ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message: &H2HeadersEvent{
				Method: "GET", Scheme: "https", Authority: "x", Path: "/",
				EndStream: true,
			},
		})
	}()
	for i := 0; i < 5; i++ {
		f, ferr := peer.rd.ReadFrame()
		if ferr != nil {
			t.Fatalf("read: %v", ferr)
		}
		if f.Header.Type == frame.TypeHeaders {
			break
		}
	}

	// Peer sends an unsolicited PUSH_PROMISE. Per RFC 9113 §6.5.2, a
	// client that advertised SETTINGS_ENABLE_PUSH=0 (our default) must
	// treat any received PUSH_PROMISE as a connection PROTOCOL_ERROR.
	pushHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/pushed.css"},
	}
	encoded := peer.encoder.Encode(pushHeaders)
	if err := peer.wr.WritePushPromise(1, 2, true, encoded); err != nil {
		t.Fatalf("WritePushPromise: %v", err)
	}

	// The reader detects the protocol error and tears down the layer.
	// LastReaderError reports the *ConnError; shutdown drains channels
	// without producing a push channel surface.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if l.LastReaderError() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rerr := l.LastReaderError()
	if rerr == nil {
		t.Fatal("LastReaderError = nil; expected ConnError(PROTOCOL_ERROR)")
	}
	var ce *ConnError
	if !errors.As(rerr, &ce) {
		t.Fatalf("LastReaderError = %T (%v); want *ConnError", rerr, rerr)
	}
	if ce.Code != ErrCodeProtocol {
		t.Errorf("ConnError.Code = %s, want PROTOCOL_ERROR", ErrCodeString(ce.Code))
	}

	// Channels() must not surface a push channel: server-push recording
	// is retired (USK-823); the reader rejects PUSH_PROMISE before any
	// channel allocation happens.
	select {
	case extra, ok := <-l.Channels():
		if !ok {
			// Channels closed by broadcastShutdown — expected.
			return
		}
		t.Fatalf("unexpected channel %T emitted after PUSH_PROMISE rejection", extra)
	case <-time.After(100 * time.Millisecond):
		// No push channel surfaced — the desired post-retire behavior.
	}
}

func TestReader_WindowUpdateAcceptedConn(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	// Send a connection-level WINDOW_UPDATE.
	if err := peer.wr.WriteWindowUpdate(0, 1024); err != nil {
		t.Fatalf("WriteWindowUpdate: %v", err)
	}

	// Allow some time for the reader to process.
	time.Sleep(50 * time.Millisecond)

	expected := int32(defaultConnectionWindowSize) + 1024
	if got := l.conn.SendWindow(); got != expected {
		t.Errorf("conn send window = %d, want %d", got, expected)
	}
}
