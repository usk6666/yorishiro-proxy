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

// TestReader_GoAwayMarksStreams pins the ClientRole half of RFC 9113 §6.8:
// an upstream GOAWAY whose last_stream_id is below a stream the proxy
// opened means the upstream never processed it, so the stream fails as
// refused.
//
// USK-1174: this test used to drive a ServerRole Layer and assert that a
// *client's* GOAWAY(0) failed the client's own stream as refused — which
// pinned the bug. The ServerRole half is now the inverted
// TestReader_GoAwayFromClient_PeerStreamsUnaffected.
func TestReader_GoAwayMarksStreams(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, id := openClientGET(t, l, peer)
	if id != 1 {
		t.Fatalf("first client stream id = %d, want 1", id)
	}

	// last_stream_id=0: stream 1 (> 0) was never processed upstream.
	if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}

	err := nextUntilError(t, ch)
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: want *layer.StreamError, got %T (%v)", err, err)
	}
	if se.Code != layer.ErrorRefused {
		t.Errorf("StreamError code = %s, want refused", se.Code)
	}
}

// TestReader_GoAwayFromClient_PeerStreamsUnaffected is the ServerRole half
// of RFC 9113 §6.8 (USK-1174): a GOAWAY's last_stream_id names the highest
// stream *initiated by the GOAWAY's receiver*. A client GOAWAY received by
// the proxy's ServerRole Layer therefore says nothing about the streams the
// client itself opened; a browser draining with GOAWAY(0) still expects
// the in-flight responses. The stream must stay open and a response sent
// afterwards must reach the client intact.
func TestReader_GoAwayFromClient_PeerStreamsUnaffected(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	ch := acceptServerStream(t, l, peer)

	if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}
	syncPing(t, peer)

	select {
	case <-ch.Closed():
		t.Fatalf("client-opened stream terminated by the client's own GOAWAY(0): Err = %v", ch.Err())
	default:
	}
	if err := ch.Err(); err != nil {
		t.Fatalf("Err after client GOAWAY = %v, want nil", err)
	}

	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := ch.Send(ctx, &envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Message:   &H2HeadersEvent{Status: 200},
		}); err != nil {
			sendErr <- err
			return
		}
		sendErr <- ch.Send(ctx, &envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Message:   &H2DataEvent{Payload: []byte("ok"), EndStream: true},
		})
	}()

	var sawHeaders, sawEnd bool
	var body []byte
	deadline := time.Now().Add(2 * time.Second)
	for !sawEnd && time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if f.Header.StreamID != 1 {
			continue
		}
		switch f.Header.Type {
		case frame.TypeHeaders:
			sawHeaders = true
		case frame.TypeData:
			p, _ := f.DataPayload()
			body = append(body, p...)
			sawEnd = f.Header.Flags.Has(frame.FlagEndStream)
		case frame.TypeRSTStream:
			code, _ := f.RSTStreamErrorCode()
			t.Fatalf("RST_STREAM(%s) on stream 1 after client GOAWAY, want the response", ErrCodeString(code))
		}
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send response: %v", err)
	}
	if !sawHeaders || !sawEnd || string(body) != "ok" {
		t.Errorf("response on stream 1: headers=%v end_stream=%v body=%q, want headers, END_STREAM, %q", sawHeaders, sawEnd, body, "ok")
	}
}

// syncPing round-trips a PING so every frame the peer wrote before it has
// been processed by the Layer's reader (frames are handled in order).
func syncPing(t *testing.T, peer *h2Peer) {
	t.Helper()
	data := [8]byte{'s', 'y', 'n', 'c'}
	if err := peer.wr.WritePing(false, data); err != nil {
		t.Fatalf("write PING: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame (PING ACK): %v", err)
		}
		if f.Header.Type == frame.TypePing && f.Header.Flags.Has(frame.FlagAck) {
			if got, _ := f.PingData(); got == data {
				return
			}
		}
	}
	t.Fatal("did not receive PING ACK")
}

// TestReader_GoAwayFromUpstream_StreamAtOrBelowLastSurvives pins that an
// upstream GOAWAY only fails the proxy-opened streams ABOVE last_stream_id
// (RFC 9113 §6.8): with streams 1 and 3 open, GOAWAY(1) refuses 3 while 1
// still receives its response.
func TestReader_GoAwayFromUpstream_StreamAtOrBelowLastSurvives(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch1, id1 := openClientGET(t, l, peer)
	ch3, id3 := openClientGET(t, l, peer)
	if id1 != 1 || id3 != 3 {
		t.Fatalf("client stream ids = %d, %d; want 1, 3", id1, id3)
	}

	if err := peer.wr.WriteGoAway(1, ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}
	enc := peer.encoder.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
	if err := peer.wr.WriteHeaders(1, true, true, enc); err != nil {
		t.Fatalf("write response HEADERS: %v", err)
	}

	err := nextUntilError(t, ch3)
	var se *layer.StreamError
	if !errors.As(err, &se) || se.Code != layer.ErrorRefused {
		t.Errorf("stream 3 Next err = %v, want StreamError{refused}", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	env, err := ch1.Next(ctx)
	if err != nil {
		t.Fatalf("stream 1 Next: %v, want the response HEADERS", err)
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok || evt.Status != 200 {
		t.Errorf("stream 1 first envelope = %T %+v, want *H2HeadersEvent{Status:200}", env.Message, env.Message)
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
