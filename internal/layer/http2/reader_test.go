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
	_, err := ch.Next(ctx)
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
	_, err := ch.Next(ctx)
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: want *layer.StreamError, got %T (%v)", err, err)
	}
	if se.Code != layer.ErrorCanceled {
		t.Errorf("StreamError code = %s, want canceled", se.Code)
	}
}

func TestReader_PushPromise_EmitsChannelAndSyntheticEnvelope(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	// Open a client stream.
	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Send a request to anchor the stream.
	go func() {
		_ = ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "https", Authority: "x", Path: "/",
			},
		})
	}()

	// Drain frames until we see HEADERS.
	for i := 0; i < 5; i++ {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.Header.Type == frame.TypeHeaders {
			break
		}
	}

	// Send a PUSH_PROMISE on stream 1 promising stream 2.
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

	// Expect a synthetic envelope on the original channel.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	hasPushAnomaly := false
	for _, a := range msg.Anomalies {
		if a.Type == envelope.H2PushPromise {
			hasPushAnomaly = true
		}
	}
	if !hasPushAnomaly {
		t.Errorf("synthetic push envelope missing H2PushPromise anomaly: %+v", msg.Anomalies)
	}
	if msg.Path != "/pushed.css" {
		t.Errorf("synthetic push path = %q, want /pushed.css", msg.Path)
	}

	// Expect a new push channel on Channels().
	pushCh := waitForChannel(t, l, time.Second)
	if pushCh == nil {
		t.Fatal("no push channel emitted")
	}
	c := pushCh.(*channel)
	if !c.isPush {
		t.Errorf("push channel isPush = false, want true")
	}
	if c.h2Stream != 2 {
		t.Errorf("push channel h2Stream = %d, want 2", c.h2Stream)
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
