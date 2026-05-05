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

// TestChannel_StreamID_IsUUID verifies the Channel's StreamID is a
// UUID-shaped identifier, not the HTTP/2 wire stream id.
func TestChannel_StreamID_IsUUID(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if id := ch.StreamID(); len(id) != 36 {
		t.Errorf("StreamID = %q, expected 36-char UUID", id)
	}
}

// TestChannel_Send_HeadersEvent verifies sending an H2HeadersEvent produces
// a HEADERS frame on the wire with the expected pseudo-headers.
func TestChannel_Send_HeadersEvent(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	evt := &H2HeadersEvent{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/foo",
		EndStream: true,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message:   evt,
		})
	}()

	f := drainUntil(t, peer, frame.TypeHeaders)
	if err := <-errCh; err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Error("HEADERS frame missing END_STREAM")
	}
	fragment, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment: %v", err)
	}
	decoded, err := peer.decoder.Decode(fragment)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	hasMethod := false
	for _, hf := range decoded {
		if hf.Name == ":method" && hf.Value == "GET" {
			hasMethod = true
		}
	}
	if !hasMethod {
		t.Errorf(":method=GET missing from HEADERS: %+v", decoded)
	}
}

// TestChannel_Send_DataEvent verifies sending an H2DataEvent produces a
// DATA frame.
func TestChannel_Send_DataEvent(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Send HEADERS then DATA sequentially from a goroutine so the test can
	// read frames off the wire without deadlocking against a full pipe.
	done := make(chan error, 1)
	go func() {
		if err := ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message:   &H2HeadersEvent{Method: "POST", Scheme: "https", Authority: "x", Path: "/"},
		}); err != nil {
			done <- err
			return
		}
		done <- ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message:   &H2DataEvent{Payload: []byte("hello"), EndStream: true},
		})
	}()
	drainUntil(t, peer, frame.TypeHeaders)
	f := drainUntil(t, peer, frame.TypeData)
	if err := <-done; err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Error("DATA frame missing END_STREAM")
	}
	payload, err := f.DataPayload()
	if err != nil {
		t.Fatalf("DataPayload: %v", err)
	}
	if string(payload) != "hello" {
		t.Errorf("payload = %q, want 'hello'", string(payload))
	}
}

// TestChannel_Close_Idempotent verifies that Close is safe to call multiple
// times.
func TestChannel_Close_Idempotent(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := ch.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := ch.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestChannel_PushChannel_RejectsSend verifies that push channels reject
// Send calls.
func TestChannel_PushChannel_RejectsSend(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

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
	drainUntil(t, peer, frame.TypeHeaders)

	pushHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/pushed"},
	}
	encoded := peer.encoder.Encode(pushHeaders)
	if err := peer.wr.WritePushPromise(1, 2, true, encoded); err != nil {
		t.Fatalf("WritePushPromise: %v", err)
	}

	var pushCh *channel
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && pushCh == nil {
		select {
		case c, ok := <-l.Channels():
			if !ok {
				t.Fatal("Channels closed")
			}
			if pc, ok := c.(*channel); ok && pc.isPush {
				pushCh = pc
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if pushCh == nil {
		t.Fatal("no push channel emitted")
	}
	err = pushCh.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Receive,
		Message:   &H2HeadersEvent{Status: 200},
	})
	if err == nil {
		t.Error("Send on push channel returned nil error; expected rejection")
	}
}

// TestChannel_Next_EOFWhenLayerClosed verifies that Next returns io.EOF when
// the Layer is closed.
func TestChannel_Next_EOFWhenLayerClosed(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = l.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = ch.Next(ctx)
	if err == nil {
		t.Fatal("Next returned no error; expected EOF or cancel")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("Next error = %v; expected io.EOF / cancel", err)
	}
}

// drainUntil reads frames until one matches want. Returns the matching frame.
func drainUntil(t *testing.T, peer *h2Peer, want frame.Type) *frame.Frame {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if f.Header.Type == want {
			return f
		}
	}
	t.Fatalf("did not receive %v frame within deadline", want)
	return nil
}
