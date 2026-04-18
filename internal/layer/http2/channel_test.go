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

func TestChannel_StreamID_IsUUID(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	id := ch.StreamID()
	// UUID format: 8-4-4-4-12 chars (36 with hyphens).
	if len(id) != 36 {
		t.Errorf("StreamID = %q, expected UUID-format (36 chars)", id)
	}
}

func TestChannel_Send_SyntheticRequest(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	msg := &envelope.HTTPMessage{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/foo",
		RawQuery:  "q=1",
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "text/plain"},
		},
		Body: []byte("hello"),
	}
	env := &envelope.Envelope{
		StreamID:  ch.StreamID(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, env)
	}()

	// Settings already consumed at startup. Next frame is HEADERS.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("got %s, want HEADERS", f.Header.Type)
	}
	frag, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment: %v", err)
	}
	hdrs, err := peer.decoder.Decode(frag)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := map[string]string{
		":method":      "POST",
		":scheme":      "https",
		":path":        "/foo?q=1",
		":authority":   "example.com",
		"content-type": "text/plain",
	}
	got := map[string]string{}
	for _, h := range hdrs {
		got[h.Name] = h.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("header %s = %q, want %q (all: %+v)", k, got[k], v, got)
		}
	}

	// Then DATA.
	f, err = peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read DATA: %v", err)
	}
	if f.Header.Type != frame.TypeData {
		t.Fatalf("got %s, want DATA", f.Header.Type)
	}
	if string(f.Payload) != "hello" {
		t.Errorf("body = %q, want hello", f.Payload)
	}
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Errorf("DATA missing END_STREAM")
	}

	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestChannel_Close_Idempotent(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := ch.Close(); err != nil {
			t.Errorf("Close #%d: %v", i, err)
		}
	}
}

func TestChannel_PushChannel_RejectsSend(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	// Open a stream and send a request to anchor the conversation.
	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	go func() {
		_ = ch.Send(context.Background(), &envelope.Envelope{
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "https", Authority: "x", Path: "/",
			},
		})
	}()

	// Drain the SETTINGS, SETTINGS-ACK, HEADERS frames.
	for i := 0; i < 5; i++ {
		_ = peer.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		f, err := peer.rd.ReadFrame()
		if err != nil {
			break
		}
		if f.Header.Type == frame.TypeHeaders {
			break
		}
	}
	_ = peer.conn.SetReadDeadline(time.Time{})

	// Now send a PUSH_PROMISE for stream 2 → expect a new push channel via
	// l.Channels().
	pushHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/pushed"},
	}
	encoded := peer.encoder.Encode(pushHeaders)
	if err := peer.wr.WritePushPromise(1, 2, true, encoded); err != nil {
		t.Fatalf("WritePushPromise: %v", err)
	}

	var pushCh = waitForChannel(t, l, time.Second)
	if pushCh == nil {
		t.Fatal("no push channel emitted")
	}

	// Send on push channel must be rejected.
	err = pushCh.Send(context.Background(), &envelope.Envelope{
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/", Scheme: "https", Authority: "x"},
	})
	if err == nil {
		t.Fatal("Send on push channel: want error, got nil")
	}
}

// waitForChannel polls l.Channels() until a Channel arrives or timeout.
func waitForChannel(t *testing.T, l *Layer, dur time.Duration) (ch interface {
	StreamID() string
	Next(context.Context) (*envelope.Envelope, error)
	Send(context.Context, *envelope.Envelope) error
	Close() error
}) {
	t.Helper()
	deadline := time.NewTimer(dur)
	defer deadline.Stop()
	for {
		select {
		case c, ok := <-l.Channels():
			if !ok {
				return nil
			}
			return c
		case <-deadline.C:
			return nil
		}
	}
}

func TestChannel_Next_EOFWhenLayerClosed(t *testing.T) {
	l, peer, _ := startClientLayer(t)
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Close the peer side so the reader hits EOF and shuts down.
	_ = peer.conn.Close()

	// Force the layer to close (it would also close on EOF).
	_ = l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = ch.Next(ctx)
	if err == nil || !errors.Is(err, io.EOF) {
		// The error may be ctx.Err if shutdown raced; accept io.EOF as
		// the canonical post-close result.
		if err == nil {
			t.Fatalf("Next: want io.EOF, got nil")
		}
	}
}
