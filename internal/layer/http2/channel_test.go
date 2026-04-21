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

// TestBodyChanged_PassthroughReturnsTrue pins the USK-617 gate flip: when an
// envelope carries a streaming body (msg.Body == nil && op.bodyReader != nil),
// bodyChanged must report "changed" so channel.Send takes the synthetic path.
// The opaque path's cached op.frames only contains bytes captured before the
// threshold handoff — taking it would emit the prefix and leave the pipe
// permanently un-drained.
func TestBodyChanged_PassthroughReturnsTrue(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	msg := &envelope.HTTPMessage{Body: nil, BodyStream: pr}
	op := &opaqueHTTP2{bodyReader: pr}
	if !bodyChanged(msg, op) {
		t.Error("bodyChanged(passthrough) = false; want true to force synthetic path (USK-617)")
	}
}

// TestChannel_Send_PassthroughDrainsBodyStream verifies that a passthrough-
// shaped envelope (msg.BodyStream set, opaqueHTTP2.bodyReader set) is routed
// through the synthetic path: headers are re-encoded on the wire, DATA frames
// are emitted for every byte fed into the pipe writer, and the final DATA
// frame carries END_STREAM. This is the core USK-617 regression guard — before
// the fix the opaque fast path would write only the captured op.frames and
// never drain the pipe.
func TestChannel_Send_PassthroughDrainsBodyStream(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	cs := ch.(*channel)

	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte(i)
	}

	pr, pw := io.Pipe()

	// If the opaque path were (incorrectly) taken, len(op.frames) > 0 is
	// required — populate a sentinel byte so the only guard that can reject
	// the opaque path is the bodyChanged passthrough gate introduced by
	// USK-617. op.layer is set to ch.layer so the cross-layer guard does
	// NOT reject; only the passthrough gate should.
	env := &envelope.Envelope{
		StreamID:  ch.StreamID(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:     "GET",
			Scheme:     "https",
			Authority:  "example.com",
			Path:       "/big",
			Body:       nil,
			BodyStream: pr,
		},
		Opaque: &opaqueHTTP2{
			layer:       cs.layer,
			streamID:    cs.h2Stream,
			frames:      [][]byte{{0xde, 0xad, 0xbe, 0xef}},
			origHeaders: []hpack.HeaderField{{Name: ":method", Value: "GET"}},
			origBody:    nil,
			bodyReader:  pr,
		},
	}

	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, env)
	}()

	// Feed the pipe in the background so writeStreamingBody can drain it.
	go func() {
		_, _ = pw.Write(body)
		_ = pw.Close()
	}()

	// First wire frame must be a real HEADERS (re-encoded via HPACK), not the
	// sentinel bytes from op.frames. Decoding succeeding and recovering
	// :method=GET proves the synthetic path was taken.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("first frame = %s, want HEADERS (synthetic path)", f.Header.Type)
	}
	frag, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment: %v", err)
	}
	hdrs, err := peer.decoder.Decode(frag)
	if err != nil {
		t.Fatalf("decode HEADERS: %v", err)
	}
	var gotMethod string
	for _, h := range hdrs {
		if h.Name == ":method" {
			gotMethod = h.Value
		}
	}
	if gotMethod != "GET" {
		t.Errorf(":method = %q, want GET (synthetic path)", gotMethod)
	}

	var collected []byte
	endStreamSeen := false
	deadline := time.Now().Add(3 * time.Second)
	for !endStreamSeen && time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read DATA: %v", err)
		}
		if f.Header.Type != frame.TypeData {
			continue
		}
		collected = append(collected, f.Payload...)
		if f.Header.Flags.Has(frame.FlagEndStream) {
			endStreamSeen = true
		}
	}
	if !endStreamSeen {
		t.Fatal("did not observe END_STREAM on any DATA frame")
	}
	if len(collected) != len(body) {
		t.Errorf("received %d body bytes, want %d", len(collected), len(body))
	}
	for i := range collected {
		if collected[i] != body[i] {
			t.Fatalf("body byte %d = %d, want %d", i, collected[i], body[i])
		}
	}

	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
}

// TestChannel_Send_CrossLayerOpaqueFallsToSynthetic verifies that an envelope
// whose opaqueHTTP2 snapshot was produced by a different Layer falls through
// to the synthetic path, even when stream IDs coincidentally match. Without
// the USK-617 same-Layer guard, cross-Layer forwarding (the common MITM case)
// would write raw frame bytes whose embedded HPACK dynamic-table indices are
// meaningless to the destination Layer's decoder.
func TestChannel_Send_CrossLayerOpaqueFallsToSynthetic(t *testing.T) {
	// Foreign Layer — used only so we have a valid, distinct *Layer pointer
	// to stamp onto the envelope's opaqueHTTP2 field.
	foreign, peerF, cleanupF := startClientLayer(t)
	defer cleanupF()
	peerF.consumePeerSettings(t)

	// Destination Layer and stream.
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	cs := ch.(*channel)
	if cs.h2Stream != 1 {
		// Both fresh client layers allocate 1 first — this is the stream-ID
		// collision that makes the layer guard essential.
		t.Fatalf("unexpected h2Stream = %d, want 1", cs.h2Stream)
	}

	body := []byte("hello-cross-layer")
	msg := &envelope.HTTPMessage{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/x",
		Headers:   []envelope.KeyValue{{Name: "content-type", Value: "text/plain"}},
		Body:      body,
	}
	// Opaque says "I came from layer foreign, stream 1" — the stream ID
	// coincidentally matches cs.h2Stream. Sentinel frame bytes would be
	// written verbatim if the cross-Layer guard fails.
	env := &envelope.Envelope{
		StreamID:  ch.StreamID(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Opaque: &opaqueHTTP2{
			layer:       foreign,
			streamID:    cs.h2Stream,
			frames:      [][]byte{{0xde, 0xad, 0xbe, 0xef}},
			origHeaders: []hpack.HeaderField{{Name: ":method", Value: "POST"}},
			origBody:    body,
		},
	}

	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, env)
	}()

	// HEADERS must be a real HPACK-encoded frame, not the sentinel 0xdeadbeef.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("first frame = %s, want HEADERS (synthetic path for cross-Layer)", f.Header.Type)
	}
	frag, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment: %v", err)
	}
	hdrs, err := peer.decoder.Decode(frag)
	if err != nil {
		t.Fatalf("decode HEADERS: %v", err)
	}
	var gotMethod, gotPath string
	for _, h := range hdrs {
		switch h.Name {
		case ":method":
			gotMethod = h.Value
		case ":path":
			gotPath = h.Value
		}
	}
	if gotMethod != "POST" || gotPath != "/x" {
		t.Errorf("headers = {:method=%q, :path=%q}, want {POST, /x}", gotMethod, gotPath)
	}

	f, err = peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read DATA: %v", err)
	}
	if f.Header.Type != frame.TypeData {
		t.Fatalf("second frame = %s, want DATA", f.Header.Type)
	}
	if string(f.Payload) != string(body) {
		t.Errorf("body = %q, want %q", f.Payload, body)
	}
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Error("DATA missing END_STREAM")
	}

	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
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
