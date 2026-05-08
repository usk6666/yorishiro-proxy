package http2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// TestLayer_DetachStream_RejectsZeroID verifies the pre-condition guard:
// stream id 0 is the connection-level identifier and DetachStream MUST
// reject it without mutating any channel state.
func TestLayer_DetachStream_RejectsZeroID(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	r, w, c, err := l.DetachStream(0)
	if err == nil {
		t.Fatal("DetachStream(0) must error")
	}
	if r != nil || w != nil || c != nil {
		t.Errorf("DetachStream(0) returned non-nil triple on error: r=%v w=%v c=%v", r, w, c != nil)
	}
}

// TestLayer_DetachStream_RejectsUnknownID verifies that DetachStream on a
// stream id that has never been registered errors out cleanly.
func TestLayer_DetachStream_RejectsUnknownID(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	if _, _, _, err := l.DetachStream(99); err == nil {
		t.Fatal("DetachStream on unknown stream id must error")
	}
}

// TestLayer_DetachStream_ServerReadsClientDataBytes verifies the
// fundamental read path: after a server-side Layer's stream is detached,
// DATA bytes the peer (client) writes on that stream surface verbatim on
// the returned reader, in arrival order.
//
// This is the §3.3.2 "DATA frame payloads arrive in arrival order on the
// returned reader" MUST.
func TestLayer_DetachStream_ServerReadsClientDataBytes(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	// Open a stream with HEADERS (no END_STREAM so DATA can follow).
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "echo.example.com"},
		{Name: ":path", Value: "/chat"},
		{Name: ":protocol", Value: "websocket"},
	}
	encoded := peer.encoder.Encode(headers)
	if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	// Drain the HEADERS envelope so the assembler advances past the
	// initial-headers phase. Without this, subsequent DATA goes through
	// without a problem, but the recv channel still carries a HEADERS
	// envelope that the detach drainer would discard — keeping the read
	// expectation tight.
	var ch *channel
	select {
	case lc := <-l.Channels():
		ch = lc.(*channel)
	case <-time.After(time.Second):
		t.Fatal("did not receive Channel within 1s")
	}
	ctxRead, cancelRead := context.WithTimeout(context.Background(), time.Second)
	defer cancelRead()
	if _, err := ch.Next(ctxRead); err != nil {
		t.Fatalf("drain HEADERS envelope: %v", err)
	}

	// Now detach the stream.
	r, _, closer, err := l.DetachStream(1)
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()
	if !ch.detachActive() {
		t.Error("detachActive() should be true after DetachStream")
	}

	// Peer writes DATA on the same stream id. The bytes should surface
	// on the detach reader.
	want := []byte("hello-from-client")
	if err := peer.wr.WriteData(1, false, want); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read = %q, want %q", got, want)
	}

	// END_STREAM signal: peer writes empty DATA(END_STREAM); reader
	// should observe io.EOF after any preceding bytes have been drained.
	if err := peer.wr.WriteData(1, true, nil); err != nil {
		t.Fatalf("WriteData(END_STREAM): %v", err)
	}
	// Read until EOF.
	tail, _ := io.ReadAll(r)
	if len(tail) != 0 {
		t.Errorf("post-END_STREAM tail bytes = %q, want empty", tail)
	}
}

// TestLayer_DetachStream_DoubleDetachRejected verifies that the second
// DetachStream call on the same id errors out — single-writer invariant
// from RFC-001 §3.3.2 (the orchestrator owns the per-stream framing
// after the first call).
func TestLayer_DetachStream_DoubleDetachRejected(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "example.com"},
	}
	encoded := peer.encoder.Encode(headers)
	if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	select {
	case <-l.Channels():
	case <-time.After(time.Second):
		t.Fatal("no Channel emitted")
	}

	if _, _, _, err := l.DetachStream(1); err != nil {
		t.Fatalf("first DetachStream: %v", err)
	}
	if _, _, _, err := l.DetachStream(1); err == nil {
		t.Error("second DetachStream on the same id must error")
	}
}

// TestLayer_DetachStream_Multiplex_SiblingStreamUnaffected exercises the
// RFC-001 §3.4.1 multiplex-isolation MUST at the http2 Layer level: a
// detached stream's per-stream byte path MUST NOT interfere with a
// sibling stream's standard event-granular Channel.
//
// Setup: two concurrent streams (id 1 and id 3) on a server-role Layer.
// Stream 1 is detached. Stream 3 still uses the standard Channel and
// receives a regular HEADERS+DATA flow that surfaces as the usual
// H2HeadersEvent / H2DataEvent envelopes.
func TestLayer_DetachStream_Multiplex_SiblingStreamUnaffected(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	// Open stream 1 (will be detached).
	hdrs1 := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/ws"},
		{Name: ":protocol", Value: "websocket"},
	}
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(hdrs1)); err != nil {
		t.Fatalf("WriteHeaders(1): %v", err)
	}

	// Drain stream 1's initial HEADERS envelope.
	var ch1 *channel
	select {
	case lc := <-l.Channels():
		ch1 = lc.(*channel)
	case <-time.After(time.Second):
		t.Fatal("no Channel for stream 1")
	}
	if _, err := ch1.Next(context.Background()); err != nil {
		t.Fatalf("drain stream 1 HEADERS: %v", err)
	}
	if ch1.H2StreamID() != 1 {
		t.Errorf("ch1.H2StreamID = %d, want 1", ch1.H2StreamID())
	}

	// Detach stream 1.
	r, _, closer1, err := l.DetachStream(1)
	if err != nil {
		t.Fatalf("DetachStream(1): %v", err)
	}
	defer func() { _ = closer1() }()

	// Open stream 3 (sibling) — regular HTTP/2 GET with body.
	hdrs3 := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/api"},
		{Name: ":authority", Value: "example.com"},
		{Name: "content-type", Value: "text/plain"},
	}
	if err := peer.wr.WriteHeaders(3, false, true, peer.encoder.Encode(hdrs3)); err != nil {
		t.Fatalf("WriteHeaders(3): %v", err)
	}
	siblingBody := []byte("payload-on-sibling-stream")
	if err := peer.wr.WriteData(3, true, siblingBody); err != nil {
		t.Fatalf("WriteData(3): %v", err)
	}

	// Stream 3's Channel should be emitted on l.Channels() AND its
	// envelopes should arrive via the standard event-granular path —
	// the detach on stream 1 must not interfere.
	var ch3 *channel
	select {
	case lc := <-l.Channels():
		ch3 = lc.(*channel)
	case <-time.After(time.Second):
		t.Fatal("no Channel for stream 3")
	}
	if ch3.H2StreamID() != 3 {
		t.Errorf("ch3.H2StreamID = %d, want 3", ch3.H2StreamID())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Drain HEADERS event.
	env, err := ch3.Next(ctx)
	if err != nil {
		t.Fatalf("ch3.Next (HEADERS): %v", err)
	}
	if _, ok := env.Message.(*H2HeadersEvent); !ok {
		t.Errorf("ch3 first envelope = %T, want *H2HeadersEvent", env.Message)
	}

	// Drain DATA event(s) until END_STREAM. Multiple DATA events may
	// arrive due to MAX_FRAME_SIZE splitting; here a small payload
	// fits in one frame.
	var got bytes.Buffer
	for got.Len() < len(siblingBody) {
		env, err := ch3.Next(ctx)
		if err != nil {
			t.Fatalf("ch3.Next (DATA): %v", err)
		}
		data, ok := env.Message.(*H2DataEvent)
		if !ok {
			t.Fatalf("expected *H2DataEvent, got %T", env.Message)
		}
		got.Write(data.Payload)
		if data.EndStream {
			break
		}
	}
	if !bytes.Equal(got.Bytes(), siblingBody) {
		t.Errorf("sibling stream body = %q, want %q", got.Bytes(), siblingBody)
	}

	// Stream 1's detach reader must NOT have surfaced any bytes from
	// stream 3 (multiplex-isolation MUST). We expect zero bytes
	// available and a Read that times out / blocks. We use a brief
	// non-blocking probe via SetReadDeadline-equivalent — io.Pipe does
	// not support deadlines, so instead we confirm the assertion in a
	// goroutine with a timeout.
	probeDone := make(chan int, 1)
	probeBuf := make([]byte, 32)
	go func() {
		n, _ := r.Read(probeBuf)
		probeDone <- n
	}()
	select {
	case n := <-probeDone:
		t.Errorf("stream 1 detach reader unexpectedly produced %d bytes, want 0 (sibling stream 3 leaked)", n)
	case <-time.After(150 * time.Millisecond):
		// Expected: no bytes from sibling on stream 1's detach reader.
	}
}

// TestLayer_DetachStream_PipeWriterEnqueuesDataFrame verifies the basic
// write path: bytes written to the returned writer surface as DATA frames
// on the wire.
func TestLayer_DetachStream_PipeWriterEnqueuesDataFrame(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
		{Name: ":protocol", Value: "websocket"},
	}
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(headers)); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	var ch *channel
	select {
	case lc := <-l.Channels():
		ch = lc.(*channel)
	case <-time.After(time.Second):
		t.Fatal("no Channel emitted")
	}
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("drain HEADERS: %v", err)
	}

	_, w, closer, err := l.DetachStream(1)
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()

	want := []byte("server-says-hi")
	writeDone := make(chan error, 1)
	go func() {
		_, werr := w.Write(want)
		writeDone <- werr
	}()

	// Read frames from peer until we see the DATA(payload=want) frame
	// for stream 1. The Layer may interleave WINDOW_UPDATE / ACK
	// frames; skip those.
	deadline := time.Now().Add(2 * time.Second)
	var saw bool
	for time.Now().Before(deadline) && !saw {
		f, ferr := peer.rd.ReadFrame()
		if ferr != nil {
			t.Fatalf("read peer frame: %v", ferr)
		}
		if f.Header.Type != frame.TypeData || f.Header.StreamID != 1 {
			continue
		}
		payload, perr := f.DataPayload()
		if perr != nil {
			t.Fatalf("DataPayload: %v", perr)
		}
		if !bytes.Equal(payload, want) {
			t.Errorf("DATA payload = %q, want %q", payload, want)
		}
		saw = true
	}
	if !saw {
		t.Fatal("peer did not observe DATA frame on stream 1")
	}
	select {
	case werr := <-writeDone:
		if werr != nil {
			t.Errorf("Write returned error: %v", werr)
		}
	case <-time.After(time.Second):
		t.Error("Write did not return within 1s")
	}
}

// TestLayer_DetachStream_DrainBufferedDataBeforeReturn verifies the
// RFC-001 §3.3.2 BodyBuffer drain MUST: DATA bytes that arrived between
// the trigger envelope (the HEADERS in this test) and the DetachStream
// call are surfaced on the returned reader in arrival order.
//
// Setup: we wait until both HEADERS + DATA have been observed by the
// Layer's reader before calling DetachStream. The DATA event is sitting
// on ch.recv; the detach drainer must forward it to the pipe.
func TestLayer_DetachStream_DrainBufferedDataBeforeReturn(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
		{Name: ":protocol", Value: "websocket"},
	}
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(headers)); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	// Wait for the Channel emission; drain the HEADERS envelope.
	var ch *channel
	select {
	case lc := <-l.Channels():
		ch = lc.(*channel)
	case <-time.After(time.Second):
		t.Fatal("no Channel emitted")
	}
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("drain HEADERS: %v", err)
	}

	// Send DATA BEFORE detaching. The Layer will accept it and queue
	// the H2DataEvent envelope on ch.recv.
	want := []byte("buffered-bytes")
	if err := peer.wr.WriteData(1, false, want); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	// Wait until the channel reports a non-empty recv buffer (lock-free
	// poll up to a short timeout) so we know the assembler has produced
	// the DATA event.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(ch.recv) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(ch.recv) == 0 {
		t.Fatal("DATA event not observed by assembler within 1s")
	}

	// NOW detach. The drainer must forward the buffered DATA payload.
	r, _, closer, err := l.DetachStream(1)
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read = %q, want %q (BodyBuffer drain MUST violated)", got, want)
	}
}

// TestLayer_DetachStream_TerminalErrorSurfacesOnReader verifies that a
// stream-level error (e.g. RST_STREAM) on the detached stream surfaces as
// a non-nil non-EOF error on the reader, so the orchestrator can
// distinguish abnormal termination from graceful EOF.
func TestLayer_DetachStream_TerminalErrorSurfacesOnReader(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
		{Name: ":protocol", Value: "websocket"},
	}
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(headers)); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	var ch *channel
	select {
	case lc := <-l.Channels():
		ch = lc.(*channel)
	case <-time.After(time.Second):
		t.Fatal("no Channel emitted")
	}
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("drain HEADERS: %v", err)
	}

	r, _, closer, err := l.DetachStream(1)
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()

	// Peer aborts the stream with RST_STREAM(INTERNAL_ERROR).
	if err := peer.wr.WriteRSTStream(1, ErrCodeInternal); err != nil {
		t.Fatalf("WriteRSTStream: %v", err)
	}

	// Reader should observe a non-EOF error within a short time.
	readDone := make(chan error, 1)
	go func() {
		_, rerr := io.ReadAll(r)
		readDone <- rerr
	}()
	select {
	case rerr := <-readDone:
		if rerr == nil || errors.Is(rerr, io.EOF) {
			t.Errorf("read err = %v, want non-EOF error from RST_STREAM", rerr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not surface terminal error within 2s")
	}
}

// TestLayer_DetachStream_DrainDoneFiresOnTerminate verifies that the
// drainer goroutine actually exits when the channel terminates — a
// concurrency-checklist item ensuring no goroutine leak on stream end.
func TestLayer_DetachStream_DrainDoneFiresOnTerminate(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
		{Name: ":protocol", Value: "websocket"},
	}
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(headers)); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	var ch *channel
	select {
	case lc := <-l.Channels():
		ch = lc.(*channel)
	case <-time.After(time.Second):
		t.Fatal("no Channel emitted")
	}
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("drain HEADERS: %v", err)
	}

	if _, _, closer, err := l.DetachStream(1); err != nil {
		t.Fatalf("DetachStream: %v", err)
	} else {
		// Trigger graceful termination via the closer.
		_ = closer()
	}

	select {
	case <-ch.drainDoneChan():
	case <-time.After(2 * time.Second):
		t.Fatal("detach drainer did not exit within 2s — goroutine leak")
	}
}
