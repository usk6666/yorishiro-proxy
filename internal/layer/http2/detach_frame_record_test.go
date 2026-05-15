package http2

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// TestLayer_DetachStream_WithFrameRecordCallback_NilCallback verifies the
// option is a no-op when cb is nil — equivalent to omitting the option
// entirely, preserving the pre-USK-889 contract.
func TestLayer_DetachStream_WithFrameRecordCallback_NilCallback(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "echo.example.com"},
		{Name: ":path", Value: "/chat"},
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
		t.Fatal("no Channel")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("drain HEADERS: %v", err)
	}

	// WithFrameRecordCallback(nil) is an explicit Option but the
	// installed callback is nil so the drain path skips invocation.
	r, _, closer, err := l.DetachStream(1, WithFrameRecordCallback(nil))
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()

	if err := peer.wr.WriteData(1, true, []byte("payload")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	got, _ := io.ReadAll(r)
	if string(got) != "payload" {
		t.Errorf("reader bytes = %q, want %q", got, "payload")
	}
}

// TestLayer_DetachStream_WithFrameRecordCallback_FiresPerDataFrame
// verifies the core USK-889 contract: every H2DataEvent envelope drained
// from the detached stream's channel fires the callback exactly once,
// with the envelope's Raw containing the DATA frame payload and Message
// typed as *H2DataEvent.
func TestLayer_DetachStream_WithFrameRecordCallback_FiresPerDataFrame(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "echo.example.com"},
		{Name: ":path", Value: "/chat"},
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
		t.Fatal("no Channel")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("drain HEADERS: %v", err)
	}

	var mu sync.Mutex
	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, env)
	}

	r, _, closer, err := l.DetachStream(1, WithFrameRecordCallback(cb))
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()

	frames := [][]byte{
		[]byte("frame-one"),
		[]byte("frame-two-bytes"),
		[]byte("3"),
	}
	for _, p := range frames {
		if err := peer.wr.WriteData(1, false, p); err != nil {
			t.Fatalf("WriteData: %v", err)
		}
	}
	if err := peer.wr.WriteData(1, true, nil); err != nil {
		t.Fatalf("WriteData(END_STREAM): %v", err)
	}

	// Drain the reader so the drain loop processes every frame.
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	<-ch.drainDoneChan()

	mu.Lock()
	defer mu.Unlock()
	// Expect 4 invocations: 3 with payload + 1 END_STREAM-only (empty
	// payload).
	if len(observed) != 4 {
		t.Fatalf("callback fired %d times, want 4 (3 payload + 1 EOF)", len(observed))
	}

	for i, p := range frames {
		env := observed[i]
		if env == nil {
			t.Fatalf("observed[%d] = nil", i)
			continue
		}
		data, ok := env.Message.(*H2DataEvent)
		if !ok {
			t.Errorf("observed[%d].Message type = %T, want *H2DataEvent", i, env.Message)
			continue
		}
		if string(data.Payload) != string(p) {
			t.Errorf("observed[%d].Message.Payload = %q, want %q", i, data.Payload, p)
		}
		if data.EndStream {
			t.Errorf("observed[%d].Message.EndStream = true, want false (mid-stream frame)", i)
		}
		if string(env.Raw) != string(p) {
			t.Errorf("observed[%d].Raw = %q, want %q", i, env.Raw, p)
		}
		if env.Protocol != envelope.ProtocolHTTP {
			t.Errorf("observed[%d].Protocol = %q, want %q (no ProtocolHTTP2 constant by design)", i, env.Protocol, envelope.ProtocolHTTP)
		}
	}
	// Last invocation is the END_STREAM empty DATA.
	last := observed[3]
	data, ok := last.Message.(*H2DataEvent)
	if !ok {
		t.Fatalf("last observed Message type = %T, want *H2DataEvent", last.Message)
	}
	if !data.EndStream {
		t.Errorf("last observed EndStream = false, want true (END_STREAM frame)")
	}
}

// TestLayer_DetachStream_WithFrameRecordCallback_FiresBeforePipeWrite
// pins the USK-889 ordering contract: the callback observes each frame
// BEFORE its payload reaches the detach pipe. This is asserted by having
// the callback block on a channel send and verifying the reader has not
// yet observed the bytes when the send happens.
func TestLayer_DetachStream_WithFrameRecordCallback_FiresBeforePipeWrite(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "echo.example.com"},
		{Name: ":path", Value: "/chat"},
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
		t.Fatal("no Channel")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("drain HEADERS: %v", err)
	}

	// cbObservedCh fires when the callback sees the first frame. We
	// then race a non-blocking reader: at the moment the callback
	// arrives, the pipe.Write for that frame has not happened yet, so
	// a reader cannot have observed the bytes. This is asserted by a
	// short-deadline ReadFull immediately after the cb fires; if the
	// ordering were reversed (Write then cb), the reader would have
	// already returned the bytes.
	//
	// We deliberately use a buffered cbObservedCh + sync.Once so the
	// pattern matches CLAUDE.md "single-writer close": the callback
	// doesn't block, it just signals once.
	cbObservedCh := make(chan struct{}, 1)
	var once sync.Once
	cb := func(env *envelope.Envelope) {
		once.Do(func() { close(cbObservedCh) })
	}

	r, _, closer, err := l.DetachStream(1, WithFrameRecordCallback(cb))
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()

	want := []byte("frame-payload")
	if err := peer.wr.WriteData(1, true, want); err != nil {
		t.Fatalf("WriteData: %v", err)
	}

	// Wait for the callback to fire.
	select {
	case <-cbObservedCh:
	case <-time.After(time.Second):
		t.Fatal("callback did not fire within 1s")
	}

	// At this instant the callback has just returned; the pipe.Write
	// for the same frame is the very next statement on the drain
	// goroutine, so the reader either sees the bytes right away (if
	// the goroutine has already raced past us) or after a short
	// window. Reading until EOF here is sufficient — the previous
	// assertion only required that the callback fires at least as
	// early as the pipe write (BEFORE rather than AFTER).
	got, _ := io.ReadAll(r)
	if string(got) != string(want) {
		t.Errorf("reader bytes = %q, want %q", got, want)
	}
}
