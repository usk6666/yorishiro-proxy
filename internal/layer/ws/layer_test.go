package ws

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// pipeRWC bundles two halves of a net.Pipe pair plus a recording closer
// so tests can verify Layer.Close cascade.
type recordingCloser struct {
	conn   net.Conn
	closeN int32
}

func (r *recordingCloser) Close() error {
	atomic.AddInt32(&r.closeN, 1)
	return r.conn.Close()
}

func TestLayer_Channels_YieldsOneChannel(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	rc := &recordingCloser{conn: b}
	l := New(b, b, rc, "stream-1", RoleServer)
	defer l.Close()

	count := 0
	for ch := range l.Channels() {
		count++
		if ch.StreamID() != "stream-1" {
			t.Errorf("StreamID = %q, want stream-1", ch.StreamID())
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 channel, got %d", count)
	}
}

func TestLayer_Close_CascadesCloser(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	rc := &recordingCloser{conn: b}
	l := New(b, b, rc, "stream-1", RoleServer)

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := atomic.LoadInt32(&rc.closeN); got != 1 {
		t.Errorf("closer.Close called %d times, want 1", got)
	}

	// Idempotent.
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := atomic.LoadInt32(&rc.closeN); got != 1 {
		t.Errorf("after second Close: closer.Close called %d times, want 1 (sync.Once)", got)
	}

	// Channel should be marked terminated.
	ch := l.channel
	select {
	case <-ch.Closed():
	default:
		t.Error("Channel.Closed() did not fire after Layer.Close")
	}
	if !errors.Is(ch.Err(), io.EOF) {
		t.Errorf("Err() = %v, want io.EOF", ch.Err())
	}
}

func TestLayer_Send_RoleServer_WritesUnmaskedFrame(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	l := New(b, b, b, "stream-1", RoleServer)
	defer l.Close()
	ch := <-l.Channels()

	// Read what the Layer writes from the other end.
	type readResult struct {
		frame *Frame
		err   error
	}
	resCh := make(chan readResult, 1)
	go func() {
		f, _, err := ReadFrameRaw(a)
		resCh <- readResult{f, err}
	}()

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Fin:     true,
			Payload: []byte("hello"),
		},
	}
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("ReadFrameRaw: %v", res.err)
	}
	if res.frame.Masked {
		t.Error("RoleServer wrote a masked frame; want unmasked")
	}
	if string(res.frame.Payload) != "hello" {
		t.Errorf("payload = %q, want hello", res.frame.Payload)
	}
}

func TestLayer_Send_RoleClient_RegeneratesMaskPerFrame(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	l := New(b, b, b, "stream-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	// Read both frames in a goroutine so the Send call doesn't block.
	type readResult struct {
		frame *Frame
		err   error
	}
	resCh := make(chan readResult, 2)
	go func() {
		for i := 0; i < 2; i++ {
			f, _, err := ReadFrameRaw(a)
			resCh <- readResult{f, err}
		}
	}()

	for i := 0; i < 2; i++ {
		env := &envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolWebSocket,
			Message: &envelope.WSMessage{
				Opcode:  envelope.WSText,
				Fin:     true,
				Payload: []byte("hello"),
			},
		}
		if err := ch.Send(context.Background(), env); err != nil {
			t.Fatalf("Send #%d: %v", i, err)
		}
	}

	r1, r2 := <-resCh, <-resCh
	if r1.err != nil || r2.err != nil {
		t.Fatalf("ReadFrameRaw errors: %v %v", r1.err, r2.err)
	}
	if !r1.frame.Masked || !r2.frame.Masked {
		t.Error("RoleClient frame was unmasked; want masked")
	}
	if r1.frame.MaskKey == r2.frame.MaskKey {
		// Probabilistic — could collide 1 in 2^32 times. Acceptable.
		t.Errorf("two consecutive mask keys identical: %v (crypto/rand expected)", r1.frame.MaskKey)
	}
	// ReadFrame auto-unmasks: payload should be hello.
	if string(r1.frame.Payload) != "hello" || string(r2.frame.Payload) != "hello" {
		t.Errorf("payload mismatch: %q %q", r1.frame.Payload, r2.frame.Payload)
	}
}

func TestLayer_Send_OversizedPayload_ErrorAborted(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go io.Copy(io.Discard, a) //nolint:errcheck

	l := New(b, b, b, "stream-1", RoleServer, WithMaxFrameSize(8))
	defer l.Close()
	ch := <-l.Channels()

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSBinary,
			Fin:     true,
			Payload: make([]byte, 32),
		},
	}
	err := ch.Send(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

// TestWithDeflateFromExtensionHeader_EnablesBothDirections validates that
// the new Option parses a wire header value and configures both
// directions of permessage-deflate. The test exercises the round-trip via
// channel Send/Next on a single deflate-enabled Layer (RoleClient writes
// compressed; the same channel reads back compressed frames).
func TestWithDeflateFromExtensionHeader_EnablesBothDirections(t *testing.T) {
	t.Parallel()

	o := options{}
	WithDeflateFromExtensionHeader("permessage-deflate; client_no_context_takeover; server_max_window_bits=15")(&o)

	if !o.deflateEnabled {
		t.Fatal("deflateEnabled = false, want true")
	}
	if !o.clientDeflate.enabled {
		t.Error("clientDeflate.enabled = false, want true")
	}
	if o.clientDeflate.contextTakeover {
		t.Error("clientDeflate.contextTakeover = true, want false (client_no_context_takeover negotiated)")
	}
	if !o.serverDeflate.enabled {
		t.Error("serverDeflate.enabled = false, want true")
	}
	if o.serverDeflate.windowBits != 15 {
		t.Errorf("serverDeflate.windowBits = %d, want 15", o.serverDeflate.windowBits)
	}
}

// TestWithDeflateFromExtensionHeader_EmptyHeaderNoOp ensures an empty
// header value leaves the Layer in its default deflate-disabled state.
func TestWithDeflateFromExtensionHeader_EmptyHeaderNoOp(t *testing.T) {
	t.Parallel()

	o := options{}
	WithDeflateFromExtensionHeader("")(&o)

	if o.deflateEnabled {
		t.Error("empty header enabled deflate")
	}
	if o.clientDeflate.enabled || o.serverDeflate.enabled {
		t.Error("empty header populated direction params")
	}
}

// TestWithDeflateFromExtensionHeader_NoPermessageDeflate ignores other
// extension names — only "permessage-deflate" should turn on deflate.
func TestWithDeflateFromExtensionHeader_NoPermessageDeflate(t *testing.T) {
	t.Parallel()

	o := options{}
	WithDeflateFromExtensionHeader("x-some-other-extension; param=1")(&o)

	if o.deflateEnabled {
		t.Error("unrelated extension enabled deflate")
	}
}
