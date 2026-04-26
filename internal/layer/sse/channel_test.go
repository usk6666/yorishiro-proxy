package sse

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// stubChannel is a minimal layer.Channel used as the "inner" handle in the
// SSE wrapper tests. It records Close calls but does not produce envelopes
// (the SSE wrapper never calls Next/Send on the inner channel; it only
// uses StreamID and Close).
type stubChannel struct {
	streamID  string
	closeN    int32
	closeOnce bool
	closed    chan struct{}
}

func newStubChannel(streamID string) *stubChannel {
	return &stubChannel{streamID: streamID, closed: make(chan struct{})}
}

func (s *stubChannel) StreamID() string                                     { return s.streamID }
func (s *stubChannel) Next(ctx context.Context) (*envelope.Envelope, error) { return nil, io.EOF }
func (s *stubChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	return errors.New("stub: Send not used")
}
func (s *stubChannel) Close() error {
	atomic.AddInt32(&s.closeN, 1)
	if !s.closeOnce {
		s.closeOnce = true
		close(s.closed)
	}
	return nil
}
func (s *stubChannel) Closed() <-chan struct{} { return s.closed }
func (s *stubChannel) Err() error              { return nil }

// closingReader wraps an io.Reader and counts Close calls so we can verify
// body cascade.
type closingReader struct {
	r      io.Reader
	closeN int32
}

func newClosingReader(r io.Reader) *closingReader { return &closingReader{r: r} }

func (c *closingReader) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *closingReader) Close() error {
	atomic.AddInt32(&c.closeN, 1)
	return nil
}

// makeFirstResponse builds a minimal HTTP response envelope as the http1
// layer would produce one for an SSE response (Direction=Receive,
// Protocol=ProtocolHTTP, status 200, Content-Type text/event-stream).
func makeFirstResponse(streamID string, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "flow-1",
		Sequence:  seq,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
			Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/event-stream"},
			},
		},
	}
}

func TestSSEChannel_FirstNextOverridesProtocol(t *testing.T) {
	t.Parallel()
	body := strings.NewReader("data: hello\n\n")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if env.Protocol != envelope.ProtocolSSE {
		t.Errorf("Protocol = %q, want %q", env.Protocol, envelope.ProtocolSSE)
	}
	if env.Direction != envelope.Receive {
		t.Errorf("Direction = %v, want Receive", env.Direction)
	}
	if env.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0", env.Sequence)
	}
	if _, ok := env.Message.(*envelope.HTTPMessage); !ok {
		t.Errorf("first envelope Message type = %T, want *envelope.HTTPMessage", env.Message)
	}
}

func TestSSEChannel_ThreeEventsThenEOF(t *testing.T) {
	t.Parallel()
	body := strings.NewReader("data: a\n\ndata: b\n\ndata: c\n\n")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	// First envelope: wrapped HTTP response.
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}

	wantData := []string{"a", "b", "c"}
	for i, want := range wantData {
		env, err := ch.Next(context.Background())
		if err != nil {
			t.Fatalf("Next #%d: %v", i, err)
		}
		if env.Protocol != envelope.ProtocolSSE {
			t.Errorf("event #%d Protocol = %q, want %q", i, env.Protocol, envelope.ProtocolSSE)
		}
		if env.Direction != envelope.Receive {
			t.Errorf("event #%d Direction = %v, want Receive", i, env.Direction)
		}
		msg, ok := env.Message.(*envelope.SSEMessage)
		if !ok {
			t.Fatalf("event #%d Message type = %T, want *envelope.SSEMessage", i, env.Message)
		}
		if msg.Data != want {
			t.Errorf("event #%d Data = %q, want %q", i, msg.Data, want)
		}
	}

	if _, err := ch.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("trailing Next err = %v, want io.EOF", err)
	}
	// Closed should fire after EOF.
	select {
	case <-ch.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed did not fire after EOF")
	}
	if !errors.Is(ch.Err(), io.EOF) {
		t.Errorf("Err() = %v, want io.EOF", ch.Err())
	}
}

func TestSSEChannel_FieldParsing(t *testing.T) {
	t.Parallel()
	body := strings.NewReader("event: ping\nid: 42\nretry: 3000\ndata: payload\n\n")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("event Next: %v", err)
	}
	msg, ok := env.Message.(*envelope.SSEMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *envelope.SSEMessage", env.Message)
	}
	if msg.Event != "ping" {
		t.Errorf("Event = %q, want %q", msg.Event, "ping")
	}
	if msg.ID != "42" {
		t.Errorf("ID = %q, want %q", msg.ID, "42")
	}
	if msg.Data != "payload" {
		t.Errorf("Data = %q, want %q", msg.Data, "payload")
	}
	if msg.Retry != 3*time.Second {
		t.Errorf("Retry = %v, want %v", msg.Retry, 3*time.Second)
	}
}

func TestSSEChannel_SendReturnsSentinel(t *testing.T) {
	t.Parallel()
	body := strings.NewReader("")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	err := ch.Send(context.Background(), &envelope.Envelope{})
	if !errors.Is(err, ErrSendUnsupported) {
		t.Errorf("Send err = %v, want errors.Is(.., ErrSendUnsupported)", err)
	}
	// Send must not be a *layer.StreamError; it is a programmer error.
	var se *layer.StreamError
	if errors.As(err, &se) {
		t.Errorf("Send returned *layer.StreamError; want plain sentinel")
	}
}

func TestSSEChannel_RawBytesPreservesWire(t *testing.T) {
	t.Parallel()
	wire := "data: hello\n\n"
	body := strings.NewReader(wire)
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("event Next: %v", err)
	}
	if got := string(env.Raw); got != wire {
		t.Errorf("Raw = %q, want %q (byte-exact wire incl. trailing blank line)", got, wire)
	}
}

func TestSSEChannel_CommentBlockSkipped(t *testing.T) {
	t.Parallel()
	body := strings.NewReader(": comment\n\ndata: real\n\n")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("event Next: %v", err)
	}
	msg := env.Message.(*envelope.SSEMessage)
	if msg.Data != "real" {
		t.Errorf("Data = %q, want %q", msg.Data, "real")
	}
	// Next call should be EOF (comment was already consumed).
	if _, err := ch.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("trailing Next err = %v, want io.EOF", err)
	}
}

func TestSSEChannel_MaxEventSizeExceeded(t *testing.T) {
	t.Parallel()
	// One oversized event well over the 64-byte cap.
	huge := strings.Repeat("x", 4096)
	body := strings.NewReader("data: " + huge + "\n\n")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body, WithMaxEventSize(64))
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}
	_, err := ch.Next(context.Background())
	if err == nil {
		t.Fatal("expected error for oversized event, got nil")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want ErrorInternalError", se.Code)
	}
	// Closed must fire and Err() must echo the same error.
	select {
	case <-ch.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed did not fire after MaxEventSize trip")
	}
	if got := ch.Err(); !errors.Is(got, se) {
		t.Errorf("Err() = %v, want same StreamError", got)
	}
}

func TestSSEChannel_StreamEndsWithoutTrailingBlankLine(t *testing.T) {
	t.Parallel()
	body := strings.NewReader("data: final")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("final event Next: %v", err)
	}
	msg := env.Message.(*envelope.SSEMessage)
	if msg.Data != "final" {
		t.Errorf("Data = %q, want %q", msg.Data, "final")
	}
	if _, err := ch.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("trailing Next err = %v, want io.EOF", err)
	}
}

func TestSSEChannel_PerEventSequenceMonotonic(t *testing.T) {
	t.Parallel()
	body := strings.NewReader("data: a\n\ndata: b\n\ndata: c\n\n")
	stub := newStubChannel("stream-1")
	const baseSeq = 7
	first := makeFirstResponse("stream-1", baseSeq)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	env0, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if env0.Sequence != baseSeq {
		t.Errorf("first Sequence = %d, want %d", env0.Sequence, baseSeq)
	}
	for i := 0; i < 3; i++ {
		env, err := ch.Next(context.Background())
		if err != nil {
			t.Fatalf("event %d Next: %v", i, err)
		}
		want := baseSeq + 1 + i
		if env.Sequence != want {
			t.Errorf("event %d Sequence = %d, want %d", i, env.Sequence, want)
		}
	}
}

func TestSSEChannel_CloseIdempotentAndCascade(t *testing.T) {
	t.Parallel()
	body := newClosingReader(strings.NewReader("data: x\n\n"))
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)

	if err := ch.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := ch.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := atomic.LoadInt32(&stub.closeN); got != 1 {
		t.Errorf("inner Close calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&body.closeN); got != 1 {
		t.Errorf("body Close calls = %d, want 1", got)
	}
	select {
	case <-ch.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed did not fire after Close")
	}
	// Subsequent Next must return the cached terminal error (io.EOF here).
	if _, err := ch.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("post-Close Next err = %v, want io.EOF", err)
	}
}

func TestSSEChannel_RetryMalformed(t *testing.T) {
	t.Parallel()
	body := strings.NewReader("retry: garbage\ndata: x\n\n")
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("event Next: %v", err)
	}
	msg := env.Message.(*envelope.SSEMessage)
	if msg.Retry != 0 {
		t.Errorf("Retry = %v, want 0 for malformed input", msg.Retry)
	}
	if msg.Data != "x" {
		t.Errorf("Data = %q, want %q", msg.Data, "x")
	}
}

func TestSSEChannel_BodyCloserCascaded(t *testing.T) {
	t.Parallel()
	body := newClosingReader(strings.NewReader(""))
	stub := newStubChannel("stream-1")
	first := makeFirstResponse("stream-1", 0)

	ch := Wrap(stub, first, body)
	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := atomic.LoadInt32(&body.closeN); got != 1 {
		t.Errorf("body Close calls = %d, want 1", got)
	}
}

func TestSSEChannel_StreamIDDelegates(t *testing.T) {
	t.Parallel()
	stub := newStubChannel("the-stream-id")
	first := makeFirstResponse("the-stream-id", 0)

	ch := Wrap(stub, first, strings.NewReader(""))
	defer ch.Close()

	if got := ch.StreamID(); got != "the-stream-id" {
		t.Errorf("StreamID = %q, want %q", got, "the-stream-id")
	}
}

// TestSSEChannel_SkipFirstEmit verifies that WithSkipFirstEmit (USK-655)
// suppresses the first-envelope emit and jumps straight to the parser, so
// the first Next() returns an SSEMessage rather than the HTTPMessage clone
// of firstResponse. The Context / streamID derived from firstResponse
// still applies to the SSE event envelopes.
func TestSSEChannel_SkipFirstEmit(t *testing.T) {
	t.Parallel()

	stub := newStubChannel("ssid")
	first := makeFirstResponse("ssid", 1)
	first.Context = envelope.EnvelopeContext{ConnID: "test-conn", TargetHost: "h"}
	body := strings.NewReader("event: ping\ndata: 1\n\n")

	ch := Wrap(stub, first, body, WithSkipFirstEmit())
	defer ch.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if env.Protocol != envelope.ProtocolSSE {
		t.Errorf("Protocol = %q, want %q (SSEMessage, not HTTPMessage clone)", env.Protocol, envelope.ProtocolSSE)
	}
	msg, ok := env.Message.(*envelope.SSEMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *SSEMessage", env.Message)
	}
	if msg.Event != "ping" || msg.Data != "1" {
		t.Errorf("event = (%q,%q), want (ping,1)", msg.Event, msg.Data)
	}
	if env.Context.ConnID != "test-conn" {
		t.Errorf("Context.ConnID = %q, want test-conn (derived from firstResponse)", env.Context.ConnID)
	}
	// Sequence starts at firstResponse.Sequence + 1 even when first emit
	// is skipped, matching what the post-swap Pipeline expects.
	if env.Sequence != 2 {
		t.Errorf("Sequence = %d, want 2 (firstResponse.Sequence + 1)", env.Sequence)
	}

	// Subsequent Next returns io.EOF (no more events).
	if _, err := ch.Next(ctx); err != io.EOF {
		t.Errorf("trailing Next = %v, want io.EOF", err)
	}
}
