package httpaggregator

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// fakeChannel implements layer.Channel for aggregator unit tests. Events
// are pre-queued via send(); the Send direction captures events for
// inspection.
type fakeChannel struct {
	mu       sync.Mutex
	recv     []*envelope.Envelope
	sent     []*envelope.Envelope
	closed   chan struct{}
	rstCalls int
	rstCode  uint32
	termErr  error
}

func newFakeChannel() *fakeChannel {
	return &fakeChannel{closed: make(chan struct{})}
}

func (f *fakeChannel) StreamID() string { return "fake-stream" }

func (f *fakeChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.recv) == 0 {
		return nil, io.EOF
	}
	env := f.recv[0]
	f.recv = f.recv[1:]
	return env, nil
}

func (f *fakeChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, env)
	return nil
}

func (f *fakeChannel) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fakeChannel) Closed() <-chan struct{} { return f.closed }
func (f *fakeChannel) Err() error              { return f.termErr }

func (f *fakeChannel) MarkTerminatedWithRST(code uint32, err error) {
	f.mu.Lock()
	f.rstCalls++
	f.rstCode = code
	f.termErr = err
	f.mu.Unlock()
}

func (f *fakeChannel) queue(env *envelope.Envelope) {
	f.mu.Lock()
	f.recv = append(f.recv, env)
	f.mu.Unlock()
}

// TestAggregator_HeadersOnly verifies a bodyless request (HEADERS
// END_STREAM) is emitted as a single HTTPMessage with no Body/BodyBuffer.
func TestAggregator_HeadersOnly(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "GET", Scheme: "https", Authority: "x", Path: "/hello",
			EndStream: true,
		},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message = %T, want *HTTPMessage", env.Message)
	}
	if msg.Method != "GET" || msg.Path != "/hello" {
		t.Errorf("msg = %+v", msg)
	}
	if msg.Body != nil || msg.BodyBuffer != nil {
		t.Errorf("body not nil: body=%v buf=%v", msg.Body, msg.BodyBuffer)
	}
}

// TestAggregator_HeadersBodyEndStream verifies HEADERS + DATA(END_STREAM)
// produces one HTTPMessage with Body set from memory-backed buffer.
func TestAggregator_HeadersBodyEndStream(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "POST", Scheme: "https", Authority: "x", Path: "/",
		},
	})
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2DataEvent{
			Payload: []byte("hello world"), EndStream: true,
		},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if string(msg.Body) != "hello world" {
		t.Errorf("Body = %q, want 'hello world'", msg.Body)
	}
}

// TestAggregator_Trailers verifies HEADERS + DATA + Trailer HEADERS
// produces one HTTPMessage with Body and Trailers populated.
func TestAggregator_Trailers(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "POST", Scheme: "https", Authority: "x", Path: "/",
		},
	})
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2DataEvent{Payload: []byte("body")},
	})
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2TrailersEvent{
			Trailers: []envelope.KeyValue{{Name: "grpc-status", Value: "0"}},
		},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if string(msg.Body) != "body" {
		t.Errorf("Body = %q, want 'body'", msg.Body)
	}
	if len(msg.Trailers) != 1 || msg.Trailers[0].Name != "grpc-status" {
		t.Errorf("Trailers = %+v", msg.Trailers)
	}
}

// TestAggregator_PeekedFirstHeaders verifies that a pre-peeked first
// envelope is replayed as the first aggregated HTTPMessage.
func TestAggregator_PeekedFirstHeaders(t *testing.T) {
	inner := newFakeChannel()
	// Peeked envelope simulates the one the caller already read.
	peeked := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "GET", Scheme: "https", Authority: "x", Path: "/peeked",
			EndStream: true,
		},
	}
	ch := Wrap(inner, RoleServer, peeked, WrapOptions{})

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Path != "/peeked" {
		t.Errorf("Path = %q, want /peeked", msg.Path)
	}
}

// TestAggregator_MaxBodySizeExceeded verifies that exceeding MaxBodySize
// yields a *layer.StreamError from Next and RST_STREAMs the inner channel.
func TestAggregator_MaxBodySizeExceeded(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2HeadersEvent{Method: "POST", Scheme: "https", Authority: "x", Path: "/"},
	})
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2DataEvent{Payload: make([]byte, 100)},
	})
	ch := Wrap(inner, RoleServer, nil, WrapOptions{MaxBodySize: 50})

	_, err := ch.Next(context.Background())
	if err == nil {
		t.Fatal("Next returned no error; expected layer.StreamError")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("err = %T %v, want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("Code = %s, want internal_error", se.Code)
	}
	if inner.rstCalls != 1 {
		t.Errorf("rstCalls = %d, want 1", inner.rstCalls)
	}
	if inner.rstCode != http2.ErrCodeInternal {
		t.Errorf("rstCode = %d, want %d", inner.rstCode, http2.ErrCodeInternal)
	}
}

// TestAggregator_Send_BodylessHeaders verifies the Send path emits a
// single H2HeadersEvent with EndStream=true when the HTTPMessage has no
// body and no trailers.
func TestAggregator_Send_BodylessHeaders(t *testing.T) {
	inner := newFakeChannel()
	ch := Wrap(inner, RoleClient, nil, WrapOptions{})

	err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET", Scheme: "https", Authority: "x", Path: "/",
		},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(inner.sent) != 1 {
		t.Fatalf("sent = %d events, want 1", len(inner.sent))
	}
	evt, ok := inner.sent[0].Message.(*http2.H2HeadersEvent)
	if !ok {
		t.Fatalf("sent[0].Message = %T, want *H2HeadersEvent", inner.sent[0].Message)
	}
	if !evt.EndStream {
		t.Error("EndStream = false, want true (bodyless)")
	}
}

// TestAggregator_Send_HeadersBody verifies the Send path emits
// HEADERS(no END_STREAM) + DATA(END_STREAM) for a body-bearing message
// with no trailers.
func TestAggregator_Send_HeadersBody(t *testing.T) {
	inner := newFakeChannel()
	ch := Wrap(inner, RoleClient, nil, WrapOptions{})

	err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST", Scheme: "https", Authority: "x", Path: "/",
			Body: []byte("hi"),
		},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(inner.sent) != 2 {
		t.Fatalf("sent = %d events, want 2", len(inner.sent))
	}
	hdr := inner.sent[0].Message.(*http2.H2HeadersEvent)
	if hdr.EndStream {
		t.Error("headers EndStream = true, want false (body follows)")
	}
	data := inner.sent[1].Message.(*http2.H2DataEvent)
	if !data.EndStream {
		t.Error("data EndStream = false, want true")
	}
	if string(data.Payload) != "hi" {
		t.Errorf("data.Payload = %q, want 'hi'", data.Payload)
	}
}

// TestAggregator_Send_HeadersBodyTrailers verifies emission of
// HEADERS + DATA + TRAILERS, with only the trailers carrying END_STREAM.
func TestAggregator_Send_HeadersBodyTrailers(t *testing.T) {
	inner := newFakeChannel()
	ch := Wrap(inner, RoleClient, nil, WrapOptions{})

	err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST", Scheme: "https", Authority: "x", Path: "/",
			Body:     []byte("x"),
			Trailers: []envelope.KeyValue{{Name: "grpc-status", Value: "0"}},
		},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(inner.sent) != 3 {
		t.Fatalf("sent = %d events, want 3 (headers + data + trailers)", len(inner.sent))
	}
	hdr := inner.sent[0].Message.(*http2.H2HeadersEvent)
	if hdr.EndStream {
		t.Error("headers EndStream = true, want false (body follows)")
	}
	data := inner.sent[1].Message.(*http2.H2DataEvent)
	if data.EndStream {
		t.Error("data EndStream = true, want false (trailers follow)")
	}
	if _, ok := inner.sent[2].Message.(*http2.H2TrailersEvent); !ok {
		t.Fatalf("sent[2] = %T, want *H2TrailersEvent", inner.sent[2].Message)
	}
}
