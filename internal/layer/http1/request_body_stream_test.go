package http1

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-1414: request body streaming at the http1 Layer seam — a client-facing
// (Send) Layer configured with WithRequestBodyMode emits the request head
// with a BodyStream, an upstream-facing (Receive) Layer's Send forwards the
// body as it is read, and the client Layer parses the next request only
// after that body ended cleanly.

// newStreamingClient builds a Send-direction Layer over a real TCP pair
// with mode as its request body-mode predicate. The returned conn is the
// client's side.
func newStreamingClient(t *testing.T, mode layer.BodyModeFunc) (*Layer, net.Conn) {
	t.Helper()
	peer, server := testConn(t)
	l := New(server, "stream-client", envelope.Send, WithRequestBodyMode(mode))
	t.Cleanup(func() {
		_ = l.Close()
		_ = peer.Close()
	})
	return l, peer
}

// wireCapture accumulates every byte an upstream peer reads.
type wireCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
	eof atomic.Bool
}

func (w *wireCapture) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

// waitLen waits until at least n bytes arrived, bounded by 5s.
func (w *wireCapture) waitLen(t *testing.T, n int) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b := w.bytes(); len(b) >= n {
			return b
		}
		if time.Now().After(deadline) {
			t.Fatalf("upstream received %q within 5s, want %d bytes", w.bytes(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitEOF waits until the peer read EOF, bounded by 5s.
func (w *wireCapture) waitEOF(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !w.eof.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("upstream peer did not read EOF within 5s (received %q)", w.bytes())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// newCapturingUpstream builds a Receive-direction Layer over a real TCP
// pair whose peer records every byte it reads.
func newCapturingUpstream(t *testing.T) (*Layer, *wireCapture) {
	t.Helper()
	peer, server := testConn(t)
	l := New(server, "stream-up", envelope.Receive)
	t.Cleanup(func() {
		_ = l.Close()
		_ = peer.Close()
	})
	w := &wireCapture{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := peer.Read(b)
			if n > 0 {
				w.mu.Lock()
				w.buf.Write(b[:n])
				w.mu.Unlock()
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					w.eof.Store(true)
				}
				return
			}
		}
	}()
	return l, w
}

// nextRequestWithin returns the next request on ch, bounded by d: the head
// must be delivered while the body is still pending.
func nextRequestWithin(t *testing.T, ch layer.Channel, d time.Duration) *envelope.Envelope {
	t.Helper()
	type res struct {
		env *envelope.Envelope
		err error
	}
	done := make(chan res, 1)
	go func() {
		env, err := ch.Next(context.Background())
		done <- res{env, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Next: %v", r.err)
		}
		return r.env
	case <-time.After(d):
		t.Fatalf("Next did not return within %v (the request head must be delivered before the body ended)", d)
		return nil
	}
}

// nextChannelWithin receives the next per-exchange Channel, bounded by 5s.
func nextChannelWithin(t *testing.T, l *Layer) layer.Channel {
	t.Helper()
	select {
	case ch, ok := <-l.Channels():
		if !ok {
			t.Fatal("Channels() closed; want another exchange")
		}
		return ch
	case <-time.After(5 * time.Second):
		t.Fatal("no Channel within 5s")
		return nil
	}
}

// sendAsync runs ch.Send(env) on its own goroutine.
func sendAsync(ch layer.Channel, env *envelope.Envelope) <-chan error {
	done := make(chan error, 1)
	go func() { done <- ch.Send(context.Background(), env) }()
	return done
}

func waitErr(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Send did not return within 5s")
		return nil
	}
}

// assertChannelsEnd asserts that the client Layer yields no further
// exchange and closes Channels() within 5s.
func assertChannelsEnd(t *testing.T, l *Layer) {
	t.Helper()
	select {
	case ch, ok := <-l.Channels():
		if ok {
			env, err := ch.Next(context.Background())
			t.Fatalf("the Layer parsed another request after an unfinished body: env=%v err=%v", env, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Channels() did not close within 5s after an unfinished request body")
	}
}

// TestRequestStream_HeadBeforeBody_ForwardedVerbatim: the request head is
// delivered while the body is pending; Envelope.Raw is the header section
// only; the upstream Send writes the head, then the body as the client
// sends it.
func TestRequestStream_HeadBeforeBody_ForwardedVerbatim(t *testing.T) {
	cl, peer := newStreamingClient(t, streamAll)
	up, wire := newCapturingUpstream(t)
	const head = "POST /up HTTP/1.1\r\nHost: up.test\r\nContent-Length: 10\r\n\r\n"
	peerWrite(t, peer, head+"hello")

	ch := nextChannelWithin(t, cl)
	before := time.Now()
	env := nextRequestWithin(t, ch, 2*time.Second)
	msg := streamedMsg(t, env)
	if string(env.Raw) != head || env.RawBuffer != nil {
		t.Errorf("Envelope.Raw = %q (RawBuffer %v), want the header section only", env.Raw, env.RawBuffer != nil)
	}
	if env.Context.ReceivedAt.IsZero() || env.Context.ReceivedAt.After(before) {
		t.Errorf("ReceivedAt = %v, want the header-arrival time (<= %v)", env.Context.ReceivedAt, before)
	}

	done := sendAsync(up.OpenExchange(), env)
	wire.waitLen(t, len(head)+5)
	peerWrite(t, peer, "world")
	if err := waitErr(t, done); err != nil {
		t.Fatalf("upstream Send: %v", err)
	}
	if got := string(wire.waitLen(t, len(head)+10)); got != head+"helloworld" {
		t.Errorf("upstream wire = %q, want %q", got, head+"helloworld")
	}
	res, ok := msg.BodyStream.Result()
	if !ok || res.Err != nil || res.Truncated {
		t.Errorf("BodyStream result = %+v (ended %v), want a clean end", res, ok)
	}
}

// TestRequestStream_BodylessRequestsBuffered: the predicate is consulted
// only for a request whose head frames body bytes; bodyless requests,
// invalid Content-Length and gRPC-Web stay buffered.
func TestRequestStream_BodylessRequestsBuffered(t *testing.T) {
	tests := []struct {
		name       string
		req        string
		wantCalled bool
		wantStream bool
	}{
		{"get without body", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", false, false},
		{"post content-length 0", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", false, false},
		{"post invalid content-length", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: x\r\n\r\n", false, false},
		{"grpc-web", "POST /s/M HTTP/1.1\r\nHost: a\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: 5\r\n\r\n\x00\x00\x00\x00\x00", false, false},
		{"post with body", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello", true, true},
		{"chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called atomic.Int32
			mode := func(env *envelope.Envelope, msg *envelope.HTTPMessage) layer.BodyMode {
				called.Add(1)
				if env.Direction != envelope.Send || msg.Method == "" {
					t.Errorf("predicate saw direction %v method %q, want the request head", env.Direction, msg.Method)
				}
				return layer.Stream()
			}
			cl, peer := newStreamingClient(t, mode)
			peerWrite(t, peer, tt.req)
			env := nextRequestWithin(t, nextChannelWithin(t, cl), 2*time.Second)
			msg := env.Message.(*envelope.HTTPMessage)
			if got := called.Load() > 0; got != tt.wantCalled {
				t.Errorf("predicate called = %v, want %v", got, tt.wantCalled)
			}
			if got := msg.BodyStream != nil; got != tt.wantStream {
				t.Errorf("streamed = %v, want %v", got, tt.wantStream)
			}
		})
	}
}

// TestRequestStream_PipelinedRequestsAfterBodyEnd (T14): two requests in
// one client write, the first with a Content-Length body: the first is
// streamed, the second is parsed only after the first body ended, and the
// upstream receives both intact, in order.
func TestRequestStream_PipelinedRequestsAfterBodyEnd(t *testing.T) {
	cl, peer := newStreamingClient(t, streamAll)
	up, wire := newCapturingUpstream(t)
	const req1 = "POST /a HTTP/1.1\r\nHost: up.test\r\nContent-Length: 5\r\n\r\nhello"
	const req2 = "GET /b HTTP/1.1\r\nHost: up.test\r\n\r\n"
	peerWrite(t, peer, req1+req2)

	ch1 := nextChannelWithin(t, cl)
	env1 := nextRequestWithin(t, ch1, 2*time.Second)
	streamedMsg(t, env1)
	if err := waitErr(t, sendAsync(up.OpenExchange(), env1)); err != nil {
		t.Fatalf("Send request 1: %v", err)
	}
	_ = ch1.Close()

	ch2 := nextChannelWithin(t, cl)
	env2 := nextRequestWithin(t, ch2, 2*time.Second)
	if m := env2.Message.(*envelope.HTTPMessage); m.Path != "/b" {
		t.Fatalf("second request path = %q, want /b (the first body must not be parsed as a request)", m.Path)
	}
	if err := waitErr(t, sendAsync(up.OpenExchange(), env2)); err != nil {
		t.Fatalf("Send request 2: %v", err)
	}
	if got := string(wire.waitLen(t, len(req1)+len(req2))); got != req1+req2 {
		t.Errorf("upstream wire = %q, want %q", got, req1+req2)
	}
}

// TestRequestStream_ClosedUnreadEndsConnection (R8): a streamed request
// whose body is closed unread (Respond / Drop) ends the connection; the
// bytes of its body are never parsed as a request.
func TestRequestStream_ClosedUnreadEndsConnection(t *testing.T) {
	cl, peer := newStreamingClient(t, streamAll)
	peerWrite(t, peer, "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n")
	ch := nextChannelWithin(t, cl)
	env := nextRequestWithin(t, ch, 2*time.Second)
	msg := streamedMsg(t, env)
	_ = ch.Close()
	select {
	case <-msg.BodyStream.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Channel.Close did not end the unread request body")
	}
	if res, _ := msg.BodyStream.Result(); !errors.Is(res.Err, envelope.ErrBodyStreamClosed) {
		t.Errorf("result err = %v, want ErrBodyStreamClosed", res.Err)
	}
	assertChannelsEnd(t, cl)
}

// TestRequestStream_ClientCutMidBody (U1): the client closes mid-body. The
// upstream Send forwards the bytes received, half-closes the upstream
// (FIN) and returns; the body ends truncated with TruncatedBody; the client
// Layer parses nothing further.
func TestRequestStream_ClientCutMidBody(t *testing.T) {
	cl, peer := newStreamingClient(t, streamAll)
	up, wire := newCapturingUpstream(t)
	const head = "PUT /cut HTTP/1.1\r\nHost: up.test\r\nContent-Length: 10\r\n\r\n"
	peerWrite(t, peer, head+"abcd")
	ch := nextChannelWithin(t, cl)
	env := nextRequestWithin(t, ch, 2*time.Second)
	msg := streamedMsg(t, env)
	done := sendAsync(up.OpenExchange(), env)
	wire.waitLen(t, len(head)+4)
	_ = peer.(*net.TCPConn).CloseWrite()

	if err := waitErr(t, done); err != nil {
		t.Errorf("upstream Send after a client cut = %v, want nil (the response keeps flowing)", err)
	}
	wire.waitEOF(t)
	if got := string(wire.bytes()); got != head+"abcd" {
		t.Errorf("upstream wire = %q, want the head and the 4 bytes received", got)
	}
	res, _ := msg.BodyStream.Result()
	if !res.Truncated || !hasAnomalyType(res.Anomalies, envelope.AnomalyTruncatedBody) {
		t.Errorf("result = %+v, want Truncated with AnomalyTruncatedBody", res)
	}
	var se *layer.StreamError
	if !errors.As(res.Err, &se) || se.Code != layer.ErrorAborted {
		t.Errorf("result err = %v, want an aborted StreamError", res.Err)
	}
	_ = ch.Close()
	assertChannelsEnd(t, cl)
}

// TestRequestStream_HeaderStageStaleKeepsStream (T10, R11): a header-stage
// stale write on a streamed PUT reports a replay-safe StaleUpstreamError
// and leaves the one-shot body untouched, so the same Envelope replayed on
// a fresh upstream Layer delivers the head and the whole body.
func TestRequestStream_HeaderStageStaleKeepsStream(t *testing.T) {
	cl, peer := newStreamingClient(t, streamAll)
	const head = "PUT /p HTTP/1.1\r\nHost: up.test\r\nContent-Length: 10\r\n\r\n"
	peerWrite(t, peer, head+"hello")
	env := nextRequestWithin(t, nextChannelWithin(t, cl), 2*time.Second)
	msg := streamedMsg(t, env)

	stalePeer, staleServer := testConn(t)
	t.Cleanup(func() { _ = stalePeer.Close() })
	stale := New(epipeConn{staleServer}, "stale-up", envelope.Receive)
	t.Cleanup(func() { _ = stale.Close() })
	err := waitErr(t, sendAsync(stale.OpenExchange(), env))
	var se *StaleUpstreamError
	if !errors.As(err, &se) {
		t.Fatalf("Send on a stale upstream = %v, want *StaleUpstreamError", err)
	}
	if se.Stage != "header" || !se.ReplaySafe {
		t.Errorf("StaleUpstreamError = %+v, want stage header, ReplaySafe true", se)
	}
	select {
	case <-msg.BodyStream.Done():
		t.Fatal("the header-stage failure ended the one-shot body; the replay has nothing to send")
	default:
	}

	fresh, wire := newCapturingUpstream(t)
	done := sendAsync(fresh.OpenExchange(), env)
	wire.waitLen(t, len(head)+5)
	peerWrite(t, peer, "world")
	if err := waitErr(t, done); err != nil {
		t.Fatalf("replayed Send: %v", err)
	}
	if got := string(wire.waitLen(t, len(head)+10)); got != head+"helloworld" {
		t.Errorf("replayed upstream wire = %q, want %q", got, head+"helloworld")
	}
}
