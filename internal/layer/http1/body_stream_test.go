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

// streamAll is a body-mode predicate that streams every body it is asked
// about.
func streamAll(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode { return layer.Stream() }

// newStreamingUpstream builds a Receive-direction Layer over a real TCP
// pair. The returned conn is the upstream server's side.
func newStreamingUpstream(t *testing.T, mode layer.BodyModeFunc, opts ...Option) (*Layer, net.Conn) {
	t.Helper()
	peer, server := testConn(t)
	all := append([]Option{WithResponseBodyMode(mode)}, opts...)
	l := New(server, "stream-up", envelope.Receive, all...)
	t.Cleanup(func() {
		_ = l.Close()
		_ = peer.Close()
	})
	// Drain whatever the Layer writes (the requests) so writes never block.
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	return l, peer
}

// sendExchange opens an exchange on l and sends a synthetic request.
func sendExchange(t *testing.T, l *Layer, method, path string, hdrs ...envelope.KeyValue) layer.Channel {
	t.Helper()
	ch := l.OpenExchange()
	if ch == nil {
		t.Fatal("OpenExchange returned nil")
	}
	msg := &envelope.HTTPMessage{
		Method:    method,
		Path:      path,
		Authority: "upstream.test",
		Headers:   append([]envelope.KeyValue{{Name: "Host", Value: "upstream.test"}}, hdrs...),
	}
	env := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: msg, StreamID: "s1"}
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatalf("Send request: %v", err)
	}
	return ch
}

func peerWrite(t *testing.T, peer net.Conn, s string) {
	t.Helper()
	if _, err := peer.Write([]byte(s)); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
}

// nextWithin calls ch.Next bounded by d.
func nextWithin(t *testing.T, ch layer.Channel, d time.Duration) *envelope.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v (the response head must be delivered while the body is still pending)", err)
	}
	return env
}

// readExactlyWithin reads exactly n bytes from r, bounded by 5s.
func readExactlyWithin(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		done <- res{b, err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("ReadFull(%d): %v", n, got.err)
		}
		return got.b
	case <-time.After(5 * time.Second):
		t.Fatalf("reading %d body bytes did not finish within 5s", n)
		return nil
	}
}

func streamedMsg(t *testing.T, env *envelope.Envelope) *envelope.HTTPMessage {
	t.Helper()
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message = %T, want *HTTPMessage", env.Message)
	}
	if msg.BodyStream == nil {
		t.Fatalf("HTTPMessage.BodyStream is nil; want a streamed body (Body=%d bytes, BodyBuffer=%v)", len(msg.Body), msg.BodyBuffer != nil)
	}
	if msg.Body != nil || msg.BodyBuffer != nil {
		t.Errorf("streamed message also carries Body (%d bytes) / BodyBuffer (%v)", len(msg.Body), msg.BodyBuffer != nil)
	}
	return msg
}

// TestStreamMode_ContentLength_HeadBeforeBody (USK-1409 T5): the head is
// delivered while the upstream is blocked mid-body; HealthCheck does not
// read the conn mid-body; the next exchange works after the body ends.
func TestStreamMode_ContentLength_HeadBeforeBody(t *testing.T) {
	l, peer := newStreamingUpstream(t, streamAll)
	ch := sendExchange(t, l, "GET", "/a")
	const head = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"
	peerWrite(t, peer, head+"first")

	env := nextWithin(t, ch, 3*time.Second)
	msg := streamedMsg(t, env)
	if string(env.Raw) != head {
		t.Errorf("env.Raw = %q, want the header section %q", env.Raw, head)
	}
	if got := readExactlyWithin(t, msg.BodyStream, 5); string(got) != "first" {
		t.Fatalf("first body bytes = %q, want %q", got, "first")
	}
	if err := l.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck mid-body = %v, want nil", err)
	}
	peerWrite(t, peer, "-last")
	rest, err := io.ReadAll(msg.BodyStream)
	if err != nil {
		t.Fatalf("ReadAll rest: %v", err)
	}
	if string(rest) != "-last" {
		t.Fatalf("rest = %q, want %q (HealthCheck must not consume body bytes)", rest, "-last")
	}
	if res, ok := msg.BodyStream.Result(); !ok || res.Err != nil {
		t.Errorf("Result = %+v, %v; want a clean end", res, ok)
	}
	_ = ch.Close()

	ch2 := sendExchange(t, l, "GET", "/b")
	peerWrite(t, peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	env2 := nextWithin(t, ch2, 3*time.Second)
	msg2 := streamedMsg(t, env2)
	if b, err := io.ReadAll(msg2.BodyStream); err != nil || string(b) != "ok" {
		t.Fatalf("second body = %q, %v; want %q", b, err, "ok")
	}
}

// TestStreamMode_Chunked_HeadBeforeBody (USK-1409 T5): chunked variant.
func TestStreamMode_Chunked_HeadBeforeBody(t *testing.T) {
	l, peer := newStreamingUpstream(t, streamAll)
	ch := sendExchange(t, l, "GET", "/c")
	peerWrite(t, peer, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n")

	env := nextWithin(t, ch, 3*time.Second)
	msg := streamedMsg(t, env)
	if got := readExactlyWithin(t, msg.BodyStream, 3); string(got) != "abc" {
		t.Fatalf("first chunk = %q, want %q", got, "abc")
	}
	peerWrite(t, peer, "2\r\nde\r\n0\r\nX-T: 1\r\n\r\n")
	rest, err := io.ReadAll(msg.BodyStream)
	if err != nil || string(rest) != "de" {
		t.Fatalf("rest = %q, %v; want %q", rest, err, "de")
	}
	res, _ := msg.BodyStream.Result()
	if len(res.Trailers) != 1 || res.Trailers[0].Name != "X-T" || res.Trailers[0].Value != "1" {
		t.Errorf("Result.Trailers = %v, want [X-T: 1]", res.Trailers)
	}
}

// TestStreamMode_NextResponseParsedAfterBodyDrained (USK-1409 T5 / R9): a
// pipelined second response is not parsed while the first body is pending,
// even when its bytes are already on the conn.
func TestStreamMode_NextResponseParsedAfterBodyDrained(t *testing.T) {
	l, peer := newStreamingUpstream(t, streamAll)
	ch1 := sendExchange(t, l, "GET", "/1")
	ch2 := sendExchange(t, l, "GET", "/2")
	peerWrite(t, peer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
	env1 := nextWithin(t, ch1, 3*time.Second)
	msg1 := streamedMsg(t, env1)

	type res struct {
		env *envelope.Envelope
		err error
	}
	got2 := make(chan res, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		e, err := ch2.Next(ctx)
		got2 <- res{e, err}
	}()

	if b := readExactlyWithin(t, msg1.BodyStream, 5); string(b) != "first" {
		t.Fatalf("body1 prefix = %q", b)
	}
	peerWrite(t, peer, "-lastHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	select {
	case r := <-got2:
		t.Fatalf("second response delivered (%v, %v) while the first body was still unread", r.env, r.err)
	case <-time.After(150 * time.Millisecond):
	}
	rest, err := io.ReadAll(msg1.BodyStream)
	if err != nil || string(rest) != "-last" {
		t.Fatalf("body1 rest = %q, %v; want %q", rest, err, "-last")
	}
	select {
	case r := <-got2:
		if r.err != nil {
			t.Fatalf("second Next: %v", r.err)
		}
		msg2 := streamedMsg(t, r.env)
		if b, err := io.ReadAll(msg2.BodyStream); err != nil || string(b) != "ok" {
			t.Fatalf("body2 = %q, %v; want %q", b, err, "ok")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second response not delivered after the first body ended")
	}
}

// TestStreamMode_UpstreamCutMidBody (USK-1409 R8 / R10): the reader gets
// the bytes sent before the cut, the result is Truncated, and the next
// Next on the channel reports the aborted exchange, not io.EOF.
func TestStreamMode_UpstreamCutMidBody(t *testing.T) {
	l, peer := newStreamingUpstream(t, streamAll)
	ch := sendExchange(t, l, "GET", "/cut")
	peerWrite(t, peer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
	env := nextWithin(t, ch, 3*time.Second)
	msg := streamedMsg(t, env)
	if b := readExactlyWithin(t, msg.BodyStream, 5); string(b) != "first" {
		t.Fatalf("prefix = %q", b)
	}
	_ = peer.Close()
	rest, err := io.ReadAll(msg.BodyStream)
	if err == nil {
		t.Fatalf("ReadAll after the cut returned nil error (rest %q)", rest)
	}
	res, ok := msg.BodyStream.Result()
	if !ok || !res.Truncated {
		t.Fatalf("Result = %+v, %v; want Truncated", res, ok)
	}
	if !hasAnomalyType(res.Anomalies, envelope.AnomalyTruncatedBody) {
		t.Errorf("Result.Anomalies = %v, want AnomalyTruncatedBody", res.Anomalies)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, nerr := ch.Next(ctx)
	var se *layer.StreamError
	if !errors.As(nerr, &se) || se.Code != layer.ErrorAborted {
		t.Fatalf("Next after the cut = %v, want an aborted *layer.StreamError", nerr)
	}
	if !l.Retired() {
		t.Error("Layer not retired after the upstream cut the body")
	}
}

// TestStreamMode_CloseUnreadBody (USK-1409 T17, producer side): closing an
// unread body completes it once with ErrBodyStreamClosed and marks the
// Layer unusable (the conn is mid-body).
func TestStreamMode_CloseUnreadBody(t *testing.T) {
	l, peer := newStreamingUpstream(t, streamAll)
	ch := sendExchange(t, l, "GET", "/unread")
	peerWrite(t, peer, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
	env := nextWithin(t, ch, 3*time.Second)
	msg := streamedMsg(t, env)
	var fired atomic.Int32
	msg.BodyStream.OnComplete(func(envelope.BodyResult) { fired.Add(1) })
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = msg.BodyStream.Close() }()
	}
	wg.Wait()
	if n := fired.Load(); n != 1 {
		t.Fatalf("OnComplete fired %d times, want 1", n)
	}
	res, _ := msg.BodyStream.Result()
	if !errors.Is(res.Err, envelope.ErrBodyStreamClosed) {
		t.Errorf("Result.Err = %v, want ErrBodyStreamClosed", res.Err)
	}
	if !l.Retired() {
		t.Error("Layer not retired after an unread body was closed")
	}
}

// TestBodyMode_GateAndContext (USK-1409 T1, HTTP/1.x side): the Layer
// decides SSE first and keeps bodyless / gRPC-Web responses buffered
// without consulting the predicate; otherwise the predicate sees the
// paired request's method and path on the Envelope context.
func TestBodyMode_GateAndContext(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		reqHeaders []envelope.KeyValue
		response   string
		consulted  bool
	}{
		{name: "plain 200 is consulted", method: "GET",
			response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", consulted: true},
		{name: "SSE is decided first", method: "GET",
			response: "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"},
		{name: "response to HEAD", method: "HEAD",
			response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"},
		{name: "204", method: "GET", response: "HTTP/1.1 204 No Content\r\n\r\n"},
		{name: "304", method: "GET", response: "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n"},
		{name: "Content-Length 0", method: "GET", response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{name: "gRPC-Web request", method: "POST",
			reqHeaders: []envelope.KeyValue{{Name: "Content-Type", Value: "application/grpc-web+proto"}},
			response:   "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"},
		{name: "gRPC-Web response", method: "POST",
			response: "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web-text\r\nContent-Length: 5\r\n\r\nhello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			var seenMethod, seenPath atomic.Value
			pred := func(env *envelope.Envelope, _ *envelope.HTTPMessage) layer.BodyMode {
				calls.Add(1)
				seenMethod.Store(env.Context.RequestMethod)
				seenPath.Store(env.Context.RequestPath)
				return layer.Stream()
			}
			l, peer := newStreamingUpstream(t, pred, WithStreamingResponseDetect(IsSSEResponse))
			ch := sendExchange(t, l, tt.method, "/gate", tt.reqHeaders...)
			peerWrite(t, peer, tt.response)
			env := nextWithin(t, ch, 3*time.Second)
			msg := env.Message.(*envelope.HTTPMessage)
			if got := calls.Load() == 1; got != tt.consulted {
				t.Fatalf("predicate calls = %d, want consulted=%v", calls.Load(), tt.consulted)
			}
			if (msg.BodyStream != nil) != tt.consulted {
				t.Fatalf("BodyStream set = %v, want %v", msg.BodyStream != nil, tt.consulted)
			}
			if !tt.consulted {
				return
			}
			if m, _ := seenMethod.Load().(string); m != tt.method {
				t.Errorf("predicate saw RequestMethod %q, want %q", m, tt.method)
			}
			if p, _ := seenPath.Load().(string); p != "/gate" {
				t.Errorf("predicate saw RequestPath %q, want %q", p, "/gate")
			}
			if b, err := io.ReadAll(msg.BodyStream); err != nil || !bytes.Equal(b, []byte("hello")) {
				t.Errorf("body = %q, %v", b, err)
			}
		})
	}
}
