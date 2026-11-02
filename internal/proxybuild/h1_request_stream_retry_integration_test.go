//go:build e2e && !e2e_smoke

// USK-1414 (R11): stale-conn retry of a request whose body is streamed. A
// header-stage failure leaves the one-shot body untouched, so the wrapper
// replays the same Envelope on a fresh upstream; once a body byte was read
// the request is never replayed.
package proxybuild

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// streamedClientRequest parses req (head plus the first body bytes) on a
// client-facing HTTP/1.x Layer that streams every request body, and
// returns the streamed Envelope and the client's side of the connection
// (to send the rest of the body).
func streamedClientRequest(t *testing.T, req string) (*envelope.Envelope, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	stream := func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode { return layer.Stream() }
	cl := http1.New(server, "client", envelope.Send, http1.WithRequestBodyMode(stream))
	t.Cleanup(func() {
		_ = cl.Close()
		_ = peer.Close()
	})
	if _, err := io.WriteString(peer, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	ch := <-cl.Channels()
	type res struct {
		env *envelope.Envelope
		err error
	}
	done := make(chan res, 1)
	go func() {
		env, nerr := ch.Next(context.Background())
		done <- res{env, nerr}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("client Next: %v", r.err)
		}
		if m, _ := r.env.Message.(*envelope.HTTPMessage); m == nil || m.BodyStream == nil {
			t.Fatal("client request was not streamed")
		}
		return r.env, peer
	case <-time.After(5 * time.Second):
		t.Fatal("the request head was not delivered while the body was pending")
		return nil, nil
	}
}

// failAfterFirstWriteConn passes the first Write (the request head) and
// fails every later one with EPIPE: an upstream that closed after reading
// the head.
type failAfterFirstWriteConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *failAfterFirstWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) == 1 {
		return c.Conn.Write(p)
	}
	return 0, syscall.EPIPE
}

// TestHTTP1_StreamedPUT_HeaderStageStale_Replays (T10): a streamed PUT
// whose head write hits a stale upstream is replayed once on a fresh
// upstream, which receives the request with its body.
func TestHTTP1_StreamedPUT_HeaderStageStale_Replays(t *testing.T) {
	s := startDummyUpstream(t)
	chain, _, _ := buildFlakyChain(t, s, 1)
	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	wrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(upCh, chain, wrap, slog.Default(), s.addr, nil)

	env, peer := streamedClientRequest(t, "PUT /replay HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nhello")
	done := make(chan error, 1)
	go func() { done <- wrapper.Send(context.Background(), env) }()
	if _, err := io.WriteString(peer, "world"); err != nil {
		t.Fatalf("write rest: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Send (streamed PUT, expected replay): %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not return")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := wrapper.Next(ctx); err != nil {
		t.Fatalf("Next after replay: %v", err)
	}
	if got := s.gotReqs.Load(); got != 1 {
		t.Errorf("fresh upstream requests = %d, want 1", got)
	}
	if got := chain.generation; got != 1 {
		t.Errorf("chain.generation = %d, want 1 (one redial)", got)
	}
}

// TestHTTP1_StreamedPUT_BodyStageStale_NoReplay (T9): once body bytes of
// a streamed PUT were read and the upstream write then fails, the request
// is not replayed: the error is a non-replay-safe body-stage
// StaleUpstreamError and no fresh upstream receives the request.
func TestHTTP1_StreamedPUT_BodyStageStale_NoReplay(t *testing.T) {
	s := startDummyUpstream(t)
	rawConn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := &failAfterFirstWriteConn{Conn: rawConn}
	initial := http1.New(conn, "stream-body-stale", envelope.Receive, http1.WithScheme("https"),
		http1.WithEnvelopeContext(envelope.EnvelopeContext{ConnID: "c", TargetHost: s.addr}))
	t.Cleanup(func() { _ = initial.Close() })
	chain := newH1Chain(initial, connector.SameUpstreamTarget(s.addr), connector.UpstreamTLSProfiled, &connector.BuildConfig{InsecureSkipVerify: true}, nil, nil)
	t.Cleanup(func() { chain.closeAll() })

	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	wrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(upCh, chain, wrap, slog.Default(), s.addr, nil)

	env, _ := streamedClientRequest(t, "PUT /no-replay HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nhello")
	done := make(chan error, 1)
	go func() { done <- wrapper.Send(context.Background(), env) }()
	var sendErr error
	select {
	case sendErr = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Send did not return")
	}
	var stale *http1.StaleUpstreamError
	if !errors.As(sendErr, &stale) {
		t.Fatalf("Send = %v, want a body-stage *http1.StaleUpstreamError", sendErr)
	}
	if stale.Stage != "body" || stale.ReplaySafe {
		t.Errorf("StaleUpstreamError = %+v, want stage body, ReplaySafe false", stale)
	}
	if got := chain.generation; got != 0 {
		t.Errorf("chain.generation = %d, want 0 (no redial after body bytes)", got)
	}
	if got := s.gotReqs.Load(); got != 0 {
		t.Errorf("fresh upstream requests = %d, want 0 (the request must not be replayed)", got)
	}
}
