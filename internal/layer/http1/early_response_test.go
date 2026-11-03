package http1

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-1415: an upstream that answers (413 ...) before the request body was
// written in full. A body-stage write failure caused by the peer (EPIPE /
// ECONNRESET) is reported as layer.ErrUpstreamStoppedReadingBody composed
// with the body-stage StaleUpstreamError, and the upstream Layer carries no
// further exchange. While a streamed body is still being forwarded, a final
// response that makes the upstream connection non-reusable, once written to
// the client, stops the forwarding.

// failWritesFromConn passes Writes before the failFrom-th (1-based) and
// fails that one and every later one with err.
type failWritesFromConn struct {
	net.Conn
	failFrom int32
	err      error
	writes   atomic.Int32
}

func (c *failWritesFromConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) >= c.failFrom {
		return 0, c.err
	}
	return c.Conn.Write(p)
}

func writeSyscallErr(errno syscall.Errno) error {
	return &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", errno)}
}

// bufferedClientRequest parses raw on a Send-direction Layer without a
// request body-mode predicate and returns the buffered request Envelope.
func bufferedClientRequest(t *testing.T, raw string) *envelope.Envelope {
	t.Helper()
	peer, server := testConn(t)
	l := New(server, "buffered-client", envelope.Send)
	t.Cleanup(func() {
		_ = l.Close()
		_ = peer.Close()
	})
	peerWrite(t, peer, raw)
	return nextRequestWithin(t, nextChannelWithin(t, l), 5*time.Second)
}

// TestSendRequest_BodyStageErrorComposition (T6): the error a body-stage
// write failure produces, for the buffered (opaque), synthetic and
// streamed send paths.
func TestSendRequest_BodyStageErrorComposition(t *testing.T) {
	const bufferedReq = "POST /upload HTTP/1.1\r\nHost: up.test\r\nContent-Length: 10\r\n\r\nhelloworld"
	const streamedHead = "POST /upload HTTP/1.1\r\nHost: up.test\r\nContent-Length: 10\r\n\r\n"

	type request func(t *testing.T) *envelope.Envelope
	opaque := func(t *testing.T) *envelope.Envelope { return bufferedClientRequest(t, bufferedReq) }
	synthetic := func(t *testing.T) *envelope.Envelope {
		return BuildSendEnvelope("POST", "http", "up.test", "/upload", "",
			[]envelope.KeyValue{{Name: "Host", Value: "up.test"}}, []byte("helloworld"))
	}
	streamed := func(t *testing.T) *envelope.Envelope {
		cl, peer := newStreamingClient(t, streamAll)
		peerWrite(t, peer, streamedHead+"hello")
		env := nextRequestWithin(t, nextChannelWithin(t, cl), 2*time.Second)
		streamedMsg(t, env)
		return env
	}

	tests := []struct {
		name         string
		req          request
		failFrom     int32
		err          error
		wantSentinel bool
		wantStage    string // "" = not a StaleUpstreamError
		wantRetired  bool
	}{
		{"opaque body ECONNRESET", opaque, 2, writeSyscallErr(syscall.ECONNRESET), true, "body", true},
		{"opaque body EPIPE", opaque, 2, writeSyscallErr(syscall.EPIPE), true, "body", true},
		{"synthetic body ECONNRESET", synthetic, 2, writeSyscallErr(syscall.ECONNRESET), true, "body", true},
		{"synthetic body EPIPE", synthetic, 2, writeSyscallErr(syscall.EPIPE), true, "body", true},
		{"streamed body ECONNRESET", streamed, 2, writeSyscallErr(syscall.ECONNRESET), true, "body", true},
		{"streamed body EPIPE", streamed, 2, writeSyscallErr(syscall.EPIPE), true, "body", true},
		{"opaque body net.ErrClosed", opaque, 2, net.ErrClosed, false, "body", true},
		{"opaque body non-stale error", opaque, 2, errors.New("disk on fire"), false, "", true},
		{"opaque head EPIPE", opaque, 1, writeSyscallErr(syscall.EPIPE), false, "header", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.req(t)
			peer, server := testConn(t)
			go func() { _, _ = io.Copy(io.Discard, peer) }()
			up := New(&failWritesFromConn{Conn: server, failFrom: tt.failFrom, err: tt.err}, "up", envelope.Receive)
			t.Cleanup(func() {
				_ = up.Close()
				_ = peer.Close()
			})

			err := waitErr(t, sendAsync(up.OpenExchange(), env))
			if err == nil {
				t.Fatal("Send = nil, want the write error")
			}
			if got := errors.Is(err, layer.ErrUpstreamStoppedReadingBody); got != tt.wantSentinel {
				t.Errorf("errors.Is(%v, ErrUpstreamStoppedReadingBody) = %v, want %v", err, got, tt.wantSentinel)
			}
			var stale *StaleUpstreamError
			if tt.wantStage == "" {
				if errors.As(err, &stale) {
					t.Errorf("Send error %v is a StaleUpstreamError, want a plain error", err)
				}
			} else {
				if !errors.As(err, &stale) {
					t.Fatalf("Send error %v is not a *StaleUpstreamError", err)
				}
				if stale.Stage != tt.wantStage {
					t.Errorf("Stage = %q, want %q", stale.Stage, tt.wantStage)
				}
				if tt.wantStage == "body" && stale.ReplaySafe {
					t.Error("a body-stage error must never be replay-safe")
				}
			}
			if got := up.Retired(); got != tt.wantRetired {
				t.Errorf("upstream Retired() = %v, want %v", got, tt.wantRetired)
			}
		})
	}
}

// gatedWriteConn passes Writes before the gateFrom-th (1-based) and blocks
// that one and every later one — as a socket whose peer stopped reading
// blocks once its send buffer is full — until release (the Write then goes
// through), a write deadline at or before now (it fails with
// os.ErrDeadlineExceeded) or Close (net.ErrClosed), the way a net.Conn's
// pending Write does.
type gatedWriteConn struct {
	net.Conn
	gateFrom int32
	writes   atomic.Int32

	blocked     chan struct{} // closed when the first gated Write blocks
	blockedOnce sync.Once
	pass        chan struct{} // closed by release
	passOnce    sync.Once
	fail        chan struct{} // closed by failWith; failErr is set first
	failOnce    sync.Once
	failErr     error
}

func newGatedWriteConn(c net.Conn, gateFrom int32) *gatedWriteConn {
	return &gatedWriteConn{
		Conn:     c,
		gateFrom: gateFrom,
		blocked:  make(chan struct{}),
		pass:     make(chan struct{}),
		fail:     make(chan struct{}),
	}
}

func (c *gatedWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) < c.gateFrom {
		return c.Conn.Write(p)
	}
	select {
	case <-c.fail:
		return 0, c.failErr
	default:
	}
	c.blockedOnce.Do(func() { close(c.blocked) })
	select {
	case <-c.fail:
		return 0, c.failErr
	case <-c.pass:
		return c.Conn.Write(p)
	}
}

func (c *gatedWriteConn) SetWriteDeadline(d time.Time) error {
	if !d.IsZero() && !d.After(time.Now()) {
		c.failWith(os.ErrDeadlineExceeded)
	}
	return c.Conn.SetWriteDeadline(d)
}

func (c *gatedWriteConn) Close() error {
	c.failWith(net.ErrClosed)
	return c.Conn.Close()
}

func (c *gatedWriteConn) release() { c.passOnce.Do(func() { close(c.pass) }) }

func (c *gatedWriteConn) failWith(err error) {
	c.failOnce.Do(func() {
		c.failErr = err
		close(c.fail)
	})
}

// waitClosed waits until ch is closed, bounded by 5s.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen within 5s", what)
	}
}

// newAnsweringUpstream builds a Receive-direction Layer over a real TCP
// pair whose peer records every byte it reads; the peer conn is returned
// so the test can write the response. wrap, when non-nil, wraps the
// Layer's side of the pair.
func newAnsweringUpstream(t *testing.T, wrap func(net.Conn) net.Conn) (*Layer, net.Conn, *wireCapture) {
	t.Helper()
	peer, server := testConn(t)
	if wrap != nil {
		server = wrap(server)
	}
	l := New(server, "answering-up", envelope.Receive)
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
	return l, peer, w
}

// readResponseHeadWithin reads a header section (through the blank line)
// from br on conn, bounded by 5s.
func readResponseHeadWithin(t *testing.T, conn net.Conn, br *bufio.Reader) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			t.Fatalf("read response head (so far %q): %v", head.String(), err)
		}
		if line == "\r\n" {
			return head.String()
		}
	}
}

// TestRequestStream_EarlyFinalResponse (T10, U-1 / R13): a streamed
// request is mid-body when the upstream answers. Once the client Channel
// wrote a final response that makes the upstream connection non-reusable,
// the forwarding stops: the upstream Send returns nil without the rest of
// the body, the upstream Layer carries no further exchange, and the client
// reads the response, then the end of its connection. A reusable response
// keeps the forwarding going: the whole body reaches the upstream and the
// client connection carries the next request.
//
// gateFrom > 0 blocks the upstream conn's Writes from that one on
// (gatedWriteConn). 2 blocks the first body write, as against an upstream
// that stopped reading: only the stop's write deadline unblocks it. 1 blocks
// the head write until the response was delivered, so the stop comes before
// the upstream Layer was registered as the body's forward target.
func TestRequestStream_EarlyFinalResponse(t *testing.T) {
	const closeResp = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	tests := []struct {
		name     string
		response string
		stop     bool
		gateFrom int32
	}{
		{"connection close", closeResp, true, 0},
		{"connection close, body write blocked", closeResp, true, 2},
		{"connection close before the body forwarding started", closeResp, true, 1},
		{"close token in list mixed case", "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nconnection: keep-alive, Close\r\n\r\n", true, 0},
		{"http10 without keep-alive", "HTTP/1.0 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n", true, 0},
		{"http10 keep-alive", "HTTP/1.0 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", false, 0},
		{"http11 keep-alive", "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl, peer := newStreamingClient(t, streamAll)
			var gate *gatedWriteConn
			var wrap func(net.Conn) net.Conn
			if tt.gateFrom > 0 {
				wrap = func(c net.Conn) net.Conn {
					gate = newGatedWriteConn(c, tt.gateFrom)
					return gate
				}
			}
			up, upPeer, wire := newAnsweringUpstream(t, wrap)
			const head = "PUT /big HTTP/1.1\r\nHost: up.test\r\nContent-Length: 10\r\n\r\n"
			peerWrite(t, peer, head+"hello")
			ch := nextChannelWithin(t, cl)
			env := nextRequestWithin(t, ch, 2*time.Second)
			streamedMsg(t, env)
			upCh := up.OpenExchange()
			done := sendAsync(upCh, env)
			wantWire := head + "hello"
			switch tt.gateFrom {
			case 0:
				wire.waitLen(t, len(head)+5)
			case 1:
				waitClosed(t, gate.blocked, "the blocked head write")
				wantWire = head
			case 2:
				wire.waitLen(t, len(head))
				waitClosed(t, gate.blocked, "the blocked body write")
				wantWire = head
			}

			peerWrite(t, upPeer, tt.response)
			resp, err := upCh.Next(context.Background())
			if err != nil {
				t.Fatalf("upstream Next: %v", err)
			}
			if err := ch.Send(context.Background(), resp); err != nil {
				t.Fatalf("client Send response: %v", err)
			}
			if tt.gateFrom == 1 {
				gate.release()
			}
			br := bufio.NewReader(peer)
			if got := readResponseHeadWithin(t, peer, br); !strings.HasPrefix(got, "HTTP/1.") || !strings.Contains(got, " 413 ") {
				t.Fatalf("client response head = %q, want the 413", got)
			}

			if !tt.stop {
				// R13: the forwarding goes on; the client sends the rest.
				peerWrite(t, peer, "world")
				if err := waitErr(t, done); err != nil {
					t.Fatalf("upstream Send = %v, want nil after the whole body", err)
				}
				if got := string(wire.waitLen(t, len(head)+10)); got != head+"helloworld" {
					t.Errorf("upstream wire = %q, want the whole request", got)
				}
				_ = ch.Close()
				peerWrite(t, peer, "GET /next HTTP/1.1\r\nHost: up.test\r\n\r\n")
				next := nextChannelWithin(t, cl)
				if env := nextRequestWithin(t, next, 2*time.Second); env.Message.(*envelope.HTTPMessage).Path != "/next" {
					t.Errorf("next request path = %q, want /next", env.Message.(*envelope.HTTPMessage).Path)
				}
				return
			}

			// U-1: the client holds the rest of its body.
			if err := waitErr(t, done); err != nil {
				t.Errorf("upstream Send = %v, want nil (the request direction ends cleanly)", err)
			}
			if !up.Retired() {
				t.Error("upstream Layer not retired; its connection is mid-request")
			}
			if got := string(wire.waitLen(t, len(wantWire))); got != wantWire {
				t.Errorf("upstream wire = %q, want %q (the head and what was forwarded before the stop)", got, wantWire)
			}
			_ = ch.Close()
			_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
			rest, err := io.ReadAll(br)
			if err != nil {
				t.Fatalf("client read %q, then %v; want its connection ended by the proxy (EOF)", rest, err)
			}
			assertChannelsEnd(t, cl)
		})
	}
}
