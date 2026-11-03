package httpaggregator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// USK-1401: HTTP/2 body streaming at the aggregator seam. Each test runs a
// real internal/layer/http2 Layer against a frame-level peer (x/net Framer)
// over net.Pipe, so the frames the aggregator causes on the wire are
// observed exactly.

// framePeer is a frame-level h2 endpoint on the far side of a net.Pipe.
type framePeer struct {
	conn net.Conn
	fr   *xhttp2.Framer

	wmu sync.Mutex
	enc *hpack.Encoder
	buf bytes.Buffer

	mu      sync.Mutex
	streams map[uint32]chan peerEv
}

// peerEv is one non-control frame the peer read (payloads copied).
type peerEv struct {
	kind   string // "headers", "data", "rst"
	data   []byte
	end    bool
	code   xhttp2.ErrCode
	fields []hpack.HeaderField
}

func newFramePeer(c net.Conn) *framePeer {
	p := &framePeer{conn: c, fr: xhttp2.NewFramer(c, c), streams: make(map[uint32]chan peerEv)}
	p.enc = hpack.NewEncoder(&p.buf)
	p.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	return p
}

func (p *framePeer) stream(id uint32) chan peerEv {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch, ok := p.streams[id]
	if !ok {
		ch = make(chan peerEv, 256)
		p.streams[id] = ch
	}
	return ch
}

func (p *framePeer) readLoop() {
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			return
		}
		var id uint32
		var ev peerEv
		switch ff := f.(type) {
		case *xhttp2.SettingsFrame:
			if !ff.IsAck() {
				p.wmu.Lock()
				_ = p.fr.WriteSettingsAck()
				p.wmu.Unlock()
			}
			continue
		case *xhttp2.PingFrame:
			continue
		case *xhttp2.MetaHeadersFrame:
			id, ev = ff.StreamID, peerEv{kind: "headers", end: ff.StreamEnded(), fields: append([]hpack.HeaderField(nil), ff.Fields...)}
		case *xhttp2.DataFrame:
			id, ev = ff.StreamID, peerEv{kind: "data", end: ff.StreamEnded(), data: append([]byte(nil), ff.Data()...)}
			if n := uint32(len(ff.Data())); n > 0 {
				p.wmu.Lock()
				_ = p.fr.WriteWindowUpdate(0, n)
				if !ff.StreamEnded() {
					_ = p.fr.WriteWindowUpdate(ff.StreamID, n)
				}
				p.wmu.Unlock()
			}
		case *xhttp2.RSTStreamFrame:
			id, ev = ff.StreamID, peerEv{kind: "rst", code: ff.ErrCode}
		default:
			continue
		}
		select {
		case p.stream(id) <- ev:
		default:
		}
	}
}

func (p *framePeer) headers(t *testing.T, id uint32, end bool, fields ...hpack.HeaderField) {
	t.Helper()
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.buf.Reset()
	for _, f := range fields {
		_ = p.enc.WriteField(f)
	}
	if err := p.fr.WriteHeaders(xhttp2.HeadersFrameParam{StreamID: id, BlockFragment: p.buf.Bytes(), EndStream: end, EndHeaders: true}); err != nil {
		t.Fatalf("peer HEADERS: %v", err)
	}
}

func (p *framePeer) data(t *testing.T, id uint32, end bool, b []byte) {
	t.Helper()
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if err := p.fr.WriteData(id, end, b); err != nil {
		t.Fatalf("peer DATA: %v", err)
	}
}

func (p *framePeer) rst(t *testing.T, id uint32, code xhttp2.ErrCode) {
	t.Helper()
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if err := p.fr.WriteRSTStream(id, code); err != nil {
		t.Fatalf("peer RST_STREAM: %v", err)
	}
}

// next waits up to 5s for the next event on stream id.
func (p *framePeer) next(t *testing.T, id uint32) peerEv {
	t.Helper()
	select {
	case ev := <-p.stream(id):
		return ev
	case <-time.After(5 * time.Second):
		t.Fatalf("peer: no frame on stream %d within 5s", id)
		return peerEv{}
	}
}

// h2Side is one http2.Layer under test plus the frame peer it talks to.
type h2Side struct {
	l    *http2.Layer
	peer *framePeer
}

func (s *h2Side) close() {
	_ = s.l.Close()
	_ = s.peer.conn.Close()
}

// newServerSide starts a ServerRole Layer (the proxy's client-facing side);
// the peer is the HTTP client.
func newServerSide(t *testing.T, opts ...http2.Option) *h2Side {
	t.Helper()
	cliConn, srvConn := net.Pipe()
	peer := newFramePeer(cliConn)
	go func() {
		_, _ = cliConn.Write([]byte(xhttp2.ClientPreface))
		peer.wmu.Lock()
		_ = peer.fr.WriteSettings()
		peer.wmu.Unlock()
	}()
	go peer.readLoop()
	l, err := http2.New(srvConn, "agg-test-server", http2.ServerRole, opts...)
	if err != nil {
		t.Fatalf("http2.New(server): %v", err)
	}
	s := &h2Side{l: l, peer: peer}
	t.Cleanup(s.close)
	return s
}

// newClientSide starts a ClientRole Layer (the proxy's upstream side); the
// peer is the origin.
func newClientSide(t *testing.T, opts ...http2.Option) *h2Side {
	t.Helper()
	cliConn, srvConn := net.Pipe()
	peer := newFramePeer(srvConn)
	ready := make(chan struct{})
	go func() {
		defer close(ready)
		pre := make([]byte, len(xhttp2.ClientPreface))
		if _, err := io.ReadFull(srvConn, pre); err != nil {
			return
		}
		go peer.readLoop()
		peer.wmu.Lock()
		_ = peer.fr.WriteSettings()
		peer.wmu.Unlock()
	}()
	l, err := http2.New(cliConn, "agg-test-client", http2.ClientRole, opts...)
	if err != nil {
		t.Fatalf("http2.New(client): %v", err)
	}
	<-ready
	s := &h2Side{l: l, peer: peer}
	t.Cleanup(s.close)
	return s
}

// acceptStream returns the next peer-initiated stream of a ServerRole Layer.
func acceptStream(t *testing.T, l *http2.Layer) layer.Channel {
	t.Helper()
	select {
	case ch := <-l.Channels():
		return ch
	case <-time.After(5 * time.Second):
		t.Fatal("no stream accepted within 5s")
		return nil
	}
}

// nextWithin calls ch.Next bounded by d. The Next context itself is not
// cancelled when nextWithin returns: a streamed body's reads run on the
// context of the Next that emitted its head (USK-1401 R7), as the
// session's long-lived context does.
func nextWithin(t *testing.T, ch layer.Channel, d time.Duration) (*envelope.Envelope, error) {
	t.Helper()
	type res struct {
		env *envelope.Envelope
		err error
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan res, 1)
	go func() {
		env, err := ch.Next(ctx)
		done <- res{env, err}
	}()
	select {
	case r := <-done:
		return r.env, r.err
	case <-time.After(d):
		cancel()
		r := <-done
		if r.err == nil {
			return r.env, nil
		}
		return nil, context.DeadlineExceeded
	}
}

// nextWithCtx is agg.Next(ctx) bounded by 5s, for a ctx the test cancels
// itself later.
func nextWithCtx(ctx context.Context, agg layer.Channel) (*envelope.Envelope, error) {
	type res struct {
		env *envelope.Envelope
		err error
	}
	done := make(chan res, 1)
	go func() {
		env, err := agg.Next(ctx)
		done <- res{env, err}
	}()
	select {
	case r := <-done:
		return r.env, r.err
	case <-time.After(5 * time.Second):
		return nil, errors.New("Next did not return the head within 5s (body buffered)")
	}
}

func httpMsg(t *testing.T, env *envelope.Envelope) *envelope.HTTPMessage {
	t.Helper()
	m, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message = %T, want *HTTPMessage", env.Message)
	}
	return m
}

func streamAll(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode { return layer.Stream() }

// recordingMode records every predicate call and answers mode.
type recordingMode struct {
	mu    sync.Mutex
	calls []recordedCall
	mode  layer.BodyMode
}

type recordedCall struct {
	dir      envelope.Direction
	ctx      envelope.EnvelopeContext
	method   string
	path     string
	status   int
	hadBody  bool
	protocol string
}

func (r *recordingMode) fn(env *envelope.Envelope, msg *envelope.HTTPMessage) layer.BodyMode {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedCall{
		dir: env.Direction, ctx: env.Context, method: msg.Method, path: msg.Path,
		status: msg.Status, hadBody: msg.Body != nil || msg.BodyBuffer != nil || msg.BodyStream != nil,
		protocol: msg.ConnectProtocol,
	})
	return r.mode
}

func (r *recordingMode) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// sendGET sends a bodyless GET through a RoleClient aggregator.
func sendRequest(t *testing.T, agg layer.Channel, method, path, rawQuery string, body []byte) {
	t.Helper()
	msg := &envelope.HTTPMessage{Method: method, Scheme: "https", Authority: "origin.test", Path: path, RawQuery: rawQuery, Body: body}
	env := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: msg}
	if err := agg.Send(context.Background(), env); err != nil {
		t.Fatalf("Send request: %v", err)
	}
}

func readAllWithin(t *testing.T, r io.Reader, d time.Duration) ([]byte, error) {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		b, err := io.ReadAll(r)
		done <- res{b, err}
	}()
	select {
	case got := <-done:
		return got.b, got.err
	case <-time.After(d):
		t.Fatalf("body read did not finish within %v", d)
		return nil, nil
	}
}

var (
	st200 = hpack.HeaderField{Name: ":status", Value: "200"}
	ctBin = hpack.HeaderField{Name: "content-type", Value: "application/octet-stream"}
)

// TestStreamMode_ResponseHeadBeforeEndStream: with a Stream predicate the
// response head is emitted after its HEADERS, before END_STREAM, and the
// body is read DATA by DATA from the stream.
func TestStreamMode_ResponseHeadBeforeEndStream(t *testing.T) {
	up := newClientSide(t)
	ch, err := up.l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	agg := Wrap(ch, RoleClient, nil, WrapOptions{BodyMode: streamAll})
	sendRequest(t, agg, "GET", "/s", "", nil)
	up.peer.next(t, 1)
	up.peer.headers(t, 1, false, st200, ctBin)
	up.peer.data(t, 1, false, []byte("abc"))

	env, err := nextWithin(t, agg, 5*time.Second)
	if err != nil {
		t.Fatalf("Next: %v (the head must be emitted before END_STREAM)", err)
	}
	msg := httpMsg(t, env)
	if msg.BodyStream == nil || msg.Body != nil || msg.BodyBuffer != nil {
		t.Fatalf("msg body = Body %d / BodyBuffer %v / BodyStream %v, want a BodyStream only", len(msg.Body), msg.BodyBuffer != nil, msg.BodyStream != nil)
	}
	if env.Context.ReceivedAt.IsZero() {
		t.Error("head ReceivedAt is zero, want the header arrival time")
	}
	up.peer.data(t, 1, true, []byte("def"))
	got, rerr := readAllWithin(t, msg.BodyStream, 5*time.Second)
	if rerr != nil || string(got) != "abcdef" {
		t.Fatalf("body = %q, %v; want abcdef", got, rerr)
	}
	if res, ok := msg.BodyStream.Result(); !ok || res.Err != nil {
		t.Errorf("BodyResult = %+v (done=%v), want a clean end", res, ok)
	}
	if _, err := nextWithin(t, agg, 2*time.Second); !errors.Is(err, io.EOF) {
		t.Errorf("Next after the body = %v, want io.EOF", err)
	}
}

// TestBodyMode_PredicateInputs (T11): the predicate sees the Envelope the
// aggregator emits — the Layer's context template (TargetHost), and for a
// response the paired request's method / path / query — and a head-only
// message.
func TestBodyMode_PredicateInputs(t *testing.T) {
	t.Run("response", func(t *testing.T) {
		up := newClientSide(t, http2.WithEnvelopeContext(envelope.EnvelopeContext{TargetHost: "origin.test:443"}))
		ch, err := up.l.OpenStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordingMode{mode: layer.Buffer()}
		agg := Wrap(ch, RoleClient, nil, WrapOptions{BodyMode: rec.fn})
		sendRequest(t, agg, "POST", "/p", "x=1", []byte("req"))
		up.peer.headers(t, 1, false, st200, ctBin)
		up.peer.data(t, 1, true, []byte("resp"))
		if _, err := nextWithin(t, agg, 5*time.Second); err != nil {
			t.Fatalf("Next: %v", err)
		}
		if rec.count() != 1 {
			t.Fatalf("predicate calls = %d, want 1", rec.count())
		}
		c := rec.calls[0]
		if c.dir != envelope.Receive || c.ctx.TargetHost != "origin.test:443" || c.ctx.RequestMethod != "POST" ||
			c.ctx.RequestPath != "/p" || c.ctx.RequestRawQuery != "x=1" || c.status != 200 || c.hadBody {
			t.Errorf("predicate saw %+v, want Receive / TargetHost origin.test:443 / POST /p?x=1 / 200 / no body", c)
		}
	})
	t.Run("request", func(t *testing.T) {
		srv := newServerSide(t, http2.WithEnvelopeContext(envelope.EnvelopeContext{TargetHost: "client.test:443"}))
		srv.peer.headers(t, 1, false,
			hpack.HeaderField{Name: ":method", Value: "PUT"}, hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: "client.test"}, hpack.HeaderField{Name: ":path", Value: "/up"})
		srv.peer.data(t, 1, true, []byte("x"))
		rec := &recordingMode{mode: layer.Buffer()}
		agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{BodyMode: rec.fn})
		if _, err := nextWithin(t, agg, 5*time.Second); err != nil {
			t.Fatalf("Next: %v", err)
		}
		if rec.count() != 1 {
			t.Fatalf("predicate calls = %d, want 1", rec.count())
		}
		c := rec.calls[0]
		if c.dir != envelope.Send || c.ctx.TargetHost != "client.test:443" || c.method != "PUT" || c.path != "/up" || c.hadBody {
			t.Errorf("predicate saw %+v, want Send / TargetHost client.test:443 / PUT /up / no body", c)
		}
	})
}

// TestBodyMode_NotConsultedForBodylessOrTunnelHeads (T11): the predicate is
// consulted only where a body would be collected; 1xx, END_STREAM HEADERS,
// extended CONNECT, SSE 2xx and a classic CONNECT request keep their own
// handling.
func TestBodyMode_NotConsultedForBodylessOrTunnelHeads(t *testing.T) {
	t.Run("1xx_then_end_stream_headers", func(t *testing.T) {
		up := newClientSide(t)
		ch, _ := up.l.OpenStream(context.Background())
		rec := &recordingMode{mode: layer.Stream()}
		agg := Wrap(ch, RoleClient, nil, WrapOptions{BodyMode: rec.fn})
		sendRequest(t, agg, "GET", "/", "", nil)
		up.peer.headers(t, 1, false, hpack.HeaderField{Name: ":status", Value: "103"}, hpack.HeaderField{Name: "link", Value: "</a>"})
		up.peer.headers(t, 1, true, hpack.HeaderField{Name: ":status", Value: "204"})
		for i := 0; i < 2; i++ {
			if _, err := nextWithin(t, agg, 5*time.Second); err != nil {
				t.Fatalf("Next %d: %v", i, err)
			}
		}
		if rec.count() != 0 {
			t.Errorf("predicate consulted %d times for 1xx / END_STREAM HEADERS, want 0", rec.count())
		}
	})
	t.Run("sse_2xx", func(t *testing.T) {
		up := newClientSide(t)
		ch, _ := up.l.OpenStream(context.Background())
		rec := &recordingMode{mode: layer.Stream()}
		agg := Wrap(ch, RoleClient, nil, WrapOptions{BodyMode: rec.fn})
		sendRequest(t, agg, "GET", "/events", "", nil)
		up.peer.headers(t, 1, false, st200, hpack.HeaderField{Name: "content-type", Value: "text/event-stream"})
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if httpMsg(t, env).BodyStream != nil || rec.count() != 0 {
			t.Errorf("SSE head: BodyStream=%v predicate calls=%d, want neither", httpMsg(t, env).BodyStream != nil, rec.count())
		}
	})
	t.Run("extended_connect_request", func(t *testing.T) {
		srv := newServerSide(t, http2.WithEnableConnectProtocol(true))
		srv.peer.headers(t, 1, false,
			hpack.HeaderField{Name: ":method", Value: "CONNECT"}, hpack.HeaderField{Name: ":protocol", Value: "websocket"},
			hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":authority", Value: "ws.test"},
			hpack.HeaderField{Name: ":path", Value: "/chat"})
		rec := &recordingMode{mode: layer.Stream()}
		agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{BodyMode: rec.fn})
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if httpMsg(t, env).BodyStream != nil || rec.count() != 0 {
			t.Errorf("extended CONNECT: BodyStream=%v predicate calls=%d, want neither", httpMsg(t, env).BodyStream != nil, rec.count())
		}
	})
	t.Run("classic_connect_request", func(t *testing.T) {
		srv := newServerSide(t)
		srv.peer.headers(t, 1, false,
			hpack.HeaderField{Name: ":method", Value: "CONNECT"}, hpack.HeaderField{Name: ":authority", Value: "tunnel.test:443"})
		srv.peer.data(t, 1, true, []byte("tunnel bytes"))
		rec := &recordingMode{mode: layer.Stream()}
		agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{BodyMode: rec.fn})
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if m := httpMsg(t, env); m.BodyStream != nil || string(m.Body) != "tunnel bytes" || rec.count() != 0 {
			t.Errorf("classic CONNECT: BodyStream=%v Body=%q predicate calls=%d, want a buffered body and no call", m.BodyStream != nil, m.Body, rec.count())
		}
	})
}

// captureChannel is a layer.Channel whose Send records event envelopes.
type captureChannel struct {
	*fakeChannel
}

func (c *captureChannel) events() []*envelope.Envelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*envelope.Envelope(nil), c.sent...)
}

// dataSizes returns the DATA payload sizes and END_STREAM flags of evs.
func dataSizes(evs []*envelope.Envelope) (sizes []int, endFlags []bool) {
	for _, e := range evs {
		if d, ok := e.Message.(*http2.H2DataEvent); ok {
			sizes = append(sizes, len(d.Payload))
			endFlags = append(endFlags, d.EndStream)
		}
	}
	return sizes, endFlags
}

// forwardTo sends env (a streamed message) through a capturing aggregator
// and returns the events it put on its inner Channel.
func forwardTo(t *testing.T, env *envelope.Envelope, role Role) []*envelope.Envelope {
	t.Helper()
	cc := &captureChannel{fakeChannel: newFakeChannel()}
	out := Wrap(cc, role, nil, WrapOptions{})
	if err := out.Send(context.Background(), env); err != nil {
		t.Fatalf("forward Send: %v", err)
	}
	return cc.events()
}

func postFields(extra ...hpack.HeaderField) []hpack.HeaderField {
	return append([]hpack.HeaderField{
		{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "client.test"}, {Name: ":path", Value: "/u"},
	}, extra...)
}

// TestBufferUpTo (T12): a body within the limit is buffered as before; a
// larger one is streamed with the probed prefix replayed at its original
// DATA boundaries; a declared content-length over the limit streams at once;
// a probe that spilled leaves no file behind.
func TestBufferUpTo(t *testing.T) {
	ten := bytes.Repeat([]byte("0123456789"), 1)
	t.Run("within_limit_buffered", func(t *testing.T) {
		srv := newServerSide(t)
		srv.peer.headers(t, 1, false, postFields()...)
		for i := 0; i < 3; i++ {
			srv.peer.data(t, 1, i == 2, ten)
		}
		agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{BodyMode: func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
			return layer.BufferUpTo(100)
		}})
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if m := httpMsg(t, env); m.BodyStream != nil || len(m.Body) != 30 {
			t.Errorf("body = %d bytes stream=%v, want 30 buffered", len(m.Body), m.BodyStream != nil)
		}
	})
	t.Run("over_limit_streamed_keeps_boundaries", func(t *testing.T) {
		srv := newServerSide(t)
		srv.peer.headers(t, 1, false, postFields()...)
		agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{BodyMode: func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
			return layer.BufferUpTo(15)
		}})
		srv.peer.data(t, 1, false, ten)
		srv.peer.data(t, 1, false, []byte("abcdefghij"))
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil {
			t.Fatalf("Next: %v (a body over the limit must be streamed)", err)
		}
		if httpMsg(t, env).BodyStream == nil {
			t.Fatal("body over the BufferUpTo limit is not streamed")
		}
		srv.peer.data(t, 1, true, []byte("klmno"))
		sizes, ends := dataSizes(forwardTo(t, env, RoleClient))
		if want := []int{10, 10, 5}; len(sizes) != 3 || sizes[0] != want[0] || sizes[1] != want[1] || sizes[2] != want[2] || !ends[2] || ends[0] || ends[1] {
			t.Errorf("forwarded DATA = %v end=%v, want [10 10 5] with END_STREAM on the last", sizes, ends)
		}
	})
	t.Run("declared_length_over_limit_streams_at_once", func(t *testing.T) {
		srv := newServerSide(t)
		srv.peer.headers(t, 1, false, postFields(hpack.HeaderField{Name: "content-length", Value: "1000"})...)
		agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{BodyMode: func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
			return layer.BufferUpTo(15)
		}})
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil {
			t.Fatalf("Next: %v (content-length over the limit must stream before any DATA)", err)
		}
		if httpMsg(t, env).BodyStream == nil {
			t.Fatal("not streamed")
		}
		_ = httpMsg(t, env).BodyStream.Close()
	})
	t.Run("spilled_probe_released", func(t *testing.T) {
		dir := t.TempDir()
		srv := newServerSide(t)
		srv.peer.headers(t, 1, false, postFields()...)
		agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{
			BodySpillDir: dir, BodySpillThreshold: 1 << 10,
			BodyMode: func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode { return layer.BufferUpTo(4 << 10) },
		})
		chunk := bytes.Repeat([]byte("s"), 2<<10)
		for i := 0; i < 3; i++ {
			srv.peer.data(t, 1, false, chunk)
		}
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil || httpMsg(t, env).BodyStream == nil {
			t.Fatalf("Next: %v (want a streamed head)", err)
		}
		srv.peer.data(t, 1, true, chunk)
		sizes, _ := dataSizes(forwardTo(t, env, RoleClient))
		if len(sizes) != 4 {
			t.Errorf("forwarded DATA sizes = %v, want four 2 KiB frames", sizes)
		}
		_ = agg.Close()
		if n := spillFiles(t, dir); n != 0 {
			t.Errorf("%d spill files remain after the streamed body ended", n)
		}
	})
}

func spillFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), config.BodySpillPrefix) {
			n++
		}
	}
	return n
}

// TestStreamedRequest_NextAfterRespondAndNoErrorReset (T13 / U2): the
// Pipeline answered a streamed request without reading its body. Next
// returns at once (the unread body is abandoned) and, the response having
// ended the exchange, Close resets the request half with
// RST_STREAM(NO_ERROR) — not CANCEL.
func TestStreamedRequest_NextAfterRespondAndNoErrorReset(t *testing.T) {
	srv := newServerSide(t)
	srv.peer.headers(t, 1, false, postFields()...)
	srv.peer.data(t, 1, false, []byte("upload..."))
	agg := Wrap(acceptStream(t, srv.l), RoleServer, nil, WrapOptions{BodyMode: streamAll})
	env, err := nextWithin(t, agg, 5*time.Second)
	if err != nil || httpMsg(t, env).BodyStream == nil {
		t.Fatalf("Next: %v (want a streamed request head)", err)
	}
	bs := httpMsg(t, env).BodyStream

	resp := &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Status: 403, Body: []byte("denied")}}
	if err := agg.Send(context.Background(), resp); err != nil {
		t.Fatalf("Send 403: %v", err)
	}
	if ev := srv.peer.next(t, 1); ev.kind != "headers" {
		t.Fatalf("peer got %v, want the 403 HEADERS", ev)
	}
	if ev := srv.peer.next(t, 1); ev.kind != "data" || !ev.end {
		t.Fatalf("peer got %v, want the 403 body with END_STREAM", ev)
	}

	start := time.Now()
	if _, err := nextWithin(t, agg, 2*time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("Next after the response = %v, want io.EOF", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Next took %v, want prompt", d)
	}
	if res, ok := bs.Result(); !ok || !errors.Is(res.Err, envelope.ErrBodyStreamClosed) {
		t.Errorf("unread body result = %+v (done=%v), want ErrBodyStreamClosed", res, ok)
	}
	_ = agg.Close()
	if ev := srv.peer.next(t, 1); ev.kind != "rst" || ev.code != xhttp2.ErrCodeNo {
		t.Errorf("after Close the peer got %v, want RST_STREAM(NO_ERROR)", ev)
	}
}

// TestStreamedResponse_UpstreamResetEndsBodyNotSend (R13): the upstream
// resets mid-body. The consumer's Send forwards the DATA received, sends no
// END_STREAM and returns nil; the producer's next Next returns the reset
// with the peer's wire code; the body result is truncated.
func TestStreamedResponse_UpstreamResetEndsBodyNotSend(t *testing.T) {
	up := newClientSide(t)
	ch, _ := up.l.OpenStream(context.Background())
	agg := Wrap(ch, RoleClient, nil, WrapOptions{BodyMode: streamAll})
	sendRequest(t, agg, "GET", "/r", "", nil)
	up.peer.headers(t, 1, false, st200, ctBin)
	up.peer.data(t, 1, false, []byte("partial"))
	env, err := nextWithin(t, agg, 5*time.Second)
	if err != nil || httpMsg(t, env).BodyStream == nil {
		t.Fatalf("Next: %v", err)
	}
	up.peer.rst(t, 1, xhttp2.ErrCode(0x1234))

	cc := &captureChannel{fakeChannel: newFakeChannel()}
	out := Wrap(cc, RoleServer, nil, WrapOptions{})
	env.Direction = envelope.Receive
	if err := out.Send(context.Background(), env); err != nil {
		t.Fatalf("consumer Send = %v, want nil (the body ended, not the Send)", err)
	}
	sizes, ends := dataSizes(cc.events())
	if len(sizes) != 1 || sizes[0] != len("partial") || ends[0] {
		t.Errorf("forwarded DATA = %v end=%v, want the 7-byte DATA without END_STREAM", sizes, ends)
	}
	res, _ := httpMsg(t, env).BodyStream.Result()
	if !res.Truncated {
		t.Errorf("BodyResult.Truncated = false, want true")
	}
	_, nerr := nextWithin(t, agg, 2*time.Second)
	var se *layer.StreamError
	if !errors.As(nerr, &se) || !se.HasPeerWireCode || se.PeerWireCode != 0x1234 {
		t.Errorf("Next after the reset = %v, want the StreamError with peer code 0x1234", nerr)
	}
}

// TestStreamedBody_ConcurrentEnds (T15): Close of the BodyStream, Close of
// the aggregator and cancellation of the Next context each unblock a Read
// waiting for DATA.
func TestStreamedBody_ConcurrentEnds(t *testing.T) {
	cases := []struct {
		name string
		end  func(agg layer.Channel, bs *envelope.BodyStream, cancel context.CancelFunc)
	}{
		{"body_close", func(_ layer.Channel, bs *envelope.BodyStream, _ context.CancelFunc) { _ = bs.Close() }},
		{"aggregator_close", func(agg layer.Channel, _ *envelope.BodyStream, _ context.CancelFunc) { _ = agg.Close() }},
		{"ctx_cancel", func(_ layer.Channel, _ *envelope.BodyStream, cancel context.CancelFunc) { cancel() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newClientSide(t)
			ch, _ := up.l.OpenStream(context.Background())
			agg := Wrap(ch, RoleClient, nil, WrapOptions{BodyMode: streamAll})
			sendRequest(t, agg, "GET", "/c", "", nil)
			up.peer.headers(t, 1, false, st200, ctBin)
			// Bounded so a buffering aggregator fails instead of hanging.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			env, err := nextWithCtx(ctx, agg)
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			bs := httpMsg(t, env).BodyStream
			if bs == nil {
				t.Fatal("not streamed")
			}
			readErr := make(chan error, 1)
			go func() {
				_, err := io.ReadAll(bs)
				readErr <- err
			}()
			time.Sleep(20 * time.Millisecond) // let the Read block on the stream
			tc.end(agg, bs, cancel)
			select {
			case err := <-readErr:
				if err == nil {
					t.Error("Read ended cleanly, want an error for a body that never ended")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Read still blocked after the end signal")
			}
			select {
			case <-bs.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("BodyStream not done")
			}
		})
	}
}

// TestEncodeWireBytes_StreamedBody (T16 / R22): a streamed message encodes
// to its HEADERS without END_STREAM and reports ErrPartialWireBytes.
func TestEncodeWireBytes_StreamedBody(t *testing.T) {
	bs := envelope.NewBodyStream(&sliceSource{chunks: [][]byte{[]byte("x")}})
	defer bs.Close()
	env := &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Status: 200, BodyStream: bs}}
	b, err := EncodeWireBytes(env)
	if !errors.Is(err, envelope.ErrPartialWireBytes) {
		t.Fatalf("err = %v, want ErrPartialWireBytes", err)
	}
	rd := frame.NewReader(bytes.NewReader(b))
	f, ferr := rd.ReadFrame()
	if ferr != nil {
		t.Fatalf("read frame: %v", ferr)
	}
	if f.Header.Type != frame.TypeHeaders || f.Header.Flags.Has(frame.FlagEndStream) {
		t.Errorf("first frame type=%v flags=%v, want HEADERS without END_STREAM", f.Header.Type, f.Header.Flags)
	}
	if _, err := rd.ReadFrame(); err == nil {
		t.Error("more frames after the HEADERS, want the head only")
	}
}

// sliceSource is a foreign BodyStreamSource yielding chunks then EOF, with
// the given trailers.
type sliceSource struct {
	chunks   [][]byte
	trailers []envelope.KeyValue
}

func (s *sliceSource) Read(p []byte) (int, error) {
	if len(s.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.chunks[0])
	s.chunks[0] = s.chunks[0][n:]
	if len(s.chunks[0]) == 0 {
		s.chunks = s.chunks[1:]
	}
	return n, nil
}

func (s *sliceSource) Finish(error) envelope.BodyResult {
	return envelope.BodyResult{Trailers: s.trailers}
}

// TestSend_ForeignBodyStream (T17 / R23): a BodyStream another protocol
// produced is sent semantically — one DATA per Read (never coalesced),
// trailers from the BodyResult, END_STREAM on the last frame — and the
// stream is closed.
func TestSend_ForeignBodyStream(t *testing.T) {
	t.Run("with_trailers", func(t *testing.T) {
		bs := envelope.NewBodyStream(&sliceSource{
			chunks:   [][]byte{[]byte("abc"), []byte("defg")},
			trailers: []envelope.KeyValue{{Name: "x-sum", Value: "7"}},
		})
		env := &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{Status: 200, BodyStream: bs}}
		evs := forwardTo(t, env, RoleServer)
		sizes, ends := dataSizes(evs)
		if len(sizes) != 2 || sizes[0] != 3 || sizes[1] != 4 || ends[0] || ends[1] {
			t.Errorf("DATA = %v end=%v, want [3 4] without END_STREAM", sizes, ends)
		}
		tr, ok := evs[len(evs)-1].Message.(*http2.H2TrailersEvent)
		if !ok || len(tr.Trailers) != 1 || tr.Trailers[0].Value != "7" {
			t.Errorf("last event = %T, want the BodyResult trailers", evs[len(evs)-1].Message)
		}
		select {
		case <-bs.Done():
		default:
			t.Error("BodyStream not closed after Send")
		}
	})
	t.Run("without_trailers", func(t *testing.T) {
		bs := envelope.NewBodyStream(&sliceSource{chunks: [][]byte{[]byte("abc"), []byte("defg")}})
		env := &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{Status: 200, BodyStream: bs}}
		sizes, ends := dataSizes(forwardTo(t, env, RoleServer))
		if len(sizes) < 2 || sizes[0] != 3 || sizes[1] != 4 || !ends[len(ends)-1] {
			t.Errorf("DATA = %v end=%v, want [3 4 ...] with END_STREAM on the last frame", sizes, ends)
		}
	})
}

// TestBufferedRawBuffer (T18 / U1): a buffered message keeps its body wire
// bytes in Envelope.RawBuffer (spilled past body_spill_threshold) instead of
// growing Envelope.Raw, capped at max_record_body_size with
// AnomalyRawBodyTruncated; releasing it removes the spill file.
func TestBufferedRawBuffer(t *testing.T) {
	chunk := bytes.Repeat([]byte("r"), 2<<10)
	run := func(t *testing.T, recordCap int64) (*envelope.Envelope, string) {
		dir := t.TempDir()
		up := newClientSide(t)
		ch, _ := up.l.OpenStream(context.Background())
		agg := Wrap(ch, RoleClient, nil, WrapOptions{BodySpillDir: dir, BodySpillThreshold: 1 << 10, MaxRecordBodySize: recordCap})
		sendRequest(t, agg, "GET", "/raw", "", nil)
		up.peer.headers(t, 1, false, st200, ctBin)
		up.peer.data(t, 1, false, chunk)
		up.peer.data(t, 1, true, chunk)
		env, err := nextWithin(t, agg, 5*time.Second)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		return env, dir
	}
	t.Run("capped", func(t *testing.T) {
		env, dir := run(t, 3<<10)
		if bytes.Contains(env.Raw, chunk[:64]) {
			t.Errorf("Envelope.Raw (%d bytes) carries body bytes, want the HEADERS block only", len(env.Raw))
		}
		if env.RawBuffer == nil || env.RawBuffer.Len() != 3<<10 || !env.RawBuffer.IsFileBacked() {
			t.Fatalf("RawBuffer = %v, want a 3 KiB file-backed capture", env.RawBuffer)
		}
		var marked bool
		for _, a := range httpMsg(t, env).Anomalies {
			marked = marked || a.Type == envelope.AnomalyRawBodyTruncated
		}
		if !marked {
			t.Error("no AnomalyRawBodyTruncated on a capture cut at max_record_body_size")
		}
		// The 4 KiB body itself spilled too (BodyBuffer); release both.
		env.ReleaseBuffers()
		if n := spillFiles(t, dir); n != 0 {
			t.Errorf("%d spill files remain after the RawBuffer was released", n)
		}
	})
	t.Run("uncapped", func(t *testing.T) {
		env, _ := run(t, 0)
		wire, err := env.WireBytes(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasSuffix(wire, append(append([]byte(nil), chunk...), chunk...)) || env.RawBuffer == nil {
			t.Errorf("wire bytes (%d) are not the HEADERS block + both DATA payloads", len(wire))
		}
		for _, a := range httpMsg(t, env).Anomalies {
			if a.Type == envelope.AnomalyRawBodyTruncated {
				t.Error("AnomalyRawBodyTruncated on an uncut capture")
			}
		}
		env.ReleaseBuffers()
	})
}
