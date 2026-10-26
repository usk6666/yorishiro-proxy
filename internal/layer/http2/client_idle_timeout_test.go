package http2

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1188: a client-facing (ServerRole) connection that has had no open
// stream for the client idle bound is sent GOAWAY(NO_ERROR, last processed
// stream id) and closed — the Go x/net/http2 Server IdleTimeout shape.
//
// Timing: every test uses a short real bound. Pass / fail is decided by
// events (a GOAWAY frame or EOF observed by the peer) with generous upper
// bounds; lower bounds are 2/3 of the bound so a scheduler hiccup cannot
// make an early GOAWAY look on time.

const (
	idleTestBound = 200 * time.Millisecond
	// idleTestLower is the earliest a GOAWAY may arrive after the idle
	// period started.
	idleTestLower = idleTestBound * 2 / 3
	// idleTestWait is the upper bound for any expected event.
	idleTestWait = 3 * time.Second
	// idleTestLinger is the post-GOAWAY linger used unless a test needs
	// the connection to stay readable longer.
	idleTestLinger = 50 * time.Millisecond
)

// withIdleGoAwayLinger overrides the 1s post-GOAWAY linger (test seam).
func withIdleGoAwayLinger(d time.Duration) Option {
	return func(o *options) { o.idleGoAwayLinger = d }
}

// withBeforeAcceptPeerStream installs the reader hook run before a new peer
// stream is registered.
func withBeforeAcceptPeerStream(fn func(uint32)) Option {
	return func(o *options) { o.beforeAcceptPeerStream = fn }
}

// withAfterRegisterPeerStream installs the reader hook run between a new
// peer stream's registration and its EventRecvHeaders transition.
func withAfterRegisterPeerStream(fn func(uint32)) Option {
	return func(o *options) { o.afterRegisterPeerStream = fn }
}

// fixedIdle returns a WithClientIdleTimeout resolver for a constant bound.
func fixedIdle(d time.Duration) func() (time.Duration, bool) {
	return func() (time.Duration, bool) { return d, true }
}

// idlePeer is an h2Peer whose frames are read by a background goroutine, so
// the Layer's writes on the synchronous net.Pipe never block on the test.
type idlePeer struct {
	*h2Peer
	t      *testing.T
	frames chan *frame.Frame
	// eof is closed when the peer's read side ends (Layer closed the
	// connection).
	eof chan struct{}
	// pending carries a split header block's tail between test steps.
	pending []byte
}

// startIdleServer starts a ServerRole Layer with the given options, sends the
// client SETTINGS, and starts the background frame reader. started is taken
// just before New, so it is no later than the Layer's own idle-clock start.
func startIdleServer(t *testing.T, opts ...Option) (l *Layer, p *idlePeer, started time.Time) {
	t.Helper()
	started = time.Now()
	l, peer, cleanup := startServerLayer(t, opts...)
	t.Cleanup(cleanup)
	p = &idlePeer{h2Peer: peer, t: t, frames: make(chan *frame.Frame, 256), eof: make(chan struct{})}
	go func() {
		defer close(p.eof)
		for {
			f, err := p.rd.ReadFrame()
			if err != nil {
				return
			}
			p.frames <- f
		}
	}()
	if err := p.wr.WriteSettings(nil); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	return l, p, started
}

// nextGoAway waits for the next GOAWAY frame, returning it and its arrival
// time. Non-GOAWAY frames are passed to onOther (may be nil).
func (p *idlePeer) nextGoAway(within time.Duration, onOther func(*frame.Frame)) (*frame.Frame, time.Time) {
	p.t.Helper()
	timer := time.NewTimer(within)
	defer timer.Stop()
	for {
		select {
		case f := <-p.frames:
			if f.Header.Type == frame.TypeGoAway {
				return f, time.Now()
			}
			if onOther != nil {
				onOther(f)
			}
		case <-p.eof:
			// Drain frames buffered before EOF.
			select {
			case f := <-p.frames:
				if f.Header.Type == frame.TypeGoAway {
					return f, time.Now()
				}
				if onOther != nil {
					onOther(f)
				}
				continue
			default:
			}
			p.t.Fatalf("connection closed without GOAWAY")
			return nil, time.Time{}
		case <-timer.C:
			p.t.Fatalf("no GOAWAY within %v", within)
			return nil, time.Time{}
		}
	}
}

// expectNoGoAway consumes frames for d and fails on a GOAWAY or EOF.
// Non-GOAWAY frames are passed to onOther (may be nil).
func (p *idlePeer) expectNoGoAway(d time.Duration, onOther func(*frame.Frame)) {
	p.t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case f := <-p.frames:
			if f.Header.Type == frame.TypeGoAway {
				last, code, _, _ := f.GoAwayInfo()
				p.t.Fatalf("unexpected GOAWAY(%s, last=%d)", ErrCodeString(code), last)
			}
			if onOther != nil {
				onOther(f)
			}
		case <-p.eof:
			p.t.Fatalf("connection closed unexpectedly")
		case <-timer.C:
			return
		}
	}
}

// awaitEOF consumes frames until the Layer closes the connection, passing
// each to onFrame (may be nil).
func (p *idlePeer) awaitEOF(within time.Duration, onFrame func(*frame.Frame)) {
	p.t.Helper()
	timer := time.NewTimer(within)
	defer timer.Stop()
	for {
		select {
		case f := <-p.frames:
			if onFrame != nil {
				onFrame(f)
			}
		case <-p.eof:
			for {
				select {
				case f := <-p.frames:
					if onFrame != nil {
						onFrame(f)
					}
				default:
					return
				}
			}
		case <-timer.C:
			p.t.Fatalf("connection not closed within %v", within)
		}
	}
}

// ping writes a PING and waits for its ACK, failing on GOAWAY / EOF.
func (p *idlePeer) ping(data [8]byte) {
	p.t.Helper()
	if err := p.wr.WritePing(false, data); err != nil {
		p.t.Fatalf("write PING: %v", err)
	}
	timer := time.NewTimer(idleTestWait)
	defer timer.Stop()
	for {
		select {
		case f := <-p.frames:
			if f.Header.Type == frame.TypeGoAway {
				p.t.Fatalf("GOAWAY while waiting for PING ACK")
			}
			if f.Header.Type == frame.TypePing && f.Header.Flags.Has(frame.FlagAck) {
				if got, _ := f.PingData(); got == data {
					return
				}
			}
		case <-p.eof:
			p.t.Fatalf("connection closed while waiting for PING ACK")
		case <-timer.C:
			p.t.Fatalf("no PING ACK")
		}
	}
}

// waitStreamEnd consumes frames until the Layer has ended stream sid
// (HEADERS / DATA with END_STREAM, or RST_STREAM), failing on GOAWAY.
func (p *idlePeer) waitStreamEnd(sid uint32) {
	p.t.Helper()
	timer := time.NewTimer(idleTestWait)
	defer timer.Stop()
	for {
		select {
		case f := <-p.frames:
			if f.Header.Type == frame.TypeGoAway {
				p.t.Fatalf("GOAWAY while waiting for stream %d to end", sid)
			}
			if f.Header.StreamID != sid {
				continue
			}
			switch f.Header.Type {
			case frame.TypeRSTStream:
				return
			case frame.TypeHeaders, frame.TypeData:
				if f.Header.Flags.Has(frame.FlagEndStream) {
					return
				}
			}
		case <-p.eof:
			p.t.Fatalf("connection closed while waiting for stream %d to end", sid)
		case <-timer.C:
			p.t.Fatalf("stream %d did not end", sid)
		}
	}
}

var idleTestRequest = []hpack.HeaderField{
	{Name: ":method", Value: "GET"},
	{Name: ":scheme", Value: "https"},
	{Name: ":path", Value: "/"},
	{Name: ":authority", Value: "example.com"},
}

// acceptChannel returns the next Channel the Layer emits.
func acceptIdleChannel(t *testing.T, l *Layer) *channel {
	t.Helper()
	select {
	case ch, ok := <-l.Channels():
		if !ok {
			t.Fatal("Channels() closed")
		}
		return ch.(*channel)
	case <-time.After(idleTestWait):
		t.Fatal("no Channel emitted")
	}
	return nil
}

// respond sends a bodyless 200 HEADERS(END_STREAM) on ch.
func respond(t *testing.T, ch *channel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), idleTestWait)
	defer cancel()
	if err := ch.Send(ctx, &envelope.Envelope{
		Direction: envelope.Receive,
		Message:   &H2HeadersEvent{Status: 200, EndStream: true},
	}); err != nil {
		t.Fatalf("Send response: %v", err)
	}
}

// nextEnvelope reads the next envelope from ch.
func nextEnvelope(t *testing.T, ch *channel) *envelope.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), idleTestWait)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return env
}

// serveGET runs one complete bodyless GET on sid and returns when the
// response END_STREAM has reached the peer.
func serveGET(t *testing.T, l *Layer, p *idlePeer, sid uint32) {
	t.Helper()
	if err := p.wr.WriteHeaders(sid, true, true, p.encoder.Encode(idleTestRequest)); err != nil {
		t.Fatalf("write HEADERS(%d): %v", sid, err)
	}
	ch := acceptIdleChannel(t, l)
	nextEnvelope(t, ch)
	respond(t, ch)
	_ = ch.Close()
	p.waitStreamEnd(sid)
}

// assertIdleGoAway checks f is GOAWAY(NO_ERROR, wantLast).
func assertIdleGoAway(t *testing.T, f *frame.Frame, wantLast uint32) {
	t.Helper()
	last, code, _, err := f.GoAwayInfo()
	if err != nil {
		t.Fatalf("GoAwayInfo: %v", err)
	}
	if code != ErrCodeNo {
		t.Errorf("GOAWAY code = %s, want NO_ERROR", ErrCodeString(code))
	}
	if last != wantLast {
		t.Errorf("GOAWAY last_stream_id = %d, want %d", last, wantLast)
	}
}

// assertNotEarly fails when the GOAWAY arrived sooner than idleTestLower
// after the idle period began at since.
func assertNotEarly(t *testing.T, since, at time.Time) {
	t.Helper()
	if el := at.Sub(since); el < idleTestLower {
		t.Errorf("GOAWAY %v after the idle period began, want >= %v (bound %v)", el, idleTestLower, idleTestBound)
	}
}

// countGoAwaysUntilEOF counts the remaining GOAWAY frames until EOF.
func (p *idlePeer) countGoAwaysUntilEOF() int {
	p.t.Helper()
	n := 0
	p.awaitEOF(idleTestWait, func(f *frame.Frame) {
		if f.Header.Type == frame.TypeGoAway {
			n++
		}
	})
	return n
}

// Test Plan #1: a connection that never opens a stream receives exactly one
// GOAWAY(NO_ERROR, last=0) about one bound after it started, then EOF. With
// streams 1 and 3 completed first, last_stream_id is 3.
func TestLayer_ClientIdleTimeout_NoStreams_GoAwayThenClose(t *testing.T) {
	tests := []struct {
		name     string
		streams  []uint32
		wantLast uint32
	}{
		{name: "never used", wantLast: 0},
		{name: "after streams 1 and 3", streams: []uint32{1, 3}, wantLast: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, p, started := startIdleServer(t,
				WithClientIdleTimeout(fixedIdle(idleTestBound)),
				withIdleGoAwayLinger(idleTestLinger))
			since := started
			for _, sid := range tt.streams {
				serveGET(t, l, p, sid)
				since = time.Now()
			}
			f, at := p.nextGoAway(idleTestWait, nil)
			assertIdleGoAway(t, f, tt.wantLast)
			assertNotEarly(t, since, at)
			if n := p.countGoAwaysUntilEOF(); n != 0 {
				t.Errorf("%d further GOAWAY frames after the idle GOAWAY, want 0", n)
			}
		})
	}
}

// Test Plan #2: the idle clock starts when the last stream closes, not when
// the connection started.
func TestLayer_ClientIdleTimeout_ClockFromLastStreamClose(t *testing.T) {
	l, p, _ := startIdleServer(t,
		WithClientIdleTimeout(fixedIdle(idleTestBound)),
		withIdleGoAwayLinger(idleTestLinger))

	if err := p.wr.WriteHeaders(1, true, true, p.encoder.Encode(idleTestRequest)); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
	ch := acceptIdleChannel(t, l)
	nextEnvelope(t, ch)
	// Hold the stream open for 0.8 of the bound, then finish it.
	p.expectNoGoAway(idleTestBound*8/10, nil)
	respond(t, ch)
	_ = ch.Close()
	p.waitStreamEnd(1)
	closed := time.Now()

	f, at := p.nextGoAway(idleTestWait, nil)
	assertIdleGoAway(t, f, 1)
	assertNotEarly(t, closed, at)
}

// Test Plan #3: PINGs do not extend the idle deadline: a peer pinging every
// bound/6 still gets GOAWAY.
func TestLayer_ClientIdleTimeout_PingDoesNotExtend(t *testing.T) {
	_, p, started := startIdleServer(t,
		WithClientIdleTimeout(fixedIdle(idleTestBound)),
		withIdleGoAwayLinger(idleTestLinger))

	deadline := time.Now().Add(idleTestWait)
	acks := 0
	var goAway *frame.Frame
	var at time.Time
	for i := 0; goAway == nil; i++ {
		if time.Now().After(deadline) {
			t.Fatalf("no GOAWAY within %v while pinging (%d PING ACKs)", idleTestWait, acks)
		}
		data := [8]byte{'i', 'd', 'l', 'e', byte(i)}
		if err := p.wr.WritePing(false, data); err != nil {
			t.Fatalf("write PING %d: %v (acks=%d)", i, err, acks)
		}
		tick := time.NewTimer(idleTestBound / 6)
	wait:
		for {
			select {
			case f := <-p.frames:
				switch {
				case f.Header.Type == frame.TypeGoAway:
					goAway, at = f, time.Now()
					break wait
				case f.Header.Type == frame.TypePing && f.Header.Flags.Has(frame.FlagAck):
					acks++
				}
			case <-p.eof:
				t.Fatalf("connection closed without GOAWAY (acks=%d)", acks)
			case <-tick.C:
				break wait
			}
		}
		tick.Stop()
	}
	if acks < 2 {
		t.Errorf("only %d PING ACKs before GOAWAY; PINGs were not exercised", acks)
	}
	assertIdleGoAway(t, goAway, 0)
	assertNotEarly(t, started, at)
}

// Test Plan #4: a stream that stays open (half-closed remote awaiting a
// response, fully open request body, or a detached extended-CONNECT tunnel)
// keeps the connection alive past the bound; once it finishes, GOAWAY
// follows about one bound later.
func TestLayer_ClientIdleTimeout_LongOpenStreamNotClosed(t *testing.T) {
	tests := []struct {
		name string
		// open opens stream 1 and returns the func that finishes it.
		open func(t *testing.T, l *Layer, p *idlePeer) (finish func())
	}{
		{
			name: "half-closed remote, response pending",
			open: func(t *testing.T, l *Layer, p *idlePeer) func() {
				if err := p.wr.WriteHeaders(1, true, true, p.encoder.Encode(idleTestRequest)); err != nil {
					t.Fatalf("write HEADERS: %v", err)
				}
				ch := acceptIdleChannel(t, l)
				nextEnvelope(t, ch)
				return func() {
					respond(t, ch)
					_ = ch.Close()
					p.waitStreamEnd(1)
				}
			},
		},
		{
			name: "open, request body pending",
			open: func(t *testing.T, l *Layer, p *idlePeer) func() {
				post := []hpack.HeaderField{
					{Name: ":method", Value: "POST"},
					{Name: ":scheme", Value: "https"},
					{Name: ":path", Value: "/stream"},
					{Name: ":authority", Value: "example.com"},
				}
				if err := p.wr.WriteHeaders(1, false, true, p.encoder.Encode(post)); err != nil {
					t.Fatalf("write HEADERS: %v", err)
				}
				ch := acceptIdleChannel(t, l)
				nextEnvelope(t, ch)
				return func() {
					if err := p.wr.WriteData(1, true, []byte("end")); err != nil {
						t.Fatalf("write DATA: %v", err)
					}
					nextEnvelope(t, ch)
					respond(t, ch)
					_ = ch.Close()
					p.waitStreamEnd(1)
				}
			},
		},
		{
			name: "extended CONNECT detached",
			open: func(t *testing.T, l *Layer, p *idlePeer) func() {
				connect := []hpack.HeaderField{
					{Name: ":method", Value: "CONNECT"},
					{Name: ":scheme", Value: "https"},
					{Name: ":authority", Value: "example.com"},
					{Name: ":path", Value: "/chat"},
					{Name: ":protocol", Value: "websocket"},
				}
				if err := p.wr.WriteHeaders(1, false, true, p.encoder.Encode(connect)); err != nil {
					t.Fatalf("write HEADERS: %v", err)
				}
				ch := acceptIdleChannel(t, l)
				nextEnvelope(t, ch)
				ctx, cancel := context.WithTimeout(context.Background(), idleTestWait)
				defer cancel()
				if err := ch.Send(ctx, &envelope.Envelope{
					Direction: envelope.Receive,
					Message:   &H2HeadersEvent{Status: 200},
				}); err != nil {
					t.Fatalf("Send 200: %v", err)
				}
				_, _, closer, err := l.DetachStream(1)
				if err != nil {
					t.Fatalf("DetachStream: %v", err)
				}
				return func() {
					_ = closer()
					p.waitStreamEnd(1)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, p, _ := startIdleServer(t,
				WithClientIdleTimeout(fixedIdle(idleTestBound)),
				withIdleGoAwayLinger(idleTestLinger))
			finish := tt.open(t, l, p)
			p.expectNoGoAway(3*idleTestBound, nil)
			p.ping([8]byte{'a', 'l', 'i', 'v', 'e'})
			finish()
			closed := time.Now()
			f, at := p.nextGoAway(idleTestWait, nil)
			assertIdleGoAway(t, f, 1)
			assertNotEarly(t, closed, at)
		})
	}
}

// Test Plan #5: a new stream's header block still waiting for CONTINUATION
// keeps the connection alive; once completed the stream is served.
func TestLayer_ClientIdleTimeout_HeaderBlockInProgress(t *testing.T) {
	l, p, _ := startIdleServer(t,
		WithClientIdleTimeout(fixedIdle(idleTestBound)),
		withIdleGoAwayLinger(idleTestLinger))

	block := p.encoder.Encode(idleTestRequest)
	half := len(block) / 2
	if err := p.wr.WriteHeaders(1, true, false, block[:half]); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
	p.expectNoGoAway(3*idleTestBound, nil)
	if err := p.wr.WriteContinuation(1, true, block[half:]); err != nil {
		t.Fatalf("write CONTINUATION: %v", err)
	}
	ch := acceptIdleChannel(t, l)
	env := nextEnvelope(t, ch)
	if evt, ok := env.Message.(*H2HeadersEvent); !ok || evt.Method != "GET" {
		t.Fatalf("first envelope = %T %+v, want GET headers", env.Message, env.Message)
	}
	respond(t, ch)
	_ = ch.Close()
	p.waitStreamEnd(1)
	f, _ := p.nextGoAway(idleTestWait, nil)
	assertIdleGoAway(t, f, 1)
}

// gate pauses the reader hook for one stream id until released.
type gate struct {
	sid     uint32
	reached chan struct{}
	release chan struct{}
	once    sync.Once
	relOnce sync.Once
}

func newGate(sid uint32) *gate {
	return &gate{sid: sid, reached: make(chan struct{}), release: make(chan struct{})}
}

// open releases the hook; idempotent. Register it with t.Cleanup after the
// Layer's own cleanup so a failing test never leaves the reader parked
// (Close waits for the reader).
func (g *gate) open() { g.relOnce.Do(func() { close(g.release) }) }

func (g *gate) hook(sid uint32) {
	if sid != g.sid {
		return
	}
	g.once.Do(func() { close(g.reached) })
	<-g.release
}

func (g *gate) waitReached(t *testing.T) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(idleTestWait):
		t.Fatalf("reader did not reach the hook for stream %d", g.sid)
	}
}

// Test Plan #6: a new stream whose HEADERS races the deadline and loses
// (GOAWAY(last=1) is sent first) is ignored: no Channel, no RST_STREAM or
// response, and no connection error — whether the request is one HEADERS,
// a HEADERS + CONTINUATION, or HEADERS + DATA + trailers. DATA on it still
// has its connection flow-control window returned.
func TestLayer_ClientIdleTimeout_StreamAfterGoAwayIgnored(t *testing.T) {
	post := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/late"},
		{Name: ":authority", Value: "example.com"},
	}
	tests := []struct {
		name string
		// first is the frame the reader pauses on; rest is written once
		// the reader is paused (it blocks until the reader resumes).
		first    func(p *idlePeer) error
		rest     func(p *idlePeer) error
		wantConn uint32 // connection WINDOW_UPDATE increment expected
	}{
		{
			name:  "HEADERS",
			first: func(p *idlePeer) error { return p.wr.WriteHeaders(3, true, true, p.encoder.Encode(idleTestRequest)) },
			rest:  func(*idlePeer) error { return nil },
		},
		{
			name: "HEADERS + CONTINUATION",
			first: func(p *idlePeer) error {
				block := p.encoder.Encode(idleTestRequest)
				if err := p.wr.WriteHeaders(3, true, false, block[:len(block)/2]); err != nil {
					return err
				}
				// Stash the rest for the CONTINUATION.
				p.pending = block[len(block)/2:]
				return nil
			},
			rest: func(p *idlePeer) error { return p.wr.WriteContinuation(3, true, p.pending) },
		},
		{
			name:  "HEADERS + DATA + trailers",
			first: func(p *idlePeer) error { return p.wr.WriteHeaders(3, false, true, p.encoder.Encode(post)) },
			rest: func(p *idlePeer) error {
				if err := p.wr.WriteData(3, false, []byte("0123456789")); err != nil {
					return err
				}
				return p.wr.WriteHeaders(3, true, true, p.encoder.Encode([]hpack.HeaderField{{Name: "x-trailer", Value: "1"}}))
			},
			wantConn: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGate(3)
			l, p, _ := startIdleServer(t,
				WithClientIdleTimeout(fixedIdle(idleTestBound)),
				withIdleGoAwayLinger(time.Second),
				withBeforeAcceptPeerStream(g.hook))
			t.Cleanup(g.open)
			serveGET(t, l, p, 1)

			if err := tt.first(p); err != nil {
				t.Fatalf("write first frame: %v", err)
			}
			g.waitReached(t)

			f, _ := p.nextGoAway(idleTestWait, nil)
			assertIdleGoAway(t, f, 1)

			restErr := make(chan error, 1)
			go func() {
				err := tt.rest(p)
				if err == nil {
					// A PING after the late frames proves the reader
					// processed them before the connection closes.
					err = p.wr.WritePing(false, [8]byte{'l', 'a', 't', 'e'})
				}
				restErr <- err
			}()
			g.open()

			var connWU uint32
			sawAck := false
			p.awaitEOF(idleTestWait, func(f *frame.Frame) {
				switch {
				case f.Header.Type == frame.TypeGoAway:
					last, code, _, _ := f.GoAwayInfo()
					t.Errorf("second GOAWAY(%s, last=%d)", ErrCodeString(code), last)
				case f.Header.StreamID == 3:
					t.Errorf("frame %v on stream 3, which is above GOAWAY last_stream_id", f.Header.Type)
				case f.Header.Type == frame.TypeWindowUpdate && f.Header.StreamID == 0:
					inc, _ := f.WindowUpdateIncrement()
					connWU += inc
				case f.Header.Type == frame.TypePing && f.Header.Flags.Has(frame.FlagAck):
					sawAck = true
				}
			})
			if err := <-restErr; err != nil {
				t.Fatalf("write late frames: %v", err)
			}
			if !sawAck {
				t.Error("no PING ACK after the late frames; the reader did not process them")
			}
			if connWU != tt.wantConn {
				t.Errorf("connection WINDOW_UPDATE total = %d, want %d", connWU, tt.wantConn)
			}
			var ce *ConnError
			if err := l.LastReaderError(); errors.As(err, &ce) {
				t.Errorf("LastReaderError = %v, want no connection error from the late frames", err)
			}
			for ch := range l.Channels() {
				t.Errorf("stream %d reached Channels() after GOAWAY", ch.(*channel).H2StreamID())
			}
		})
	}
}

// Test Plan #7: a new stream already registered when the deadline passes
// (reader paused between registration and the open transition) wins: no
// GOAWAY while it is pending or open, it is served, and GOAWAY(last=3)
// follows about one bound after it closes.
func TestLayer_ClientIdleTimeout_StreamRegisteredBeforeDeadlineWins(t *testing.T) {
	g := newGate(3)
	l, p, _ := startIdleServer(t,
		WithClientIdleTimeout(fixedIdle(idleTestBound)),
		withIdleGoAwayLinger(idleTestLinger),
		withAfterRegisterPeerStream(g.hook))
	t.Cleanup(g.open)
	serveGET(t, l, p, 1)

	if err := p.wr.WriteHeaders(3, true, true, p.encoder.Encode(idleTestRequest)); err != nil {
		t.Fatalf("write HEADERS(3): %v", err)
	}
	g.waitReached(t)
	p.expectNoGoAway(idleTestBound*3/2, nil)
	g.open()

	ch := acceptIdleChannel(t, l)
	nextEnvelope(t, ch)
	p.expectNoGoAway(idleTestBound*3/2, nil)
	respond(t, ch)
	_ = ch.Close()
	p.waitStreamEnd(3)
	closed := time.Now()

	f, at := p.nextGoAway(idleTestWait, nil)
	assertIdleGoAway(t, f, 3)
	assertNotEarly(t, closed, at)
}

// Test Plan #8: a disabled bound (resolver ok=false) and no option at all
// never close the connection; it stays usable.
func TestLayer_ClientIdleTimeout_Disabled(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{name: "resolver disabled", opts: []Option{
			WithClientIdleTimeout(func() (time.Duration, bool) { return 0, false }),
			withIdleGoAwayLinger(idleTestLinger),
		}},
		{name: "no option", opts: []Option{withIdleGoAwayLinger(idleTestLinger)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, p, _ := startIdleServer(t, tt.opts...)
			p.expectNoGoAway(3*idleTestBound, nil)
			serveGET(t, l, p, 1)
			p.expectNoGoAway(3*idleTestBound, nil)
			p.ping([8]byte{'u', 's', 'a', 'b', 'l', 'e'})
		})
	}
}

// Test Plan #9a: Close() during the post-GOAWAY linger sends no second
// GOAWAY.
func TestLayer_ClientIdleTimeout_CloseAfterIdleGoAwayNoDuplicate(t *testing.T) {
	l, p, _ := startIdleServer(t,
		WithClientIdleTimeout(fixedIdle(idleTestBound)),
		withIdleGoAwayLinger(10*time.Second))
	f, _ := p.nextGoAway(idleTestWait, nil)
	assertIdleGoAway(t, f, 0)

	closeDone := make(chan error, 1)
	go func() { closeDone <- l.Close() }()
	if n := p.countGoAwaysUntilEOF(); n != 0 {
		t.Errorf("Close() after the idle GOAWAY wrote %d more GOAWAY frames, want 0", n)
	}
	select {
	case <-closeDone:
	case <-time.After(idleTestWait):
		t.Fatal("Close() did not return")
	}
}

// Test Plan #9b: Close() before the deadline stops the idle goroutine.
func TestLayer_ClientIdleTimeout_CloseBeforeDeadlineNoLeak(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	cliConn, srvConn := net.Pipe()
	go func() {
		_, _ = cliConn.Write([]byte(ClientPreface))
		_, _ = io.Copy(io.Discard, cliConn)
	}()
	l, err := New(srvConn, "idle-leak", ServerRole, WithClientIdleTimeout(fixedIdle(time.Hour)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = l.Close()
	_ = cliConn.Close()
	if err := goleak.Find(ignore); err != nil {
		t.Fatalf("goroutines leaked after Close: %v", err)
	}
}

// Added: the idle GOAWAY is not issued on a ClientRole
// Layer even when the option is passed.
func TestLayer_ClientIdleTimeout_IgnoredOnClientRole(t *testing.T) {
	l, peer, cleanup := startClientLayer(t,
		WithClientIdleTimeout(fixedIdle(idleTestBound)),
		withIdleGoAwayLinger(idleTestLinger))
	defer cleanup()
	peer.consumePeerSettings(t)
	_ = peer.conn.SetReadDeadline(time.Now().Add(3 * idleTestBound))
	for {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("ReadFrame: %v", err)
			}
			break
		}
		if f.Header.Type == frame.TypeGoAway {
			t.Fatal("ClientRole Layer sent an idle GOAWAY")
		}
	}
	if l.IsShutdown() {
		t.Fatal("ClientRole Layer shut down by the idle bound")
	}
}
