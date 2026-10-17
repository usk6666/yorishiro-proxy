package http1

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// withAfterInitialYieldForTest installs the USK-1184 test seam: fn runs in
// the Send-direction goroutine of New right after the initial deferred-parse
// Channel has been handed to Channels(), before the goroutine waits for that
// Channel to terminate. Sibling of http2's withAfterLoopsStartHook (USK-1138).
func withAfterInitialYieldForTest(fn func()) Option {
	return func(o *options) { o.afterInitialYield = fn }
}

// probeConn wraps the Layer's net.Conn to observe the parser's reads without
// adding ordering edges after a read returns:
//   - firstRead is closed when the first Read is entered. The close happens
//     BEFORE the parser writes anything that depends on that read, so a
//     receiver of firstRead is not ordered after those writes.
//   - inFlight / maxInFlight count concurrent Read calls on the conn, which
//     exposes a second parser running on the same bufio.Reader.
//   - errDelay makes a failing Read sleep before returning its error. It is a
//     plain sleep, not a signal: it keeps the reading goroutine's follow-up
//     writes (parseFailed, termMu acquisition) behind a concurrent
//     Layer.Close without creating the happens-before edge that would hide
//     the race from the detector.
type probeConn struct {
	net.Conn
	firstRead   chan struct{}
	firstOnce   sync.Once
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	errDelay    time.Duration
}

func newProbeConn(c net.Conn, errDelay time.Duration) *probeConn {
	return &probeConn{Conn: c, firstRead: make(chan struct{}), errDelay: errDelay}
}

func (c *probeConn) Read(p []byte) (int, error) {
	n := c.inFlight.Add(1)
	for {
		m := c.maxInFlight.Load()
		if n <= m || c.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	c.firstOnce.Do(func() { close(c.firstRead) })
	rn, err := c.Conn.Read(p)
	c.inFlight.Add(-1)
	if err != nil && c.errDelay > 0 {
		time.Sleep(c.errDelay)
	}
	return rn, err
}

func waitSignal(t *testing.T, sig <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-sig:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitNext(t *testing.T, res <-chan nextResult, d time.Duration, what string) nextResult {
	t.Helper()
	select {
	case r := <-res:
		return r
	case <-time.After(d):
		t.Fatalf("%s: Next did not return within %v", what, d)
		return nextResult{}
	}
}

func drainChannels(t *testing.T, l *Layer) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-l.Channels():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("Channels() did not close after Layer.Close")
		}
	}
}

// TestLayer_CloseDuringInitialDeferredParse_NoFlagRace pins the USK-1184
// race: Layer.Close (production: ConnectionStack.Close from a ctx watcher in
// proxybuild) lands while the initial Channel's deferred parse is blocked in
// conn.Read. Layer.Close fires the initial Channel's termDone via
// active.markTerminated, so the New goroutine wakes and reads parseFailed /
// connClosed while the Next goroutine — unblocked by conn.Close — writes
// parseFailed. Nothing orders the two: the writer's own markTerminated is a
// no-op once Layer.Close won termOnce.
//
// The hook parks the New goroutine until the parse is inside conn.Read and
// Layer.Close has returned, so its select sees termDone and l.closed ready
// together; select picks at random, hence the iterations. The assertion is
// the race detector (make test runs -race).
func TestLayer_CloseDuringInitialDeferredParse_NoFlagRace(t *testing.T) {
	const iterations = 64
	for i := 0; i < iterations; i++ {
		runCloseDuringInitialParse(t)
	}
}

func runCloseDuringInitialParse(t *testing.T) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()

	probe := newProbeConn(server, 5*time.Millisecond)
	release := make(chan struct{})
	var releaseOnce sync.Once
	doRelease := func() { releaseOnce.Do(func() { close(release) }) }
	defer doRelease()

	l := New(probe, "conn-t1", envelope.Send,
		withAfterInitialYieldForTest(func() { <-release }))
	defer l.Close()

	ch := <-l.Channels()
	res := nextAsync(ch)
	waitSignal(t, probe.firstRead, "deferred parse to enter conn.Read")

	_ = l.Close()
	doRelease()

	r := waitNext(t, res, 2*time.Second, "initial deferred Next after Layer.Close")
	if r.err == nil {
		t.Fatalf("Next after Layer.Close: got envelope %+v, want an error", r.env)
	}
	drainChannels(t, l)
}

// TestChannel_CloseDuringDeferredParse_NoSecondParser pins the contract
// hardening half of USK-1184: Channel.Close on the initial Channel while its
// deferred Next is still parsing must not hand the bufio.Reader to the spawn
// loop. Before the fix, Close released the reader and fired termDone, the
// New goroutine saw no terminal flag and started spawnLoopSend, whose
// parseRequest issued a second concurrent conn.Read on the same reader.
func TestChannel_CloseDuringDeferredParse_NoSecondParser(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	probe := newProbeConn(server, 0)
	l := New(probe, "conn-t2", envelope.Send)
	defer l.Close()

	ch := <-l.Channels()
	res := nextAsync(ch)
	waitSignal(t, probe.firstRead, "deferred parse to enter conn.Read")

	_ = ch.Close()

	// Give a wrongly started spawn loop time to reach conn.Read.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && probe.maxInFlight.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := probe.maxInFlight.Load(); got != 1 {
		t.Errorf("concurrent conn.Read calls after Channel.Close = %d, want 1 (a second parser started on the shared reader)", got)
	}

	req := "GET /t2 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	go func() { _, _ = client.Write([]byte(req)) }()

	r := waitNext(t, res, 2*time.Second, "in-flight deferred Next")
	if r.err != nil {
		t.Fatalf("in-flight deferred Next: err = %v, want the request", r.err)
	}
	msg, ok := r.env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type = %T, want *envelope.HTTPMessage", r.env.Message)
	}
	if msg.Method != "GET" || msg.Path != "/t2" {
		t.Errorf("request = %s %s, want GET /t2", msg.Method, msg.Path)
	}
}

// TestChannel_NextAfterClose_DeferredReturnsErrWithoutParsing pins that a
// deferred Next on an already-closed initial Channel returns the terminal
// error (Err) instead of starting a parse. Closing the initial Channel
// before any Next hands the reader to the spawn loop, which owns the next
// request; a late Next on the closed Channel would otherwise park a second
// parser on the shared reader.
func TestChannel_NextAfterClose_DeferredReturnsErrWithoutParsing(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	l := New(server, "conn-t3", envelope.Send)
	defer l.Close()

	ch := <-l.Channels()
	_ = ch.Close()

	req := "GET /t3 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	go func() { _, _ = client.Write([]byte(req)) }()

	ch2 := recvChannel(t, l, 2*time.Second)
	r2 := waitNext(t, nextAsync(ch2), 2*time.Second, "spawn-loop Channel")
	if r2.err != nil {
		t.Fatalf("spawn-loop Next: %v", r2.err)
	}
	if msg, ok := r2.env.Message.(*envelope.HTTPMessage); !ok || msg.Path != "/t3" {
		t.Fatalf("spawn-loop Next message = %+v, want path /t3", r2.env.Message)
	}

	r := waitNext(t, nextAsync(ch), time.Second, "Next on the closed initial Channel")
	if !errors.Is(r.err, io.EOF) {
		t.Errorf("Next on closed initial Channel: err = %v, want io.EOF", r.err)
	}
	if r.env != nil {
		t.Errorf("Next on closed initial Channel: env = %+v, want nil", r.env)
	}
	if !errors.Is(ch.Err(), io.EOF) {
		t.Errorf("Err() = %v, want io.EOF", ch.Err())
	}
}

// TestLayer_CloseDuringBodyRead_NoStreamIDRace pins the currentStreamID half
// of USK-1184: parseRequest mints currentStreamID on the parsing goroutine
// once the request head is parsed, then blocks reading the body. Layer.Close
// on another goroutine runs active.markTerminated → releaseStreamState, which
// reads currentStreamID. Covered for the initial deferred-parse Channel and
// for a spawn-loop (second keep-alive) Channel.
//
// Deliberately no signal from the parsing goroutine to the closer: the
// test sleeps, because any channel or atomic hand-off from the writer side
// would add the ordering edge that hides the race. The assertion is the race
// detector; the ReleaseStream count proves the read actually happened.
func TestLayer_CloseDuringBodyRead_NoStreamIDRace(t *testing.T) {
	const partialPost = "POST /t4 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nab"

	tests := []struct {
		name     string
		keepWarm bool // serve one complete request first so the spawn loop parses the partial one
	}{
		{name: "initial deferred-parse channel", keepWarm: false},
		{name: "spawn-loop channel", keepWarm: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()

			rec := &recordingReleaser{}
			probe := newProbeConn(server, 50*time.Millisecond)
			l := New(probe, "conn-t4", envelope.Send,
				WithEnvelopeContext(envelope.EnvelopeContext{ConnID: "conn-t4"}),
				WithStateReleaser(rec),
			)
			defer l.Close()

			ch := <-l.Channels()
			if tt.keepWarm {
				first := "GET /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
				go func() { _, _ = client.Write([]byte(first)) }()
				r := waitNext(t, nextAsync(ch), 2*time.Second, "first keep-alive request")
				if r.err != nil {
					t.Fatalf("first Next: %v", r.err)
				}
				_ = ch.Close()
			}

			var res <-chan nextResult
			if !tt.keepWarm {
				res = nextAsync(ch)
			}
			go func() { _, _ = client.Write([]byte(partialPost)) }()

			// Let the parser mint currentStreamID and park on the body read.
			time.Sleep(100 * time.Millisecond)
			streamsBefore := rec.streamCount()
			_ = l.Close()

			if res != nil {
				r := waitNext(t, res, 2*time.Second, "deferred Next after Layer.Close")
				if r.err == nil {
					t.Fatalf("Next after Layer.Close: got envelope, want an error")
				}
			}
			drainChannels(t, l)

			if got := rec.streamCount() - streamsBefore; got != 1 {
				t.Errorf("ReleaseStream calls for the in-flight exchange = %d, want 1", got)
			}
		})
	}
}
