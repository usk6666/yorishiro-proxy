package http2

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1180: Layer.Close must not park forever enqueueing its GOAWAY when the
// writer queue is full. The wedge is built from real producers only:
//
//   - the writer is stuck in a socket write because the peer stopped
//     reading (net.Pipe has no buffer, so the first frame written after the
//     peer pauses blocks);
//   - the reader keeps enqueueing two WINDOW_UPDATEs per DATA frame the peer
//     sends (maybeWindowUpdate) until writerQueue is full, after which the
//     reader itself parks in enqueueWrite.
//
// Until USK-1166 the writer could also be stuck waiting for flow-control
// window; that wedge no longer exists (the writer parks DATA per stream and
// keeps serving the queue — see writer_flowcontrol_test.go), so the stuck
// writer is now produced by the one cause that remains: a peer that does
// not read.

const closeFullQueueBound = 2 * time.Second

// closeProbeFrame is a summary of one frame the Layer wrote to the peer.
type closeProbeFrame struct {
	typ      frame.Type
	streamID uint32
	flags    frame.Flags
	n        int
}

// startCloseProbeReader reads every frame the Layer writes so net.Pipe never
// back-pressures the writer for any reason other than flow control. The
// goroutine exits when the pipe closes.
func startCloseProbeReader(peer *h2Peer) <-chan closeProbeFrame {
	out := make(chan closeProbeFrame, 4096)
	go func() {
		defer close(out)
		for {
			f, err := peer.rd.ReadFrame()
			if err != nil {
				return
			}
			out <- closeProbeFrame{typ: f.Header.Type, streamID: f.Header.StreamID, flags: f.Header.Flags, n: int(f.Header.Length)}
		}
	}()
	return out
}

// startPausableProbeReader is startCloseProbeReader with a pause: after
// pause() the goroutine stops reading (it may finish the frame it is
// currently reading) and exits, so the Layer's next socket write blocks.
func startPausableProbeReader(peer *h2Peer) (frames <-chan closeProbeFrame, pause func()) {
	out := make(chan closeProbeFrame, 4096)
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(out)
		for {
			select {
			case <-stop:
				return
			default:
			}
			f, err := peer.rd.ReadFrame()
			if err != nil {
				return
			}
			out <- closeProbeFrame{typ: f.Header.Type, streamID: f.Header.StreamID, flags: f.Header.Flags, n: int(f.Header.Length)}
		}
	}()
	return out, func() { once.Do(func() { close(stop) }) }
}

// drainCloseProbeFrames discards frames for d.
func drainCloseProbeFrames(frames <-chan closeProbeFrame, d time.Duration) {
	deadline := time.After(d)
	for {
		select {
		case <-frames:
		case <-deadline:
			return
		}
	}
}

// sendAsyncEnv sends msg on ch from a goroutine and reports the result. The
// context is bounded so the goroutine terminates even if the Layer wedges.
func sendAsyncEnv(ch layer.Channel, msg envelope.Message) <-chan error {
	errc := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		errc <- ch.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: msg})
	}()
	return errc
}

// drainChannel consumes ch until it errors, so receive-side delivery never
// back-pressures the reader goroutine.
func drainChannel(ch layer.Channel) {
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := ch.Next(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}()
}

// floodData writes HEADERS (if hdr is non-nil) and then n small DATA frames
// on streamID from the peer side. It never sends a WINDOW_UPDATE for the
// stream the Layer's writer is blocked on.
func floodData(peer *h2Peer, streamID uint32, hdr []byte, endHeaders bool, n int) <-chan error {
	done := make(chan error, 1)
	go func() {
		if hdr != nil {
			if err := peer.wr.WriteHeaders(streamID, false, endHeaders, hdr); err != nil {
				done <- err
				return
			}
		}
		for i := 0; i < n; i++ {
			if err := peer.wr.WriteData(streamID, false, make([]byte, 100)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	return done
}

// waitWriterQueueFull polls until writerQueue is at capacity — the
// precondition for the hang — or fails the test.
func waitWriterQueueFull(t *testing.T, l *Layer) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(l.writerQueue) == cap(l.writerQueue) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("precondition: writerQueue never filled (len=%d cap=%d)", len(l.writerQueue), cap(l.writerQueue))
}

// assertCloseBoundedNoLeak calls l.Close and asserts it returns within
// closeFullQueueBound, then tears the peer down and asserts no goroutine
// (reader / writer / Close / helpers) outlives the Layer.
func assertCloseBoundedNoLeak(t *testing.T, l *Layer, peer *h2Peer, ignore goleak.Option) {
	t.Helper()
	closed := make(chan struct{})
	go func() {
		_ = l.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(closeFullQueueBound):
		t.Errorf("Layer.Close did not return within %v with the writer blocked on flow control and writerQueue full", closeFullQueueBound)
	}
	_ = peer.conn.Close()
	if err := goleak.Find(ignore); err != nil {
		t.Errorf("goroutines leaked after Layer.Close: %v", err)
	}
}

func TestLayer_Close_WriterBlockedQueueFull_ClientRole(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)
	frames, pause := startPausableProbeReader(peer)

	lc1, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sendAsyncEnv(lc1, &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true}); err != nil {
		t.Fatalf("send headers 1: %v", err)
	}
	drainCloseProbeFrames(frames, 100*time.Millisecond)

	// The peer stops reading: the writer's next socket write blocks.
	pause()
	drainChannel(lc1)
	hdr := peer.encoder.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
	_ = floodData(peer, 1, hdr, true, 60)

	waitWriterQueueFull(t, l)
	assertCloseBoundedNoLeak(t, l, peer, ignore)
}

func TestLayer_Close_WriterBlockedQueueFull_ServerRole(t *testing.T) {
	ignore := goleak.IgnoreCurrent()

	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)
	frames, pause := startPausableProbeReader(peer)
	drainCloseProbeFrames(frames, 100*time.Millisecond)

	reqHdr := func(method string) []byte {
		return peer.encoder.Encode([]hpack.HeaderField{
			{Name: ":method", Value: method}, {Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/"},
		})
	}
	acceptChannel := func() layer.Channel {
		t.Helper()
		select {
		case ch := <-l.Channels():
			return ch
		case <-time.After(2 * time.Second):
			t.Fatal("no channel")
		}
		return nil
	}

	// The peer stops reading: the writer's next socket write blocks.
	pause()
	// Stream 1: POST whose request body the client floods in small frames.
	_ = floodData(peer, 1, reqHdr("POST"), true, 60)
	drainChannel(acceptChannel())

	waitWriterQueueFull(t, l)
	assertCloseBoundedNoLeak(t, l, peer, ignore)
}

// Normal Close (queue has room) still delivers GOAWAY(NO_ERROR) to the peer.
func TestLayer_Close_SendsGoAway(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(t *testing.T, opts ...Option) (*Layer, *h2Peer, func())
	}{
		{"ClientRole", startClientLayer},
		{"ServerRole", startServerLayer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, peer, cleanup := tc.start(t)
			defer cleanup()
			peer.consumePeerSettings(t)
			peer.sendInitialSettings(t)
			peer.expectSettingsAck(t)
			frames := startCloseProbeReader(peer)

			closed := make(chan struct{})
			go func() {
				_ = l.Close()
				close(closed)
			}()

			sawGoAway := false
			deadline := time.After(2 * time.Second)
		loop:
			for {
				select {
				case f, ok := <-frames:
					if !ok {
						break loop
					}
					if f.typ == frame.TypeGoAway {
						sawGoAway = true
						break loop
					}
				case <-deadline:
					break loop
				}
			}
			<-closed
			if !sawGoAway {
				t.Errorf("Layer.Close did not write GOAWAY to the peer")
			}
		})
	}
}
