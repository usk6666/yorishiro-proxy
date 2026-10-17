package http2

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1166 review round 1: the write scheduler's per-connection state must
// stay bounded by what the peer can legitimately make us track (StreamMap),
// and a reset must stop DATA mid-grant, not only while parked.

// S-1 (CWE-770): HEADERS refused for exceeding MAX_CONCURRENT_STREAMS never
// create a StreamMap entry, so the RST_STREAM(REFUSED_STREAM) the reader
// writes for each must not leave a connection-lifetime reset entry behind.
func TestWriteSched_RefusedStreamsDoNotGrowResetSet(t *testing.T) {
	l, peer, cleanup := startServerLayer(t, WithMaxConcurrentStreams(2))
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)
	frames := startCloseProbeReader(peer)
	go func() {
		for ch := range l.Channels() {
			go drainChannel(ch)
		}
	}()

	enc := peer.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/"},
	})
	// Hold the concurrency limit: two open streams, no END_STREAM.
	for _, id := range []uint32{1, 3} {
		if err := peer.wr.WriteHeaders(id, false, true, enc); err != nil {
			t.Fatal(err)
		}
	}
	// Flood new stream ids; each is refused before any per-stream state
	// is allocated. The fragment is never decoded.
	const refused = 200
	for i := 0; i < refused; i++ {
		if err := peer.wr.WriteHeaders(uint32(5+2*i), false, true, enc); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	deadline := time.After(5 * time.Second)
	for got < refused {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatalf("probe reader closed after %d RST_STREAM", got)
			}
			if f.typ == frame.TypeRSTStream {
				got++
			}
		case <-deadline:
			t.Fatalf("precondition: only %d of %d refused streams got RST_STREAM", got, refused)
		}
	}
	// A round trip through the writer orders this read after every RST.
	if err := peer.wr.WritePing(false, [8]byte{9}); err != nil {
		t.Fatal(err)
	}
	if !waitFCFrame(frames, fcProbeTimeout, isPingAck) {
		t.Fatal("precondition: PING ACK missing")
	}

	if n := len(l.sched.reset); n > 2 {
		t.Errorf("write scheduler holds %d reset entries after %d refused streams; want <= 2 (the streams StreamMap knows)", n, refused)
	}
}

// S-2 (CWE-770): the same stream reset over and over (RST_STREAM on an
// already-closed stream is accepted, RFC 9113 §5.4.2) must not grow the
// cross-goroutine pending hand-off while the writer is not draining it.
// First error wins.
func TestWriteSched_RepeatedResetsCoalesce(t *testing.T) {
	l := &Layer{sched: newWriteSched(), windowUpdated: make(chan struct{}, 1)}
	first := errors.New("first")
	l.resetStreamWrites(1, first)
	for i := 0; i < 1000; i++ {
		l.resetStreamWrites(1, errors.New("later"))
		l.resetStreamWrites(3, nil)
	}
	if n := len(l.sched.pending); n != 2 {
		t.Errorf("pending resets = %d after 2001 resets on 2 streams, want 2", n)
	}
}

// F-1: a reset observed while the writer is in the middle of a large window
// grant stops the remaining DATA at the next frame boundary.
func TestWriter_FlowControl_RSTStopsDataMidGrant(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	// Gated probe reader: while gate is held it stops reading after at
	// most the frame in progress, so the Layer's next socket write blocks.
	var gate sync.Mutex
	frames := make(chan closeProbeFrame, 4096)
	go func() {
		defer close(frames)
		for {
			gate.Lock()
			//nolint:staticcheck // empty critical section is the gate
			gate.Unlock()
			f, err := peer.rd.ReadFrame()
			if err != nil {
				return
			}
			frames <- closeProbeFrame{typ: f.Header.Type, streamID: f.Header.StreamID, flags: f.Header.Flags, n: int(f.Header.Length)}
		}
	}()

	lc1 := fcOpenPost(t, l)
	const maxWin = 1<<31 - 1
	if err := peer.wr.WriteWindowUpdate(0, maxWin-65535); err != nil {
		t.Fatal(err)
	}
	if err := peer.wr.WriteWindowUpdate(1, maxWin-65535); err != nil {
		t.Fatal(err)
	}
	if err := peer.wr.WritePing(false, [8]byte{1}); err != nil {
		t.Fatal(err)
	}
	if !waitFCFrame(frames, fcProbeTimeout, isPingAck) {
		t.Fatal("precondition: PING ACK missing")
	}

	const body = 16 << 20
	errc := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		errc <- lc1.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
			Message: &H2DataEvent{Payload: make([]byte, body), EndStream: true}})
	}()
	if !waitFCFrame(frames, fcProbeTimeout, func(f closeProbeFrame) bool {
		return f.typ == frame.TypeData && f.streamID == 1
	}) {
		t.Fatal("precondition: no DATA written on stream 1")
	}
	gate.Lock()
	before := fcDataBytes(collectFCFrames(frames, 50*time.Millisecond), 1)

	if err := peer.wr.WriteRSTStream(1, ErrCodeCancel); err != nil {
		gate.Unlock()
		t.Fatal(err)
	}
	// Wait until the reader has recorded the reset for the writer.
	recorded := false
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		l.sched.mu.Lock()
		recorded = len(l.sched.pending) > 0
		l.sched.mu.Unlock()
		if recorded {
			break
		}
	}
	select {
	case err := <-errc:
		gate.Unlock()
		t.Fatalf("precondition: DATA Send returned (%v) before the gate opened; writer was not mid-grant", err)
	default:
	}
	gate.Unlock()
	if !recorded {
		t.Fatal("precondition: reader did not record the RST_STREAM")
	}

	after := fcDataBytes(collectFCFrames(frames, 500*time.Millisecond), 1)
	if limit := 2 * int(frame.DefaultMaxFrameSize); after > limit {
		t.Errorf("%d DATA bytes written on stream 1 after the peer's RST_STREAM was read (before=%d, body=%d); want <= %d", after, before, body, limit)
	}
	err := waitSendResult(t, errc, 2*time.Second, "DATA after mid-grant RST")
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Errorf("DATA Send after mid-grant RST_STREAM(CANCEL) = %v, want *layer.StreamError", err)
	}
}

// S-3 (CWE-672): an empty END_STREAM DATA whose caller gave up while it
// was parked behind flow-controlled DATA must not reach the wire later.
func TestWriter_FlowControl_AbandonedEmptyEndStreamNotWritten(t *testing.T) {
	l, peer, frames, cleanup := fcClientSetup(t, true)
	defer cleanup()
	lc1 := fcOpenPost(t, l)
	dataErr := fcSendBlocked(t, lc1, frames, 1, false)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	endErr := make(chan error, 1)
	go func() {
		endErr <- lc1.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
			Message: &H2DataEvent{EndStream: true}})
	}()
	if err := waitSendResult(t, endErr, 2*time.Second, "empty END_STREAM DATA with short ctx"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("empty END_STREAM DATA Send = %v, want context.DeadlineExceeded", err)
	}

	if err := peer.wr.WriteWindowUpdate(1, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := waitSendResult(t, dataErr, 2*time.Second, "parked DATA"); err != nil {
		t.Fatalf("parked DATA Send = %v", err)
	}
	for _, f := range collectFCFrames(frames, 300*time.Millisecond) {
		if f.typ == frame.TypeData && f.streamID == 1 && f.flags.Has(frame.FlagEndStream) {
			t.Errorf("END_STREAM DATA (%d bytes) written on stream 1 after its Send was abandoned", f.n)
		}
	}
}
