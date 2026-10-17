package http2

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1166: the writer must never block the connection on flow control.
// DATA that does not fit the peer's stream / connection window is parked per
// stream while the writer keeps serving every other frame; a reset (either
// side), a GOAWAY refusal, or the caller giving up withdraws the parked
// DATA instead of writing it later.
//
// All scenarios drive the real producers: channel.Send on a real
// OpenStream / peer-initiated channel, the reader goroutine handling real
// peer frames (RST_STREAM, GOAWAY, WINDOW_UPDATE, PING, DATA) written by an
// h2Peer over net.Pipe. Window sizes are the RFC 9113 §6.9.2 defaults
// (65,535) unless the peer changes them. Fixture shapes follow
// channel_refused_test.go and close_full_queue_test.go.

const fcProbeTimeout = time.Second

// fcBlockedBody is larger than the default 65,535-byte stream window, so a
// DATA Send carrying it cannot complete until the peer grants more window.
const fcBlockedBody = 200000

// waitFCFrame consumes frames until one matches pred (true) or the timeout
// elapses (false).
func waitFCFrame(frames <-chan closeProbeFrame, timeout time.Duration, pred func(closeProbeFrame) bool) bool {
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return false
			}
			if pred(f) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// collectFCFrames returns every frame the Layer writes during d.
func collectFCFrames(frames <-chan closeProbeFrame, d time.Duration) []closeProbeFrame {
	var out []closeProbeFrame
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return out
			}
			out = append(out, f)
		case <-deadline:
			return out
		}
	}
}

func fcDataBytes(fs []closeProbeFrame, streamID uint32) int {
	n := 0
	for _, f := range fs {
		if f.typ == frame.TypeData && f.streamID == streamID {
			n += f.n
		}
	}
	return n
}

func isPingAck(f closeProbeFrame) bool {
	return f.typ == frame.TypePing && f.flags.Has(frame.FlagAck)
}

func isHeadersOn(id uint32) func(closeProbeFrame) bool {
	return func(f closeProbeFrame) bool { return f.typ == frame.TypeHeaders && f.streamID == id }
}

// waitSendResult waits for a Send result or fails the test.
func waitSendResult(t *testing.T, errc <-chan error, timeout time.Duration, what string) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(timeout):
		t.Fatalf("%s: Send did not return within %v", what, timeout)
		return nil
	}
}

// fcClientSetup starts a ClientRole Layer whose peer has completed the
// SETTINGS exchange and grown the connection window so only the stream
// window limits DATA. It returns the frame probe.
func fcClientSetup(t *testing.T, growConn bool) (*Layer, *h2Peer, <-chan closeProbeFrame, func()) {
	t.Helper()
	l, peer, cleanup := startClientLayer(t)
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)
	frames := startCloseProbeReader(peer)
	if growConn {
		if err := peer.wr.WriteWindowUpdate(0, 10<<20); err != nil {
			t.Fatal(err)
		}
	}
	return l, peer, frames, cleanup
}

// fcOpenPost opens a client stream and sends a body-bearing request HEADERS.
func fcOpenPost(t *testing.T, l *Layer) layer.Channel {
	t.Helper()
	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := waitSendResult(t, sendAsyncEnv(ch, &H2HeadersEvent{Method: "POST", Scheme: "https", Authority: "example.com", Path: "/upload"}), 2*time.Second, "POST HEADERS"); err != nil {
		t.Fatalf("send POST HEADERS: %v", err)
	}
	return ch
}

// fcSendBlocked starts a DATA Send larger than the stream window and waits
// until the window-sized prefix has been written (the writer is now out of
// window for that stream).
func fcSendBlocked(t *testing.T, ch layer.Channel, frames <-chan closeProbeFrame, streamID uint32, endStream bool) <-chan error {
	t.Helper()
	errc := sendAsyncEnv(ch, &H2DataEvent{Payload: make([]byte, fcBlockedBody), EndStream: endStream})
	written := fcDataBytes(collectFCFrames(frames, 300*time.Millisecond), streamID)
	if written != 65535 {
		t.Fatalf("precondition: stream %d DATA written before block = %d, want 65535", streamID, written)
	}
	return errc
}

// 1. A stream blocked on its own window does not stop PING ACK or another
// stream's HEADERS.
func TestWriter_FlowControl_BlockedStreamDoesNotStallOthers(t *testing.T) {
	l, peer, frames, cleanup := fcClientSetup(t, true)
	defer cleanup()

	lc1 := fcOpenPost(t, l)
	_ = fcSendBlocked(t, lc1, frames, 1, true)

	if err := peer.wr.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	pingOK := waitFCFrame(frames, fcProbeTimeout, isPingAck)

	lc3, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = sendAsyncEnv(lc3, &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true})
	hdrOK := waitFCFrame(frames, fcProbeTimeout, isHeadersOn(3))
	if !pingOK || !hdrOK {
		t.Errorf("writer stalled by stream 1 flow control: PING ACK written=%v, stream 3 HEADERS written=%v", pingOK, hdrOK)
	}
}

// 2. A peer RST_STREAM on the blocked stream releases its Send and the rest of
// the connection keeps flowing. RST_STREAM(NO_ERROR) is RFC 9113 §8.1's
// "stop sending the request body, without error", so that Send returns nil.
func TestWriter_FlowControl_PeerRSTReleasesBlockedSend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     uint32
		wantCode layer.ErrorCode // zero: want nil error
	}{
		{"REFUSED_STREAM", ErrCodeRefusedStream, layer.ErrorRefused},
		{"CANCEL", ErrCodeCancel, layer.ErrorCanceled},
		{"NO_ERROR", ErrCodeNo, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, peer, frames, cleanup := fcClientSetup(t, true)
			defer cleanup()

			lc1 := fcOpenPost(t, l)
			dataErr := fcSendBlocked(t, lc1, frames, 1, true)

			if err := peer.wr.WriteRSTStream(1, tc.code); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-dataErr:
				if tc.wantCode == 0 {
					if err != nil {
						t.Errorf("stream 1 Send after RST_STREAM(NO_ERROR) = %v, want nil", err)
					}
				} else {
					var se *layer.StreamError
					if !errors.As(err, &se) || se.Code != tc.wantCode {
						t.Errorf("stream 1 Send after RST_STREAM(%s) = %v, want *layer.StreamError code %v", tc.name, err, tc.wantCode)
					}
				}
			case <-time.After(fcProbeTimeout):
				t.Errorf("stream 1 Send still blocked %v after peer RST_STREAM(%s)", fcProbeTimeout, tc.name)
			}

			if err := peer.wr.WritePing(false, [8]byte{1}); err != nil {
				t.Fatal(err)
			}
			pingOK := waitFCFrame(frames, fcProbeTimeout, isPingAck)
			lc3, err := l.OpenStream(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_ = sendAsyncEnv(lc3, &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true})
			hdrOK := waitFCFrame(frames, fcProbeTimeout, isHeadersOn(3))
			if !pingOK || !hdrOK {
				t.Errorf("writer stalled after peer RST: PING ACK written=%v, stream 3 HEADERS written=%v", pingOK, hdrOK)
			}
		})
	}
}

// 3. GOAWAY(last_stream_id=1) refuses blocked stream 3: its Send fails with
// ErrorRefused and stream 1 (still live) gets its WINDOW_UPDATE and PING ACK.
func TestWriter_FlowControl_GoAwayRefusesBlockedStream(t *testing.T) {
	l, peer, frames, cleanup := fcClientSetup(t, true)
	defer cleanup()

	lc1, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := waitSendResult(t, sendAsyncEnv(lc1, &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true}), 2*time.Second, "GET HEADERS"); err != nil {
		t.Fatal(err)
	}
	drainChannel(lc1)
	lc3 := fcOpenPost(t, l)
	dataErr := fcSendBlocked(t, lc3, frames, 3, true)

	if err := peer.wr.WriteGoAway(1, ErrCodeNo, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dataErr:
		var se *layer.StreamError
		if !errors.As(err, &se) || se.Code != layer.ErrorRefused {
			t.Errorf("stream 3 Send after GOAWAY(last=1) = %v, want *layer.StreamError ErrorRefused", err)
		}
	case <-time.After(fcProbeTimeout):
		t.Errorf("stream 3 Send still blocked %v after GOAWAY(last=1)", fcProbeTimeout)
	}

	enc := peer.encoder.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
	if err := peer.wr.WriteHeaders(1, false, true, enc); err != nil {
		t.Fatal(err)
	}
	if err := peer.wr.WriteData(1, false, make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	wuOK := waitFCFrame(frames, fcProbeTimeout, func(f closeProbeFrame) bool {
		return f.typ == frame.TypeWindowUpdate && f.streamID == 1
	})
	if err := peer.wr.WritePing(false, [8]byte{9}); err != nil {
		t.Fatal(err)
	}
	pingOK := waitFCFrame(frames, fcProbeTimeout, isPingAck)
	if !wuOK || !pingOK {
		t.Errorf("writer stalled after GOAWAY: stream 1 WINDOW_UPDATE written=%v, PING ACK written=%v", wuOK, pingOK)
	}
}

// 4. ServerRole: the client resets stream 1 while the response body is blocked;
// stream 3's response HEADERS must still be written.
func TestWriter_FlowControl_ServerRole_ClientRSTWhileBlocked(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)
	frames := startCloseProbeReader(peer)
	if err := peer.wr.WriteWindowUpdate(0, 10<<20); err != nil {
		t.Fatal(err)
	}

	open := func(id uint32) layer.Channel {
		t.Helper()
		enc := peer.encoder.Encode([]hpack.HeaderField{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/"},
		})
		if err := peer.wr.WriteHeaders(id, true, true, enc); err != nil {
			t.Fatal(err)
		}
		select {
		case ch := <-l.Channels():
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := ch.Next(ctx); err != nil {
				t.Fatal(err)
			}
			return ch
		case <-time.After(2 * time.Second):
			t.Fatal("no channel")
		}
		return nil
	}
	ch1 := open(1)
	ch3 := open(3)

	if err := waitSendResult(t, sendAsyncEnv(ch1, &H2HeadersEvent{Status: 200}), 2*time.Second, "response HEADERS 1"); err != nil {
		t.Fatal(err)
	}
	dataErr := fcSendBlocked(t, ch1, frames, 1, true)

	if err := peer.wr.WriteRSTStream(1, ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dataErr:
		var se *layer.StreamError
		if !errors.As(err, &se) {
			t.Errorf("stream 1 response DATA Send after client RST = %v, want *layer.StreamError", err)
		}
	case <-time.After(fcProbeTimeout):
		t.Errorf("stream 1 response DATA Send still blocked after client RST_STREAM(CANCEL)")
	}

	_ = sendAsyncEnv(ch3, &H2HeadersEvent{Status: 200, EndStream: true})
	if !waitFCFrame(frames, fcProbeTimeout, isHeadersOn(3)) {
		t.Errorf("writer stalled: stream 3 response HEADERS not written after client RST on stream 1")
	}
}

// 5. Connection window exhausted: HEADERS, RST_STREAM and PING ACK still go
// out; the parked DATA resumes once the peer grants connection window.
func TestWriter_FlowControl_ConnWindowExhausted(t *testing.T) {
	l, peer, frames, cleanup := fcClientSetup(t, false)
	defer cleanup()
	// Large stream windows so only the (default 65,535) connection window
	// limits stream 1.
	if err := peer.wr.WriteSettings([]frame.Setting{{ID: frame.SettingInitialWindowSize, Value: 1 << 20}}); err != nil {
		t.Fatal(err)
	}
	if !waitFCFrame(frames, fcProbeTimeout, func(f closeProbeFrame) bool {
		return f.typ == frame.TypeSettings && f.flags.Has(frame.FlagAck)
	}) {
		t.Fatal("precondition: SETTINGS ACK missing")
	}

	lc1 := fcOpenPost(t, l)
	dataErr := fcSendBlocked(t, lc1, frames, 1, true)
	if got := l.conn.SendWindow(); got != 0 {
		t.Fatalf("precondition: connection send window = %d, want 0", got)
	}

	lc3, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = sendAsyncEnv(lc3, &H2HeadersEvent{Method: "POST", Scheme: "https", Authority: "example.com", Path: "/"})
	hdrOK := waitFCFrame(frames, fcProbeTimeout, isHeadersOn(3))
	_ = lc3.Close() // abnormal close: RST_STREAM(CANCEL) on stream 3
	rstOK := waitFCFrame(frames, fcProbeTimeout, func(f closeProbeFrame) bool {
		return f.typ == frame.TypeRSTStream && f.streamID == 3
	})
	if err := peer.wr.WritePing(false, [8]byte{5}); err != nil {
		t.Fatal(err)
	}
	pingOK := waitFCFrame(frames, fcProbeTimeout, isPingAck)
	if !hdrOK || !rstOK || !pingOK {
		t.Errorf("control frames stalled by exhausted connection window: stream 3 HEADERS=%v RST_STREAM=%v PING ACK=%v", hdrOK, rstOK, pingOK)
	}

	if err := peer.wr.WriteWindowUpdate(0, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := waitSendResult(t, dataErr, 2*time.Second, "stream 1 DATA after connection WINDOW_UPDATE"); err != nil {
		t.Errorf("stream 1 DATA Send = %v, want nil", err)
	}
	if got := fcDataBytes(collectFCFrames(frames, 200*time.Millisecond), 1); got != fcBlockedBody-65535 {
		t.Errorf("stream 1 DATA resumed with %d bytes, want %d", got, fcBlockedBody-65535)
	}
}

// 6. Reader/writer deadlock: stream 1 is blocked on its stream window; the
// peer streams >32 DATA frames on stream 3 (two WINDOW_UPDATEs queued per
// frame) and only then grants stream 1 window. The grant must be read and
// stream 1 must complete; Close must return and leave no goroutine behind.
func TestWriter_FlowControl_NoReaderWriterDeadlock(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	l, peer, frames, cleanup := fcClientSetup(t, true)
	defer cleanup()

	lc1 := fcOpenPost(t, l)
	lc3, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := waitSendResult(t, sendAsyncEnv(lc3, &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true}), 2*time.Second, "GET HEADERS"); err != nil {
		t.Fatal(err)
	}
	dataErr := fcSendBlocked(t, lc1, frames, 1, true)
	drainChannel(lc3)

	peerDone := make(chan error, 1)
	go func() {
		enc := peer.encoder.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
		if err := peer.wr.WriteHeaders(3, false, true, enc); err != nil {
			peerDone <- err
			return
		}
		for i := 0; i < 60; i++ {
			if err := peer.wr.WriteData(3, false, make([]byte, 100)); err != nil {
				peerDone <- err
				return
			}
		}
		peerDone <- peer.wr.WriteWindowUpdate(1, 1<<20)
	}()

	select {
	case err := <-dataErr:
		if err != nil {
			t.Errorf("stream 1 DATA Send = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		select {
		case err := <-peerDone:
			t.Errorf("stream 1 never completed although the peer granted window (peer write err=%v)", err)
		default:
			t.Errorf("deadlock: the peer cannot deliver its WINDOW_UPDATE (Layer reader parked on a full writerQueue)")
		}
	}
	assertCloseBoundedNoLeak(t, l, peer, ignore)
	_ = frames
}

// 7. RFC 9113 §5.1: no DATA is written on a stream after RST_STREAM was
// received or sent on it, even if the peer later grants window for it.
func TestWriter_FlowControl_NoDataAfterRST(t *testing.T) {
	t.Run("RST received", func(t *testing.T) {
		l, peer, frames, cleanup := fcClientSetup(t, true)
		defer cleanup()
		lc1 := fcOpenPost(t, l)
		_ = fcSendBlocked(t, lc1, frames, 1, true)

		if err := peer.wr.WriteRSTStream(1, ErrCodeCancel); err != nil {
			t.Fatal(err)
		}
		if err := peer.wr.WriteWindowUpdate(1, 1<<20); err != nil {
			t.Fatal(err)
		}
		if got := fcDataBytes(collectFCFrames(frames, 500*time.Millisecond), 1); got != 0 {
			t.Errorf("%d DATA bytes written on stream 1 after the peer reset it", got)
		}
	})
	t.Run("RST sent", func(t *testing.T) {
		l, peer, frames, cleanup := fcClientSetup(t, true)
		defer cleanup()
		lc1 := fcOpenPost(t, l)
		_ = fcSendBlocked(t, lc1, frames, 1, true)

		_ = lc1.Close() // abnormal close: RST_STREAM(CANCEL)
		if !waitFCFrame(frames, fcProbeTimeout, func(f closeProbeFrame) bool {
			return f.typ == frame.TypeRSTStream && f.streamID == 1
		}) {
			t.Errorf("RST_STREAM for stream 1 not written while its DATA was blocked")
		}
		if err := peer.wr.WriteWindowUpdate(1, 1<<20); err != nil {
			t.Fatal(err)
		}
		if got := fcDataBytes(collectFCFrames(frames, 500*time.Millisecond), 1); got != 0 {
			t.Errorf("%d DATA bytes written on stream 1 after RST_STREAM was sent", got)
		}
	})
}

// 8. Per-stream ordering: trailer HEADERS queued while the stream's DATA is
// parked are written after all of that DATA.
func TestWriter_FlowControl_TrailersAfterParkedData(t *testing.T) {
	l, peer, frames, cleanup := fcClientSetup(t, true)
	defer cleanup()
	lc1 := fcOpenPost(t, l)
	dataErr := fcSendBlocked(t, lc1, frames, 1, false)
	trErr := sendAsyncEnv(lc1, &H2TrailersEvent{Trailers: []envelope.KeyValue{{Name: "x-checksum", Value: "abc"}}})
	// Let the trailer reach the writer before the window opens.
	time.Sleep(100 * time.Millisecond)

	if err := peer.wr.WriteWindowUpdate(1, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := waitSendResult(t, dataErr, 2*time.Second, "DATA"); err != nil {
		t.Fatalf("DATA Send = %v", err)
	}
	if err := waitSendResult(t, trErr, 2*time.Second, "trailers"); err != nil {
		t.Fatalf("trailers Send = %v", err)
	}
	fs := collectFCFrames(frames, 200*time.Millisecond)
	dataSeen := 0
	trailerSeen := false
	for _, f := range fs {
		switch {
		case f.typ == frame.TypeData && f.streamID == 1:
			if trailerSeen {
				t.Errorf("stream 1 DATA (%d bytes) written after its trailer HEADERS", f.n)
			}
			dataSeen += f.n
		case f.typ == frame.TypeHeaders && f.streamID == 1:
			trailerSeen = true
			if !f.flags.Has(frame.FlagEndStream) {
				t.Errorf("trailer HEADERS without END_STREAM")
			}
		}
	}
	if !trailerSeen || dataSeen != fcBlockedBody-65535 {
		t.Errorf("trailer written=%v, remaining DATA bytes=%d (want %d)", trailerSeen, dataSeen, fcBlockedBody-65535)
	}
}

// 9. A Send whose ctx expires while its DATA is parked withdraws that DATA:
// none of it is written once window arrives, and other streams proceed.
func TestWriter_FlowControl_CtxCancelWithdrawsParkedData(t *testing.T) {
	l, peer, frames, cleanup := fcClientSetup(t, true)
	defer cleanup()
	lc1 := fcOpenPost(t, l)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		errc <- lc1.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
			Message: &H2DataEvent{Payload: make([]byte, fcBlockedBody), EndStream: true}})
	}()
	if err := waitSendResult(t, errc, 2*time.Second, "DATA with short ctx"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DATA Send = %v, want context.DeadlineExceeded", err)
	}
	// Discard the window-sized prefix written before the block.
	_ = collectFCFrames(frames, 100*time.Millisecond)

	if err := peer.wr.WriteWindowUpdate(1, 1<<20); err != nil {
		t.Fatal(err)
	}
	if got := fcDataBytes(collectFCFrames(frames, 500*time.Millisecond), 1); got != 0 {
		t.Errorf("%d DATA bytes of a withdrawn Send written on stream 1 after the window opened", got)
	}

	lc3, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = sendAsyncEnv(lc3, &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true})
	if !waitFCFrame(frames, fcProbeTimeout, isHeadersOn(3)) {
		t.Errorf("stream 3 HEADERS not written after a withdrawn Send on stream 1")
	}
}
