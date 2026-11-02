package http2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1399: per-stream receive credit follows consumer reads (RFC-001 §9.1
// point 3). The tests drive a real Layer over net.Pipe against a raw frame
// peer. PING → PING ACK is the FIFO barrier: the reader enqueues the ACK
// after every frame that preceded the PING has been handled, and the writer
// applies any stream credit recorded before it dispatches that ACK, so the
// frames collected before the ACK are exactly the Layer's reaction to
// everything the peer and the test did before the PING.

// wfTimeout bounds every wait in this file. It is a failure bound only;
// no assertion depends on timing.
const wfTimeout = 5 * time.Second

// wfFrame summarises one frame the Layer wrote to the peer. Fields are
// copied out of the frame inside the reader goroutine.
type wfFrame struct {
	typ      frame.Type
	streamID uint32
	flags    frame.Flags
	inc      uint32  // WINDOW_UPDATE increment
	code     uint32  // RST_STREAM / GOAWAY error code
	ping     [8]byte // PING data
}

// wfPeer is an h2Peer whose inbound frames are read continuously by a
// background goroutine (net.Pipe has no buffer, so the Layer's writer
// would otherwise block) and whose writes are serialised.
type wfPeer struct {
	*h2Peer
	frames chan wfFrame
	wmu    sync.Mutex
}

// startWindowPeer starts a Layer with start, completes the SETTINGS
// exchange and returns the Layer and the peer.
func startWindowPeer(t *testing.T, start func(*testing.T, ...Option) (*Layer, *h2Peer, func()), opts ...Option) (*Layer, *wfPeer) {
	t.Helper()
	l, raw, cleanup := start(t, opts...)
	t.Cleanup(cleanup)
	p := &wfPeer{h2Peer: raw, frames: make(chan wfFrame, 16384)}
	go p.readLoop()
	p.write(t, func(wr *frame.Writer) error { return wr.WriteSettings(nil) })
	p.until(t, func(f wfFrame) bool {
		return f.typ == frame.TypeSettings && f.flags.Has(frame.FlagAck)
	})
	return l, p
}

func (p *wfPeer) readLoop() {
	defer close(p.frames)
	for {
		f, err := p.rd.ReadFrame()
		if err != nil {
			return
		}
		s := wfFrame{typ: f.Header.Type, streamID: f.Header.StreamID, flags: f.Header.Flags}
		switch f.Header.Type {
		case frame.TypeWindowUpdate:
			s.inc, _ = f.WindowUpdateIncrement()
		case frame.TypeRSTStream:
			s.code, _ = f.RSTStreamErrorCode()
		case frame.TypeGoAway:
			_, s.code, _, _ = f.GoAwayInfo()
		case frame.TypePing:
			s.ping, _ = f.PingData()
		}
		p.frames <- s
	}
}

// write runs fn against the peer's frame writer and fails the test if it
// does not complete within wfTimeout (a Layer whose reader is stuck stops
// reading the pipe, so the write would block).
func (p *wfPeer) write(t *testing.T, fn func(*frame.Writer) error) {
	t.Helper()
	if err := waitErr(p.writeAsync(fn)); err != nil {
		t.Fatalf("peer write: %v", err)
	}
}

// writeAsync is write without waiting; the result arrives on the channel.
func (p *wfPeer) writeAsync(fn func(*frame.Writer) error) <-chan error {
	errc := make(chan error, 1)
	go func() {
		p.wmu.Lock()
		defer p.wmu.Unlock()
		errc <- fn(p.wr)
	}()
	return errc
}

func waitErr(errc <-chan error) error {
	select {
	case err := <-errc:
		return err
	case <-time.After(wfTimeout):
		return errors.New("blocked: the Layer stopped reading the connection")
	}
}

// until collects frames until pred matches one, returning every frame up to
// and including the match.
func (p *wfPeer) until(t *testing.T, pred func(wfFrame) bool) []wfFrame {
	t.Helper()
	var out []wfFrame
	deadline := time.After(wfTimeout)
	for {
		select {
		case f, ok := <-p.frames:
			if !ok {
				t.Fatalf("connection closed while waiting; frames so far: %v", summarize(out))
			}
			out = append(out, f)
			if pred(f) {
				return out
			}
		case <-deadline:
			t.Fatalf("timed out waiting for frame; frames so far: %v", summarize(out))
		}
	}
}

// barrier sends PING(tag) and returns the frames the Layer wrote before the
// matching PING ACK.
func (p *wfPeer) barrier(t *testing.T, tag byte) []wfFrame {
	t.Helper()
	data := [8]byte{'b', 'a', 'r', 'r', 'i', 'e', 'r', tag}
	p.write(t, func(wr *frame.Writer) error { return wr.WritePing(false, data) })
	got := p.until(t, func(f wfFrame) bool {
		return f.typ == frame.TypePing && f.flags.Has(frame.FlagAck) && f.ping == data
	})
	return got[:len(got)-1]
}

type wuSummary struct {
	connCount   int
	connSum     uint64
	streamCount map[uint32]int
	streamSum   map[uint32]uint64
	streamIncs  map[uint32][]uint32
}

func windowUpdates(frames []wfFrame) wuSummary {
	s := wuSummary{streamCount: map[uint32]int{}, streamSum: map[uint32]uint64{}, streamIncs: map[uint32][]uint32{}}
	for _, f := range frames {
		if f.typ != frame.TypeWindowUpdate {
			continue
		}
		if f.streamID == 0 {
			s.connCount++
			s.connSum += uint64(f.inc)
			continue
		}
		s.streamCount[f.streamID]++
		s.streamSum[f.streamID] += uint64(f.inc)
		s.streamIncs[f.streamID] = append(s.streamIncs[f.streamID], f.inc)
	}
	return s
}

func rstCode(frames []wfFrame, streamID uint32) (uint32, bool) {
	for _, f := range frames {
		if f.typ == frame.TypeRSTStream && f.streamID == streamID {
			return f.code, true
		}
	}
	return 0, false
}

func summarize(frames []wfFrame) []string {
	out := make([]string, 0, len(frames))
	for _, f := range frames {
		s := f.typ.String()
		switch f.typ {
		case frame.TypeWindowUpdate:
			s += "(" + itoaU(f.streamID) + ",+" + itoaU(f.inc) + ")"
		case frame.TypeRSTStream, frame.TypeGoAway:
			s += "(" + itoaU(f.streamID) + "," + ErrCodeString(f.code) + ")"
		default:
			s += "(" + itoaU(f.streamID) + ")"
		}
		out = append(out, s)
	}
	return out
}

func itoaU(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// smallWindow advertises the RFC 9113 default 65535-byte stream window, so a
// half-window credit batch is 32767 bytes and the per-stream event cap is
// max(1024, 65535/1024) = 1024.
func smallWindow() Option { return WithInitialSettings(DefaultSettings()) }

func withAfterWindowUpdateWrite(fn func(streamID uint32)) Option {
	return func(o *options) { o.afterWindowUpdateWrite = fn }
}

func (p *wfPeer) requestHeaders(path string) []byte {
	return p.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: path},
	})
}

func (p *wfPeer) statusHeaders() []byte {
	return p.encoder.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
}

// paddedData builds a raw DATA frame with the PADDED flag: pad-length byte,
// payload, padLen zero bytes (RFC 9113 §6.1).
func paddedData(streamID uint32, payload []byte, padLen uint8) []byte {
	length := 1 + len(payload) + int(padLen)
	b := make([]byte, 0, 9+length)
	b = append(b, byte(length>>16), byte(length>>8), byte(length))
	b = append(b, byte(frame.TypeData), byte(frame.FlagPadded))
	b = binary.BigEndian.AppendUint32(b, streamID&0x7fffffff)
	b = append(b, padLen)
	b = append(b, payload...)
	b = append(b, make([]byte, padLen)...)
	return b
}

// nextData reads events from ch until a DATA event arrives and returns it.
func nextData(t *testing.T, ch layer.Channel) *H2DataEvent {
	t.Helper()
	for {
		env, err := nextWithin(ch, wfTimeout)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if d, ok := env.Message.(*H2DataEvent); ok {
			return d
		}
	}
}

// expectComplete reads ch to io.EOF and returns the concatenated DATA.
func expectComplete(t *testing.T, ch layer.Channel) []byte {
	t.Helper()
	var body []byte
	sawHeaders := false
	for {
		env, err := nextWithin(ch, wfTimeout)
		if err != nil {
			if !sawHeaders {
				t.Fatalf("stream did not deliver HEADERS: %v", err)
			}
			if errors.Is(err, io.EOF) {
				return body
			}
			t.Fatalf("stream ended with %v, want io.EOF", err)
		}
		switch m := env.Message.(type) {
		case *H2HeadersEvent:
			sawHeaders = true
		case *H2DataEvent:
			body = append(body, m.Payload...)
		}
	}
}

// TestStreamWindow_UnreadStreamDoesNotStallSiblings: on one connection, a
// stream whose consumer never calls Next must not stop a sibling stream from
// completing (USK-1399 acceptance 1).
func TestStreamWindow_UnreadStreamDoesNotStallSiblings(t *testing.T) {
	t.Run("ClientRole", func(t *testing.T) {
		l, p := startWindowPeer(t, startClientLayer)
		ctx, cancel := context.WithTimeout(context.Background(), wfTimeout)
		defer cancel()
		open := func(path string) layer.Channel {
			ch, err := l.OpenStream(ctx)
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			if err := ch.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
				Message: &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: path, EndStream: true}}); err != nil {
				t.Fatalf("Send HEADERS: %v", err)
			}
			return ch
		}
		chA := open("/a")
		chB := open("/b")
		idA, idB := chA.(*channel).H2StreamID(), chB.(*channel).H2StreamID()

		peerDone := p.writeAsync(func(wr *frame.Writer) error {
			if err := wr.WriteHeaders(idA, false, true, p.statusHeaders()); err != nil {
				return err
			}
			for i := 0; i < 64; i++ {
				if err := wr.WriteData(idA, false, make([]byte, 100)); err != nil {
					return err
				}
			}
			if err := wr.WriteHeaders(idB, false, true, p.statusHeaders()); err != nil {
				return err
			}
			return wr.WriteData(idB, true, []byte("ok"))
		})

		if got := expectComplete(t, chB); string(got) != "ok" {
			t.Fatalf("stream B body = %q, want %q", got, "ok")
		}
		if err := waitErr(peerDone); err != nil {
			t.Fatalf("peer writes: %v", err)
		}
	})

	t.Run("ServerRole", func(t *testing.T) {
		l, p := startWindowPeer(t, startServerLayer)
		peerDone := p.writeAsync(func(wr *frame.Writer) error {
			if err := wr.WriteHeaders(1, false, true, p.requestHeaders("/a")); err != nil {
				return err
			}
			for i := 0; i < 64; i++ {
				if err := wr.WriteData(1, false, make([]byte, 100)); err != nil {
					return err
				}
			}
			if err := wr.WriteHeaders(3, false, true, p.requestHeaders("/b")); err != nil {
				return err
			}
			return wr.WriteData(3, true, []byte("ok"))
		})
		_ = acceptChannel(t, l) // stream A: never read
		chB := acceptChannel(t, l)
		if got := expectComplete(t, chB); string(got) != "ok" {
			t.Fatalf("stream B body = %q, want %q", got, "ok")
		}
		if err := waitErr(peerDone); err != nil {
			t.Fatalf("peer writes: %v", err)
		}
	})
}

// TestStreamWindow_DetachedUnreadStreamDoesNotStallSiblings: a detached
// stream whose byte reader is never read must not stop sibling streams.
func TestStreamWindow_DetachedUnreadStreamDoesNotStallSiblings(t *testing.T) {
	l, p := startWindowPeer(t, startServerLayer)
	p.write(t, func(wr *frame.Writer) error {
		return wr.WriteHeaders(1, false, true, p.encoder.Encode([]hpack.HeaderField{
			{Name: ":method", Value: "CONNECT"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/chat"},
			{Name: ":protocol", Value: "websocket"},
		}))
	})
	chA := acceptChannel(t, l)
	if _, err := nextWithin(chA, wfTimeout); err != nil {
		t.Fatalf("A HEADERS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wfTimeout)
	defer cancel()
	if err := chA.Send(ctx, &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
		Message: &H2HeadersEvent{Status: 200}}); err != nil {
		t.Fatalf("A response HEADERS: %v", err)
	}
	r, _, closer, err := l.DetachStream(1)
	if err != nil {
		t.Fatalf("DetachStream: %v", err)
	}
	defer func() { _ = closer() }()
	_ = r // never read

	peerDone := p.writeAsync(func(wr *frame.Writer) error {
		for i := 0; i < 64; i++ {
			if err := wr.WriteData(1, false, make([]byte, 100)); err != nil {
				return err
			}
		}
		if err := wr.WriteHeaders(3, false, true, p.requestHeaders("/b")); err != nil {
			return err
		}
		return wr.WriteData(3, true, []byte("ok"))
	})
	chB := acceptChannel(t, l)
	if got := expectComplete(t, chB); string(got) != "ok" {
		t.Fatalf("stream B body = %q, want %q", got, "ok")
	}
	if err := waitErr(peerDone); err != nil {
		t.Fatalf("peer writes: %v", err)
	}
}

// TestStreamWindow_StreamCreditFollowsReads: stream-level WINDOW_UPDATE is
// sent for bytes the consumer read, batched at half the advertised stream
// window; connection-level WINDOW_UPDATE still follows arrival (USK-1399
// acceptance 3).
func TestStreamWindow_StreamCreditFollowsReads(t *testing.T) {
	l, p := startWindowPeer(t, startServerLayer, smallWindow())
	p.write(t, func(wr *frame.Writer) error { return wr.WriteHeaders(1, false, true, p.requestHeaders("/up")) })
	ch := acceptChannel(t, l)
	if _, err := nextWithin(ch, wfTimeout); err != nil {
		t.Fatalf("HEADERS: %v", err)
	}

	p.write(t, func(wr *frame.Writer) error {
		for i := 0; i < 4; i++ {
			if err := wr.WriteData(1, false, make([]byte, 10000)); err != nil {
				return err
			}
		}
		return nil
	})
	got := windowUpdates(p.barrier(t, 1))
	if got.connCount != 4 || got.connSum != 40000 {
		t.Errorf("connection WINDOW_UPDATE on arrival = %d frames / %d bytes, want 4 / 40000", got.connCount, got.connSum)
	}
	if got.streamCount[1] != 0 {
		t.Fatalf("stream WINDOW_UPDATE before any read: %v, want none", got.streamIncs[1])
	}

	for i := 0; i < 3; i++ {
		nextData(t, ch)
	}
	if got := windowUpdates(p.barrier(t, 2)); got.streamCount[1] != 0 {
		t.Fatalf("stream WINDOW_UPDATE after reading 30000 bytes (< half window): %v, want none", got.streamIncs[1])
	}

	nextData(t, ch)
	got = windowUpdates(p.barrier(t, 3))
	if got.streamCount[1] != 1 || got.streamSum[1] != 40000 {
		t.Fatalf("stream WINDOW_UPDATE after reading 40000 bytes = %v, want exactly one of 40000", got.streamIncs[1])
	}
}

// TestStreamWindow_PaddingCredit: padding never reaches the consumer, so its
// stream credit is returned at arrival and rides the next batch; the total
// stream credit equals the sum of DATA frame lengths.
func TestStreamWindow_PaddingCredit(t *testing.T) {
	l, p := startWindowPeer(t, startServerLayer, smallWindow())
	p.write(t, func(wr *frame.Writer) error { return wr.WriteHeaders(1, false, true, p.requestHeaders("/pad")) })
	ch := acceptChannel(t, l)
	if _, err := nextWithin(ch, wfTimeout); err != nil {
		t.Fatalf("HEADERS: %v", err)
	}

	// Phase 1: 128 padding-only frames (Length 256 each = 32768 bytes, all
	// padding). No Next: the credit is returned without any read.
	p.write(t, func(wr *frame.Writer) error {
		for i := 0; i < 128; i++ {
			if err := wr.WriteRawBytes(paddedData(1, nil, 255)); err != nil {
				return err
			}
		}
		return nil
	})
	got := windowUpdates(p.barrier(t, 1))
	if got.streamCount[1] != 1 || got.streamSum[1] != 32768 {
		t.Fatalf("padding-only frames: stream WINDOW_UPDATE = %v, want exactly one of 32768", got.streamIncs[1])
	}

	// Phase 2: 15 frames of 2000 payload + 255 padding (Length 2256 each).
	// The padding credit (15*256) arrives first; the threshold is crossed
	// only by the last read: 3840 + 14*2000 = 31840 < 32767 <= 33840.
	p.write(t, func(wr *frame.Writer) error {
		for i := 0; i < 15; i++ {
			if err := wr.WriteRawBytes(paddedData(1, bytes.Repeat([]byte{'x'}, 2000), 255)); err != nil {
				return err
			}
		}
		return nil
	})
	read := 0
	for read < 14 {
		if d := nextData(t, ch); len(d.Payload) == 2000 {
			read++
		}
	}
	if got := windowUpdates(p.barrier(t, 2)); got.streamCount[1] != 0 {
		t.Fatalf("stream WINDOW_UPDATE before the batch threshold: %v, want none", got.streamIncs[1])
	}
	if d := nextData(t, ch); len(d.Payload) != 2000 {
		t.Fatalf("15th payload = %d bytes, want 2000", len(d.Payload))
	}
	got = windowUpdates(p.barrier(t, 3))
	if got.streamCount[1] != 1 || got.streamSum[1] != 15*2256 {
		t.Fatalf("stream WINDOW_UPDATE after all reads = %v, want exactly one of %d (sum of frame lengths)", got.streamIncs[1], 15*2256)
	}
}

// TestStreamWindow_PeerExceedsStreamWindow: DATA beyond the advertised stream
// window is a stream error FLOW_CONTROL_ERROR (RFC 9113 §6.9.1): the stream
// is reset, its connection credit is returned, and the connection stays up.
func TestStreamWindow_PeerExceedsStreamWindow(t *testing.T) {
	l, p := startWindowPeer(t, startServerLayer, smallWindow())
	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(1, false, true, p.requestHeaders("/a")); err != nil {
			return err
		}
		for i := 0; i < 4; i++ { // 4 * 16384 = 65536 = window + 1
			if err := wr.WriteData(1, false, make([]byte, 16384)); err != nil {
				return err
			}
		}
		return nil
	})
	chA := acceptChannel(t, l)
	frames := p.barrier(t, 1)
	code, ok := rstCode(frames, 1)
	if !ok || code != ErrCodeFlowControl {
		t.Fatalf("frames %v: want RST_STREAM(1, FLOW_CONTROL_ERROR)", summarize(frames))
	}
	if got := windowUpdates(frames); got.connSum != 65536 {
		t.Errorf("connection credit = %d, want 65536 (every DATA byte, including the rejected frame)", got.connSum)
	}

	for {
		_, err := nextWithin(chA, wfTimeout)
		if err == nil {
			continue
		}
		var se *layer.StreamError
		if !errors.As(err, &se) {
			t.Fatalf("stream A ended with %v, want *layer.StreamError", err)
		}
		break
	}

	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(3, false, true, p.requestHeaders("/b")); err != nil {
			return err
		}
		return wr.WriteData(3, true, []byte("ok"))
	})
	if got := expectComplete(t, acceptChannel(t, l)); string(got) != "ok" {
		t.Fatalf("stream B body = %q, want %q", got, "ok")
	}
}

// TestStreamWindow_LocalWindowRaisedBeforeWindowUpdateWrite: the Layer's own
// receive window must include a credit before the WINDOW_UPDATE carrying it
// can reach the peer, or bytes the peer sends the moment it reads the
// update are counted against a stale window (spurious FLOW_CONTROL_ERROR).
func TestStreamWindow_LocalWindowRaisedBeforeWindowUpdateWrite(t *testing.T) {
	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hook := func(streamID uint32) {
		if streamID == 0 {
			return
		}
		first := false
		once.Do(func() { first = true; close(reached) })
		if first {
			select {
			case <-release:
			case <-time.After(2 * wfTimeout):
			}
		}
	}
	l, p := startWindowPeer(t, startServerLayer, smallWindow(), withAfterWindowUpdateWrite(hook))
	var relOnce sync.Once
	releaseWriter := func() { relOnce.Do(func() { close(release) }) }
	defer releaseWriter()

	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(1, false, true, p.requestHeaders("/a")); err != nil {
			return err
		}
		for _, n := range []int{16384, 16384, 16384, 16383} { // exactly the 65535 window
			if err := wr.WriteData(1, false, make([]byte, n)); err != nil {
				return err
			}
		}
		return nil
	})
	ch := acceptChannel(t, l)
	read := 0
	for read < 65535 {
		read += len(nextData(t, ch).Payload)
	}

	// The writer is now paused right after the first stream WINDOW_UPDATE hit
	// the socket. Spend the granted credit immediately.
	wu := p.until(t, func(f wfFrame) bool { return f.typ == frame.TypeWindowUpdate && f.streamID == 1 })
	inc := wu[len(wu)-1].inc
	select {
	case <-reached:
	case <-time.After(wfTimeout):
		t.Fatal("writer hook not reached")
	}
	p.write(t, func(wr *frame.Writer) error {
		for left := int(inc); left > 0; {
			n := left
			if n > 16384 {
				n = 16384
			}
			if err := wr.WriteData(1, false, make([]byte, n)); err != nil {
				return err
			}
			left -= n
		}
		return nil
	})
	if d := nextData(t, ch); len(d.Payload) == 0 {
		t.Fatal("granted DATA not delivered")
	}
	releaseWriter()
	if frames := p.barrier(t, 1); len(frames) > 0 {
		if code, ok := rstCode(frames, 1); ok {
			t.Fatalf("stream reset with %s after the peer spent granted credit", ErrCodeString(code))
		}
	}
}

// TestStreamWindow_EventCapResetsStream: a peer flooding a stream with
// zero-length DATA (not flow-controlled) is reset with ENHANCE_YOUR_CALM once
// the stream's queue holds the per-stream event cap; siblings are unaffected.
func TestStreamWindow_EventCapResetsStream(t *testing.T) {
	l, p := startWindowPeer(t, startServerLayer, smallWindow())
	const eventCap = 1024 // max(1024, 65535/1024)
	peerDone := p.writeAsync(func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(1, false, true, p.requestHeaders("/flood")); err != nil {
			return err
		}
		for i := 0; i < eventCap+1; i++ {
			if err := wr.WriteData(1, false, nil); err != nil {
				return err
			}
		}
		if err := wr.WriteHeaders(3, false, true, p.requestHeaders("/b")); err != nil {
			return err
		}
		return wr.WriteData(3, true, []byte("ok"))
	})
	chA := acceptChannel(t, l)
	chB := acceptChannel(t, l)
	if got := expectComplete(t, chB); string(got) != "ok" {
		t.Fatalf("stream B body = %q, want %q", got, "ok")
	}
	if err := waitErr(peerDone); err != nil {
		t.Fatalf("peer writes: %v", err)
	}
	frames := p.barrier(t, 1)
	if code, ok := rstCode(frames, 1); !ok || code != ErrCodeEnhanceYourCalm {
		t.Fatalf("frames %v: want RST_STREAM(1, ENHANCE_YOUR_CALM)", summarize(frames))
	}
	events := 0
	for {
		_, err := nextWithin(chA, wfTimeout)
		if err == nil {
			events++
			continue
		}
		var se *layer.StreamError
		if !errors.As(err, &se) {
			t.Fatalf("stream A ended with %v after %d events, want *layer.StreamError", err, events)
		}
		break
	}
	if events == 0 {
		t.Error("queued events were not delivered before the stream error")
	}
}

// TestStreamWindow_NoCreditAfterEndStream: reading the rest of a stream whose
// END_STREAM has been received sends no stream WINDOW_UPDATE (the peer can
// send no more DATA on it).
func TestStreamWindow_NoCreditAfterEndStream(t *testing.T) {
	l, p := startWindowPeer(t, startServerLayer, smallWindow())
	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(1, false, true, p.requestHeaders("/a")); err != nil {
			return err
		}
		for i := 0; i < 4; i++ {
			if err := wr.WriteData(1, i == 3, make([]byte, 10000)); err != nil {
				return err
			}
		}
		return nil
	})
	ch := acceptChannel(t, l)
	_ = p.barrier(t, 1) // every frame, END_STREAM included, has been handled
	if got := expectComplete(t, ch); len(got) != 40000 {
		t.Fatalf("body = %d bytes, want 40000", len(got))
	}
	if got := windowUpdates(p.barrier(t, 2)); got.streamCount[1] != 0 {
		t.Fatalf("stream WINDOW_UPDATE after END_STREAM: %v, want none", got.streamIncs[1])
	}
}

// TestStreamWindow_CloseReleasesQueue: closing a stream with unread events
// releases them, resets the stream, and later DATA on it only returns
// connection credit; the connection stays usable.
func TestStreamWindow_CloseReleasesQueue(t *testing.T) {
	l, p := startWindowPeer(t, startServerLayer, smallWindow())
	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(1, false, true, p.requestHeaders("/a")); err != nil {
			return err
		}
		for i := 0; i < 3; i++ {
			if err := wr.WriteData(1, false, make([]byte, 10000)); err != nil {
				return err
			}
		}
		return nil
	})
	ch := acceptChannel(t, l).(*channel)
	_ = p.barrier(t, 1)
	if n := ch.queuedEvents(); n != 4 {
		t.Fatalf("queued events before Close = %d, want 4 (HEADERS + 3 DATA)", n)
	}
	_ = ch.Close()
	if n := ch.queuedEvents(); n != 0 {
		t.Fatalf("queued events after Close = %d, want 0", n)
	}
	frames := p.until(t, func(f wfFrame) bool { return f.typ == frame.TypeRSTStream && f.streamID == 1 })
	if code := frames[len(frames)-1].code; code != ErrCodeCancel {
		t.Fatalf("RST_STREAM code = %s, want CANCEL", ErrCodeString(code))
	}

	p.write(t, func(wr *frame.Writer) error { return wr.WriteData(1, false, make([]byte, 5000)) })
	got := windowUpdates(p.barrier(t, 2))
	if got.connSum != 5000 || got.streamCount[1] != 0 {
		t.Fatalf("late DATA on a reset stream: conn credit %d (want 5000), stream updates %v (want none)", got.connSum, got.streamIncs[1])
	}

	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(3, false, true, p.requestHeaders("/b")); err != nil {
			return err
		}
		return wr.WriteData(3, true, []byte("ok"))
	})
	if body := expectComplete(t, acceptChannel(t, l)); string(body) != "ok" {
		t.Fatalf("stream B body = %q, want %q", body, "ok")
	}
}

// informationalHeaders encodes a 1xx response header block carrying one
// large header, so a few blocks exceed a small stream window in bytes while
// staying far below the per-stream event cap.
func (p *wfPeer) informationalHeaders(size int) []byte {
	return p.encoder.Encode([]hpack.HeaderField{
		{Name: ":status", Value: "103"},
		{Name: "link", Value: string(bytes.Repeat([]byte{'l'}, size))},
	})
}

// writeHeaderBlock writes block on streamID as HEADERS (no END_STREAM)
// followed by as many CONTINUATION frames as the default maximum frame size
// requires.
func writeHeaderBlock(wr *frame.Writer, streamID uint32, block []byte) error {
	const maxFrame = frame.DefaultMaxFrameSize
	first := block
	if len(first) > maxFrame {
		first = first[:maxFrame]
	}
	rest := block[len(first):]
	if err := wr.WriteHeaders(streamID, false, len(rest) == 0, first); err != nil {
		return err
	}
	for len(rest) > 0 {
		n := len(rest)
		if n > maxFrame {
			n = maxFrame
		}
		if err := wr.WriteContinuation(streamID, n == len(rest), rest[:n]); err != nil {
			return err
		}
		rest = rest[n:]
	}
	return nil
}

// openGET opens a client stream and sends a bodyless GET on it.
func openGET(ctx context.Context, t *testing.T, l *Layer, path string) layer.Channel {
	t.Helper()
	ch, err := l.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := ch.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Message: &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: path, EndStream: true}}); err != nil {
		t.Fatalf("Send HEADERS: %v", err)
	}
	return ch
}

// TestStreamWindow_QueuedHeaderBlockBudgetResetsStream: header blocks carry
// no flow-control credit, so the bytes of the header blocks one stream
// queues unread (here 1xx responses, which a peer may send any number of)
// are bounded by a budget equal to the advertised stream window. A breach
// resets the stream with ENHANCE_YOUR_CALM long before the event cap; the
// consumer gets the queued events, then the stream error; siblings are
// unaffected.
func TestStreamWindow_QueuedHeaderBlockBudgetResetsStream(t *testing.T) {
	l, p := startWindowPeer(t, startClientLayer, smallWindow())
	ctx, cancel := context.WithTimeout(context.Background(), wfTimeout)
	defer cancel()
	chA := openGET(ctx, t, l, "/a")
	chB := openGET(ctx, t, l, "/b")
	idA, idB := chA.(*channel).H2StreamID(), chB.(*channel).H2StreamID()

	// 32 blocks of ~10 KB raw + ~10 KB decoded each: ~640 KB of queued
	// header bytes against a 65535-byte budget, and 32 events against a
	// 1024-event cap.
	const blocks = 32
	peerDone := p.writeAsync(func(wr *frame.Writer) error {
		for i := 0; i < blocks; i++ {
			if err := wr.WriteHeaders(idA, false, true, p.informationalHeaders(10000)); err != nil {
				return err
			}
		}
		if err := wr.WriteHeaders(idB, false, true, p.statusHeaders()); err != nil {
			return err
		}
		return wr.WriteData(idB, true, []byte("ok"))
	})
	if got := expectComplete(t, chB); string(got) != "ok" {
		t.Fatalf("stream B body = %q, want %q", got, "ok")
	}
	if err := waitErr(peerDone); err != nil {
		t.Fatalf("peer writes: %v", err)
	}
	frames := p.barrier(t, 1)
	if code, ok := rstCode(frames, idA); !ok || code != ErrCodeEnhanceYourCalm {
		t.Fatalf("frames %v: want RST_STREAM(%d, ENHANCE_YOUR_CALM)", summarize(frames), idA)
	}
	events := 0
	for {
		_, err := nextWithin(chA, wfTimeout)
		if err == nil {
			events++
			continue
		}
		var se *layer.StreamError
		if !errors.As(err, &se) {
			t.Fatalf("stream A ended with %v after %d events, want *layer.StreamError", err, events)
		}
		break
	}
	if events == 0 || events >= blocks {
		t.Errorf("stream A delivered %d events before the stream error, want between 1 and %d", events, blocks-1)
	}
}

// TestStreamWindow_ReadingConsumerTakesManyLargeHeaderBlocks: the queued
// header-block budget bounds what waits unread, not what a peer may send. A
// consumer that takes each 1xx block as it arrives receives every one of
// them, and the final response, with no reset — even when one block alone
// is larger than the budget.
func TestStreamWindow_ReadingConsumerTakesManyLargeHeaderBlocks(t *testing.T) {
	l, p := startWindowPeer(t, startClientLayer, smallWindow())
	ctx, cancel := context.WithTimeout(context.Background(), wfTimeout)
	defer cancel()
	ch := openGET(ctx, t, l, "/a")
	id := ch.(*channel).H2StreamID()

	const blocks = 32
	for i := 0; i < blocks; i++ {
		p.write(t, func(wr *frame.Writer) error {
			return writeHeaderBlock(wr, id, p.informationalHeaders(40000))
		})
		env, err := nextWithin(ch, wfTimeout)
		if err != nil {
			t.Fatalf("1xx block %d: %v", i, err)
		}
		if h, ok := env.Message.(*H2HeadersEvent); !ok || h.Status != 103 {
			t.Fatalf("1xx block %d: got %T, want 103 HEADERS", i, env.Message)
		}
	}
	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(id, false, true, p.statusHeaders()); err != nil {
			return err
		}
		return wr.WriteData(id, true, []byte("ok"))
	})
	if got := expectComplete(t, ch); string(got) != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
	if code, ok := rstCode(p.barrier(t, 1), id); ok {
		t.Fatalf("stream reset with %s while its consumer kept reading", ErrCodeString(code))
	}
}

// TestStreamWindow_RepeatedOverWindowDataResetsOnce: further over-window DATA
// on a stream whose FLOW_CONTROL_ERROR reset is queued but not yet written
// queues no second RST_STREAM; its connection credit is still returned.
func TestStreamWindow_RepeatedOverWindowDataResetsOnce(t *testing.T) {
	var armed atomic.Bool
	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hook := func(streamID uint32) {
		if streamID != 0 || !armed.Load() {
			return
		}
		first := false
		once.Do(func() { first = true; close(reached) })
		if first {
			select {
			case <-release:
			case <-time.After(2 * wfTimeout):
			}
		}
	}
	l, p := startWindowPeer(t, startServerLayer, smallWindow(), withAfterWindowUpdateWrite(hook))
	var relOnce sync.Once
	releaseWriter := func() { relOnce.Do(func() { close(release) }) }
	defer releaseWriter()

	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteHeaders(1, false, true, p.requestHeaders("/a")); err != nil {
			return err
		}
		for i := 0; i < 3; i++ { // 49152 of the 65535 window
			if err := wr.WriteData(1, false, make([]byte, 16384)); err != nil {
				return err
			}
		}
		return nil
	})
	_ = acceptChannel(t, l)
	_ = p.barrier(t, 1)

	// Hold the writer right after the first over-window frame's connection
	// WINDOW_UPDATE, so the RST_STREAM queued behind it is not yet written
	// (the stream stays open) when the second over-window frame is read.
	armed.Store(true)
	p.write(t, func(wr *frame.Writer) error { return wr.WriteData(1, false, make([]byte, 16384)) })
	select {
	case <-reached:
	case <-time.After(wfTimeout):
		t.Fatal("writer hook not reached")
	}
	// The PING is read only after the second DATA frame has been handled.
	p.write(t, func(wr *frame.Writer) error {
		if err := wr.WriteData(1, false, make([]byte, 16384)); err != nil {
			return err
		}
		return wr.WritePing(false, [8]byte{'h', 'a', 'n', 'd', 'l', 'e', 'd'})
	})
	releaseWriter()

	frames := p.barrier(t, 2)
	rsts := 0
	for _, f := range frames {
		if f.typ == frame.TypeRSTStream && f.streamID == 1 {
			rsts++
			if f.code != ErrCodeFlowControl {
				t.Errorf("RST_STREAM code = %s, want FLOW_CONTROL_ERROR", ErrCodeString(f.code))
			}
		}
	}
	if rsts != 1 {
		t.Errorf("frames %v: %d RST_STREAM on stream 1, want exactly 1", summarize(frames), rsts)
	}
	if got := windowUpdates(frames); got.connSum != 2*16384 {
		t.Errorf("connection credit for the two over-window frames = %d, want %d", got.connSum, 2*16384)
	}
}

// TestChannelNext_QueuedEventsPrecedeStreamError: when Next's wait picks the
// stream error while events are queued, it must still return every queued
// event first, then the error. In production the wait sees the queue
// notification and the error ready at once when the reader queues the last
// events and fails the stream between Next's empty pop and its select, and
// select then picks either; that window is too narrow to hit reliably, so
// the test queues the events without a notification, leaving the error as
// the only thing that wakes the waiting Next.
func TestChannelNext_QueuedEventsPrecedeStreamError(t *testing.T) {
	l, _, cleanup := startServerLayer(t)
	t.Cleanup(cleanup)
	const iterations = 200
	const events = 3
	type result struct {
		n   int
		err error
	}
	for it := 0; it < iterations; it++ {
		ch := newChannel(l, 1)
		resc := make(chan result, 1)
		go func() {
			n := 0
			for {
				_, err := ch.Next(context.Background())
				if err != nil {
					resc <- result{n, err}
					return
				}
				n++
			}
		}()
		// Give Next the chance to park on the empty queue.
		for i := 0; i < 4; i++ {
			runtime.Gosched()
		}
		time.Sleep(20 * time.Microsecond)

		// failStream's producer order: queued events, errCh, terminate,
		// close the receive side. The events are queued without waking the
		// consumer (see above).
		ch.qMu.Lock()
		for i := 0; i < events; i++ {
			ch.q = append(ch.q, queuedEvent{env: newDetachDataEnvelope([]byte{byte(i)}, false)})
		}
		ch.qMu.Unlock()
		se := &layer.StreamError{Code: layer.ErrorProtocol, Reason: "test"}
		ch.errCh <- se
		ch.markTerminated(se)
		ch.closeRecv()

		select {
		case r := <-resc:
			if r.n != events {
				t.Fatalf("iteration %d: Next returned %d events before %v, want %d", it, r.n, r.err, events)
			}
			if !errors.Is(r.err, se) {
				t.Fatalf("iteration %d: Next ended with %v, want the stream error", it, r.err)
			}
		case <-time.After(wfTimeout):
			t.Fatalf("iteration %d: Next did not return", it)
		}
	}
}
