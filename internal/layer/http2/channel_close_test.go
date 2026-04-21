package http2

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// TestChannel_Close_SkipsRSTOnBilateralEndStream is the USK-618 acceptance
// guard: when both sides have sent END_STREAM (sentEndStream && recvEndStream),
// Close must NOT emit RST_STREAM. Emitting RST on a wire-closed stream
// violates RFC 9113 §5.1 and provokes a peer PROTOCOL_ERROR + GOAWAY that
// aborts every other concurrent stream on the shared connection — the
// production failure pattern that USK-613's
// TestMultipleConcurrentStreams_RecordingIsolation caught.
func TestChannel_Close_SkipsRSTOnBilateralEndStream(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/",
	}
	env := &envelope.Envelope{
		StreamID:  ch.StreamID(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, env)
	}()

	// Drain the outbound HEADERS (our request). The request has no body, so
	// END_STREAM is on the HEADERS frame — no DATA follows.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read request HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("got %s, want HEADERS", f.Header.Type)
	}
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Fatalf("request HEADERS missing END_STREAM (expected GET with no body)")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Peer sends the response: HEADERS with END_STREAM, no body. This drives
	// the Layer's reader to asmDone → markRecvEnded.
	respHeaders := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
	}
	encoded := peer.encoder.Encode(respHeaders)
	if err := peer.wr.WriteHeaders(f.Header.StreamID, true /*endStream*/, true /*endHeaders*/, encoded); err != nil {
		t.Fatalf("write response HEADERS: %v", err)
	}

	ctxCons, cancelCons := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCons()

	// First Next yields the response envelope.
	if _, err := ch.Next(ctxCons); err != nil {
		t.Fatalf("Next (response env): %v", err)
	}
	// Second Next returns io.EOF — this synchronizes the consumer with the
	// reader's close(ch.recv), which in turn happens-after markRecvEnded.
	// By the time we observe EOF, recvEndStream is guaranteed true.
	if _, err := ch.Next(ctxCons); !errors.Is(err, io.EOF) {
		t.Fatalf("Next (EOF): got %v, want io.EOF", err)
	}

	// Both halves have closed on the wire. Close must NOT emit RST_STREAM.
	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Give the writer goroutine a chance to dispatch any pending frame and
	// assert that no unexpected frame arrives. (A RST emitted by the buggy
	// code would flush promptly; a short deadline suffices.)
	assertNoFrame(t, peer, 200*time.Millisecond, "RST must be suppressed after bilateral END_STREAM")
}

// TestChannel_Close_EmitsRSTOnOpenStreamNoSendNoRecv is the abnormal-
// termination companion: opening a stream and closing it without ever sending
// or receiving anything must emit RST_STREAM(CANCEL). The stream is in
// state=open from the peer's perspective — our Close is a legitimate
// cancellation.
func TestChannel_Close_EmitsRSTOnOpenStreamNoSendNoRecv(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	cs := ch.(*channel)

	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	expectRSTStream(t, peer, cs.h2Stream, ErrCodeCancel)
}

// TestChannel_Close_EmitsRSTWhenSendWithoutRecv covers the mid-flight case:
// we successfully sent our request (END_STREAM), but the peer never sent a
// response. recvEndStream stays false, so Close must still RST. This is the
// canonical "upstream hung, local ctx cancelled" scenario.
func TestChannel_Close_EmitsRSTWhenSendWithoutRecv(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	cs := ch.(*channel)

	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/",
	}
	env := &envelope.Envelope{
		StreamID:  ch.StreamID(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}
	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, env)
	}()

	// Drain the outbound HEADERS so Send completes.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("got %s, want HEADERS", f.Header.Type)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}

	// No peer response — recv half is not ended. Close must emit RST.
	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	expectRSTStream(t, peer, cs.h2Stream, ErrCodeCancel)
}

// TestChannel_Close_PushChannelAlwaysRSTs verifies the isPush override:
// even if somehow both halves appeared closed on a push channel, we RST
// because we never wanted the push in the first place (RFC 9113 §8.4).
// We model this by directly constructing a push channel and setting both
// flags. Any future code that accidentally inverted the gate on push would
// fail this test.
func TestChannel_Close_PushChannelAlwaysRSTs(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	// Hand-construct a push channel and register it with the Layer so
	// Close's enqueueWrite can route through the writer.
	const pushID uint32 = 2
	pc := newChannel(l, pushID, true /*isPush*/)
	pc.sentEndStream = true
	pc.recvEndStream = true
	l.registerChannel(pushID, pc)

	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	expectRSTStream(t, peer, pushID, ErrCodeCancel)
}

// expectRSTStream reads frames from peer until a RST_STREAM for streamID is
// observed. Fails on timeout or the first non-RST/wrong-stream frame.
func expectRSTStream(t *testing.T, peer *h2Peer, streamID uint32, wantCode uint32) {
	t.Helper()
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = peer.conn.SetReadDeadline(time.Time{}) }()

	for {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("waiting for RST_STREAM on stream %d: %v", streamID, err)
		}
		// Ignore unrelated connection-level frames (e.g. WINDOW_UPDATE,
		// SETTINGS ACKs) that may land before the RST.
		if f.Header.StreamID != streamID {
			continue
		}
		if f.Header.Type != frame.TypeRSTStream {
			t.Fatalf("stream %d: got %s, want RST_STREAM", streamID, f.Header.Type)
		}
		code, err := f.RSTStreamErrorCode()
		if err != nil {
			t.Fatalf("RSTStreamErrorCode: %v", err)
		}
		if code != wantCode {
			t.Errorf("RST_STREAM code = %d, want %d", code, wantCode)
		}
		return
	}
}

// assertNoFrame asserts that no stream-carrying frame arrives within within.
// Connection-level frames (stream 0) may legitimately arrive (WINDOW_UPDATE,
// PING, etc.) — only a frame on a non-zero stream would indicate a leak.
func assertNoFrame(t *testing.T, peer *h2Peer, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		_ = peer.conn.SetReadDeadline(time.Now().Add(remaining))
		f, err := peer.rd.ReadFrame()
		if err != nil {
			// Any read error here (including deadline) means no surprising
			// frame arrived; reset the deadline and return clean.
			_ = peer.conn.SetReadDeadline(time.Time{})
			if isDeadlineExceeded(err) {
				return
			}
			// A real I/O error is still a clean pass — we were asserting
			// absence of a frame and definitely got none.
			return
		}
		if f.Header.StreamID == 0 {
			// Connection-level frame, not our concern.
			continue
		}
		_ = peer.conn.SetReadDeadline(time.Time{})
		t.Fatalf("%s: got unexpected stream frame type=%s stream=%d flags=0x%x",
			msg, f.Header.Type, f.Header.StreamID, f.Header.Flags)
	}
}

func isDeadlineExceeded(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	// net.Error with Timeout() — covers net.Pipe's timeoutError.
	type timeoutErr interface {
		Timeout() bool
	}
	var te timeoutErr
	if errors.As(err, &te) {
		return te.Timeout()
	}
	return false
}
