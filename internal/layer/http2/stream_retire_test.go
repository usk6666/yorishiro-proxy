package http2

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1144 / USK-1176: a stream that has ended in both directions must leave
// the Layer's bookkeeping (StreamMap, l.assemblers, l.channels, sched.reset)
// so that a long-lived connection is not refused after
// SETTINGS_MAX_CONCURRENT_STREAMS cumulative requests, and so that memory
// does not grow with the number of streams the connection has carried.

var usk1144RequestFields = []hpack.HeaderField{
	{Name: ":method", Value: "GET"},
	{Name: ":scheme", Value: "https"},
	{Name: ":authority", Value: "example.com"},
	{Name: ":path", Value: "/usk-1144"},
}

// mustFragment returns the header block fragment of a HEADERS frame.
func mustFragment(t *testing.T, f *frame.Frame) []byte {
	t.Helper()
	b, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment: %v", err)
	}
	return b
}

// serveBodylessResponses answers every peer stream with a bodyless
// `:status 200` HEADERS(END_STREAM) once the request HEADERS has been read,
// then closes the Channel — the shape of a session finishing a GET.
func serveBodylessResponses(l *Layer) {
	go func() {
		for ch := range l.Channels() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if _, err := ch.Next(ctx); err != nil {
				cancel()
				_ = ch.Close()
				continue
			}
			_ = ch.Send(ctx, &envelope.Envelope{
				Direction: envelope.Receive,
				Message:   &H2HeadersEvent{Status: 200, EndStream: true},
			})
			cancel()
			_ = ch.Close()
		}
	}()
}

// roundTripBodylessGET writes a bodyless GET on sid and reads frames until
// the response HEADERS for sid arrives, failing on RST_STREAM or GOAWAY.
func roundTripBodylessGET(t *testing.T, l *Layer, peer *h2Peer, n int, sid uint32) {
	t.Helper()
	if err := peer.wr.WriteHeaders(sid, true, true, peer.encoder.Encode(usk1144RequestFields)); err != nil {
		t.Fatalf("request #%d (stream %d): write HEADERS: %v", n, sid, err)
	}
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = peer.conn.SetReadDeadline(time.Time{}) }()
	for {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("request #%d (stream %d): read: %v (ActiveCount=%d)", n, sid, err, l.conn.Streams().ActiveCount())
		}
		if f.Header.Type == frame.TypeGoAway {
			_, code, _, _ := f.GoAwayInfo()
			t.Fatalf("request #%d (stream %d): GOAWAY(%s)", n, sid, ErrCodeString(code))
		}
		if f.Header.StreamID != sid {
			continue
		}
		if f.Header.Type == frame.TypeRSTStream {
			code, _ := f.RSTStreamErrorCode()
			t.Fatalf("request #%d (stream %d): RST_STREAM(%s); ActiveCount=%d half-closed(remote)=%d closed=%d",
				n, sid, ErrCodeString(code), l.conn.Streams().ActiveCount(),
				l.conn.Streams().Count(StateHalfClosedRemote), l.conn.Streams().Count(StateClosed))
		}
		if f.Header.Type == frame.TypeHeaders {
			if _, err := peer.decoder.Decode(mustFragment(t, f)); err != nil {
				t.Fatalf("request #%d (stream %d): decode response: %v", n, sid, err)
			}
			return
		}
	}
}

// waitFor polls cond until it reports true or d elapses. The writer
// goroutine retires a stream after the frame that closed it is written, so
// the peer can observe the frame before the bookkeeping is updated.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// layerMapSizes returns len(l.channels) and len(l.assemblers) under l.mu.
func layerMapSizes(l *Layer) (channels, assemblers int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.channels), len(l.assemblers)
}

// streamMapSize returns the number of StreamMap entries under its lock.
func streamMapSize(l *Layer) int {
	sm := l.conn.Streams()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return len(sm.streams)
}

// TestLayer_ServerRole_SequentialRequestsBeyondMaxConcurrentStreams pins the
// USK-1144 reproduction: with the default SETTINGS_MAX_CONCURRENT_STREAMS
// (500), the 501st sequential request on one connection used to be refused
// because completed streams stayed half-closed (remote) forever.
func TestLayer_ServerRole_SequentialRequestsBeyondMaxConcurrentStreams(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	limit := int(l.conn.LocalSettings().MaxConcurrentStreams)
	if limit == 0 {
		t.Fatal("test requires a non-zero advertised MAX_CONCURRENT_STREAMS")
	}
	total := limit + 1

	serveBodylessResponses(l)
	for i := 0; i < total; i++ {
		roundTripBodylessGET(t, l, peer, i+1, uint32(2*i+1))
	}

	if !waitFor(2*time.Second, func() bool { return l.conn.Streams().ActiveCount() == 0 }) {
		t.Errorf("ServerRole ActiveCount after %d completed exchanges = %d, want 0", total, l.conn.Streams().ActiveCount())
	}
}

// TestLayer_ClientRole_ActiveStreamCountReturnsToZero pins that a ClientRole
// (upstream-side) Layer stops counting streams whose request and response
// have both ended — the count the upstream pool's capacity check reads.
func TestLayer_ClientRole_ActiveStreamCountReturnsToZero(t *testing.T) {
	const total = 10
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	for i := 0; i < total; i++ {
		ch, err := l.OpenStream(context.Background())
		if err != nil {
			t.Fatalf("exchange #%d: OpenStream: %v", i+1, err)
		}
		sendErr := make(chan error, 1)
		go func() {
			sendErr <- ch.Send(context.Background(), &envelope.Envelope{
				Direction: envelope.Send,
				Message:   &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true},
			})
		}()
		f := drainUntil(t, peer, frame.TypeHeaders)
		if err := <-sendErr; err != nil {
			t.Fatalf("exchange #%d: Send: %v", i+1, err)
		}
		if _, err := peer.decoder.Decode(mustFragment(t, f)); err != nil {
			t.Fatalf("exchange #%d: decode request: %v", i+1, err)
		}
		resp := peer.encoder.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
		if err := peer.wr.WriteHeaders(f.Header.StreamID, true, true, resp); err != nil {
			t.Fatalf("exchange #%d: write response: %v", i+1, err)
		}
		if _, err := nextWithin(ch, 2*time.Second); err != nil {
			t.Fatalf("exchange #%d: Next: %v", i+1, err)
		}
		_, _ = nextWithin(ch, 2*time.Second) // io.EOF
		_ = ch.Close()
	}

	if !waitFor(2*time.Second, func() bool { return l.ActiveStreamCount() == 0 }) {
		t.Errorf("ClientRole ActiveStreamCount after %d completed exchanges = %d, want 0", total, l.ActiveStreamCount())
	}
}

// TestLayer_ServerRole_ChannelsPrunedAfterSequentialStreams pins USK-1176:
// the per-stream maps do not keep growing across sequential streams, and a
// finished stream can no longer be detached.
func TestLayer_ServerRole_ChannelsPrunedAfterSequentialStreams(t *testing.T) {
	const total = 50
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	serveBodylessResponses(l)
	for i := 0; i < total; i++ {
		roundTripBodylessGET(t, l, peer, i+1, uint32(2*i+1))
	}

	ok := waitFor(2*time.Second, func() bool {
		c, a := layerMapSizes(l)
		return c == 0 && a == 0 && streamMapSize(l) == 0
	})
	if !ok {
		c, a := layerMapSizes(l)
		t.Errorf("after %d finished streams: len(channels)=%d len(assemblers)=%d len(StreamMap)=%d, want 0/0/0",
			total, c, a, streamMapSize(l))
	}

	_, _, _, err := l.DetachStream(1)
	if err == nil {
		t.Fatal("DetachStream on a finished stream succeeded, want a \"not registered\" error")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("DetachStream on a finished stream: err = %v, want \"not registered\"", err)
	}
}

// TestLayer_ServerRole_LateWindowUpdateAndRSTOnClosedStream pins RFC 9113
// §5.1 ("closed"): WINDOW_UPDATE and RST_STREAM can arrive for a short
// period after a stream closed and must be ignored — no RST_STREAM, no
// GOAWAY, and the connection keeps serving.
func TestLayer_ServerRole_LateWindowUpdateAndRSTOnClosedStream(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	serveBodylessResponses(l)
	roundTripBodylessGET(t, l, peer, 1, 1)
	// Let the stream retire so the late frames hit the closed-stream path.
	if !waitFor(time.Second, func() bool { return streamMapSize(l) == 0 }) {
		t.Fatalf("stream 1 not retired: len(StreamMap)=%d", streamMapSize(l))
	}

	if err := peer.wr.WriteWindowUpdate(1, 1024); err != nil {
		t.Fatalf("write late WINDOW_UPDATE: %v", err)
	}
	if err := peer.wr.WriteRSTStream(1, ErrCodeCancel); err != nil {
		t.Fatalf("write late RST_STREAM: %v", err)
	}
	// A frame for stream 1 in the reply stream would be a violation; the
	// round trip on stream 3 fails on RST_STREAM/GOAWAY for stream 3 or
	// on a read error if the connection was dropped.
	//
	// The write runs concurrently with the reads: if the Layer dropped the
	// connection its reader no longer drains the synchronous pipe, so a
	// write here would block while the Layer's writer blocks on its GOAWAY.
	frag3 := peer.encoder.Encode(usk1144RequestFields)
	go func() { _ = peer.wr.WriteHeaders(3, true, true, frag3) }()
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("connection dropped after late frames on closed stream 1: %v", err)
		}
		switch {
		case f.Header.Type == frame.TypeGoAway:
			_, code, _, _ := f.GoAwayInfo()
			t.Fatalf("GOAWAY(%s) after late frames on closed stream 1", ErrCodeString(code))
		case f.Header.Type == frame.TypeRSTStream:
			code, _ := f.RSTStreamErrorCode()
			t.Fatalf("RST_STREAM(%s) on stream %d after late frames on closed stream 1", ErrCodeString(code), f.Header.StreamID)
		case f.Header.Type == frame.TypeHeaders && f.Header.StreamID == 3:
			return
		}
	}
}

// TestLayer_ServerRole_HeadersOnClosedPeerStreamIsConnectionError pins
// RFC 9113 §5.1.1: a peer may not reuse a stream id. HEADERS on a stream
// that already closed is a connection error PROTOCOL_ERROR and must never
// open a new stream (a new Channel).
func TestLayer_ServerRole_HeadersOnClosedPeerStreamIsConnectionError(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	emitted := make(chan layer.Channel, 4)
	go func() {
		first := true
		for ch := range l.Channels() {
			if !first {
				emitted <- ch
				_ = ch.Close()
				continue
			}
			first = false
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if _, err := ch.Next(ctx); err == nil {
				_ = ch.Send(ctx, &envelope.Envelope{
					Direction: envelope.Receive,
					Message:   &H2HeadersEvent{Status: 200, EndStream: true},
				})
			}
			cancel()
			_ = ch.Close()
		}
	}()

	roundTripBodylessGET(t, l, peer, 1, 1)
	if !waitFor(time.Second, func() bool { return streamMapSize(l) == 0 }) {
		t.Fatalf("stream not retired: len(StreamMap)=%d", streamMapSize(l))
	}

	if err := peer.wr.WriteHeaders(1, true, true, peer.encoder.Encode(usk1144RequestFields)); err != nil {
		t.Fatalf("write HEADERS reusing stream 1: %v", err)
	}
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v (want GOAWAY PROTOCOL_ERROR for HEADERS reusing closed stream 1)", err)
		}
		if f.Header.Type == frame.TypeGoAway {
			_, code, _, _ := f.GoAwayInfo()
			if code != ErrCodeProtocol {
				t.Errorf("GOAWAY code = %s, want PROTOCOL_ERROR", ErrCodeString(code))
			}
			break
		}
	}
	select {
	case ch := <-emitted:
		t.Errorf("HEADERS reusing closed stream 1 emitted a new Channel %s", ch.StreamID())
	default:
	}
}

// TestLayer_ClientRole_LateDataAfterLocalResetKeepsConnection pins RFC 9113
// §5.1 ("closed"): after this endpoint sent RST_STREAM, frames the peer had
// already queued must be ignored. DATA still counts against the connection
// receive window, so a connection-level WINDOW_UPDATE must replenish it, and
// the connection must keep working.
func TestLayer_ClientRole_LateDataAfterLocalResetKeepsConnection(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message:   &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", EndStream: true},
		})
	}()
	f := drainUntil(t, peer, frame.TypeHeaders)
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
	sid := f.Header.StreamID
	if _, err := peer.decoder.Decode(mustFragment(t, f)); err != nil {
		t.Fatalf("decode request: %v", err)
	}

	// Abandon the stream before any response: Close emits RST_STREAM(CANCEL).
	_ = ch.Close()
	rst := drainUntil(t, peer, frame.TypeRSTStream)
	if rst.Header.StreamID != sid {
		t.Fatalf("RST_STREAM on stream %d, want %d", rst.Header.StreamID, sid)
	}
	if !waitFor(time.Second, func() bool { return streamMapSize(l) == 0 }) {
		t.Fatalf("stream not retired: len(StreamMap)=%d", streamMapSize(l))
	}

	// The peer had already queued a response.
	resp := peer.encoder.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
	if err := peer.wr.WriteHeaders(sid, false, true, resp); err != nil {
		t.Fatalf("write late HEADERS: %v", err)
	}
	const lateLen = 100
	if err := peer.wr.WriteData(sid, true, make([]byte, lateLen)); err != nil {
		t.Fatalf("write late DATA: %v", err)
	}

	sawConnWU := false
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for !sawConnWU {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read after late DATA: %v (connection dropped, or no connection-level WINDOW_UPDATE)", err)
		}
		switch f.Header.Type {
		case frame.TypeGoAway:
			_, code, _, _ := f.GoAwayInfo()
			t.Fatalf("GOAWAY(%s) after late DATA on reset stream %d", ErrCodeString(code), sid)
		case frame.TypeRSTStream:
			code, _ := f.RSTStreamErrorCode()
			t.Fatalf("RST_STREAM(%s) on stream %d after late DATA", ErrCodeString(code), f.Header.StreamID)
		case frame.TypeWindowUpdate:
			inc, _ := f.WindowUpdateIncrement()
			if f.Header.StreamID == 0 && inc == lateLen {
				sawConnWU = true
			}
		}
	}
	_ = peer.conn.SetReadDeadline(time.Time{})

	// The connection still opens and completes a new stream.
	ch2, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream after late DATA: %v", err)
	}
	defer ch2.Close()
	go func() {
		sendErr <- ch2.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send,
			Message:   &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/2", EndStream: true},
		})
	}()
	f2 := drainUntil(t, peer, frame.TypeHeaders)
	if err := <-sendErr; err != nil {
		t.Fatalf("Send on second stream: %v", err)
	}
	if f2.Header.StreamID <= sid {
		t.Fatalf("second stream id %d, want > %d", f2.Header.StreamID, sid)
	}
}

// TestLayer_ClientRole_LateHeadersAfterLocalResetKeepsHPACKInSync pins that
// a response HEADERS arriving on a stream this endpoint already reset is
// still HPACK-decoded (RFC 9113 §4.3: every header block updates the
// decoder's dynamic table) before being dropped, so later responses that
// reference the dynamic table decode correctly.
func TestLayer_ClientRole_LateHeadersAfterLocalResetKeepsHPACKInSync(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	peer.expectSettingsAck(t)

	open := func(path string) (layer.Channel, uint32) {
		t.Helper()
		ch, err := l.OpenStream(context.Background())
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		sendErr := make(chan error, 1)
		go func() {
			sendErr <- ch.Send(context.Background(), &envelope.Envelope{
				Direction: envelope.Send,
				Message:   &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: path, EndStream: true},
			})
		}()
		f := drainUntil(t, peer, frame.TypeHeaders)
		if err := <-sendErr; err != nil {
			t.Fatalf("Send: %v", err)
		}
		if _, err := peer.decoder.Decode(mustFragment(t, f)); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return ch, f.Header.StreamID
	}

	ch1, sid1 := open("/1")
	_ = ch1.Close()
	drainUntil(t, peer, frame.TypeRSTStream)
	if !waitFor(time.Second, func() bool { return streamMapSize(l) == 0 }) {
		t.Fatalf("stream not retired: len(StreamMap)=%d", streamMapSize(l))
	}

	// The late response inserts x-usk1144 into the peer encoder's dynamic
	// table (incremental indexing); the next response references it.
	respFields := []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "x-usk1144", Value: "dynamic-table-entry"}}
	if err := peer.wr.WriteHeaders(sid1, true, true, peer.encoder.Encode(respFields)); err != nil {
		t.Fatalf("write late HEADERS: %v", err)
	}

	ch2, sid2 := open("/2")
	defer ch2.Close()
	if err := peer.wr.WriteHeaders(sid2, true, true, peer.encoder.Encode(respFields)); err != nil {
		t.Fatalf("write response on stream %d: %v", sid2, err)
	}
	env, err := nextWithin(ch2, 2*time.Second)
	if err != nil {
		t.Fatalf("Next on stream %d: %v", sid2, err)
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok {
		t.Fatalf("Message = %T, want *H2HeadersEvent", env.Message)
	}
	found := false
	for _, kv := range evt.Headers {
		if kv.Name == "x-usk1144" && kv.Value == "dynamic-table-entry" {
			found = true
		}
	}
	if !found {
		t.Errorf("stream %d response headers = %v, want x-usk1144: dynamic-table-entry (HPACK desync after late HEADERS)", sid2, evt.Headers)
	}
}

// TestLayer_ServerRole_RefusedStreamKeepsHPACKInSync pins that the header
// block of a stream refused for exceeding MAX_CONCURRENT_STREAMS is still
// HPACK-decoded (RFC 9113 §4.3), and that a later frame on the refused id is
// handled as a frame on a closed stream (the refusal closes it, §5.1).
func TestLayer_ServerRole_RefusedStreamKeepsHPACKInSync(t *testing.T) {
	l, peer, cleanup := startServerLayer(t, WithMaxConcurrentStreams(1))
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	// A write into a connection the Layer dropped would block forever on
	// the synchronous pipe; fail instead.
	_ = peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	reqFields := append(append([]hpack.HeaderField(nil), usk1144RequestFields...),
		hpack.HeaderField{Name: "x-usk1144", Value: "dynamic-table-entry"})

	// Stream 1 stays open (no END_STREAM) so stream 3 exceeds the limit.
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(reqFields)); err != nil {
		t.Fatalf("write HEADERS stream 1: %v", err)
	}
	ch1 := acceptChannel(t, l)
	if _, err := nextWithin(ch1, 2*time.Second); err != nil {
		t.Fatalf("stream 1 Next: %v", err)
	}

	// The refused block adds a second dynamic-table entry the next block
	// references.
	refused := append(append([]hpack.HeaderField(nil), reqFields...),
		hpack.HeaderField{Name: "x-usk1144-refused", Value: "second-entry"})
	if err := peer.wr.WriteHeaders(3, true, true, peer.encoder.Encode(refused)); err != nil {
		t.Fatalf("write HEADERS stream 3: %v", err)
	}
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	rst := drainUntil(t, peer, frame.TypeRSTStream)
	_ = peer.conn.SetReadDeadline(time.Time{})
	if code, _ := rst.RSTStreamErrorCode(); rst.Header.StreamID != 3 || code != ErrCodeRefusedStream {
		t.Fatalf("got RST_STREAM(%s) on stream %d, want REFUSED_STREAM on 3", ErrCodeString(code), rst.Header.StreamID)
	}
	// A late frame on the refused (closed) stream is ignored.
	if err := peer.wr.WriteRSTStream(3, ErrCodeCancel); err != nil {
		t.Fatalf("write RST_STREAM stream 3: %v", err)
	}

	// Finish stream 1 so stream 5 fits under the limit.
	if err := peer.wr.WriteData(1, true, nil); err != nil {
		t.Fatalf("write END_STREAM stream 1: %v", err)
	}
	_, _ = nextWithin(ch1, 2*time.Second)
	sendErr := make(chan error, 1)
	go func() {
		sendErr <- ch1.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Receive,
			Message:   &H2HeadersEvent{Status: 200, EndStream: true},
		})
	}()
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	drainUntil(t, peer, frame.TypeHeaders)
	_ = peer.conn.SetReadDeadline(time.Time{})
	if err := <-sendErr; err != nil {
		t.Fatalf("stream 1 response: %v", err)
	}
	_ = ch1.Close()
	if !waitFor(time.Second, func() bool { return l.conn.Streams().ActiveCount() == 0 }) {
		t.Fatalf("stream 1 not retired: ActiveCount=%d", l.conn.Streams().ActiveCount())
	}

	if err := peer.wr.WriteHeaders(5, true, true, peer.encoder.Encode(refused)); err != nil {
		t.Fatalf("write HEADERS stream 5: %v", err)
	}
	ch5 := acceptChannel(t, l)
	defer ch5.Close()
	env, err := nextWithin(ch5, 2*time.Second)
	if err != nil {
		t.Fatalf("stream 5 Next: %v (connection dropped after refused stream?)", err)
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok {
		t.Fatalf("Message = %T, want *H2HeadersEvent", env.Message)
	}
	found := false
	for _, kv := range evt.Headers {
		if kv.Name == "x-usk1144-refused" && kv.Value == "second-entry" {
			found = true
		}
	}
	if !found {
		t.Errorf("stream 5 headers = %v, want x-usk1144-refused: second-entry (HPACK desync after refused stream)", evt.Headers)
	}
}

// usk1144TrailerEntry is a header the peer's late trailers insert into its
// HPACK encoder's dynamic table; the next header block references it.
var usk1144TrailerEntry = hpack.HeaderField{Name: "x-usk1144-trailer", Value: "late-trailer-entry"}

// writeLateTrailers writes a trailers block (HEADERS with END_STREAM but
// without END_HEADERS, then a CONTINUATION) on sid, so both the HEADERS and
// the CONTINUATION routing of a closed stream are exercised.
func writeLateTrailers(peer *h2Peer, sid uint32) error {
	frag := peer.encoder.Encode([]hpack.HeaderField{usk1144TrailerEntry})
	half := len(frag) / 2
	if err := peer.wr.WriteHeaders(sid, true, false, frag[:half]); err != nil {
		return err
	}
	return peer.wr.WriteContinuation(sid, true, frag[half:])
}

// watchGoAway reads frames from the peer side until the connection closes and
// reports the code of the first GOAWAY. Running the reads in the background
// keeps the Layer's writer from blocking on the synchronous pipe, so a test
// fails on its assertion instead of hanging.
func watchGoAway(peer *h2Peer) <-chan uint32 {
	out := make(chan uint32, 1)
	go func() {
		for {
			f, err := peer.rd.ReadFrame()
			if err != nil {
				return
			}
			if f.Header.Type == frame.TypeGoAway {
				_, code, _, _ := f.GoAwayInfo()
				out <- code
				return
			}
		}
	}()
	return out
}

// hasKeyValue reports whether kvs contains name: value.
func hasKeyValue(kvs []envelope.KeyValue, name, value string) bool {
	for _, kv := range kvs {
		if kv.Name == name && kv.Value == value {
			return true
		}
	}
	return false
}

// TestLayer_ServerRole_TrailersAfterLocalCancelAreIgnored pins RFC 9113 §5.1
// ("closed"): once this endpoint has sent RST_STREAM, frames the peer had
// already queued on the stream — here the request trailers — MUST be
// ignored, not treated as stream-id reuse (connection error PROTOCOL_ERROR).
// The trailers block is still HPACK-decoded (§4.3), so the next request that
// references its dynamic-table entry decodes correctly.
func TestLayer_ServerRole_TrailersAfterLocalCancelAreIgnored(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	// Request headers without END_STREAM: the body / trailers are to follow.
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(usk1144RequestFields)); err != nil {
		t.Fatalf("write HEADERS stream 1: %v", err)
	}
	ch1 := acceptChannel(t, l)
	if _, err := nextWithin(ch1, 2*time.Second); err != nil {
		t.Fatalf("stream 1 Next: %v", err)
	}
	// The consumer abandons the stream: RST_STREAM(CANCEL).
	_ = ch1.Close()
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	rst := drainUntil(t, peer, frame.TypeRSTStream)
	_ = peer.conn.SetReadDeadline(time.Time{})
	if code, _ := rst.RSTStreamErrorCode(); rst.Header.StreamID != 1 || code != ErrCodeCancel {
		t.Fatalf("got RST_STREAM(%s) on stream %d, want CANCEL on 1", ErrCodeString(code), rst.Header.StreamID)
	}
	if !waitFor(time.Second, func() bool { return streamMapSize(l) == 0 }) {
		t.Fatalf("stream 1 not retired after RST_STREAM(CANCEL): len(StreamMap)=%d", streamMapSize(l))
	}

	goAway := watchGoAway(peer)
	req3 := append(append([]hpack.HeaderField(nil), usk1144RequestFields...), usk1144TrailerEntry)
	writeErr := make(chan error, 1)
	go func() {
		_ = peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeLateTrailers(peer, 1); err != nil {
			writeErr <- err
			return
		}
		writeErr <- peer.wr.WriteHeaders(3, true, true, peer.encoder.Encode(req3))
	}()

	var ch3 layer.Channel
	select {
	case code := <-goAway:
		t.Fatalf("GOAWAY(%s) after trailers on locally reset stream 1, want them ignored", ErrCodeString(code))
	case ch3 = <-l.Channels():
	case <-time.After(3 * time.Second):
		t.Fatal("no Channel for stream 3 within 3s after trailers on locally reset stream 1")
	}
	if ch3 == nil {
		// Channels() closes when the connection is torn down.
		select {
		case code := <-goAway:
			t.Fatalf("GOAWAY(%s) after trailers on locally reset stream 1, want them ignored", ErrCodeString(code))
		case <-time.After(time.Second):
			t.Fatal("connection closed after trailers on locally reset stream 1, want them ignored")
		}
	}
	defer ch3.Close()
	env, err := nextWithin(ch3, 2*time.Second)
	if err != nil {
		t.Fatalf("stream 3 Next: %v", err)
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok {
		t.Fatalf("Message = %T, want *H2HeadersEvent", env.Message)
	}
	if !hasKeyValue(evt.Headers, usk1144TrailerEntry.Name, usk1144TrailerEntry.Value) {
		t.Errorf("stream 3 headers = %v, want %s: %s (HPACK desync after ignored trailers)",
			evt.Headers, usk1144TrailerEntry.Name, usk1144TrailerEntry.Value)
	}
	if err := <-writeErr; err != nil {
		t.Errorf("peer write: %v", err)
	}
}

// TestLayer_ServerRole_TrailersOnRefusedStreamAreIgnored pins the same rule
// for a stream refused with RST_STREAM(REFUSED_STREAM) for exceeding
// MAX_CONCURRENT_STREAMS: the peer's trailers (and CONTINUATION) on it are
// decoded and discarded, not a connection error.
func TestLayer_ServerRole_TrailersOnRefusedStreamAreIgnored(t *testing.T) {
	l, peer, cleanup := startServerLayer(t, WithMaxConcurrentStreams(1))
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	_ = peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// Stream 1 stays open so stream 3 exceeds the limit.
	if err := peer.wr.WriteHeaders(1, false, true, peer.encoder.Encode(usk1144RequestFields)); err != nil {
		t.Fatalf("write HEADERS stream 1: %v", err)
	}
	ch1 := acceptChannel(t, l)
	defer ch1.Close()
	if _, err := nextWithin(ch1, 2*time.Second); err != nil {
		t.Fatalf("stream 1 Next: %v", err)
	}
	if err := peer.wr.WriteHeaders(3, false, true, peer.encoder.Encode(usk1144RequestFields)); err != nil {
		t.Fatalf("write HEADERS stream 3: %v", err)
	}
	_ = peer.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	rst := drainUntil(t, peer, frame.TypeRSTStream)
	_ = peer.conn.SetReadDeadline(time.Time{})
	if code, _ := rst.RSTStreamErrorCode(); rst.Header.StreamID != 3 || code != ErrCodeRefusedStream {
		t.Fatalf("got RST_STREAM(%s) on stream %d, want REFUSED_STREAM on 3", ErrCodeString(code), rst.Header.StreamID)
	}

	goAway := watchGoAway(peer)
	writeErr := make(chan error, 1)
	go func() {
		_ = peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeLateTrailers(peer, 3); err != nil {
			writeErr <- err
			return
		}
		// Stream 1's trailers reference the entry stream 3's trailers added.
		writeErr <- peer.wr.WriteHeaders(1, true, true, peer.encoder.Encode([]hpack.HeaderField{usk1144TrailerEntry}))
	}()

	type nextResult struct {
		env *envelope.Envelope
		err error
	}
	next := make(chan nextResult, 1)
	go func() {
		env, err := nextWithin(ch1, 3*time.Second)
		next <- nextResult{env, err}
	}()
	var res nextResult
	select {
	case code := <-goAway:
		t.Fatalf("GOAWAY(%s) after trailers on refused stream 3, want them ignored", ErrCodeString(code))
	case res = <-next:
	}
	if res.err != nil {
		// A torn-down connection ends the Channel too; name the GOAWAY.
		select {
		case code := <-goAway:
			t.Fatalf("GOAWAY(%s) after trailers on refused stream 3, want them ignored (stream 1 Next: %v)", ErrCodeString(code), res.err)
		case <-time.After(time.Second):
		}
		t.Fatalf("stream 1 trailers Next: %v", res.err)
	}
	evt, ok := res.env.Message.(*H2TrailersEvent)
	if !ok {
		t.Fatalf("Message = %T, want *H2TrailersEvent", res.env.Message)
	}
	if !hasKeyValue(evt.Trailers, usk1144TrailerEntry.Name, usk1144TrailerEntry.Value) {
		t.Errorf("stream 1 trailers = %v, want %s: %s (HPACK desync after refused stream's trailers)",
			evt.Trailers, usk1144TrailerEntry.Name, usk1144TrailerEntry.Value)
	}
	if err := <-writeErr; err != nil {
		t.Errorf("peer write: %v", err)
	}
}
