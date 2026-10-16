package http2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1137 (defect A): RFC 9113 §6.2 puts END_STREAM on the HEADERS frame
// that opens a header block; CONTINUATION frames never carry it (§6.10).
// A header block split across HEADERS(END_STREAM, !END_HEADERS) +
// CONTINUATION*(END_HEADERS) must therefore produce the same events and
// stream state as the same block in a single HEADERS frame. Real clients
// emit exactly this shape whenever the block exceeds SETTINGS_MAX_FRAME_SIZE
// (x/net http2 Transport writeHeaders, Chrome on large :path values).

// bigHeaderValue mirrors the reporter's reproducer (10 KiB per value). It is
// below the current 16 KiB HPACK string cap so this test isolates defect A
// from the separate limit defects of the same Issue.
var bigHeaderValue = strings.Repeat("x", 10*1024)

// bigRegularHeaders returns 4×10 KiB regular headers — an HPACK block far
// larger than the 16 KiB default SETTINGS_MAX_FRAME_SIZE.
func bigRegularHeaders() []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: "x-a", Value: bigHeaderValue},
		{Name: "x-b", Value: bigHeaderValue},
		{Name: "x-c", Value: bigHeaderValue},
		{Name: "x-d", Value: bigHeaderValue},
	}
}

func smallRegularHeaders() []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: "user-agent", Value: "usk-1137"},
		{Name: "x-small", Value: "v"},
	}
}

func getRequestPseudo() []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/usk-1137"},
	}
}

// encodeBlock HPACK-encodes hdrs with the peer's encoder and returns an owned
// copy (Encoder.Encode reuses its internal buffer).
func encodeBlock(p *h2Peer, hdrs []hpack.HeaderField) []byte {
	return append([]byte(nil), p.encoder.Encode(hdrs)...)
}

// splitHeaderBlock splits block into parts fragments. When firstLen > 0 the
// first fragment is exactly firstLen bytes and the remainder is split evenly
// into parts-1 fragments; otherwise the whole block is split evenly. Every
// fragment must fit the default SETTINGS_MAX_FRAME_SIZE.
func splitHeaderBlock(t *testing.T, block []byte, parts, firstLen int) [][]byte {
	t.Helper()
	if parts < 1 {
		t.Fatalf("splitHeaderBlock: parts = %d", parts)
	}
	var out [][]byte
	rest := block
	if firstLen > 0 && parts > 1 {
		out = append(out, rest[:firstLen])
		rest = rest[firstLen:]
		parts--
	}
	size := (len(rest) + parts - 1) / parts
	for i := 0; i < parts; i++ {
		end := size
		if i == parts-1 || end > len(rest) {
			end = len(rest)
		}
		out = append(out, rest[:end])
		rest = rest[end:]
	}
	for i, f := range out {
		if len(f) > int(frame.DefaultMaxFrameSize) {
			t.Fatalf("fragment %d is %d bytes, exceeds default max frame size %d", i, len(f), frame.DefaultMaxFrameSize)
		}
		if len(f) == 0 {
			t.Fatalf("fragment %d is empty (block %d bytes, parts %d)", i, len(block), parts)
		}
	}
	return out
}

// writeSplitHeaders writes frags as HEADERS(+CONTINUATION*) on streamID.
// END_STREAM is placed on the HEADERS frame only, as RFC 9113 §6.2 requires.
func writeSplitHeaders(t *testing.T, p *h2Peer, streamID uint32, endStream bool, frags [][]byte) {
	t.Helper()
	if err := p.wr.WriteHeaders(streamID, endStream, len(frags) == 1, frags[0]); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
	for i := 1; i < len(frags); i++ {
		if err := p.wr.WriteContinuation(streamID, i == len(frags)-1, frags[i]); err != nil {
			t.Fatalf("write CONTINUATION %d: %v", i, err)
		}
	}
}

// drainPeerInBackground consumes every frame the Layer writes so the Layer's
// writer never blocks on the synchronous net.Pipe. Exits when the pipe closes.
func drainPeerInBackground(p *h2Peer) {
	go func() {
		for {
			if _, err := p.rd.ReadFrame(); err != nil {
				return
			}
		}
	}()
}

// streamStateOf reads a stream's state under the StreamMap lock (race-safe;
// StreamMap.Get returns an unlocked pointer).
func streamStateOf(l *Layer, id uint32) (StreamState, bool) {
	sm := l.conn.Streams()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		return StateIdle, false
	}
	return s.State, true
}

// waitStreamState polls until stream id reaches want or the deadline passes.
// The reader goroutine performs the transition after delivering the event,
// so a short poll avoids racing it.
func waitStreamState(t *testing.T, l *Layer, id uint32, want StreamState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var got StreamState
	var ok bool
	for time.Now().Before(deadline) {
		got, ok = streamStateOf(l, id)
		if ok && got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("stream %d state = %s (exists=%v), want %s", id, got, ok, want)
}

// nextWithin calls ch.Next with a bounded deadline so a missing END_STREAM
// fails fast instead of hanging the package.
func nextWithin(ch layer.Channel, d time.Duration) (*envelope.Envelope, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return ch.Next(ctx)
}

func acceptChannel(t *testing.T, l *Layer) layer.Channel {
	t.Helper()
	select {
	case ch := <-l.Channels():
		if ch == nil {
			t.Fatal("nil Channel")
		}
		return ch
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive Channel within 2s")
	}
	return nil
}

func wantKeyValues(hdrs []hpack.HeaderField) []envelope.KeyValue {
	out := make([]envelope.KeyValue, 0, len(hdrs))
	for _, h := range hdrs {
		out = append(out, envelope.KeyValue{Name: h.Name, Value: h.Value})
	}
	return out
}

func equalKeyValues(a, b []envelope.KeyValue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// recvRequestResult is what the ServerRole Layer produced for one header
// block delivered as a given fragment layout.
type recvRequestResult struct {
	evt     *H2HeadersEvent
	raw     []byte
	block   []byte
	nextErr error
}

// recvSplitRequest starts a fresh ServerRole Layer, sends a body-less GET
// whose header block is split into parts fragments (END_STREAM on HEADERS),
// and returns the first event plus the result of the following Next. It also
// asserts the stream ends half-closed (remote).
func recvSplitRequest(t *testing.T, regular []hpack.HeaderField, parts, firstLen int) recvRequestResult {
	t.Helper()
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	drainPeerInBackground(peer)

	block := encodeBlock(peer, append(getRequestPseudo(), regular...))
	frags := splitHeaderBlock(t, block, parts, firstLen)
	writeSplitHeaders(t, peer, 1, true, frags)

	ch := acceptChannel(t, l)
	env, err := nextWithin(ch, 2*time.Second)
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok {
		t.Fatalf("first Message = %T, want *H2HeadersEvent", env.Message)
	}
	_, nextErr := nextWithin(ch, time.Second)
	waitStreamState(t, l, 1, StateHalfClosedRemote)
	return recvRequestResult{evt: evt, raw: env.Raw, block: block, nextErr: nextErr}
}

// TestLayer_ServerRole_SplitHeaderBlock_LatchesEndStream covers Test Plan #1:
// a body-less request whose header block is split across HEADERS(END_STREAM,
// !END_HEADERS) + CONTINUATION frames completes with EndStream=true, io.EOF,
// and the stream half-closed (remote) — identical to the single-frame case.
func TestLayer_ServerRole_SplitHeaderBlock_LatchesEndStream(t *testing.T) {
	tests := []struct {
		name     string
		regular  []hpack.HeaderField
		parts    int
		firstLen int
		// compareSingle runs the same block as one HEADERS frame and checks
		// the split result equals it (only possible when the block fits one
		// frame).
		compareSingle bool
	}{
		{name: "small block, 1 CONTINUATION, split after first byte", regular: smallRegularHeaders(), parts: 2, firstLen: 1, compareSingle: true},
		{name: "small block, 1 CONTINUATION, even split", regular: smallRegularHeaders(), parts: 2, compareSingle: true},
		{name: "small block, 2 CONTINUATION", regular: smallRegularHeaders(), parts: 3, compareSingle: true},
		{name: "4x10KiB block, 2 CONTINUATION", regular: bigRegularHeaders(), parts: 3},
		{name: "4x10KiB block, 3 CONTINUATION", regular: bigRegularHeaders(), parts: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := recvSplitRequest(t, tt.regular, tt.parts, tt.firstLen)

			if !got.evt.EndStream {
				t.Error("EndStream = false, want true (END_STREAM was on the HEADERS frame)")
			}
			if !errors.Is(got.nextErr, io.EOF) {
				t.Errorf("second Next err = %v, want io.EOF", got.nextErr)
			}
			if got.evt.Method != "GET" || got.evt.Path != "/usk-1137" || got.evt.Authority != "example.com" || got.evt.Scheme != "https" {
				t.Errorf("pseudo-headers = %s %s://%s%s, want GET https://example.com/usk-1137",
					got.evt.Method, got.evt.Scheme, got.evt.Authority, got.evt.Path)
			}
			if want := wantKeyValues(tt.regular); !equalKeyValues(got.evt.Headers, want) {
				t.Errorf("Headers differ from wire order (got %d fields, want %d)", len(got.evt.Headers), len(want))
			}
			if !bytes.Equal(got.raw, got.block) {
				t.Errorf("Envelope.Raw is %d bytes, want the full %d-byte HPACK block", len(got.raw), len(got.block))
			}

			if !tt.compareSingle {
				return
			}
			ref := recvSplitRequest(t, tt.regular, 1, 0)
			if ref.evt.EndStream != got.evt.EndStream {
				t.Errorf("split EndStream = %v, single-frame EndStream = %v", got.evt.EndStream, ref.evt.EndStream)
			}
			if !equalKeyValues(ref.evt.Headers, got.evt.Headers) {
				t.Error("split Headers differ from single-frame Headers")
			}
			if (ref.nextErr == nil) != (got.nextErr == nil) || !errors.Is(got.nextErr, ref.nextErr) {
				t.Errorf("split second Next err = %v, single-frame = %v", got.nextErr, ref.nextErr)
			}
		})
	}
}

// TestLayer_ClientRole_SplitResponseHeaderBlock_LatchesEndStream covers Test
// Plan #2: a body-less 204 response whose header block (4×10 KiB headers)
// spans HEADERS(END_STREAM, !END_HEADERS) + CONTINUATION yields Status=204,
// EndStream=true, then io.EOF.
func TestLayer_ClientRole_SplitResponseHeaderBlock_LatchesEndStream(t *testing.T) {
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
			Message: &H2HeadersEvent{
				Method:    "GET",
				Scheme:    "https",
				Authority: "example.com",
				Path:      "/usk-1137",
				EndStream: true,
			},
		})
	}()
	reqFrame := drainUntil(t, peer, frame.TypeHeaders)
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
	streamID := reqFrame.Header.StreamID
	drainPeerInBackground(peer)

	regular := bigRegularHeaders()
	block := encodeBlock(peer, append([]hpack.HeaderField{{Name: ":status", Value: "204"}}, regular...))
	writeSplitHeaders(t, peer, streamID, true, splitHeaderBlock(t, block, 3, 0))

	env, err := nextWithin(ch, 2*time.Second)
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok {
		t.Fatalf("first Message = %T, want *H2HeadersEvent", env.Message)
	}
	if evt.Status != 204 {
		t.Errorf("Status = %d, want 204", evt.Status)
	}
	if !evt.EndStream {
		t.Error("EndStream = false, want true (END_STREAM was on the HEADERS frame)")
	}
	if want := wantKeyValues(regular); !equalKeyValues(evt.Headers, want) {
		t.Errorf("Headers differ from wire order (got %d fields, want %d)", len(evt.Headers), len(want))
	}
	if !bytes.Equal(env.Raw, block) {
		t.Errorf("Envelope.Raw is %d bytes, want the full %d-byte HPACK block", len(env.Raw), len(block))
	}
	if _, err := nextWithin(ch, time.Second); !errors.Is(err, io.EOF) {
		t.Errorf("second Next err = %v, want io.EOF", err)
	}
}

// TestLayer_ServerRole_SplitTrailerBlock_TransitionsStreamState covers Test
// Plan #3: gRPC-style trailers split across HEADERS(END_STREAM, !END_HEADERS)
// + CONTINUATION already produce H2TrailersEvent + io.EOF, but the stream
// state must also reach half-closed (remote).
func TestLayer_ServerRole_SplitTrailerBlock_TransitionsStreamState(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	drainPeerInBackground(peer)

	reqBlock := encodeBlock(peer, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/pkg.Svc/Method"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	})
	if err := peer.wr.WriteHeaders(1, false, true, reqBlock); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}
	if err := peer.wr.WriteData(1, false, []byte{0, 0, 0, 0, 1, 0x08}); err != nil {
		t.Fatalf("write DATA: %v", err)
	}
	trailers := []hpack.HeaderField{
		{Name: "grpc-status", Value: "0"},
		{Name: "grpc-message", Value: "ok"},
		{Name: "x-trailer-big", Value: bigHeaderValue},
	}
	trailerBlock := encodeBlock(peer, trailers)
	writeSplitHeaders(t, peer, 1, true, splitHeaderBlock(t, trailerBlock, 2, 0))

	ch := acceptChannel(t, l)
	var gotTrailers *H2TrailersEvent
	for i := 0; i < 3; i++ {
		env, err := nextWithin(ch, 2*time.Second)
		if err != nil {
			t.Fatalf("Next #%d: %v", i, err)
		}
		if tr, ok := env.Message.(*H2TrailersEvent); ok {
			gotTrailers = tr
		}
	}
	if gotTrailers == nil {
		t.Fatal("no H2TrailersEvent received")
	}
	if want := wantKeyValues(trailers); !equalKeyValues(gotTrailers.Trailers, want) {
		t.Errorf("Trailers differ from wire order (got %d fields, want %d)", len(gotTrailers.Trailers), len(want))
	}
	if _, err := nextWithin(ch, time.Second); !errors.Is(err, io.EOF) {
		t.Errorf("Next after trailers err = %v, want io.EOF", err)
	}
	waitStreamState(t, l, 1, StateHalfClosedRemote)
}
