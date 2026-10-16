package http2

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-1137 (defect C): Google Ad Manager sends a 21–26 KiB :path. With the
// old 16 KiB HPACK string cap the ServerRole Layer failed to decode the
// header block and tore the connection down, so the browser saw
// ERR_HTTP2_PROTOCOL_ERROR and nothing was recorded. The block is larger
// than the 16 KiB default SETTINGS_MAX_FRAME_SIZE, so it always arrives as
// HEADERS(END_STREAM, !END_HEADERS) + CONTINUATION(END_HEADERS).

// largePath mirrors the reporter's reproducer C (`?q=` + 21000 'x').
var largePath = "/?q=" + strings.Repeat("x", 21000)

// TestLayer_ServerRole_LargePath_SplitAcrossContinuation covers Test Plan #8:
// a body-less GET whose 21 KiB :path is sent as raw (non-Huffman) HPACK split
// across HEADERS + CONTINUATION yields one H2HeadersEvent carrying the full
// path (split into Path and RawQuery), then io.EOF.
func TestLayer_ServerRole_LargePath_SplitAcrossContinuation(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)
	drainPeerInBackground(peer)

	// A dedicated non-Huffman encoder keeps the wire value at its full
	// 21 KiB (curl and Chrome both emit raw literals when Huffman would
	// not shrink the string enough to matter; either way the value is
	// above 16 KiB on the wire).
	enc := hpack.NewEncoder(4096, false)
	block := append([]byte(nil), enc.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "securepubads.g.doubleclick.net"},
		{Name: ":path", Value: largePath},
		{Name: "user-agent", Value: "usk-1137"},
	})...)
	writeSplitHeaders(t, peer, 1, true, splitHeaderBlock(t, block, 2, 0))

	ch := acceptChannel(t, l)
	env, err := nextWithin(ch, 2*time.Second)
	if err != nil {
		t.Fatalf("first Next: %v (21 KiB :path must decode under the default HPACK limits)", err)
	}
	evt, ok := env.Message.(*H2HeadersEvent)
	if !ok {
		t.Fatalf("first Message = %T, want *H2HeadersEvent", env.Message)
	}
	// H2HeadersEvent splits :path into Path and RawQuery at the first '?'.
	if got := evt.Path + "?" + evt.RawQuery; evt.Path != "/" || got != largePath {
		t.Errorf("Path = %q, RawQuery is %d bytes; want the full %d-byte :path %q?<%d bytes>",
			evt.Path, len(evt.RawQuery), len(largePath), "/", len(largePath)-2)
	}
	if evt.Method != "GET" || evt.Authority != "securepubads.g.doubleclick.net" {
		t.Errorf("pseudo-headers = %s %s, want GET securepubads.g.doubleclick.net", evt.Method, evt.Authority)
	}
	if !evt.EndStream {
		t.Error("EndStream = false, want true")
	}
	if _, err := nextWithin(ch, time.Second); !errors.Is(err, io.EOF) {
		t.Errorf("second Next err = %v, want io.EOF", err)
	}
}

// indexedBombBlock builds a header block that inserts one entry of exactly
// 4096 bytes (RFC 7541 §4.1 size: name + value + 32) into the dynamic table
// with "Literal Header Field with Incremental Indexing — New Name" (§6.2.1)
// and then references it refs times with one-byte "Indexed Header Field"
// representations (§6.1, dynamic index 62). The raw block stays ~4.4 KiB —
// well inside one frame and the 1 MiB fragment cap — while the decoded
// header list grows by 4096 bytes per reference: the classic HPACK bomb.
func indexedBombBlock(refs int) []byte {
	const name = "x-bomb"
	value := strings.Repeat("b", 4096-32-len(name))
	enc := hpack.NewEncoder(4096, false)
	block := append([]byte(nil), enc.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/bomb"},
	})...)
	block = append(block, 0x40, byte(len(name)))
	block = append(block, name...)
	// value length 4058 as a 7-bit-prefix HPACK integer: 127, then 3931.
	block = append(block, 0x7f, byte((len(value)-127)%128|0x80), byte((len(value)-127)/128))
	block = append(block, value...)
	for i := 0; i < refs; i++ {
		block = append(block, 0x80|62)
	}
	return block
}

// TestLayer_ServerRole_DynamicTableExpansion covers Test Plan #9: the decoded
// header-list cap (1 MiB) is what bounds an HPACK bomb. A block expanding to
// ~800 KiB is accepted (browser parity is well below that); one expanding
// past 1 MiB tears the connection down without producing an event.
func TestLayer_ServerRole_DynamicTableExpansion(t *testing.T) {
	tests := []struct {
		name      string
		refs      int
		wantEvent bool
	}{
		// 1 + 200 references × 4096 bytes ≈ 804 KiB decoded.
		{name: "expands to ~800 KiB (under cap)", refs: 200, wantEvent: true},
		// 1 + 300 references × 4096 bytes ≈ 1.2 MiB decoded.
		{name: "expands past 1 MiB (over cap)", refs: 300, wantEvent: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, peer, cleanup := startServerLayer(t)
			defer cleanup()
			peer.consumePeerSettings(t)
			peer.sendInitialSettings(t)
			drainPeerInBackground(peer)

			block := indexedBombBlock(tt.refs)
			writeSplitHeaders(t, peer, 1, true, splitHeaderBlock(t, block, 1, 0))

			ch := acceptChannel(t, l)
			env, err := nextWithin(ch, 2*time.Second)
			if !tt.wantEvent {
				if err == nil {
					t.Fatalf("Next returned an envelope (%T) for a header list past 1 MiB, want a connection error", env.Message)
				}
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("Next timed out, want the Layer torn down by the over-cap header block")
				}
				select {
				case <-l.shutdown:
				case <-time.After(2 * time.Second):
					t.Fatal("Layer did not shut down after the over-cap header block")
				}
				l.lastErrMu.Lock()
				lastErr := l.lastErr
				l.lastErrMu.Unlock()
				if !errors.Is(lastErr, hpack.ErrHeaderListTooLarge) {
					t.Errorf("Layer terminal error = %v, want hpack.ErrHeaderListTooLarge", lastErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Next: %v (an ~800 KiB decoded header list must be accepted)", err)
			}
			evt, ok := env.Message.(*H2HeadersEvent)
			if !ok {
				t.Fatalf("Message = %T, want *H2HeadersEvent", env.Message)
			}
			if got, want := len(evt.Headers), tt.refs+1; got != want {
				t.Errorf("decoded %d regular headers, want %d", got, want)
			}
		})
	}
}
