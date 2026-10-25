//go:build e2e && !e2e_smoke

// ws_deflate_oversize_integration_test.go — USK-1321 acceptance gate.
//
// A permessage-deflate message whose decompressed size exceeds the WS
// Layer's 16 MiB decompression cap used to be truncated to its first
// 16 MiB, re-compressed and forwarded with no error and no mark in the
// record; under context takeover the receive window was then reset, so
// the next back-referencing message failed to decode and tore the session
// down. The proxy must instead:
//
//   - forward an unmodified over-cap message as the received wire frame,
//     so the peer gets the full content (both deflate modes, both
//     directions);
//   - keep the LZ77 window in step so later messages still relay;
//   - record the overflow (ws_anomaly_decompressed_too_large +
//     BodyTruncated) while recording the first 16 MiB as the payload;
//   - refuse (not forward truncated) a modified over-cap message or one
//     whose verbatim frame no longer matches the peer's window;
//   - fail closed in Input Safety when payload rules cannot see the whole
//     message.
//
// Messages are 17 MiB of plaintext; subtests run sequentially to keep the
// peak memory of the -race run bounded.

package ws_test

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

const (
	// oversizeCap mirrors the WS Layer's default decompression cap
	// (config.MaxWebSocketFrameSize).
	oversizeCap = 16 << 20

	oversizeTailLen = 64 << 10
	oversizeMarker  = "END-MARKER"

	// negotiatedNoContextTakeover disables context takeover both ways.
	negotiatedNoContextTakeover = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"

	oversizeReadTimeout = 60 * time.Second
)

// oversizeTail returns a 64 KiB non-repeating tail (an 8-digit hex
// counter), so later messages can back-reference it under context
// takeover and a dropped window shows up as a decode failure.
func oversizeTail() []byte {
	tail := make([]byte, 0, oversizeTailLen)
	for i := 0; len(tail) < oversizeTailLen; i++ {
		tail = fmt.Appendf(tail, "%08x", i)
	}
	return tail[:oversizeTailLen]
}

// oversizePlaintext returns total bytes: 'A' padding + extra + the 64 KiB
// hex tail + END-MARKER.
func oversizePlaintext(total int, extra []byte) []byte {
	tail := oversizeTail()
	pad := total - len(extra) - len(tail) - len(oversizeMarker)
	out := make([]byte, 0, total)
	out = append(out, bytes.Repeat([]byte("A"), pad)...)
	out = append(out, extra...)
	out = append(out, tail...)
	out = append(out, oversizeMarker...)
	return out
}

// encodeWSFrame returns the wire bytes of f.
func encodeWSFrame(t *testing.T, f *ws.Frame) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := ws.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	return buf.Bytes()
}

var oversizeClientMask = [4]byte{0xAA, 0xBB, 0xCC, 0xDD}

// writeCompressed writes one single-frame compressed text message from
// the client (c2s=true, masked) or the server, returning the wire bytes.
func (h *wsHarness) writeCompressed(c2s bool, payload []byte) []byte {
	h.t.Helper()
	f := &ws.Frame{Fin: true, RSV1: true, Opcode: ws.OpcodeText, Payload: payload}
	conn := h.upstreamB
	if c2s {
		f.Masked = true
		f.MaskKey = oversizeClientMask
		conn = h.clientA
	}
	raw := encodeWSFrame(h.t, f)
	if _, err := conn.Write(raw); err != nil {
		h.t.Fatalf("write compressed frame: %v", err)
	}
	return raw
}

// readRelayed reads the next frame the proxy relayed to the receiving end
// of the c2s / s2c direction, with a deadline long enough for a 17 MiB
// inflate under -race.
func (h *wsHarness) readRelayed(c2s bool) (*ws.Frame, error) {
	conn := h.clientA
	if c2s {
		conn = h.upstreamB
	}
	_ = conn.SetReadDeadline(time.Now().Add(oversizeReadTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	return ws.ReadFrame(conn)
}

func (h *wsHarness) mustReadRelayed(c2s bool) *ws.Frame {
	h.t.Helper()
	f, err := h.readRelayed(c2s)
	if err != nil {
		h.t.Fatalf("read relayed frame: %v", err)
	}
	return f
}

// expectNoRelayed asserts the proxy relays no frame in this direction:
// the read ends in EOF, a reset, or the deadline.
func (h *wsHarness) expectNoRelayed(c2s bool, wait time.Duration) {
	h.t.Helper()
	conn := h.clientA
	if c2s {
		conn = h.upstreamB
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	f, err := ws.ReadFrame(conn)
	if err == nil {
		h.t.Errorf("proxy relayed a frame (opcode 0x%X, RSV1=%v, %d payload bytes); want none", f.Opcode, f.RSV1, len(f.Payload))
	}
}

// nudgeUpstream makes the proxy dial upstream with one uncompressed
// client frame (RSV1=0 leaves both deflate windows untouched).
func (h *wsHarness) nudgeUpstream() {
	h.t.Helper()
	h.writeClientFrame(true, ws.OpcodeText, []byte("nudge"))
	_ = h.mustReadRelayed(true)
}

// closeHandshake performs a graceful RFC 6455 closing handshake through
// the proxy so the Stream ends in State=complete.
func (h *wsHarness) closeHandshake() {
	h.t.Helper()
	h.writeClientFrame(true, ws.OpcodeClose, []byte{0x03, 0xE8})
	_ = h.mustReadRelayed(true)
	h.writeServerFrame(true, ws.OpcodeClose, []byte{0x03, 0xE8})
	_ = h.mustReadRelayed(false)
}

// peerInflator returns an inflater mirroring the receiving peer: one
// long-lived window under context takeover, a fresh one per message
// otherwise.
type peerInflator struct {
	contextTakeover bool
	inf             multiFrameInflator
}

func (p *peerInflator) Inflate(t *testing.T, src []byte) []byte {
	t.Helper()
	if !p.contextTakeover {
		p.inf = multiFrameInflator{}
	}
	return p.inf.Inflate(t, src)
}

func wsFlowsByDirection(store *testStore, dir string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range wsFlowsOnly(store.allFlows()) {
		if f.Direction == dir {
			out = append(out, f)
		}
	}
	return out
}

func wsStreamOf(t *testing.T, store *testStore) *flow.Stream {
	t.Helper()
	for _, st := range store.getStreams() {
		if st.Protocol == "ws" {
			return st
		}
	}
	t.Fatal("no ws Stream recorded")
	return nil
}

// waitStreamState polls until the ws Stream has a terminal State.
func waitStreamState(t *testing.T, store *testStore) *flow.Stream {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range store.getStreams() {
			if st.Protocol == "ws" && (st.State == "complete" || st.State == "error") {
				return st
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return wsStreamOf(t, store)
}

// T1 + T2: an unmodified over-cap message reaches the peer as the
// received wire frame and inflates to the full plaintext, in both
// directions and both deflate modes.
func TestWSDeflateOversize_UnmodifiedReachesPeerIntact(t *testing.T) {
	cases := []struct {
		name       string
		c2s        bool
		negotiated string
	}{
		{"server-to-client/context-takeover", false, "permessage-deflate"},
		{"client-to-server/context-takeover", true, "permessage-deflate"},
		{"server-to-client/no-context-takeover", false, negotiatedNoContextTakeover},
		{"client-to-server/no-context-takeover", true, negotiatedNoContextTakeover},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			h := newWSHarness(t, ctx, harnessOpts{})
			h.performDeflateUpgrade(ctx, tc.negotiated)
			if !tc.c2s {
				h.nudgeUpstream()
			}

			plain := oversizePlaintext(17<<20, nil)
			comp := newMultiFrameDeflator(t).Compress(t, plain)
			h.writeCompressed(tc.c2s, comp)
			got := h.mustReadRelayed(tc.c2s)

			if !got.RSV1 {
				t.Error("relayed frame RSV1 = false, want true")
			}
			if !bytes.Equal(got.Payload, comp) {
				t.Errorf("relayed compressed payload (len %d) != the sender's frame payload (len %d)", len(got.Payload), len(comp))
			}
			if tc.c2s && got.MaskKey != oversizeClientMask {
				t.Errorf("relayed mask key = %x, want the client's %x (verbatim frame)", got.MaskKey, oversizeClientMask)
			}
			inflated := (&peerInflator{contextTakeover: true}).Inflate(t, got.Payload)
			if len(inflated) != len(plain) {
				t.Errorf("peer inflated %d bytes, want %d", len(inflated), len(plain))
			}
			if !bytes.HasSuffix(inflated, []byte(oversizeMarker)) {
				t.Errorf("peer inflated payload lacks %s", oversizeMarker)
			}
			if !bytes.Equal(inflated, plain) {
				t.Error("peer inflated payload differs from the sender's plaintext")
			}
		})
	}
}

// T3: context takeover after an over-cap message. (a) an unmodified
// message back-referencing the over-cap message's tail inflates at the
// client and is recorded correctly; (b) a message modified by Transform is
// re-compressed against the window the client holds and inflates.
func TestWSDeflateOversize_ContextTakeover_FollowingMessagesRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	xfm := wsrules.NewTransformEngine()
	xfm.SetRules([]wsrules.TransformRule{{
		ID:             "rewrite-msg3",
		Enabled:        true,
		Priority:       1,
		Direction:      wsrules.DirectionReceive,
		ActionType:     wsrules.TransformReplacePayload,
		PayloadPattern: regexp.MustCompile(`REWRITE-ME`),
		PayloadReplace: []byte("REWRITTEN!"),
	}})
	h := newWSHarness(t, ctx, harnessOpts{transformEngine: xfm})
	h.performDeflateUpgrade(ctx, "permessage-deflate")
	h.nudgeUpstream()

	tail := oversizeTail()
	msg1 := oversizePlaintext(17<<20, nil)
	msg2 := append([]byte("msg2 "), tail[len(tail)-16<<10:]...)
	msg3 := append([]byte("REWRITE-ME "), tail[len(tail)-24<<10:len(tail)-8<<10]...)
	want3 := bytes.Replace(msg3, []byte("REWRITE-ME"), []byte("REWRITTEN!"), 1)

	sd := newMultiFrameDeflator(t)
	inf := &peerInflator{contextTakeover: true}

	h.writeCompressed(false, sd.Compress(t, msg1))
	if got := inf.Inflate(t, h.mustReadRelayed(false).Payload); !bytes.Equal(got, msg1) {
		t.Fatalf("msg1: client inflated %d bytes, want the full %d", len(got), len(msg1))
	}

	h.writeCompressed(false, sd.Compress(t, msg2))
	f2, err := h.readRelayed(false)
	if err != nil {
		t.Fatalf("msg2 (back-references msg1's tail) was not relayed: %v", err)
	}
	if got := inf.Inflate(t, f2.Payload); !bytes.Equal(got, msg2) {
		t.Errorf("msg2: client inflated %q..., want %q...", trimForLog(got), trimForLog(msg2))
	}

	h.writeCompressed(false, sd.Compress(t, msg3))
	f3, err := h.readRelayed(false)
	if err != nil {
		t.Fatalf("msg3 (modified) was not relayed: %v", err)
	}
	if got := inf.Inflate(t, f3.Payload); !bytes.Equal(got, want3) {
		t.Errorf("msg3: client inflated %q..., want %q...", trimForLog(got), trimForLog(want3))
	}

	h.closeHandshake()
	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(10 * time.Second)

	var sawMsg2 bool
	for _, f := range wsFlowsByDirection(h.store, "receive") {
		if bytes.Equal(f.Body, msg2) {
			sawMsg2 = true
		}
	}
	if !sawMsg2 {
		t.Error("no receive flow recorded msg2's plaintext")
	}
}

// T4: the record shows the overflow. The over-cap Flow carries the anomaly
// key (naming the cap), BodyTruncated, the 16 MiB prefix as Body and the
// complete wire frame as RawBytes; an under-cap message in the same Stream
// carries none of it.
func TestWSDeflateOversize_RecordShowsOverflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	h := newWSHarness(t, ctx, harnessOpts{})
	h.performDeflateUpgrade(ctx, "permessage-deflate")
	h.nudgeUpstream()

	plain := oversizePlaintext(17<<20, nil)
	small := []byte("small message after the big one")
	sd := newMultiFrameDeflator(t)
	raw := h.writeCompressed(false, sd.Compress(t, plain))
	_ = h.mustReadRelayed(false)
	h.writeCompressed(false, sd.Compress(t, small))
	_ = h.mustReadRelayed(false)

	h.closeHandshake()
	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(10 * time.Second)

	var big, sm *flow.Flow
	for _, f := range wsFlowsByDirection(h.store, "receive") {
		switch {
		case bytes.Equal(f.RawBytes, raw):
			big = f
		case bytes.Equal(f.Body, small):
			sm = f
		}
	}
	if big == nil {
		t.Fatal("no receive flow with RawBytes == the over-cap wire frame")
	}
	detail, ok := big.Metadata["ws_anomaly_decompressed_too_large"]
	if !ok {
		t.Errorf("over-cap flow Metadata lacks ws_anomaly_decompressed_too_large: %v", big.Metadata)
	} else if !strings.Contains(detail, "16777216") {
		t.Errorf("anomaly detail = %q, want it to name the 16777216-byte cap", detail)
	}
	if !big.BodyTruncated {
		t.Error("over-cap flow BodyTruncated = false, want true")
	}
	if len(big.Body) != oversizeCap || !bytes.Equal(big.Body, plain[:oversizeCap]) {
		t.Errorf("over-cap flow Body len = %d, want the first %d bytes of the plaintext", len(big.Body), oversizeCap)
	}
	if sm == nil {
		t.Fatal("no receive flow for the small message")
	}
	if _, has := sm.Metadata["ws_anomaly_decompressed_too_large"]; has || sm.BodyTruncated {
		t.Errorf("under-cap flow marked as overflowed: %v BodyTruncated=%v", sm.Metadata, sm.BodyTruncated)
	}
	if st := waitStreamState(t, h.store); st.State != "complete" {
		t.Errorf("ws Stream State = %q (FailureReason %q), want complete", st.State, st.FailureReason)
	}
}

// T5: a truncated message modified by Transform is not forwarded: the
// client gets no frame, the Stream ends in error, and the modified variant
// is still recorded.
func TestWSDeflateOversize_ModifiedTruncatedMessageRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	xfm := wsrules.NewTransformEngine()
	xfm.SetRules([]wsrules.TransformRule{{
		ID:             "rewrite-prefix",
		Enabled:        true,
		Priority:       1,
		Direction:      wsrules.DirectionReceive,
		ActionType:     wsrules.TransformReplacePayload,
		PayloadPattern: regexp.MustCompile(`^AAAA`),
		PayloadReplace: []byte("BBBB"),
	}})
	h := newWSHarness(t, ctx, harnessOpts{transformEngine: xfm})
	h.performDeflateUpgrade(ctx, "permessage-deflate")
	h.nudgeUpstream()

	plain := oversizePlaintext(17<<20, nil)
	h.writeCompressed(false, newMultiFrameDeflator(t).Compress(t, plain))
	h.expectNoRelayed(false, 15*time.Second)

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(10 * time.Second)

	st := waitStreamState(t, h.store)
	if st.State != "error" || st.FailureReason != "aborted" {
		t.Errorf("ws Stream State=%q FailureReason=%q, want error/aborted", st.State, st.FailureReason)
	}
	var sawModified bool
	for _, f := range wsFlowsByDirection(h.store, "receive") {
		if f.Metadata["variant"] == "modified" && bytes.HasPrefix(f.Body, []byte("BBBB")) {
			sawModified = true
		}
	}
	if !sawModified {
		t.Error("modified variant of the refused message was not recorded")
	}
}

// T6: under context takeover, once an earlier message was modified the
// verbatim frame of a later over-cap message no longer matches the
// client's window, so it is refused instead of relayed.
func TestWSDeflateOversize_WindowDivergenceRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	xfm := wsrules.NewTransformEngine()
	xfm.SetRules([]wsrules.TransformRule{{
		ID:             "rewrite-msg1",
		Enabled:        true,
		Priority:       1,
		Direction:      wsrules.DirectionReceive,
		ActionType:     wsrules.TransformReplacePayload,
		PayloadPattern: regexp.MustCompile(`msg-one-marker`),
		PayloadReplace: []byte("MSG-ONE-REWRITE"),
	}})
	h := newWSHarness(t, ctx, harnessOpts{transformEngine: xfm})
	h.performDeflateUpgrade(ctx, "permessage-deflate")
	h.nudgeUpstream()

	tail := oversizeTail()
	chunk := tail[:16<<10]
	msg1 := append([]byte("msg-one-marker "), chunk...)
	msg2 := oversizePlaintext(17<<20, chunk) // back-references msg1's chunk

	sd := newMultiFrameDeflator(t)
	h.writeCompressed(false, sd.Compress(t, msg1))
	_ = h.mustReadRelayed(false)
	h.writeCompressed(false, sd.Compress(t, msg2))
	h.expectNoRelayed(false, 15*time.Second)

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(10 * time.Second)

	if st := waitStreamState(t, h.store); st.State != "error" {
		t.Errorf("ws Stream State=%q, want error", st.State)
	}
}

// T9: characterization guard — a message of exactly 16 MiB decompressed
// keeps today's behaviour: relayed in full, no anomaly, not truncated.
func TestWSDeflateOversize_AtCapUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	h := newWSHarness(t, ctx, harnessOpts{})
	h.performDeflateUpgrade(ctx, "permessage-deflate")
	h.nudgeUpstream()

	plain := oversizePlaintext(oversizeCap, nil)
	h.writeCompressed(false, newMultiFrameDeflator(t).Compress(t, plain))
	got := (&peerInflator{contextTakeover: true}).Inflate(t, h.mustReadRelayed(false).Payload)
	if !bytes.Equal(got, plain) {
		t.Errorf("client inflated %d bytes, want the full %d", len(got), len(plain))
	}

	h.closeHandshake()
	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(10 * time.Second)

	var found bool
	for _, f := range wsFlowsByDirection(h.store, "receive") {
		if len(f.Body) != oversizeCap {
			continue
		}
		found = true
		if _, has := f.Metadata["ws_anomaly_decompressed_too_large"]; has || f.BodyTruncated {
			t.Errorf("at-cap flow marked as overflowed: BodyTruncated=%v", f.BodyTruncated)
		}
	}
	if !found {
		t.Error("no receive flow with the 16 MiB body")
	}
}

// T12 (U2): Input Safety with payload rules fails closed on a Send-direction
// over-cap message — "DROP TABLE" sits past the 16 MiB scan window — and
// without Safety rules the same message is forwarded verbatim.
func TestWSDeflateOversize_SafetyFailsClosedPastScanWindow(t *testing.T) {
	plain := oversizePlaintext(17<<20, []byte(" DROP TABLE users; "))
	if bytes.Contains(plain[:oversizeCap], []byte("DROP TABLE")) {
		t.Fatal("fixture: DROP TABLE must lie past the cap")
	}

	t.Run("destructive-sql preset blocks", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		safety := wsrules.NewSafetyEngine()
		if err := safety.LoadPreset(common.PresetDestructiveSQL); err != nil {
			t.Fatal(err)
		}
		h := newWSHarness(t, ctx, harnessOpts{safetyEngine: safety})
		h.performDeflateUpgrade(ctx, "permessage-deflate")
		h.writeCompressed(true, newMultiFrameDeflator(t).Compress(t, plain))
		// A Safety Drop leaves the session running, so an uncompressed
		// sentinel frame must be the first thing upstream sees.
		h.writeClientFrame(true, ws.OpcodeText, []byte("sentinel"))
		got := h.mustReadRelayed(true)
		if got.RSV1 || string(got.Payload) != "sentinel" {
			t.Errorf("upstream first frame: RSV1=%v %d payload bytes, want the uncompressed sentinel (over-cap message blocked)", got.RSV1, len(got.Payload))
		}
		h.closeClient()
		h.closeUpstream()
		_ = h.waitSessionDone(10 * time.Second)
	})

	t.Run("no safety rules forwards verbatim", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		h := newWSHarness(t, ctx, harnessOpts{})
		h.performDeflateUpgrade(ctx, "permessage-deflate")
		comp := newMultiFrameDeflator(t).Compress(t, plain)
		h.writeCompressed(true, comp)
		got := h.mustReadRelayed(true)
		if !bytes.Equal(got.Payload, comp) {
			t.Errorf("upstream compressed payload (len %d) != the client's (len %d)", len(got.Payload), len(comp))
		}
		h.closeClient()
		h.closeUpstream()
		_ = h.waitSessionDone(10 * time.Second)
	})
}

func trimForLog(b []byte) []byte {
	if len(b) > 32 {
		return b[:32]
	}
	return b
}
