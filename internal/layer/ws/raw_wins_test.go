package ws

import (
	"bytes"
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1238: RFC-001 §9.3 D4 "Raw wins" on WebSocket. A raw-authoritative
// envelope (plugin msg["raw"]) is written to the wire verbatim; anything
// else keeps the Message re-encode path.

// pluginRawFrame is a frame the Message path can never produce: a masked
// text frame with a fixed mask key and RSV2 set (Send zeroes RSV2 and
// draws a fresh mask).
func pluginRawFrame() []byte {
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	payload := []byte("PLUGIN")
	maskPayload(key, payload)
	out := []byte{0x80 | 0x20 | OpcodeText, 0x80 | byte(len(payload))}
	out = append(out, key[:]...)
	return append(out, payload...)
}

// TestChannel_Send_RawWins pins the Layer contract for every write mode
// (client-side masked, server-side unmasked, RFC 8441 h2 mode).
func TestChannel_Send_RawWins(t *testing.T) {
	modes := []struct {
		name string
		role Role
		opts []Option
	}{
		{name: "RoleClient", role: RoleClient},
		{name: "RoleServer", role: RoleServer},
		{name: "RoleClient h2Mode", role: RoleClient, opts: []Option{WithH2Mode(true)}},
	}
	cases := []struct {
		name    string
		auth    bool
		raw     []byte
		wantRaw bool
	}{
		{name: "marked writes Raw verbatim", auth: true, raw: pluginRawFrame(), wantRaw: true},
		{name: "marked with nil Raw takes Message path", auth: true, raw: nil},
		{name: "unmarked ignores Raw", auth: false, raw: pluginRawFrame()},
	}
	for _, m := range modes {
		for _, tc := range cases {
			t.Run(m.name+"/"+tc.name, func(t *testing.T) {
				rwc := newFakeRWC(nil)
				l := New(rwc, rwc, rwc, "s-raw-wins", m.role, m.opts...)
				defer l.Close()
				ch := <-l.Channels()

				env := &envelope.Envelope{
					Direction:        envelope.Send,
					Protocol:         envelope.ProtocolWebSocket,
					Raw:              tc.raw,
					RawAuthoritative: tc.auth,
					Message: &envelope.WSMessage{
						Opcode: envelope.WSText, Fin: true, Payload: []byte("message"),
					},
				}
				if err := ch.Send(context.Background(), env); err != nil {
					t.Fatalf("Send: %v", err)
				}
				got := rwc.writer.Bytes()
				if tc.wantRaw {
					if !bytes.Equal(got, tc.raw) {
						t.Errorf("wire = %x, want plugin raw %x", got, tc.raw)
					}
					return
				}
				frame, consumed, err := ReadFrameRaw(bytes.NewReader(got))
				if err != nil {
					t.Fatalf("parse Message-path frame %x: %v", got, err)
				}
				if len(consumed) != len(got) {
					t.Errorf("wire has %d trailing bytes after the frame", len(got)-len(consumed))
				}
				if string(frame.Payload) != "message" || frame.RSV2 {
					t.Errorf("Message-path frame = payload %q RSV2=%v, want payload %q RSV2=false", frame.Payload, frame.RSV2, "message")
				}
			})
		}
	}
}

// Deflate resync fixtures: m2 repeats m0, so a compressor whose LZ77
// window misses m1 back-references into the wrong bytes on a peer that
// did inflate m1. len(m1) >= len(m0) makes the stale distance land in m1.
var (
	resyncM0 = []byte("the quick brown fox jumps over the lazy dog 0123456789")
	resyncM1 = []byte("ZYXWVUTSRQPONMLKJIHGFEDCBA zyxwvutsrqponmlkjihgfedcba 9876543210!!")
)

// wireFrame builds a frame as role would put it on the wire: masked with
// a fixed key for RoleClient (client→server), unmasked for RoleServer.
// b0 carries the FIN / RSV / opcode bits.
func wireFrame(role Role, b0 byte, payload []byte) []byte {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, &Frame{
		Fin: b0&0x80 != 0, RSV1: b0&0x40 != 0, Opcode: b0 & 0x0F,
		Masked: role == RoleClient, MaskKey: [4]byte{0x0A, 0x0B, 0x0C, 0x0D}, Payload: payload,
	})
	return buf.Bytes()
}

// resyncStep is one Send in the deflate resync scenario: a raw-wins
// envelope carrying raw, or (ping) a Message-path Ping control frame.
type resyncStep struct {
	raw  []byte
	ping bool
}

// TestChannel_Send_RawWins_DeflateContextResync: after a raw-wins
// compressed message on a context-takeover direction, the Layer's send
// compressor must have advanced its window exactly as the peer's
// inflater did, so the next Message-path compressed frame still decodes.
// Covered for both write roles, with a Message-path control frame
// between raw-wins fragments (RFC 6455 §5.4), and with
// no_context_takeover (resync skipped; every message starts fresh).
func TestChannel_Send_RawWins_DeflateContextResync(t *testing.T) {
	roles := []struct {
		name string
		role Role
		peer Role
		opt  func(deflateParams) Option
	}{
		{name: "RoleClient", role: RoleClient, peer: RoleServer, opt: WithClientDeflate},
		{name: "RoleServer", role: RoleServer, peer: RoleClient, opt: WithServerDeflate},
	}
	for _, rl := range roles {
		for _, takeover := range []bool{true, false} {
			// The compressed m1 a plugin would forward verbatim: with context
			// takeover, as produced by a long-lived flate writer that already
			// saw m0; without, from a fresh writer.
			var m1c []byte
			if takeover {
				m1c = deflateCompressWithContext(t, [][]byte{resyncM0, resyncM1})[1]
			} else {
				m1c = deflateCompressWithContext(t, [][]byte{resyncM1})[0]
			}
			half := len(m1c) / 2
			whole := wireFrame(rl.role, 0x80|0x40|OpcodeText, m1c)
			fragA := wireFrame(rl.role, 0x40|OpcodeText, m1c[:half])
			fragB := wireFrame(rl.role, 0x80|OpcodeContinuation, m1c[half:])
			cases := []struct {
				name  string
				steps []resyncStep
			}{
				{name: "single frame", steps: []resyncStep{{raw: whole}}},
				{name: "fragments in two envelopes", steps: []resyncStep{{raw: fragA}, {raw: fragB}}},
				{name: "fragments in one raw", steps: []resyncStep{{raw: append(append([]byte(nil), fragA...), fragB...)}}},
				{name: "Message-path Ping between raw fragments", steps: []resyncStep{{raw: fragA}, {ping: true}, {raw: fragB}}},
			}
			params := deflateParams{enabled: true, contextTakeover: takeover, windowBits: 15}
			for _, tc := range cases {
				name := rl.name + "/context_takeover/" + tc.name
				if !takeover {
					name = rl.name + "/no_context_takeover/" + tc.name
				}
				t.Run(name, func(t *testing.T) {
					runDeflateResyncCase(t, rl.role, rl.peer, rl.opt(params), takeover, tc.steps)
				})
			}
		}
	}
}

func runDeflateResyncCase(t *testing.T, role, peerRole Role, deflateOpt Option, takeover bool, steps []resyncStep) {
	t.Helper()
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-resync", role, WithDeflateEnabled(true), deflateOpt)
	defer l.Close()
	ch := <-l.Channels()
	wc := ch.(*wsChannel)

	send := func(env *envelope.Envelope) {
		t.Helper()
		if err := ch.Send(context.Background(), env); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	msgEnv := func(m *envelope.WSMessage) *envelope.Envelope {
		return &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket, Message: m}
	}

	send(msgEnv(&envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Compressed: true, Payload: resyncM0}))
	for _, st := range steps {
		if st.ping {
			send(msgEnv(&envelope.WSMessage{Opcode: envelope.WSPing, Fin: true, Payload: []byte("keepalive")}))
			continue
		}
		before := rwc.writer.Len()
		send(&envelope.Envelope{
			Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
			Raw: st.raw, RawAuthoritative: true,
			Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Compressed: true, Payload: resyncM1},
		})
		if got := rwc.writer.Bytes()[before:]; !bytes.Equal(got, st.raw) {
			t.Fatalf("raw-wins bytes not written verbatim:\n got %x\nwant %x", got, st.raw)
		}
		if !takeover {
			// no_context_takeover: resync returns before touching the
			// send-side fragment state, even for an unfinished fragment.
			if _, onPtr := wc.fragStateForDirection(wc.sendDirection()); *onPtr {
				t.Fatalf("no_context_takeover: resync assembled a fragment; want early return")
			}
		}
	}
	send(msgEnv(&envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Compressed: true, Payload: resyncM0}))

	// The peer: an independent Layer reading the same bytes with the
	// same negotiated inflater parameters.
	wire := append([]byte(nil), rwc.writer.Bytes()...)
	peer := newFakeRWC(wire)
	pl := New(peer, peer, peer, "s-peer", peerRole, WithDeflateEnabled(true), deflateOpt)
	defer pl.Close()
	pch := <-pl.Channels()
	var fins [][]byte
	for {
		env, err := pch.Next(context.Background())
		if err != nil {
			break
		}
		if m := env.Message.(*envelope.WSMessage); m.Fin && m.Opcode != envelope.WSPing {
			fins = append(fins, m.Payload)
		}
	}
	want := [][]byte{resyncM0, resyncM1, resyncM0}
	if len(fins) != len(want) {
		t.Fatalf("peer decoded %d messages, want %d: %q", len(fins), len(want), fins)
	}
	for i := range want {
		if !bytes.Equal(fins[i], want[i]) {
			t.Errorf("peer message %d = %q, want %q", i, fins[i], want[i])
		}
	}
}
