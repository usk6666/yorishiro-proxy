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

// maskedFrame builds a client→server frame with a fixed mask key and the
// given first byte (FIN / RSV / opcode bits).
func maskedFrame(b0 byte, payload []byte) []byte {
	key := [4]byte{0x0A, 0x0B, 0x0C, 0x0D}
	var buf bytes.Buffer
	_ = WriteFrame(&buf, &Frame{
		Fin: b0&0x80 != 0, RSV1: b0&0x40 != 0, Opcode: b0 & 0x0F,
		Masked: true, MaskKey: key, Payload: payload,
	})
	return buf.Bytes()
}

// TestChannel_Send_RawWins_DeflateContextResync: after a raw-wins
// compressed message on a context-takeover direction, the Layer's send
// compressor must have advanced its window exactly as the peer's
// inflater did, so the next Message-path compressed frame still decodes.
func TestChannel_Send_RawWins_DeflateContextResync(t *testing.T) {
	// The client's compressed m1 as produced by a long-lived flate writer
	// that already saw m0 (the bytes a plugin would forward verbatim).
	m1c := deflateCompressWithContext(t, [][]byte{resyncM0, resyncM1})[1]
	half := len(m1c) / 2

	whole := maskedFrame(0x80|0x40|OpcodeText, m1c)
	fragA := maskedFrame(0x40|OpcodeText, m1c[:half])
	fragB := maskedFrame(0x80|OpcodeContinuation, m1c[half:])

	cases := []struct {
		name string
		raws [][]byte // one raw-wins Send per element
	}{
		{name: "single frame", raws: [][]byte{whole}},
		{name: "fragments in two envelopes", raws: [][]byte{fragA, fragB}},
		{name: "fragments in one raw", raws: [][]byte{append(append([]byte(nil), fragA...), fragB...)}},
	}
	params := deflateParams{enabled: true, contextTakeover: true, windowBits: 15}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rwc := newFakeRWC(nil)
			l := New(rwc, rwc, rwc, "s-resync", RoleClient,
				WithDeflateEnabled(true), WithClientDeflate(params))
			defer l.Close()
			ch := <-l.Channels()

			send := func(env *envelope.Envelope) {
				t.Helper()
				if err := ch.Send(context.Background(), env); err != nil {
					t.Fatalf("Send: %v", err)
				}
			}
			msgEnv := func(payload []byte) *envelope.Envelope {
				return &envelope.Envelope{
					Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
					Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Compressed: true, Payload: payload},
				}
			}

			send(msgEnv(resyncM0))
			m0Len := rwc.writer.Len()
			var rawAll []byte
			for _, raw := range tc.raws {
				rawAll = append(rawAll, raw...)
				send(&envelope.Envelope{
					Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
					Raw: raw, RawAuthoritative: true,
					Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Compressed: true, Payload: resyncM1},
				})
			}
			send(msgEnv(resyncM0))

			wire := rwc.writer.Bytes()
			if !bytes.Equal(wire[m0Len:m0Len+len(rawAll)], rawAll) {
				t.Fatalf("raw-wins bytes not written verbatim:\n got %x\nwant %x", wire[m0Len:min(len(wire), m0Len+len(rawAll))], rawAll)
			}

			// The peer: an independent Layer reading the same bytes with a
			// persistent (context-takeover) inflater.
			peer := newFakeRWC(append([]byte(nil), wire...))
			pl := New(peer, peer, peer, "s-peer", RoleServer,
				WithDeflateEnabled(true), WithClientDeflate(params))
			defer pl.Close()
			pch := <-pl.Channels()
			var fins [][]byte
			for {
				env, err := pch.Next(context.Background())
				if err != nil {
					break
				}
				if m := env.Message.(*envelope.WSMessage); m.Fin {
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
		})
	}
}
