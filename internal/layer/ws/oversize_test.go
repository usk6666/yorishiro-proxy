package ws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-1321: a permessage-deflate message whose decompressed size exceeds
// the Layer's decompression cap must reach the peer unchanged (the wire
// frame is forwarded verbatim), the record must carry the
// WSDecompressedTooLarge anomaly, and a modified truncated message must be
// refused rather than forwarded truncated.

// oversizeTestCap is the decompression cap the unit tests run with so the
// over-cap scenarios stay small.
const oversizeTestCap = 64

func oversizeParams(contextTakeover bool) deflateParams {
	return deflateParams{enabled: true, contextTakeover: contextTakeover, windowBits: 15}
}

// oversizeTail is a non-repeating tail the follow-up message back-references
// under context takeover.
var oversizeTail = []byte("TAIL-UNIQUE-0123456789-abcdefghijklmnopqrstuvwxyz-END")

// oversizeMessages returns (big, next): big decompresses past
// oversizeTestCap; next back-references big's tail.
func oversizeMessages() (big, next []byte) {
	big = append(bytes.Repeat([]byte("X"), 200), oversizeTail...)
	next = append([]byte("next message "), oversizeTail...)
	return big, next
}

// compressMessages compresses msgs as one peer would: a shared writer
// under context takeover, a fresh writer per message otherwise.
func compressMessages(t *testing.T, contextTakeover bool, msgs ...[]byte) [][]byte {
	t.Helper()
	if contextTakeover {
		return deflateCompressWithContext(t, msgs)
	}
	out := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, deflateCompress(t, m))
	}
	return out
}

// encodeFrame serialises f into its wire bytes.
func encodeFrame(t *testing.T, f *Frame) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	return buf.Bytes()
}

// compressedServerFrame returns an unmasked single-frame compressed text
// message as a server would write it.
func compressedServerFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	return encodeFrame(t, &Frame{Fin: true, RSV1: true, Opcode: OpcodeText, Payload: payload})
}

// newOversizeRelay builds the two Layers a relay uses for server→client
// traffic: rd (RoleClient) reads the server's frames from wire; wr
// (RoleServer) writes server→client frames into out.
func newOversizeRelay(t *testing.T, wire []byte, p deflateParams) (rd, wr layer.Channel, out *bytes.Buffer) {
	t.Helper()
	rdRWC := newFakeRWC(wire)
	rdL := New(rdRWC, rdRWC, rdRWC, "s-1", RoleClient,
		WithDeflateEnabled(true), WithServerDeflate(p), withInflateCap(oversizeTestCap))
	t.Cleanup(func() { _ = rdL.Close() })
	wrRWC := newFakeRWC(nil)
	wrL := New(wrRWC, wrRWC, wrRWC, "s-1", RoleServer,
		WithDeflateEnabled(true), WithServerDeflate(p), withInflateCap(oversizeTestCap))
	t.Cleanup(func() { _ = wrL.Close() })
	return <-rdL.Channels(), <-wrL.Channels(), wrRWC.writer
}

// peerInflate parses the frames in wire and inflates every compressed one
// the way the receiving peer would (one long-lived window under context
// takeover). It returns the plaintext of each compressed message.
func peerInflate(t *testing.T, wire []byte, p deflateParams) [][]byte {
	t.Helper()
	ds := newDeflateState(p)
	r := bytes.NewReader(wire)
	var out [][]byte
	for r.Len() > 0 {
		f, err := ReadFrame(r)
		if err != nil {
			t.Fatalf("peer: ReadFrame: %v", err)
		}
		if !f.RSV1 {
			out = append(out, f.Payload)
			continue
		}
		plain, err := ds.decompress(f.Payload, 1<<20)
		if err != nil {
			t.Fatalf("peer: inflate: %v", err)
		}
		out = append(out, plain)
	}
	return out
}

func wsAnomalyOf(msg *envelope.WSMessage, typ envelope.AnomalyType) *envelope.Anomaly {
	for i := range msg.Anomalies {
		if msg.Anomalies[i].Type == typ {
			return &msg.Anomalies[i]
		}
	}
	return nil
}

func mustNextWS(t *testing.T, ch layer.Channel) (*envelope.Envelope, *envelope.WSMessage) {
	t.Helper()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return env, env.Message.(*envelope.WSMessage)
}

func wantSendRefused(t *testing.T, err error) {
	t.Helper()
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Send err = %v, want *layer.StreamError refusing the truncated message", err)
	}
	if se.Code != layer.ErrorAborted {
		t.Errorf("Send StreamError.Code = %v, want ErrorAborted", se.Code)
	}
	if !strings.Contains(se.Reason, strconv.Itoa(oversizeTestCap)) {
		t.Errorf("Send StreamError.Reason = %q, want it to name the %d-byte cap", se.Reason, oversizeTestCap)
	}
}

// T8 (single-frame part): the over-cap message carries the anomaly and a
// cap-sized payload; the following back-referencing message decodes.
func TestOversize_Next_SingleFrame_RecordsAnomalyAndKeepsWindow(t *testing.T) {
	for _, ct := range []bool{true, false} {
		t.Run("contextTakeover="+strconv.FormatBool(ct), func(t *testing.T) {
			big, next := oversizeMessages()
			comp := compressMessages(t, ct, big, next)
			wire := append(compressedServerFrame(t, comp[0]), compressedServerFrame(t, comp[1])...)
			rd, _, _ := newOversizeRelay(t, wire, oversizeParams(ct))

			_, m1 := mustNextWS(t, rd)
			if !bytes.Equal(m1.Payload, big[:oversizeTestCap]) {
				t.Errorf("over-cap payload = %q, want the first %d bytes", m1.Payload, oversizeTestCap)
			}
			a := wsAnomalyOf(m1, envelope.AnomalyWSDecompressedTooLarge)
			if a == nil {
				t.Fatalf("over-cap message Anomalies = %+v, want %s", m1.Anomalies, envelope.AnomalyWSDecompressedTooLarge)
			}
			if !strings.Contains(a.Detail, strconv.Itoa(oversizeTestCap)) {
				t.Errorf("anomaly Detail = %q, want it to name the cap %d", a.Detail, oversizeTestCap)
			}
			if ct && !strings.Contains(a.Detail, strconv.Itoa(len(big))) {
				t.Errorf("anomaly Detail = %q, want the full size %d under context takeover", a.Detail, len(big))
			}

			_, m2 := mustNextWS(t, rd)
			if !bytes.Equal(m2.Payload, next) {
				t.Errorf("follow-up payload = %q, want %q", m2.Payload, next)
			}
			if len(m2.Anomalies) != 0 {
				t.Errorf("follow-up Anomalies = %+v, want none", m2.Anomalies)
			}
		})
	}
}

// T8: fragmented over-cap message (receive side only). The FIN envelope
// carries the anomaly; the next context-takeover message decodes.
func TestOversize_Next_Fragmented_RecordsAnomalyAndKeepsWindow(t *testing.T) {
	big, next := oversizeMessages()
	comp := compressMessages(t, true, big, next)
	half := len(comp[0]) / 2
	var wire []byte
	wire = append(wire, encodeFrame(t, &Frame{Fin: false, RSV1: true, Opcode: OpcodeText, Payload: comp[0][:half]})...)
	wire = append(wire, encodeFrame(t, &Frame{Fin: true, Opcode: OpcodeContinuation, Payload: comp[0][half:]})...)
	wire = append(wire, compressedServerFrame(t, comp[1])...)
	rd, _, _ := newOversizeRelay(t, wire, oversizeParams(true))

	_, start := mustNextWS(t, rd)
	if start.Fin {
		t.Fatal("first envelope Fin = true, want the start fragment")
	}
	_, fin := mustNextWS(t, rd)
	if len(fin.Payload) != oversizeTestCap {
		t.Errorf("FIN payload len = %d, want %d", len(fin.Payload), oversizeTestCap)
	}
	if wsAnomalyOf(fin, envelope.AnomalyWSDecompressedTooLarge) == nil {
		t.Errorf("FIN envelope Anomalies = %+v, want %s", fin.Anomalies, envelope.AnomalyWSDecompressedTooLarge)
	}
	_, m3 := mustNextWS(t, rd)
	if !bytes.Equal(m3.Payload, next) {
		t.Errorf("follow-up payload = %q, want %q", m3.Payload, next)
	}
}

// An unmodified over-cap message is written verbatim (the received wire
// frame); the following message still decodes at the peer.
func TestOversize_Send_UnmodifiedForwardedVerbatim(t *testing.T) {
	for _, ct := range []bool{true, false} {
		t.Run("contextTakeover="+strconv.FormatBool(ct), func(t *testing.T) {
			p := oversizeParams(ct)
			big, next := oversizeMessages()
			comp := compressMessages(t, ct, big, next)
			wire := append(compressedServerFrame(t, comp[0]), compressedServerFrame(t, comp[1])...)
			rd, wr, out := newOversizeRelay(t, wire, p)

			env1, _ := mustNextWS(t, rd)
			if err := wr.Send(context.Background(), env1); err != nil {
				t.Fatalf("Send over-cap: %v", err)
			}
			if !bytes.Equal(out.Bytes(), env1.Raw) {
				t.Errorf("written bytes (len %d) != received wire frame (len %d)", out.Len(), len(env1.Raw))
			}
			env2, _ := mustNextWS(t, rd)
			if err := wr.Send(context.Background(), env2); err != nil {
				t.Fatalf("Send follow-up: %v", err)
			}
			got := peerInflate(t, out.Bytes(), p)
			if len(got) != 2 || !bytes.Equal(got[0], big) || !bytes.Equal(got[1], next) {
				t.Errorf("peer decoded %q, want [%q %q]", got, big, next)
			}
		})
	}
}

// A modified truncated message is refused: nothing is written and the
// Channel terminates.
func TestOversize_Send_ModifiedRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *envelope.WSMessage)
	}{
		{"payload", func(m *envelope.WSMessage) { m.Payload = append([]byte("Y"), m.Payload[1:]...) }},
		{"payload in place", func(m *envelope.WSMessage) { m.Payload[0] = 'Y' }},
		{"opcode", func(m *envelope.WSMessage) { m.Opcode = envelope.WSBinary }},
		{"compressed", func(m *envelope.WSMessage) { m.Compressed = false }},
		{"fin", func(m *envelope.WSMessage) { m.Fin = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			big, _ := oversizeMessages()
			comp := compressMessages(t, true, big)
			rd, wr, out := newOversizeRelay(t, compressedServerFrame(t, comp[0]), oversizeParams(true))
			env, msg := mustNextWS(t, rd)
			tc.mutate(msg)
			wantSendRefused(t, wr.Send(context.Background(), env))
			if out.Len() != 0 {
				t.Errorf("refused Send wrote %d bytes, want 0", out.Len())
			}
			select {
			case <-wr.Closed():
			default:
				t.Error("Channel not terminated after a refused Send")
			}
		})
	}
}

// Envelope.Clone drops the Layer's Opaque snapshot (e.g. intercept
// modify_and_forward); the anomaly alone must make Send fail closed.
func TestOversize_Send_AnomalyWithoutSnapshotRefused(t *testing.T) {
	big, _ := oversizeMessages()
	comp := compressMessages(t, true, big)
	rd, wr, out := newOversizeRelay(t, compressedServerFrame(t, comp[0]), oversizeParams(true))
	env, _ := mustNextWS(t, rd)
	wantSendRefused(t, wr.Send(context.Background(), env.Clone()))
	if out.Len() != 0 {
		t.Errorf("refused Send wrote %d bytes, want 0", out.Len())
	}
}

// Under context takeover a verbatim frame is only valid while both legs
// share the same LZ77 window. A modified earlier message makes them diverge,
// so the unmodified over-cap message that follows is refused.
func TestOversize_Send_WindowDivergenceRefused(t *testing.T) {
	small := append([]byte("small message "), oversizeTail...)
	big, _ := oversizeMessages()
	big = append(append([]byte{}, oversizeTail...), big...)
	comp := compressMessages(t, true, small, big)
	wire := append(compressedServerFrame(t, comp[0]), compressedServerFrame(t, comp[1])...)
	rd, wr, out := newOversizeRelay(t, wire, oversizeParams(true))

	env1, m1 := mustNextWS(t, rd)
	m1.Payload = []byte("rewritten by a transform")
	if err := wr.Send(context.Background(), env1); err != nil {
		t.Fatalf("Send modified small message: %v", err)
	}
	written := out.Len()

	env2, _ := mustNextWS(t, rd)
	wantSendRefused(t, wr.Send(context.Background(), env2))
	if out.Len() != written {
		t.Errorf("refused Send wrote %d bytes, want 0", out.Len()-written)
	}
}

// Raw wins (a plugin's msg["raw"]) still applies to a truncated message.
func TestOversize_Send_RawWinsAllowed(t *testing.T) {
	big, _ := oversizeMessages()
	comp := compressMessages(t, true, big)
	rd, wr, out := newOversizeRelay(t, compressedServerFrame(t, comp[0]), oversizeParams(true))
	env, _ := mustNextWS(t, rd)
	custom := encodeFrame(t, &Frame{Fin: true, Opcode: OpcodeText, Payload: []byte("plugin raw")})
	env.Raw = custom
	env.RawAuthoritative = true
	if err := wr.Send(context.Background(), env); err != nil {
		t.Fatalf("raw-wins Send: %v", err)
	}
	if !bytes.Equal(out.Bytes(), custom) {
		t.Errorf("written = %x, want the plugin's raw bytes %x", out.Bytes(), custom)
	}
}

// A message at or under the cap keeps today's behaviour: no anomaly, no
// Opaque snapshot, re-compressed on Send.
func TestOversize_AtCapUnchanged(t *testing.T) {
	msg := bytes.Repeat([]byte("Z"), oversizeTestCap)
	comp := compressMessages(t, true, msg)
	rd, wr, out := newOversizeRelay(t, compressedServerFrame(t, comp[0]), oversizeParams(true))
	env, m := mustNextWS(t, rd)
	if !bytes.Equal(m.Payload, msg) || len(m.Anomalies) != 0 {
		t.Fatalf("at-cap message: payload len %d anomalies %+v", len(m.Payload), m.Anomalies)
	}
	if env.Opaque != nil {
		t.Errorf("at-cap message Opaque = %T, want nil", env.Opaque)
	}
	if err := wr.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := peerInflate(t, out.Bytes(), oversizeParams(true))
	if len(got) != 1 || !bytes.Equal(got[0], msg) {
		t.Errorf("peer decoded %q, want %q", got, msg)
	}
	if _, err := rd.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("trailing Next err = %v, want io.EOF", err)
	}
}
