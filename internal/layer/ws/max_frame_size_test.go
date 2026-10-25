package ws

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-1322: WithMaxFrameSize (web_socket.max_frame_size) must govern the
// receive side too — the frame-length check in the parser and the
// permessage-deflate caps (compressed input, fragment accumulator, and
// decompressed output) — not only the Send-side pre-mask check.

// patternedPayload returns n deterministic, non-uniform bytes.
func patternedPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// storedDeflate encodes msgs as one permessage-deflate peer would with a
// shared writer, but at flate.NoCompression (stored blocks): the encoded
// size exceeds the plaintext, which is what the >16 MiB compressed-size
// cases need, and it is fast under -race. The RFC 7692 sync trailer is
// stripped from each message.
func storedDeflate(t *testing.T, msgs ...[]byte) [][]byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.NoCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	out := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		buf.Reset()
		if _, err := w.Write(m); err != nil {
			t.Fatalf("flate write: %v", err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("flate flush: %v", err)
		}
		out = append(out, bytes.TrimSuffix(append([]byte(nil), buf.Bytes()...), flateTrailer))
	}
	return out
}

// readRoleFrame returns the wire bytes of a single-frame message a Layer
// of role reads: RoleServer reads masked client frames, RoleClient reads
// unmasked server frames.
func readRoleFrame(t *testing.T, role Role, opcode byte, payload []byte) []byte {
	t.Helper()
	if role == RoleServer {
		return makeMaskedFrame(t, true, opcode, [4]byte{0x11, 0x22, 0x33, 0x44}, payload)
	}
	return makeFrame(t, true, opcode, payload)
}

// frameHeaderOnly returns just the header of a frame claiming n payload
// bytes (64-bit extended length); the length check fires before the
// payload is read, so the payload need not be present.
func frameHeaderOnly(role Role, n uint64) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x80 | OpcodeBinary)
	b1 := byte(127)
	if role == RoleServer {
		b1 |= 0x80
	}
	buf.WriteByte(b1)
	_ = binary.Write(&buf, binary.BigEndian, n)
	if role == RoleServer {
		buf.Write([]byte{1, 2, 3, 4})
	}
	return buf.Bytes()
}

var maxFrameRoles = []struct {
	name string
	role Role
}{
	{name: "RoleServer(masked)", role: RoleServer},
	{name: "RoleClient(unmasked)", role: RoleClient},
}

// wantFrameTooLarge asserts err is the receive-side oversize protocol
// error naming n and capN, and that the Channel is terminated.
func wantFrameTooLarge(t *testing.T, ch layer.Channel, err error, n, capN int64) {
	t.Helper()
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next err = %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("StreamError.Code = %v, want ErrorProtocol", se.Code)
	}
	want := fmt.Sprintf("frame payload too large: %d > %d", n, capN)
	if !strings.Contains(se.Reason, want) {
		t.Errorf("StreamError.Reason = %q, want it to contain %q", se.Reason, want)
	}
	if ch.Err() == nil {
		t.Error("Channel.Err() = nil after oversize frame, want terminal error")
	}
}

// Test Plan #3: a raised cap lets a frame above the 16 MiB default through
// intact, in both read roles.
func TestMaxFrameSize_Next_RaisedCapAcceptsFrameAboveDefault(t *testing.T) {
	const capN = 17 << 20
	payload := patternedPayload(int(maxFramePayloadSize) + 64<<10)
	for _, rl := range maxFrameRoles {
		t.Run(rl.name, func(t *testing.T) {
			wire := readRoleFrame(t, rl.role, OpcodeBinary, payload)
			rwc := newFakeRWC(wire)
			l := New(rwc, rwc, rwc, "s-big", rl.role, WithMaxFrameSize(capN))
			defer l.Close()
			ch := <-l.Channels()

			env, err := ch.Next(context.Background())
			if err != nil {
				t.Fatalf("Next: %v (want the %d-byte frame accepted under a %d cap)", err, len(payload), capN)
			}
			msg := env.Message.(*envelope.WSMessage)
			if !bytes.Equal(msg.Payload, payload) {
				t.Errorf("Payload len %d differs from the sent %d-byte payload", len(msg.Payload), len(payload))
			}
			if !bytes.Equal(env.Raw, wire) {
				t.Errorf("Raw len %d differs from the %d-byte wire frame", len(env.Raw), len(wire))
			}
		})
	}
}

// Test Plan #4: a lowered cap rejects a larger frame on receive exactly
// like today's 16 MiB overflow — ErrorProtocol, Channel terminated,
// nothing written to the peer.
func TestMaxFrameSize_Next_LoweredCapRejectsFrame(t *testing.T) {
	const capN = 1 << 20
	const n = 2 << 20
	for _, rl := range maxFrameRoles {
		t.Run(rl.name, func(t *testing.T) {
			wire := readRoleFrame(t, rl.role, OpcodeBinary, patternedPayload(n))
			rwc := newFakeRWC(wire)
			l := New(rwc, rwc, rwc, "s-small", rl.role, WithMaxFrameSize(capN))
			defer l.Close()
			ch := <-l.Channels()

			_, err := ch.Next(context.Background())
			wantFrameTooLarge(t, ch, err, n, capN)
			if rwc.writer.Len() != 0 {
				t.Errorf("rejected frame wrote %d bytes to the peer, want 0", rwc.writer.Len())
			}
		})
	}
}

// Test Plan #9 (characterization): without WithMaxFrameSize the receive
// cap stays at the 16 MiB default.
func TestMaxFrameSize_Next_DefaultCapUnchanged(t *testing.T) {
	n := int64(maxFramePayloadSize) + 1
	for _, rl := range maxFrameRoles {
		t.Run(rl.name, func(t *testing.T) {
			rwc := newFakeRWC(frameHeaderOnly(rl.role, uint64(n)))
			l := New(rwc, rwc, rwc, "s-default", rl.role)
			defer l.Close()
			ch := <-l.Channels()
			_, err := ch.Next(context.Background())
			wantFrameTooLarge(t, ch, err, n, maxFramePayloadSize)
		})
	}
	if _, err := ReadFrame(bytes.NewReader(frameHeaderOnly(RoleClient, uint64(n)))); err == nil {
		t.Error("ReadFrame accepted a frame over the 16 MiB default")
	}
	if _, _, err := ReadFrameRawLimit(bytes.NewReader(frameHeaderOnly(RoleClient, uint64(n))), 0); err == nil {
		t.Error("ReadFrameRawLimit(limit=0) accepted a frame over the 16 MiB default")
	}
}

// ReadFrameRawLimit enforces the caller's cap: at the cap the frame is
// returned verbatim, one byte over it is rejected before the payload is
// read.
func TestReadFrameRawLimit_EnforcesCallerCap(t *testing.T) {
	const capN = 10
	ok := makeFrame(t, true, OpcodeBinary, patternedPayload(capN))
	f, raw, err := ReadFrameRawLimit(bytes.NewReader(ok), capN)
	if err != nil {
		t.Fatalf("at-cap frame: %v", err)
	}
	if !bytes.Equal(raw, ok) || len(f.Payload) != capN {
		t.Errorf("at-cap frame: raw/payload mismatch (raw %d bytes, payload %d)", len(raw), len(f.Payload))
	}
	_, _, err = ReadFrameRawLimit(bytes.NewReader(makeFrame(t, true, OpcodeBinary, patternedPayload(capN+1))), capN)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("frame payload too large: %d > %d", capN+1, capN)) {
		t.Errorf("over-cap frame err = %v, want frame payload too large: %d > %d", err, capN+1, capN)
	}
}

// deflateReader builds a RoleClient Layer (reads unmasked server frames)
// with permessage-deflate negotiated server→client.
func deflateReader(t *testing.T, wire []byte, takeover bool, opts ...Option) layer.Channel {
	t.Helper()
	rwc := newFakeRWC(wire)
	p := deflateParams{enabled: true, contextTakeover: takeover, windowBits: 15}
	all := append([]Option{WithDeflateEnabled(true), WithServerDeflate(p)}, opts...)
	l := New(rwc, rwc, rwc, "s-deflate", RoleClient, all...)
	t.Cleanup(func() { _ = l.Close() })
	return <-l.Channels()
}

// Test Plan #6: under a raised cap a single compressed frame whose
// compressed size exceeds 16 MiB decodes fully, with no over-cap anomaly.
func TestMaxFrameSize_Deflate_CompressedFrameAboveDefault(t *testing.T) {
	plain := patternedPayload(17 << 20)
	comp := storedDeflate(t, plain)[0]
	if int64(len(comp)) <= maxFramePayloadSize {
		t.Fatalf("fixture: compressed size %d must exceed the 16 MiB default", len(comp))
	}
	ch := deflateReader(t, compressedServerFrame(t, comp), false, WithMaxFrameSize(32<<20))
	_, msg := mustNextWS(t, ch)
	if !bytes.Equal(msg.Payload, plain) {
		t.Errorf("decoded payload len %d, want the %d-byte plaintext", len(msg.Payload), len(plain))
	}
	if a := wsAnomalyOf(msg, envelope.AnomalyWSDecompressedTooLarge); a != nil {
		t.Errorf("unexpected over-cap anomaly under a 32 MiB cap: %+v", a)
	}
}

// Test Plan #7: the decompression cap follows max_frame_size in both
// directions.
func TestMaxFrameSize_Deflate_DecompressCapFollowsMaxFrameSize(t *testing.T) {
	t.Run("raised cap decodes 20 MiB without anomaly", func(t *testing.T) {
		plain := make([]byte, 20<<20)
		ch := deflateReader(t, compressedServerFrame(t, deflateCompress(t, plain)), false, WithMaxFrameSize(32<<20))
		_, msg := mustNextWS(t, ch)
		if len(msg.Payload) != len(plain) {
			t.Errorf("decoded payload len %d, want %d", len(msg.Payload), len(plain))
		}
		if a := wsAnomalyOf(msg, envelope.AnomalyWSDecompressedTooLarge); a != nil {
			t.Errorf("unexpected over-cap anomaly under a 32 MiB cap: %+v", a)
		}
	})
	t.Run("lowered cap marks 2 MiB over-cap and forwards verbatim", func(t *testing.T) {
		const capN = 1 << 20
		plain := make([]byte, 2<<20)
		wire := compressedServerFrame(t, deflateCompress(t, plain))
		ch := deflateReader(t, wire, false, WithMaxFrameSize(capN))
		env, msg := mustNextWS(t, ch)
		a := wsAnomalyOf(msg, envelope.AnomalyWSDecompressedTooLarge)
		if a == nil {
			t.Fatalf("no WSDecompressedTooLarge anomaly for a 2 MiB message under a 1 MiB cap (payload len %d)", len(msg.Payload))
		}
		if !strings.Contains(a.Detail, "1048576") {
			t.Errorf("anomaly Detail = %q, want it to report the 1048576 cap", a.Detail)
		}
		if len(msg.Payload) != capN {
			t.Errorf("recorded payload len %d, want the first %d bytes", len(msg.Payload), capN)
		}

		p := deflateParams{enabled: true, contextTakeover: false, windowBits: 15}
		wrRWC := newFakeRWC(nil)
		wrL := New(wrRWC, wrRWC, wrRWC, "s-deflate", RoleServer,
			WithDeflateEnabled(true), WithServerDeflate(p), WithMaxFrameSize(capN))
		defer wrL.Close()
		wr := <-wrL.Channels()
		if err := wr.Send(context.Background(), env); err != nil {
			t.Fatalf("Send unmodified over-cap message: %v", err)
		}
		if !bytes.Equal(wrRWC.writer.Bytes(), wire) {
			t.Errorf("written %d bytes, want the %d-byte received frame verbatim", wrRWC.writer.Len(), len(wire))
		}
	})
}

// Test Plan #8: under a raised cap a fragmented compressed message whose
// accumulated compressed size exceeds 16 MiB reassembles and decodes.
func TestMaxFrameSize_Deflate_FragmentedAboveDefault(t *testing.T) {
	plain := patternedPayload(18 << 20)
	comp := storedDeflate(t, plain)[0]
	half := len(comp) / 2
	wire := append(
		buildFrameRSV1(t, false, OpcodeBinary, comp[:half]),
		makeFrame(t, true, OpcodeContinuation, comp[half:])...)
	ch := deflateReader(t, wire, true, WithMaxFrameSize(32<<20))

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next (first fragment): %v", err)
	}
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next (FIN fragment): %v", err)
	}
	msg := env.Message.(*envelope.WSMessage)
	if !bytes.Equal(msg.Payload, plain) {
		t.Errorf("decoded payload len %d, want the %d-byte plaintext", len(msg.Payload), len(plain))
	}
	if a := wsAnomalyOf(msg, envelope.AnomalyWSDecompressedTooLarge); a != nil {
		t.Errorf("unexpected over-cap anomaly under a 32 MiB cap: %+v", a)
	}
}

// buildFrameRSV1 returns an unmasked frame with RSV1 set.
func buildFrameRSV1(t *testing.T, fin bool, opcode byte, payload []byte) []byte {
	t.Helper()
	return encodeFrame(t, &Frame{Fin: fin, RSV1: true, Opcode: opcode, Payload: payload})
}

// Test Plan #10: a plugin raw-wins compressed frame over the 16 MiB default
// still advances the send-side deflate window (the resync parse is bounded
// by the raw bytes, not the cap), so the next Message-path compressed
// frame decodes at the peer.
func TestMaxFrameSize_RawWins_ResyncAboveDefault(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: true, windowBits: 15}
	big := patternedPayload(17 << 20)
	bigC := storedDeflate(t, resyncM0, big)[1]
	raw := wireFrame(RoleClient, 0x80|0x40|OpcodeBinary, bigC)

	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-rawwins", RoleClient, WithDeflateEnabled(true), WithClientDeflate(params))
	defer l.Close()
	ch := <-l.Channels()
	msgEnv := func(m *envelope.WSMessage) *envelope.Envelope {
		return &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket, Message: m}
	}
	for i, env := range []*envelope.Envelope{
		msgEnv(&envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Compressed: true, Payload: resyncM0}),
		{
			Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
			Raw: raw, RawAuthoritative: true,
			Message: &envelope.WSMessage{Opcode: envelope.WSBinary, Fin: true, Compressed: true},
		},
		msgEnv(&envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Compressed: true, Payload: resyncM0}),
	} {
		if err := ch.Send(context.Background(), env); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	peer := newFakeRWC(append([]byte(nil), rwc.writer.Bytes()...))
	pl := New(peer, peer, peer, "s-peer", RoleServer, WithDeflateEnabled(true), WithClientDeflate(params),
		WithMaxFrameSize(32<<20))
	defer pl.Close()
	pch := <-pl.Channels()
	var got [][]byte
	for {
		env, err := pch.Next(context.Background())
		if err != nil {
			break
		}
		got = append(got, env.Message.(*envelope.WSMessage).Payload)
	}
	if len(got) != 3 {
		t.Fatalf("peer decoded %d messages, want 3", len(got))
	}
	if !bytes.Equal(got[1], big) {
		t.Errorf("peer message 1: len %d, want the %d-byte plaintext", len(got[1]), len(big))
	}
	if !bytes.Equal(got[2], resyncM0) {
		t.Errorf("peer message 2 = %q, want %q (send window did not advance over the raw-wins frame)", got[2], resyncM0)
	}
}
