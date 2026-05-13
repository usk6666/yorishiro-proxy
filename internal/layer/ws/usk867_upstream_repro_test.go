package ws

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-867: localize the failure point upstream of (*deflateState).decompress.
//
// The companion file deflate_wire_repro_test.go proves that the captured
// wire-format payloads decode cleanly when fed directly into
// (*deflateState).decompress. So the defect must live one of three places:
//
//   (1) ReadFrame — the WS frame parser reads two frames from a single
//       TCP read window incorrectly, e.g. mid-frame boundary confusion.
//   (2) applyDeflate — fragment state (*onPtr / *bufPtr) is polluted across
//       single-frame compressed messages and the second message takes a
//       wrong branch.
//   (3) Something further out (session loop, intercept hold, keepalive
//       Send race). Those are not exercisable from this package alone.
//
// These tests cover (1) and (2). If any of them fail, that hypothesis is
// confirmed. If they all pass, the defect is in (3).

// ---- B-1: ReadFrame across a TCP read boundary ---------------------------

// buildCompressedTextFrame returns wire bytes for an unmasked text frame
// with FIN=1, RSV1=1 and the given payload. This is the frame shape the
// proxy sees on the upstream→client direction (where USK-867's
// "upstream.Next" error surfaces). The bytes are byte-exact and do not
// involve any TCP/socket layer.
func buildCompressedTextFrame(payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x80 | 0x40 | OpcodeText) // FIN=1, RSV1=1, opcode=text
	plen := len(payload)
	switch {
	case plen <= 125:
		buf.WriteByte(byte(plen))
	case plen <= 65535:
		buf.WriteByte(126)
		_ = binary.Write(&buf, binary.BigEndian, uint16(plen))
	default:
		buf.WriteByte(127)
		_ = binary.Write(&buf, binary.BigEndian, uint64(plen))
	}
	buf.Write(payload)
	return buf.Bytes()
}

func TestReadFrame_USK867_TwoCompressedFramesInOneRead_BytesReader(t *testing.T) {
	// Real "first"→"second" compressed payloads from stream 265e311b.
	msg1Payload, _ := hex.DecodeString("4acb2c2a2e0100")
	msg2Payload, _ := hex.DecodeString("2a4e4dcecf4b0100")

	wire := append(buildCompressedTextFrame(msg1Payload), buildCompressedTextFrame(msg2Payload)...)
	r := bytes.NewReader(wire)

	f1, raw1, err := ReadFrameRaw(r)
	if err != nil {
		t.Fatalf("msg1 ReadFrameRaw: %v", err)
	}
	if !f1.Fin || !f1.RSV1 || f1.Opcode != OpcodeText {
		t.Fatalf("msg1 frame flags: fin=%v rsv1=%v opcode=%#x", f1.Fin, f1.RSV1, f1.Opcode)
	}
	if !bytes.Equal(f1.Payload, msg1Payload) {
		t.Fatalf("msg1 payload mismatch: got %x want %x", f1.Payload, msg1Payload)
	}
	if !bytes.Equal(raw1, buildCompressedTextFrame(msg1Payload)) {
		t.Errorf("msg1 raw bytes mismatch: got %x", raw1)
	}

	// The crucial assertion: ReadFrame for msg1 must NOT consume any bytes
	// belonging to msg2. The reader cursor must be exactly at the start of
	// msg2's first header byte.
	remaining, _ := io.ReadAll(r)
	if !bytes.Equal(remaining, buildCompressedTextFrame(msg2Payload)) {
		t.Fatalf("after reading msg1, reader contains %x; want msg2 wire bytes %x",
			remaining, buildCompressedTextFrame(msg2Payload))
	}
}

func TestReadFrame_USK867_TwoCompressedFramesInOneRead_Concatenated(t *testing.T) {
	// Same as above but reads msg1 and msg2 from the SAME io.Reader instance
	// in sequence — the path exercised when the underlying TCP socket
	// happened to coalesce both frames into one read.
	msg1Payload, _ := hex.DecodeString("4acb2c2a2e0100")
	msg2Payload, _ := hex.DecodeString("2a4e4dcecf4b0100")
	wire := append(buildCompressedTextFrame(msg1Payload), buildCompressedTextFrame(msg2Payload)...)
	r := bytes.NewReader(wire)

	for i, want := range [][]byte{msg1Payload, msg2Payload} {
		f, _, err := ReadFrameRaw(r)
		if err != nil {
			t.Fatalf("frame %d ReadFrameRaw: %v", i+1, err)
		}
		if !f.Fin || !f.RSV1 || f.Opcode != OpcodeText {
			t.Fatalf("frame %d flags: fin=%v rsv1=%v opcode=%#x", i+1, f.Fin, f.RSV1, f.Opcode)
		}
		if !bytes.Equal(f.Payload, want) {
			t.Fatalf("frame %d payload = %x, want %x", i+1, f.Payload, want)
		}
	}
}

// chunkyReader serves bytes from a slice but reports a varying number of
// bytes per Read(), modelling a real TCP socket that may deliver frames in
// arbitrary chunks. The chunkSize sequence drives reads of length
// chunkSize[0], chunkSize[1], … cycling at the end.
type chunkyReader struct {
	buf       []byte
	offset    int
	chunkSize []int
	step      int
}

func (cr *chunkyReader) Read(p []byte) (int, error) {
	if cr.offset >= len(cr.buf) {
		return 0, io.EOF
	}
	sz := cr.chunkSize[cr.step%len(cr.chunkSize)]
	cr.step++
	if sz > len(p) {
		sz = len(p)
	}
	if sz > len(cr.buf)-cr.offset {
		sz = len(cr.buf) - cr.offset
	}
	n := copy(p, cr.buf[cr.offset:cr.offset+sz])
	cr.offset += n
	return n, nil
}

func TestReadFrame_USK867_FragmentedTCPReads(t *testing.T) {
	// Drive ReadFrame across pathological TCP-chunking patterns. If the
	// frame parser has any reliance on full-frame-per-read semantics, one
	// of these will surface it. ReadFrame uses io.ReadFull internally so
	// these should all succeed.
	msg1Payload, _ := hex.DecodeString("4acb2c2a2e0100")
	msg2Payload, _ := hex.DecodeString("2a4e4dcecf4b0100")
	wire := append(buildCompressedTextFrame(msg1Payload), buildCompressedTextFrame(msg2Payload)...)

	cases := []struct {
		name      string
		chunkSize []int
	}{
		{"byte-by-byte", []int{1}},
		{"3-byte-chunks", []int{3}},
		{"split-mid-header", []int{1, 99}},         // first chunk just the FIN/RSV/opcode byte
		{"split-mid-payload", []int{4, 99}},        // 2-byte header + part of payload, then rest
		{"frame-boundary-then-tail", []int{9, 99}}, // exactly msg1 (9 bytes), then msg2 in one chunk
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cr := &chunkyReader{buf: wire, chunkSize: tc.chunkSize}
			for i, want := range [][]byte{msg1Payload, msg2Payload} {
				f, _, err := ReadFrameRaw(cr)
				if err != nil {
					t.Fatalf("frame %d: %v", i+1, err)
				}
				if !f.RSV1 || f.Opcode != OpcodeText {
					t.Fatalf("frame %d flags: rsv1=%v opcode=%#x", i+1, f.RSV1, f.Opcode)
				}
				if !bytes.Equal(f.Payload, want) {
					t.Fatalf("frame %d payload = %x, want %x", i+1, f.Payload, want)
				}
			}
		})
	}
}

// ---- B-2: applyDeflate fragment-state pollution across single-frame msgs --

func TestApplyDeflate_USK867_TwoSingleFrameMessages_NoStatePollution(t *testing.T) {
	// Build a wsChannel through the public Layer constructor so the deflate
	// state and options are wired exactly as production code wires them.
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleClient,
		WithDeflateEnabled(true),
		// Configure BOTH directions with context-takeover. The Receive
		// direction for RoleClient maps to serverDS (see deflateForDirection).
		WithClientDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
		WithServerDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer l.Close()
	chIface := <-l.Channels()
	ch := chIface.(*wsChannel)

	// USK-867 stream 265e311b s→c bytes: "first" then a synthesized "second"
	// that exercises the same decode path. (We use these because they are
	// the exact wire form produced by Node ws@8.20.1 in the live failure.)
	msg1Payload, _ := hex.DecodeString("4acb2c2a2e0100")
	msg2Payload, _ := hex.DecodeString("2a4e4dcecf4b0100")

	for i, tc := range []struct {
		payload  []byte
		expected string
	}{
		{msg1Payload, "first"},
		{msg2Payload, "second"},
	} {
		frame := &Frame{
			Fin:     true,
			RSV1:    true,
			Opcode:  OpcodeText,
			Payload: tc.payload,
		}
		msg := &envelope.WSMessage{Opcode: envelope.WSText, Fin: true}
		// Receive direction so serverDS is used (RoleClient → upstream-facing).
		se := ch.applyDeflate(frame, envelope.Receive, msg)
		if se != nil {
			t.Fatalf("msg%d applyDeflate: %v", i+1, se)
		}
		if !msg.Compressed {
			t.Errorf("msg%d Compressed flag not set", i+1)
		}
		if string(msg.Payload) != tc.expected {
			t.Errorf("msg%d Payload = %q, want %q", i+1, msg.Payload, tc.expected)
		}
		// Critical invariant: after a (RSV1=1, FIN=1) single-frame compressed
		// message, the fragment state for this direction MUST remain quiescent.
		// If serverFragOn is true after msg1, msg2 enters the wrong branch in
		// applyDeflate — exactly the USK-867 symptom shape.
		if ch.serverFragOn {
			t.Errorf("after msg%d, serverFragOn = true; want false (single-frame msg must not arm continuation state)", i+1)
		}
		if len(ch.serverFragBuf) != 0 {
			t.Errorf("after msg%d, serverFragBuf len = %d; want 0", i+1, len(ch.serverFragBuf))
		}
	}
}

// Same as above but for the Send direction (clientDS / clientFragBuf path).
// Confirms the c→s decode path is also free of cross-message fragment
// pollution.
func TestApplyDeflate_USK867_TwoSingleFrameMessages_SendDirection(t *testing.T) {
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleClient,
		WithDeflateEnabled(true),
		WithClientDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
		WithServerDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer l.Close()
	chIface := <-l.Channels()
	ch := chIface.(*wsChannel)

	// Use stream 0f99451a c→s payloads, "p3-01-deflate-hello" → "p3-01-deflate-second".
	msg1Payload, _ := hex.DecodeString("2a30d63530d44d494dcb492c49d5cd48cdc9c90700")
	msg2Payload, _ := hex.DecodeString("2a40112a4e4dcecf4b0100")

	for i, tc := range []struct {
		payload  []byte
		expected string
	}{
		{msg1Payload, "p3-01-deflate-hello"},
		{msg2Payload, "p3-01-deflate-second"},
	} {
		frame := &Frame{
			Fin:     true,
			RSV1:    true,
			Opcode:  OpcodeText,
			Payload: tc.payload,
		}
		msg := &envelope.WSMessage{Opcode: envelope.WSText, Fin: true}
		se := ch.applyDeflate(frame, envelope.Send, msg)
		if se != nil {
			t.Fatalf("msg%d applyDeflate: %v", i+1, se)
		}
		if string(msg.Payload) != tc.expected {
			t.Errorf("msg%d Payload = %q, want %q", i+1, msg.Payload, tc.expected)
		}
		if ch.clientFragOn {
			t.Errorf("after msg%d, clientFragOn = true; want false", i+1)
		}
		if len(ch.clientFragBuf) != 0 {
			t.Errorf("after msg%d, clientFragBuf len = %d; want 0", i+1, len(ch.clientFragBuf))
		}
	}
}
