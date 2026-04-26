package ws

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// fakeRWC is a (reader, writer, closer) triple suitable for driving the
// WSLayer in unit tests. The reader side is a bytes.Buffer (or any
// io.Reader); the writer side captures everything written. Close is a
// no-op (counted) so tests can verify cascade.
type fakeRWC struct {
	reader io.Reader
	writer *bytes.Buffer

	mu     sync.Mutex
	closed int
}

func (f *fakeRWC) Read(p []byte) (int, error)  { return f.reader.Read(p) }
func (f *fakeRWC) Write(p []byte) (int, error) { return f.writer.Write(p) }
func (f *fakeRWC) Close() error {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
	return nil
}

func newFakeRWC(input []byte) *fakeRWC {
	return &fakeRWC{
		reader: bytes.NewReader(input),
		writer: &bytes.Buffer{},
	}
}

// helper: build an unmasked frame and return the bytes (using buildFrame
// from frame_test.go).
func makeFrame(t *testing.T, fin bool, opcode byte, payload []byte) []byte {
	t.Helper()
	return buildFrame(t, fin, opcode, false, [4]byte{}, payload)
}

func makeMaskedFrame(t *testing.T, fin bool, opcode byte, key [4]byte, payload []byte) []byte {
	t.Helper()
	masked := make([]byte, len(payload))
	copy(masked, payload)
	maskPayload(key, masked)
	return buildFrame(t, fin, opcode, true, key, masked)
}

// ---------------- Round-trip tests ----------------

func TestChannel_Next_TextFrame(t *testing.T) {
	t.Parallel()
	wire := makeFrame(t, true, OpcodeText, []byte("hello"))
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if env.Protocol != envelope.ProtocolWebSocket {
		t.Errorf("Protocol = %q, want %q", env.Protocol, envelope.ProtocolWebSocket)
	}
	if env.Direction != envelope.Receive {
		t.Errorf("Direction = %v, want Receive (RoleClient reads upstream)", env.Direction)
	}
	if env.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0", env.Sequence)
	}
	if env.StreamID != "s-1" {
		t.Errorf("StreamID = %q, want s-1", env.StreamID)
	}
	if env.FlowID == "" {
		t.Error("FlowID empty")
	}
	if !bytes.Equal(env.Raw, wire) {
		t.Errorf("Raw = %v, want %v (wire bytes verbatim)", env.Raw, wire)
	}
	msg := env.Message.(*envelope.WSMessage)
	if msg.Opcode != envelope.WSText {
		t.Errorf("Opcode = %v, want WSText", msg.Opcode)
	}
	if !msg.Fin {
		t.Error("Fin = false, want true")
	}
	if string(msg.Payload) != "hello" {
		t.Errorf("Payload = %q, want hello", msg.Payload)
	}
}

func TestChannel_Next_BinaryFrame(t *testing.T) {
	t.Parallel()
	wire := makeFrame(t, true, OpcodeBinary, []byte{0x00, 0x01, 0xFF})
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	msg := env.Message.(*envelope.WSMessage)
	if msg.Opcode != envelope.WSBinary {
		t.Errorf("Opcode = %v, want WSBinary", msg.Opcode)
	}
	if !bytes.Equal(msg.Payload, []byte{0x00, 0x01, 0xFF}) {
		t.Errorf("Payload mismatch: %v", msg.Payload)
	}
}

func TestChannel_Next_PingPong(t *testing.T) {
	t.Parallel()
	wire := append(makeFrame(t, true, OpcodePing, []byte("ping")),
		makeFrame(t, true, OpcodePong, []byte("pong"))...)
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	env1, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if env1.Message.(*envelope.WSMessage).Opcode != envelope.WSPing {
		t.Errorf("first Opcode = %v, want WSPing", env1.Message.(*envelope.WSMessage).Opcode)
	}

	env2, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if env2.Message.(*envelope.WSMessage).Opcode != envelope.WSPong {
		t.Errorf("second Opcode = %v, want WSPong", env2.Message.(*envelope.WSMessage).Opcode)
	}
	if env2.Sequence != 1 {
		t.Errorf("second Sequence = %d, want 1", env2.Sequence)
	}
}

func TestChannel_Next_ContinuationEmittedAsIndependentEnvelope(t *testing.T) {
	t.Parallel()
	wire := append(makeFrame(t, false, OpcodeText, []byte("frag1")),
		makeFrame(t, true, OpcodeContinuation, []byte("frag2"))...)
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	env1, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m1 := env1.Message.(*envelope.WSMessage)
	if m1.Opcode != envelope.WSText || m1.Fin {
		t.Errorf("first envelope: Opcode=%v Fin=%v, want WSText/false", m1.Opcode, m1.Fin)
	}
	if string(m1.Payload) != "frag1" {
		t.Errorf("first Payload = %q, want frag1", m1.Payload)
	}

	env2, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m2 := env2.Message.(*envelope.WSMessage)
	if m2.Opcode != envelope.WSContinuation || !m2.Fin {
		t.Errorf("second envelope: Opcode=%v Fin=%v, want WSContinuation/true", m2.Opcode, m2.Fin)
	}
	if string(m2.Payload) != "frag2" {
		t.Errorf("second Payload = %q, want frag2", m2.Payload)
	}
	if env2.Sequence != 1 {
		t.Errorf("second Sequence = %d, want 1", env2.Sequence)
	}
}

func TestChannel_Next_CloseFrameMapsToEOFOnNextCall(t *testing.T) {
	t.Parallel()
	closeBody := make([]byte, 2+len("bye"))
	binary.BigEndian.PutUint16(closeBody[:2], 1000)
	copy(closeBody[2:], "bye")
	wire := makeFrame(t, true, OpcodeClose, closeBody)
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	msg := env.Message.(*envelope.WSMessage)
	if msg.Opcode != envelope.WSClose {
		t.Errorf("Opcode = %v, want WSClose", msg.Opcode)
	}
	if msg.CloseCode != 1000 {
		t.Errorf("CloseCode = %d, want 1000", msg.CloseCode)
	}
	if msg.CloseReason != "bye" {
		t.Errorf("CloseReason = %q, want bye", msg.CloseReason)
	}

	// Next call must return io.EOF.
	_, err = ch.Next(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Errorf("second Next = %v, want io.EOF", err)
	}
	// Channel should be terminated.
	select {
	case <-ch.Closed():
	default:
		t.Error("Closed() did not fire after Close-frame EOF mapping")
	}
}

func TestChannel_Next_PreFrameEOFGraceful(t *testing.T) {
	t.Parallel()
	// Empty input — peer abandoned without sending a frame.
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	_, err := ch.Next(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Errorf("Next = %v, want io.EOF (graceful)", err)
	}
	if !errors.Is(ch.Err(), io.EOF) {
		t.Errorf("Err() = %v, want io.EOF", ch.Err())
	}
}

func TestChannel_Next_MalformedFrame_StreamErrorProtocol(t *testing.T) {
	t.Parallel()
	// Control frame with FIN=0 (forbidden). 0x09 (Ping no-FIN) is
	// rejected by validateFrameConstraints.
	wire := []byte{0x09, 0x04, 'p', 'i', 'n', 'g'}
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next = %v (%T), want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("Code = %v, want ErrorProtocol", se.Code)
	}
	if !strings.HasPrefix(se.Reason, "ws: ") {
		t.Errorf("Reason = %q, want ws-prefixed", se.Reason)
	}
}

func TestChannel_Next_MidFrameEOF_StreamErrorAborted(t *testing.T) {
	t.Parallel()
	// Frame header says payload=5, but only 2 bytes follow. Mid-frame
	// EOF → io.ErrUnexpectedEOF in ReadFrame, which we map to Aborted.
	wire := []byte{0x81, 0x05, 'H', 'e'}
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next = %v (%T), want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorAborted {
		t.Errorf("Code = %v, want ErrorAborted", se.Code)
	}
}

func TestChannel_Next_RawIsByteEqualToWire(t *testing.T) {
	t.Parallel()
	maskKey := [4]byte{0x01, 0x02, 0x03, 0x04}
	wire := makeMaskedFrame(t, true, OpcodeText, maskKey, []byte("hello"))
	rwc := newFakeRWC(wire)
	l := New(rwc, rwc, rwc, "s-1", RoleServer) // reads masked client→server frames
	defer l.Close()
	ch := <-l.Channels()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(env.Raw, wire) {
		t.Errorf("Raw mismatch:\n got: %v\nwant: %v", env.Raw, wire)
	}
	// And Direction should be Send (RoleServer reads from client).
	if env.Direction != envelope.Send {
		t.Errorf("Direction = %v, want Send (RoleServer reads from client)", env.Direction)
	}
	msg := env.Message.(*envelope.WSMessage)
	if !msg.Masked {
		t.Error("WSMessage.Masked = false, want true")
	}
	if msg.Mask != maskKey {
		t.Errorf("Mask = %v, want %v", msg.Mask, maskKey)
	}
	// Payload exposed on WSMessage is auto-unmasked by ReadFrame.
	if string(msg.Payload) != "hello" {
		t.Errorf("Payload = %q, want hello", msg.Payload)
	}
}

// ---------------- Send tests ----------------

func TestChannel_Send_RoleServer_RoundTrip(t *testing.T) {
	t.Parallel()
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleServer)
	defer l.Close()
	ch := <-l.Channels()

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSText,
			Fin:     true,
			Payload: []byte("hello"),
		},
	}
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}

	frame, _, err := ReadFrameRaw(bytes.NewReader(rwc.writer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Masked {
		t.Error("RoleServer wrote masked frame; want unmasked")
	}
	if string(frame.Payload) != "hello" {
		t.Errorf("Payload = %q, want hello", frame.Payload)
	}
}

func TestChannel_Send_CloseFrame_EncodesStructuredFields(t *testing.T) {
	t.Parallel()
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleServer)
	defer l.Close()
	ch := <-l.Channels()

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:      envelope.WSClose,
			Fin:         true,
			CloseCode:   1001,
			CloseReason: "going away",
		},
	}
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	frame, _, err := ReadFrameRaw(bytes.NewReader(rwc.writer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Opcode != OpcodeClose {
		t.Errorf("Opcode = %d, want OpcodeClose", frame.Opcode)
	}
	if len(frame.Payload) < 2 {
		t.Fatalf("Payload too short: %d bytes", len(frame.Payload))
	}
	gotCode := binary.BigEndian.Uint16(frame.Payload[:2])
	if gotCode != 1001 {
		t.Errorf("CloseCode wire = %d, want 1001", gotCode)
	}
	if string(frame.Payload[2:]) != "going away" {
		t.Errorf("CloseReason wire = %q, want going away", frame.Payload[2:])
	}
}

func TestChannel_Closed_ErrContract(t *testing.T) {
	t.Parallel()
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	ch := <-l.Channels()

	// Drive Next to graceful EOF.
	if _, err := ch.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("Next = %v, want io.EOF", err)
	}
	// Closed must fire AND Err must be populated already.
	select {
	case <-ch.Closed():
	default:
		t.Fatal("Closed not fired")
	}
	if !errors.Is(ch.Err(), io.EOF) {
		t.Errorf("Err = %v, want io.EOF", ch.Err())
	}

	// Channel.Close is a no-op and returns nil.
	if err := ch.Close(); err != nil {
		t.Errorf("Channel.Close() = %v, want nil", err)
	}
	// Layer.Close can still tear down.
	_ = l.Close()
}

// ---------------- Deflate tests ----------------

func TestChannel_Next_DeflateOff_FrameWithRSV1IsLeftAlone(t *testing.T) {
	t.Parallel()
	// Build a frame with RSV1=1 manually. Without WithDeflateEnabled, the
	// channel must NOT touch the payload (Compressed stays false).
	var buf bytes.Buffer
	buf.WriteByte(0xC1) // FIN=1, RSV1=1, Opcode=Text
	buf.WriteByte(0x05)
	buf.Write([]byte("nodef"))
	rwc := newFakeRWC(buf.Bytes())
	l := New(rwc, rwc, rwc, "s-1", RoleClient)
	defer l.Close()
	ch := <-l.Channels()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	msg := env.Message.(*envelope.WSMessage)
	if msg.Compressed {
		t.Error("Compressed = true, want false (deflate disabled)")
	}
	if string(msg.Payload) != "nodef" {
		t.Errorf("Payload = %q, want nodef", msg.Payload)
	}
}

func TestChannel_Next_DeflateOn_DecompressesSingleFrame(t *testing.T) {
	t.Parallel()
	// Compress a payload using the same primitive as the Layer.
	ds := newDeflateState(deflateParams{enabled: true, contextTakeover: true, windowBits: 15})
	plain := []byte("hello world hello world")
	compressed, err := ds.compress(plain, maxFramePayloadSize)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	// Wrap as RSV1=1, FIN=1, Opcode=Text.
	var buf bytes.Buffer
	buf.WriteByte(0xC1) // FIN=1, RSV1=1, Opcode=Text
	if len(compressed) <= 125 {
		buf.WriteByte(byte(len(compressed)))
	} else {
		// Test payload won't be that long.
		t.Fatalf("test setup: payload too long: %d", len(compressed))
	}
	buf.Write(compressed)

	rwc := newFakeRWC(buf.Bytes())
	l := New(rwc, rwc, rwc, "s-1", RoleClient,
		WithDeflateEnabled(true),
		WithServerDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer l.Close()
	ch := <-l.Channels()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	msg := env.Message.(*envelope.WSMessage)
	if !msg.Compressed {
		t.Error("Compressed = false, want true")
	}
	if string(msg.Payload) != string(plain) {
		t.Errorf("Payload = %q, want %q", msg.Payload, plain)
	}
}

func TestChannel_Send_DeflateOn_CompressesPayload(t *testing.T) {
	t.Parallel()
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleServer,
		WithDeflateEnabled(true),
		WithServerDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer l.Close()
	ch := <-l.Channels()

	plain := []byte("hello world hello world hello world hello world")
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:     envelope.WSText,
			Fin:        true,
			Compressed: true,
			Payload:    plain,
		},
	}
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	frame, _, err := ReadFrameRaw(bytes.NewReader(rwc.writer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !frame.RSV1 {
		t.Error("RSV1 = false on wire, want true (Compressed=true Send)")
	}
	if bytes.Equal(frame.Payload, plain) {
		t.Error("wire payload equals plain bytes; expected compression")
	}

	// Decompress with a fresh state (single frame, identity round-trip).
	ds := newDeflateState(deflateParams{enabled: true, contextTakeover: true, windowBits: 15})
	got, err := ds.decompress(frame.Payload, maxFramePayloadSize)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("decompress(wire) = %q, want %q", got, plain)
	}
}

func TestChannel_Deflate_ContextTakeoverMultiMessageRoundTrip(t *testing.T) {
	t.Parallel()
	// Two-channel pair: peerA encodes, peerB decodes.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	encoder := New(b, b, b, "s-1", RoleClient,
		WithDeflateEnabled(true),
		WithClientDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer encoder.Close()
	encCh := <-encoder.Channels()

	decoder := New(a, a, a, "s-1", RoleServer,
		WithDeflateEnabled(true),
		WithClientDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer decoder.Close()
	decCh := <-decoder.Channels()

	msgs := [][]byte{
		[]byte("dictionary-payload-AAAA-BBBB"),
		[]byte("dictionary-payload-AAAA-BBBB-again"),
		[]byte("entirely-different-trailing-bytes"),
	}

	type result struct {
		got [][]byte
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		var got [][]byte
		for i := 0; i < len(msgs); i++ {
			env, err := decCh.Next(context.Background())
			if err != nil {
				resCh <- result{got, err}
				return
			}
			got = append(got, env.Message.(*envelope.WSMessage).Payload)
		}
		resCh <- result{got, nil}
	}()

	for _, m := range msgs {
		env := &envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolWebSocket,
			Message: &envelope.WSMessage{
				Opcode:     envelope.WSText,
				Fin:        true,
				Compressed: true,
				Payload:    m,
			},
		}
		if err := encCh.Send(context.Background(), env); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("decoder error: %v", res.err)
	}
	if len(res.got) != len(msgs) {
		t.Fatalf("got %d messages, want %d", len(res.got), len(msgs))
	}
	for i, m := range msgs {
		if string(res.got[i]) != string(m) {
			t.Errorf("msg %d: got %q, want %q", i, res.got[i], m)
		}
	}
}

func TestChannel_Deflate_FragmentedCompressedMessage(t *testing.T) {
	t.Parallel()
	// Build a fragmented compressed message manually:
	//  - Start frame: FIN=0, RSV1=1, Opcode=Text, payload=first half of compressed bytes
	//  - Continuation frame: FIN=1, RSV1=0, Opcode=Continuation, payload=second half
	ds := newDeflateState(deflateParams{enabled: true, contextTakeover: true, windowBits: 15})
	plain := []byte("hello world hello world hello world hello world")
	compressed, err := ds.compress(plain, maxFramePayloadSize)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	half := len(compressed) / 2
	frag1 := compressed[:half]
	frag2 := compressed[half:]

	var wire bytes.Buffer
	// Start fragment: FIN=0, RSV1=1, Opcode=Text.
	wire.WriteByte(0x41) // 0100_0001
	wire.WriteByte(byte(len(frag1)))
	wire.Write(frag1)
	// Continuation FIN: FIN=1, Opcode=Continuation.
	wire.WriteByte(0x80)
	wire.WriteByte(byte(len(frag2)))
	wire.Write(frag2)

	rwc := newFakeRWC(wire.Bytes())
	l := New(rwc, rwc, rwc, "s-1", RoleClient,
		WithDeflateEnabled(true),
		WithServerDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer l.Close()
	ch := <-l.Channels()

	env1, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m1 := env1.Message.(*envelope.WSMessage)
	if !m1.Compressed {
		t.Error("first envelope: Compressed = false, want true")
	}
	if m1.Fin {
		t.Error("first envelope: Fin = true, want false")
	}
	if !bytes.Equal(m1.Payload, frag1) {
		t.Errorf("first envelope: Payload = %v, want verbatim compressed half", m1.Payload)
	}

	env2, err := ch.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m2 := env2.Message.(*envelope.WSMessage)
	if !m2.Compressed {
		t.Error("FIN envelope: Compressed = false, want true")
	}
	if !m2.Fin {
		t.Error("FIN envelope: Fin = false, want true")
	}
	if string(m2.Payload) != string(plain) {
		t.Errorf("FIN envelope: Payload = %q, want decompressed %q", m2.Payload, plain)
	}
}

func TestValidateFragmentAppend_OverflowReturnsProtocolError(t *testing.T) {
	t.Parallel()
	// have+add equals the cap → permitted.
	if se := validateFragmentAppend(int(maxCompressedPayloadSize)-1, 1); se != nil {
		t.Errorf("at-cap append rejected: %v", se)
	}
	// have+add exceeds the cap by 1 → rejected with ErrorProtocol.
	se := validateFragmentAppend(int(maxCompressedPayloadSize), 1)
	if se == nil {
		t.Fatal("over-cap append accepted; want StreamError")
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("Code = %v, want ErrorProtocol", se.Code)
	}
	if !strings.Contains(se.Reason, "fragment buffer overflow") {
		t.Errorf("Reason = %q, want it to contain 'fragment buffer overflow'", se.Reason)
	}
}

func TestChannel_Next_DeflateFragmentBufferOverflow_RejectsContinuation(t *testing.T) {
	t.Parallel()
	// Build a stream where the start fragment already pushes the buffer
	// to the cap, then the next continuation pushes it over. The Layer
	// must surface a StreamError(ErrorProtocol) with "fragment buffer
	// overflow" before any decompression is attempted.
	//
	// We don't actually need maxCompressedPayloadSize-many bytes on the
	// wire — the cap check uses len, so we can target the trip via
	// math.MaxInt-style arithmetic. But our cap is 16 MiB; it is
	// cheaper (test-time-wise) to lower the bar via a controlled call
	// to validateFragmentAppend (already covered above) and verify the
	// integration end-to-end with a synthetic small-cap regression.
	//
	// Instead, exercise the cap check via the actual code path by sending
	// a 64-byte start fragment, then a continuation that — were
	// maxCompressedPayloadSize artificially low — would overflow. The
	// at-cap unit test above and the decompress side cap together
	// guarantee correctness; this test pins the wire-level integration
	// for the on-overflow path documented behavior: error returned, fragment
	// state reset.
	//
	// Use a low-cap path: simulate the overflow by directly verifying that
	// after a synthetic in-place buffer at the cap, validateFragmentAppend
	// trips the channel. The unit test in TestValidateFragmentAppend
	// already covers the math.

	// Sanity: at the wire level, a normal fragmented compressed message
	// must still succeed (we have TestChannel_Deflate_FragmentedCompressedMessage).
	//
	// This second case verifies the on-error path in applyDeflate by
	// manually setting up the fragment state at the cap and exercising the
	// continuation branch.
	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleClient,
		WithDeflateEnabled(true),
		WithServerDeflate(deflateParams{enabled: true, contextTakeover: true, windowBits: 15}),
	)
	defer l.Close()
	chIface := <-l.Channels()
	ch := chIface.(*wsChannel)

	// Manually set the fragment buffer to one byte under the cap and the
	// fragmentation flag on (Receive direction = serverFragBuf for RoleClient).
	ch.serverFragBuf = make([]byte, maxCompressedPayloadSize)
	ch.serverFragOn = true

	// Now hand-craft a continuation frame whose payload is 1 byte —
	// pushing total to cap+1 → overflow.
	frame := &Frame{
		Fin:     false,
		RSV1:    false,
		Opcode:  OpcodeContinuation,
		Payload: []byte{0xAA},
	}
	msg := &envelope.WSMessage{
		Opcode: envelope.WSContinuation,
	}
	se := ch.applyDeflate(frame, envelope.Receive, msg)
	if se == nil {
		t.Fatal("applyDeflate accepted overflow continuation; want StreamError")
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("Code = %v, want ErrorProtocol", se.Code)
	}
	// Buffer must be reset on overflow so subsequent legitimate messages
	// are not contaminated.
	if len(ch.serverFragBuf) != 0 {
		t.Errorf("serverFragBuf len after overflow = %d, want 0 (reset)", len(ch.serverFragBuf))
	}
	if ch.serverFragOn {
		t.Error("serverFragOn after overflow = true, want false (reset)")
	}
}
