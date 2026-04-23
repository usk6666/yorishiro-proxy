package http2

import (
	"bytes"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// decodeFirstHeaderBlock reads frames from b, collecting the HEADERS (+
// CONTINUATION) header block fragment(s) until END_HEADERS, decodes via a
// fresh hpack.Decoder with the default table size, and returns the
// (decoded, remaining-buf-contents) pair.
func decodeFirstHeaderBlock(t *testing.T, buf []byte) ([]hpack.HeaderField, []*frame.Frame) {
	t.Helper()
	rdr := frame.NewReader(bytes.NewReader(buf))
	var fragment []byte
	var collected []*frame.Frame
	endHeaders := false
	for !endHeaders {
		f, err := rdr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		collected = append(collected, f)
		switch f.Header.Type {
		case frame.TypeHeaders, frame.TypeContinuation:
			fragment = append(fragment, f.Payload...)
			if f.Header.Flags&frame.FlagEndHeaders != 0 {
				endHeaders = true
			}
		default:
			t.Fatalf("unexpected frame type while collecting HEADERS: %v", f.Header.Type)
		}
	}
	// Keep reading the remaining frames for the caller.
	for {
		f, err := rdr.ReadFrame()
		if err != nil {
			break
		}
		collected = append(collected, f)
	}
	dec := hpack.NewDecoder(defaultEncoderTableSize)
	hdrs, err := dec.Decode(fragment)
	if err != nil {
		t.Fatalf("hpack.Decode: %v", err)
	}
	return hdrs, collected
}

// findHeader returns the value of the first (name, ?) entry, or "" when not found.
func findHeader(hdrs []hpack.HeaderField, name string) string {
	for _, hf := range hdrs {
		if hf.Name == name {
			return hf.Value
		}
	}
	return ""
}

func TestEncodeWireBytes_HeadersOnlyRequest(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/path",
			Headers: []envelope.KeyValue{
				{Name: "x-injected", Value: "by-proxy"},
			},
		},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	if len(out) < frame.HeaderSize {
		t.Fatalf("out too short: %d", len(out))
	}
	hdrs, all := decodeFirstHeaderBlock(t, out)
	if v := findHeader(hdrs, ":method"); v != "GET" {
		t.Errorf(":method = %q, want GET", v)
	}
	if v := findHeader(hdrs, ":path"); v != "/path" {
		t.Errorf(":path = %q, want /path", v)
	}
	if v := findHeader(hdrs, "x-injected"); v != "by-proxy" {
		t.Errorf("x-injected = %q, want by-proxy", v)
	}
	// With no body/trailers, the initial HEADERS frame must carry END_STREAM.
	if all[0].Header.Flags&frame.FlagEndStream == 0 {
		t.Errorf("initial HEADERS missing END_STREAM flag (headers-only message)")
	}
}

func TestEncodeWireBytes_HeadersAndBody(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status: 200,
			Headers: []envelope.KeyValue{
				{Name: "content-type", Value: "text/plain"},
			},
			Body: []byte("hello-world"),
		},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	_, all := decodeFirstHeaderBlock(t, out)
	// Expect initial HEADERS (no END_STREAM) + DATA with END_STREAM.
	if all[0].Header.Flags&frame.FlagEndStream != 0 {
		t.Errorf("HEADERS must NOT carry END_STREAM when body present")
	}
	var gotBody []byte
	var dataSaw bool
	for _, f := range all[1:] {
		if f.Header.Type != frame.TypeData {
			t.Errorf("unexpected non-DATA frame after HEADERS: %v", f.Header.Type)
			continue
		}
		dataSaw = true
		gotBody = append(gotBody, f.Payload...)
	}
	if !dataSaw {
		t.Fatalf("no DATA frame emitted")
	}
	if !bytes.Equal(gotBody, []byte("hello-world")) {
		t.Errorf("body round-trip = %q, want hello-world", gotBody)
	}
	// Last DATA frame must carry END_STREAM.
	last := all[len(all)-1]
	if last.Header.Flags&frame.FlagEndStream == 0 {
		t.Errorf("last DATA frame missing END_STREAM")
	}
}

func TestEncodeWireBytes_HeadersBodyAndTrailers(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:  200,
			Headers: []envelope.KeyValue{{Name: "content-type", Value: "text/plain"}},
			Body:    []byte("body"),
			Trailers: []envelope.KeyValue{
				{Name: "grpc-status", Value: "0"},
			},
		},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	rdr := frame.NewReader(bytes.NewReader(out))
	var frames []*frame.Frame
	for {
		f, err := rdr.ReadFrame()
		if err != nil {
			break
		}
		frames = append(frames, f)
	}
	// Expect: HEADERS, DATA (no END_STREAM), HEADERS (trailers, END_STREAM).
	if len(frames) != 3 {
		t.Fatalf("frame count = %d, want 3", len(frames))
	}
	if frames[0].Header.Type != frame.TypeHeaders {
		t.Errorf("frame[0] type = %v, want HEADERS", frames[0].Header.Type)
	}
	if frames[0].Header.Flags&frame.FlagEndStream != 0 {
		t.Errorf("frame[0] must NOT carry END_STREAM when trailers present")
	}
	if frames[1].Header.Type != frame.TypeData {
		t.Errorf("frame[1] type = %v, want DATA", frames[1].Header.Type)
	}
	if frames[1].Header.Flags&frame.FlagEndStream != 0 {
		t.Errorf("DATA must NOT carry END_STREAM when trailers follow")
	}
	if frames[2].Header.Type != frame.TypeHeaders {
		t.Errorf("frame[2] type = %v, want HEADERS (trailers)", frames[2].Header.Type)
	}
	if frames[2].Header.Flags&frame.FlagEndStream == 0 {
		t.Errorf("trailer HEADERS missing END_STREAM")
	}
	// Decode trailers via a fresh decoder (dynamic tables independent) to
	// assert round-trip content.
	initDec := hpack.NewDecoder(defaultEncoderTableSize)
	if _, err := initDec.Decode(frames[0].Payload); err != nil {
		t.Fatalf("decode initial HEADERS: %v", err)
	}
	trailers, err := initDec.Decode(frames[2].Payload)
	if err != nil {
		t.Fatalf("decode trailer HEADERS: %v", err)
	}
	if v := findHeader(trailers, "grpc-status"); v != "0" {
		t.Errorf("grpc-status = %q, want 0; trailers=%v", v, trailers)
	}
}

func TestEncodeWireBytes_ContinuationFragmentation(t *testing.T) {
	// Build headers whose encoded block exceeds DefaultMaxFrameSize so the
	// encoder must fragment HEADERS + CONTINUATION.
	const maxFrameSize = frame.DefaultMaxFrameSize
	// Using literal-never-indexed style encoding, but easier: just stack
	// many medium-sized headers. Each ~512-byte value * 40 = ~20 KB > 16 KB.
	big := bytes.Repeat([]byte("x"), 512)
	msg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/",
	}
	for i := 0; i < 40; i++ {
		name := "x-large-" + string(rune('a'+(i%26)))
		// Make names unique via a counter suffix so HPACK cannot index-reuse.
		if i >= 26 {
			name = name + string(rune('a'+(i-26)))
		}
		msg.Headers = append(msg.Headers, envelope.KeyValue{Name: name, Value: string(big)})
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	_, all := decodeFirstHeaderBlock(t, out)
	// Verify HEADERS -> at least one CONTINUATION -> end.
	if all[0].Header.Type != frame.TypeHeaders {
		t.Fatalf("first frame = %v, want HEADERS", all[0].Header.Type)
	}
	if all[0].Header.Flags&frame.FlagEndHeaders != 0 {
		t.Errorf("HEADERS must NOT carry END_HEADERS when CONTINUATION follows (block larger than maxFrameSize=%d)", maxFrameSize)
	}
	sawContinuation := false
	for _, f := range all[1:] {
		if f.Header.Type == frame.TypeContinuation {
			sawContinuation = true
			break
		}
	}
	if !sawContinuation {
		t.Errorf("no CONTINUATION frame emitted for oversized header block")
	}
}

// TestEncodeWireBytes_BodyBufferMaterialized verifies that a message whose
// body is carried on BodyBuffer (possibly file-backed) round-trips through
// the offline encoder into DATA frames that decode back to the original
// bytes. This is the USK-632 replacement for the old passthrough-partial
// path; h2 no longer emits ErrPartialWireBytes from wireencode.
func TestEncodeWireBytes_BodyBufferMaterialized(t *testing.T) {
	// 15 MiB body — large enough to force multiple DATA frames under the
	// default MaxFrameSize (16 KiB) and to be plausibly file-backed.
	const bodySize = 15 << 20
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = byte(i % 251)
	}

	bb := bodybuf.NewMemory(nil)
	defer bb.Release()
	if _, err := bb.Write(body); err != nil {
		t.Fatalf("bodybuf.Write: %v", err)
	}

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:     200,
			Headers:    []envelope.KeyValue{{Name: "content-type", Value: "application/octet-stream"}},
			BodyBuffer: bb,
		},
	}
	out, err := EncodeWireBytes(env)
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}

	// Decode the full frame sequence: HEADERS (no END_STREAM) + DATA* with
	// END_STREAM on the last frame. Accumulate DATA payloads and compare.
	rdr := frame.NewReader(bytes.NewReader(out))
	first, err := rdr.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if first.Header.Type != frame.TypeHeaders {
		t.Fatalf("first frame = %v, want HEADERS", first.Header.Type)
	}
	if first.Header.Flags&frame.FlagEndStream != 0 {
		t.Errorf("HEADERS must NOT carry END_STREAM when body present")
	}
	dec := hpack.NewDecoder(defaultEncoderTableSize)
	if _, derr := dec.Decode(first.Payload); derr != nil {
		t.Fatalf("decode HEADERS: %v", derr)
	}

	var collected []byte
	var last *frame.Frame
	for {
		f, rerr := rdr.ReadFrame()
		if rerr != nil {
			break
		}
		if f.Header.Type != frame.TypeData {
			t.Fatalf("unexpected non-DATA frame: %v", f.Header.Type)
		}
		collected = append(collected, f.Payload...)
		last = f
	}
	if last == nil {
		t.Fatal("no DATA frames emitted")
	}
	if last.Header.Flags&frame.FlagEndStream == 0 {
		t.Error("last DATA frame missing END_STREAM")
	}
	if len(collected) != len(body) {
		t.Fatalf("body round-trip = %d bytes, want %d", len(collected), len(body))
	}
	if !bytes.Equal(collected, body) {
		t.Error("body bytes differ after encode/decode round-trip")
	}
}

func TestEncodeWireBytes_NilEnvelope(t *testing.T) {
	if _, err := EncodeWireBytes(nil); err == nil {
		t.Error("expected error for nil envelope")
	}
}

func TestEncodeWireBytes_NonHTTPMessage(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.RawMessage{Bytes: []byte("raw")},
	}
	if _, err := EncodeWireBytes(env); err == nil {
		t.Error("expected error for non-HTTP message")
	}
}
