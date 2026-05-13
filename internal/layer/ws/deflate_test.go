package ws

import (
	"bytes"
	"compress/flate"
	"fmt"
	"math"
	"sync"
	"testing"
)

// deflateCompress compresses data using raw DEFLATE (no zlib/gzip wrapper),
// matching the permessage-deflate wire format. The 4-byte trailer
// (0x00 0x00 0xFF 0xFF) is stripped per RFC 7692 Section 7.2.1.
func deflateCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	// Flush instead of Close to get the sync marker (0x00 0x00 0xFF 0xFF)
	// that we need to strip per RFC 7692.
	if err := w.Flush(); err != nil {
		t.Fatalf("flate flush: %v", err)
	}

	compressed := buf.Bytes()
	// Strip the trailing sync marker per RFC 7692 Section 7.2.1.
	trailer := []byte{0x00, 0x00, 0xff, 0xff}
	if bytes.HasSuffix(compressed, trailer) {
		compressed = compressed[:len(compressed)-4]
	}
	return compressed
}

func TestDeflateState_Decompress_SingleMessage(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: false,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	original := []byte("Hello, World!")
	compressed := deflateCompress(t, original)

	decompressed, err := ds.decompress(compressed, 1<<20)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Errorf("decompress = %q, want %q", decompressed, original)
	}
}

func TestDeflateState_Decompress_MultipleMessages_NoContextTakeover(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: false,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	messages := []string{"first message", "second message", "third message"}
	for _, msg := range messages {
		original := []byte(msg)
		compressed := deflateCompress(t, original)

		decompressed, err := ds.decompress(compressed, 1<<20)
		if err != nil {
			t.Fatalf("decompress %q: %v", msg, err)
		}
		if !bytes.Equal(decompressed, original) {
			t.Errorf("decompress %q = %q, want %q", msg, decompressed, original)
		}
	}
}

func TestDeflateState_Decompress_EmptyPayload(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: false,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	result, err := ds.decompress(nil, 1<<20)
	if err != nil {
		t.Fatalf("decompress nil: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("decompress nil = %v, want empty", result)
	}

	result, err = ds.decompress([]byte{}, 1<<20)
	if err != nil {
		t.Fatalf("decompress empty: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("decompress empty = %v, want empty", result)
	}
}

func TestDeflateState_Decompress_MaxSizeLimit(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: false,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	// Create data larger than the limit.
	original := bytes.Repeat([]byte("A"), 1000)
	compressed := deflateCompress(t, original)

	maxSize := int64(100)
	decompressed, err := ds.decompress(compressed, maxSize)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if int64(len(decompressed)) != maxSize {
		t.Errorf("decompressed length = %d, want %d", len(decompressed), maxSize)
	}
}

func TestDeflateState_Decompress_InvalidData(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: false,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	_, err := ds.decompress([]byte{0xFF, 0xFE, 0xFD}, 1<<20)
	if err == nil {
		t.Error("decompress invalid data should return error")
	}
}

func TestDeflateState_Close(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	}
	ds := newDeflateState(params)

	original := []byte("test")
	compressed := deflateCompress(t, original)

	_, err := ds.decompress(compressed, 1<<20)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}

	// Close should not panic.
	ds.close()
	// Double close should not panic.
	ds.close()
}

// deflateCompressWithContext compresses multiple messages using a single flate
// writer, simulating the context takeover mode where the LZ77 sliding window
// is preserved across messages. Returns the compressed payloads with the
// RFC 7692 trailer stripped (matching the wire format).
func deflateCompressWithContext(t *testing.T, messages [][]byte) [][]byte {
	t.Helper()
	trailer := []byte{0x00, 0x00, 0xff, 0xff}
	var compressed [][]byte

	// Use a resettableWriter pattern: a single flate writer, but we capture
	// each message's output separately by flushing after each write.
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}

	for i, msg := range messages {
		buf.Reset()
		if _, err := w.Write(msg); err != nil {
			t.Fatalf("flate write message %d: %v", i, err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("flate flush message %d: %v", i, err)
		}
		out := make([]byte, buf.Len())
		copy(out, buf.Bytes())
		// Strip the trailing sync marker per RFC 7692 Section 7.2.1.
		if bytes.HasSuffix(out, trailer) {
			out = out[:len(out)-4]
		}
		compressed = append(compressed, out)
	}
	return compressed
}

func TestDeflateState_Decompress_MultipleMessages_ContextTakeover(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	messages := [][]byte{
		[]byte("first message"),
		[]byte("second message"),
		[]byte("third message"),
	}
	compressedMsgs := deflateCompressWithContext(t, messages)

	for i, msg := range messages {
		decompressed, err := ds.decompress(compressedMsgs[i], 1<<20)
		if err != nil {
			t.Fatalf("decompress message %d: %v", i, err)
		}
		if !bytes.Equal(decompressed, msg) {
			t.Errorf("decompress message %d = %q, want %q", i, decompressed, msg)
		}
	}
}

func TestDeflateState_Decompress_ContextTakeover_RepeatedContent(t *testing.T) {
	// With context takeover, repeated content should produce smaller compressed
	// payloads as the compressor can reference previous data. This test verifies
	// that such back-references are correctly resolved during decompression.
	params := deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	repeated := []byte("The quick brown fox jumps over the lazy dog.")
	messages := [][]byte{repeated, repeated, repeated}
	compressedMsgs := deflateCompressWithContext(t, messages)

	// Verify that later messages are smaller (compressor uses back-references).
	if len(compressedMsgs[2]) >= len(compressedMsgs[0]) {
		t.Logf("compressed sizes: msg0=%d msg1=%d msg2=%d",
			len(compressedMsgs[0]), len(compressedMsgs[1]), len(compressedMsgs[2]))
		// Not a hard failure — compression ratio depends on the algorithm,
		// but for identical repeated content we expect smaller payloads.
	}

	for i, msg := range messages {
		decompressed, err := ds.decompress(compressedMsgs[i], 1<<20)
		if err != nil {
			t.Fatalf("decompress message %d: %v", i, err)
		}
		if !bytes.Equal(decompressed, msg) {
			t.Errorf("decompress message %d = %q, want %q", i, decompressed, msg)
		}
	}
}

func TestDeflateState_Decompress_ContextTakeover_ManyMessages(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	// Generate 20 messages to exercise the sliding window across many iterations.
	var messages [][]byte
	for i := 0; i < 20; i++ {
		messages = append(messages, []byte(fmt.Sprintf("message number %d with some padding data to fill the window", i)))
	}
	compressedMsgs := deflateCompressWithContext(t, messages)

	for i, msg := range messages {
		decompressed, err := ds.decompress(compressedMsgs[i], 1<<20)
		if err != nil {
			t.Fatalf("decompress message %d: %v", i, err)
		}
		if !bytes.Equal(decompressed, msg) {
			t.Errorf("decompress message %d = %q, want %q", i, decompressed, msg)
		}
	}
}

func TestDeflateState_Decompress_ContextTakeover_EmptyPayload(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	// Empty payload should be handled gracefully even in context takeover mode.
	result, err := ds.decompress(nil, 1<<20)
	if err != nil {
		t.Fatalf("decompress nil: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("decompress nil = %v, want empty", result)
	}

	// After empty payload, normal messages should still work.
	messages := [][]byte{[]byte("after empty")}
	compressedMsgs := deflateCompressWithContext(t, messages)
	decompressed, err := ds.decompress(compressedMsgs[0], 1<<20)
	if err != nil {
		t.Fatalf("decompress after empty: %v", err)
	}
	if !bytes.Equal(decompressed, messages[0]) {
		t.Errorf("decompress after empty = %q, want %q", decompressed, messages[0])
	}
}

func TestDeflateState_Close_ContextTakeover(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	}
	ds := newDeflateState(params)

	// Decompress one message to populate the dictionary.
	messages := [][]byte{[]byte("test")}
	compressedMsgs := deflateCompressWithContext(t, messages)
	_, err := ds.decompress(compressedMsgs[0], 1<<20)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}

	// Close should release resources without panic.
	ds.close()
	if ds.dict != nil {
		t.Error("dict should be nil after close")
	}
	// Double close should not panic.
	ds.close()
}

func TestDeflateState_Decompress_ContextTakeover_MaxSizeTruncationResetsDictionary(t *testing.T) {
	// When maxSize truncation occurs during context takeover decompression, the
	// dictionary must be reset to prevent LZ77 window desync with the peer's
	// compressor. After truncation, subsequent messages should still decompress
	// (without context) rather than silently produce incorrect data.
	params := deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	// Compress 3 messages with shared context.
	messages := [][]byte{
		[]byte("first message with some content"),
		bytes.Repeat([]byte("X"), 200), // This will be truncated by maxSize=50
		[]byte("third message"),        // Must still be processable after reset
	}
	compressedMsgs := deflateCompressWithContext(t, messages)

	// Decompress first message normally (large maxSize).
	decompressed, err := ds.decompress(compressedMsgs[0], 1<<20)
	if err != nil {
		t.Fatalf("decompress message 0: %v", err)
	}
	if !bytes.Equal(decompressed, messages[0]) {
		t.Errorf("message 0 = %q, want %q", decompressed, messages[0])
	}
	// Dictionary should be populated.
	if ds.dict == nil {
		t.Fatal("dict should be non-nil after first message")
	}

	// Decompress second message with a small maxSize that forces truncation.
	decompressed, err = ds.decompress(compressedMsgs[1], 50)
	if err != nil {
		t.Fatalf("decompress message 1 (truncated): %v", err)
	}
	if len(decompressed) != 50 {
		t.Errorf("truncated message length = %d, want 50", len(decompressed))
	}
	// After truncation, dictionary must be reset to nil.
	if ds.dict != nil {
		t.Error("dict should be nil after maxSize truncation (LZ77 window desync prevention)")
	}
}

func TestCheckAllocationOverflow(t *testing.T) {
	trailerLen := len(flateTrailer)

	tests := []struct {
		name       string
		payloadLen int
		wantErr    bool
	}{
		{
			name:       "normal size",
			payloadLen: 1024,
			wantErr:    false,
		},
		{
			name:       "zero payload",
			payloadLen: 0,
			wantErr:    false,
		},
		{
			name:       "overflow: math.MaxInt",
			payloadLen: math.MaxInt,
			wantErr:    true,
		},
		{
			name:       "overflow: math.MaxInt - trailerLen + 1",
			payloadLen: math.MaxInt - trailerLen + 1,
			wantErr:    true,
		},
		{
			name:       "boundary: exactly math.MaxInt - trailerLen",
			payloadLen: math.MaxInt - trailerLen,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAllocationOverflow(tt.payloadLen, trailerLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkAllocationOverflow(%d, %d) error = %v, wantErr %v",
					tt.payloadLen, trailerLen, err, tt.wantErr)
			}
		})
	}
}

func TestParseDeflateExtension_Basic(t *testing.T) {
	tests := []struct {
		name                    string
		header                  string
		wantEnabled             bool
		wantClientContextTkover bool
		wantServerContextTkover bool
		wantClientWindowBits    int
		wantServerWindowBits    int
	}{
		{
			name:        "empty header",
			header:      "",
			wantEnabled: false,
		},
		{
			name:                    "basic permessage-deflate",
			header:                  "permessage-deflate",
			wantEnabled:             true,
			wantClientContextTkover: true,
			wantServerContextTkover: true,
			wantClientWindowBits:    15,
			wantServerWindowBits:    15,
		},
		{
			name:                    "with server_no_context_takeover",
			header:                  "permessage-deflate; server_no_context_takeover",
			wantEnabled:             true,
			wantClientContextTkover: true,
			wantServerContextTkover: false,
			wantClientWindowBits:    15,
			wantServerWindowBits:    15,
		},
		{
			name:                    "with client_no_context_takeover",
			header:                  "permessage-deflate; client_no_context_takeover",
			wantEnabled:             true,
			wantClientContextTkover: false,
			wantServerContextTkover: true,
			wantClientWindowBits:    15,
			wantServerWindowBits:    15,
		},
		{
			name:                    "with both no_context_takeover",
			header:                  "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
			wantEnabled:             true,
			wantClientContextTkover: false,
			wantServerContextTkover: false,
			wantClientWindowBits:    15,
			wantServerWindowBits:    15,
		},
		{
			name:                    "with window bits",
			header:                  "permessage-deflate; server_max_window_bits=10; client_max_window_bits=12",
			wantEnabled:             true,
			wantClientContextTkover: true,
			wantServerContextTkover: true,
			wantClientWindowBits:    12,
			wantServerWindowBits:    10,
		},
		{
			name:                    "with all parameters",
			header:                  "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=9; client_max_window_bits=11",
			wantEnabled:             true,
			wantClientContextTkover: false,
			wantServerContextTkover: false,
			wantClientWindowBits:    11,
			wantServerWindowBits:    9,
		},
		{
			name:        "unrelated extension",
			header:      "x-webkit-deflate-frame",
			wantEnabled: false,
		},
		{
			name:                    "multiple extensions with permessage-deflate",
			header:                  "x-webkit-deflate-frame, permessage-deflate; server_no_context_takeover",
			wantEnabled:             true,
			wantClientContextTkover: true,
			wantServerContextTkover: false,
			wantClientWindowBits:    15,
			wantServerWindowBits:    15,
		},
		{
			name:                    "window bits out of range low",
			header:                  "permessage-deflate; server_max_window_bits=7",
			wantEnabled:             true,
			wantClientContextTkover: true,
			wantServerContextTkover: true,
			wantClientWindowBits:    15,
			wantServerWindowBits:    15, // 7 is out of range, default 15
		},
		{
			name:                    "window bits out of range high",
			header:                  "permessage-deflate; client_max_window_bits=16",
			wantEnabled:             true,
			wantClientContextTkover: true,
			wantServerContextTkover: true,
			wantClientWindowBits:    15, // 16 is out of range, default 15
			wantServerWindowBits:    15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := parseDeflateExtension(tt.header)

			if client.enabled != tt.wantEnabled {
				t.Errorf("client.enabled = %v, want %v", client.enabled, tt.wantEnabled)
			}
			if server.enabled != tt.wantEnabled {
				t.Errorf("server.enabled = %v, want %v", server.enabled, tt.wantEnabled)
			}
			if !tt.wantEnabled {
				return
			}
			if client.contextTakeover != tt.wantClientContextTkover {
				t.Errorf("client.contextTakeover = %v, want %v", client.contextTakeover, tt.wantClientContextTkover)
			}
			if server.contextTakeover != tt.wantServerContextTkover {
				t.Errorf("server.contextTakeover = %v, want %v", server.contextTakeover, tt.wantServerContextTkover)
			}
			if client.windowBits != tt.wantClientWindowBits {
				t.Errorf("client.windowBits = %d, want %d", client.windowBits, tt.wantClientWindowBits)
			}
			if server.windowBits != tt.wantServerWindowBits {
				t.Errorf("server.windowBits = %d, want %d", server.windowBits, tt.wantServerWindowBits)
			}
		})
	}
}

func TestDeflateState_Decompress_CompressedPayloadTooLarge(t *testing.T) {
	params := deflateParams{
		enabled:         true,
		contextTakeover: false,
		windowBits:      15,
	}
	ds := newDeflateState(params)
	defer ds.close()

	// Create a payload that exceeds maxCompressedPayloadSize (= maxFramePayloadSize).
	oversized := make([]byte, maxCompressedPayloadSize+1)
	_, err := ds.decompress(oversized, 1<<30)
	if err == nil {
		t.Fatal("expected error for oversized compressed payload, got nil")
	}

	want := fmt.Sprintf("compressed payload too large: %d > %d", len(oversized), maxCompressedPayloadSize)
	if got := err.Error(); !bytes.Contains([]byte(got), []byte(want)) {
		t.Errorf("error message = %q, want it to contain %q", got, want)
	}
}

// --- compress tests (USK-642) ---

func TestDeflateState_Compress_Decompress_RoundTrip(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: false, windowBits: 15}
	enc := newDeflateState(params)
	dec := newDeflateState(params)
	defer enc.close()
	defer dec.close()

	cases := [][]byte{
		[]byte("Hello, World!"),
		bytes.Repeat([]byte("ABCD"), 100),
		[]byte("short"),
		[]byte(""),
	}
	for i, plain := range cases {
		compressed, err := enc.compress(plain, maxFramePayloadSize)
		if err != nil {
			t.Fatalf("case %d: compress: %v", i, err)
		}
		// Empty input passes through.
		if len(plain) == 0 {
			if len(compressed) != 0 {
				t.Errorf("case %d: empty input produced %d bytes, want 0", i, len(compressed))
			}
			continue
		}
		got, err := dec.decompress(compressed, maxFramePayloadSize)
		if err != nil {
			t.Fatalf("case %d: decompress: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("case %d: round-trip mismatch:\n got: %q\nwant: %q", i, got, plain)
		}
	}
}

func TestDeflateState_Compress_ContextTakeoverPreservesDictionary(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: true, windowBits: 15}
	enc := newDeflateState(params)
	dec := newDeflateState(params)
	defer enc.close()
	defer dec.close()

	msgs := [][]byte{
		[]byte("dictionary-payload-aaaa-bbbb"),
		[]byte("dictionary-payload-aaaa-bbbb-extended"),
		[]byte("dictionary-payload-aaaa-bbbb-yet-more"),
	}
	for i, m := range msgs {
		compressed, err := enc.compress(m, maxFramePayloadSize)
		if err != nil {
			t.Fatalf("msg %d compress: %v", i, err)
		}
		got, err := dec.decompress(compressed, maxFramePayloadSize)
		if err != nil {
			t.Fatalf("msg %d decompress: %v", i, err)
		}
		if !bytes.Equal(got, m) {
			t.Errorf("msg %d: got %q, want %q", i, got, m)
		}
	}
	// Dictionary should be populated on the encoder.
	if len(enc.dict) == 0 {
		t.Error("encoder dict empty after context-takeover messages")
	}
}

func TestDeflateState_Compress_NoContextTakeoverLeavesDictionaryEmpty(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: false, windowBits: 15}
	enc := newDeflateState(params)
	defer enc.close()

	if _, err := enc.compress([]byte("test data"), maxFramePayloadSize); err != nil {
		t.Fatal(err)
	}
	if len(enc.dict) != 0 {
		t.Errorf("dict populated despite contextTakeover=false: len=%d", len(enc.dict))
	}
}

func TestDeflateState_Compress_RejectsOversizedOutput(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: false, windowBits: 15}
	enc := newDeflateState(params)
	defer enc.close()

	// Random-ish bytes don't compress well; a tiny maxSize forces overflow.
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i ^ (i >> 3))
	}
	if _, err := enc.compress(payload, 4); err == nil {
		t.Fatal("expected error for oversized output")
	}
}

func TestDeflateState_Compress_DefaultMaxSize(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: false, windowBits: 15}
	enc := newDeflateState(params)
	defer enc.close()

	// maxSize=0 falls back to maxFramePayloadSize.
	if _, err := enc.compress([]byte("default-cap"), 0); err != nil {
		t.Fatalf("compress with maxSize=0: %v", err)
	}
}

// TestDeflateState_Compress_BFINAL_ZeroForContextTakeover is the USK-867
// root-cause regression. RFC 7692 §7.2.1 requires the compressed output
// (after trailer stripping) to end with an empty stored block carrying
// BFINAL=0 so a peer holding a single persistent inflater (e.g. Node ws
// + zlib) can continue decoding subsequent frames. Go's flate.Writer
// emits BFINAL=0 on Flush and BFINAL=1 on Close — calling Close here was
// the bug that prior PRs missed.
//
// We bit-decode the trailing byte of the stripped output and assert the
// BFINAL bit at position 2 (the LSB of the 3-bit empty-stored-block
// header packed into the post-payload byte) is 0. Concretely: a Flush-
// terminated empty stored block writes the 3 bits "0 0 0" starting at
// bit offset 2 of the trailing byte, so bit-2 of that byte must be 0.
// With the buggy Close path that bit is 1.
func TestDeflateState_Compress_BFINAL_ZeroForContextTakeover(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: true, windowBits: 15}
	enc := newDeflateState(params)
	defer enc.close()

	out, err := enc.compress([]byte("first"), maxFramePayloadSize)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("compress produced empty output for non-empty input")
	}
	last := out[len(out)-1]
	if last&0x04 != 0 {
		t.Errorf("trailing byte = 0x%02x, BFINAL bit (mask 0x04) is SET — "+
			"this would terminate a persistent-inflater peer (USK-867). "+
			"Expected BFINAL=0 from Z_SYNC_FLUSH.", last)
	}
}

// TestDeflateState_Compress_ContinuousInflater_USK867 is the wire-level
// regression for USK-867. It mirrors the production scenario in which
// the proxy's compress() output is consumed by a peer (Node ws@8.20.1)
// that holds a single persistent flate.Reader across all frames in the
// permessage-deflate stream, rather than creating a fresh reader per
// message as the proxy itself does.
//
// Concretely the test:
//
//   - Drives enc.compress() three times (context-takeover ON) producing
//     three RFC-7692-stripped frames.
//   - Re-attaches the 4-byte 00 00 ff ff sync trailer to each frame and
//     concatenates them into one byte stream.
//   - Decodes the stream with a single flate.NewReader (no dict needed
//     because the dict is implicit in the continuous LZ77 state).
//   - Asserts the inflater yields "firstsecondthird" in order.
//
// This test FAILS on the pre-fix code where compress() calls Close():
// the persistent inflater hits BFINAL=1 inside the first frame's trailer
// and reports io.EOF after returning just "first", so the second/third
// frames are unrecoverable. After switching compress() to Flush() it
// passes because BFINAL=0 keeps the stream open for the entire sequence.
//
// The earlier PR-#864 integration tests did not catch this because both
// the encoder AND decoder were proxy code, which creates a fresh
// flate.NewReaderDict per message and is therefore BFINAL-tolerant.
func TestDeflateState_Compress_ContinuousInflater_USK867(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: true, windowBits: 15}
	enc := newDeflateState(params)
	defer enc.close()

	msgs := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	var stream bytes.Buffer
	for i, m := range msgs {
		out, err := enc.compress(m, maxFramePayloadSize)
		if err != nil {
			t.Fatalf("msg %d compress: %v", i, err)
		}
		stream.Write(out)
		stream.Write(flateTrailer) // re-attach per-frame sync trailer
	}

	reader := flate.NewReader(&stream)
	defer reader.Close()

	var got bytes.Buffer
	buf := make([]byte, 16)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if err != nil {
			// The stream legitimately ends in unexpected EOF: the last
			// frame's tail is an empty BFINAL=0 stored block, so the
			// inflater is still expecting another block when input runs
			// out. EOF and io.ErrUnexpectedEOF are both acceptable.
			break
		}
	}

	want := []byte("firstsecondthird")
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("continuous-inflater decode = %q, want %q\n"+
			"this asserts BFINAL=0 across frames; a BFINAL=1 terminator "+
			"in any frame would cut decoding short here (USK-867 symptom)",
			got.String(), want)
	}
}

// TestDeflateState_ConcurrentCompressDecompress_RaceFree is the Phase C
// race-detector probe for USK-867's defense-in-depth mutex. It exercises
// compress + decompress on the SAME *deflateState from multiple
// goroutines and asserts no race-detector hit fires.
//
// Production paths today are externally serialised — clientWS.clientDS
// is only touched by clientWS.Next; upstreamWS.clientDS is only touched
// by upstreamWS.Send (via the wsSendSerializer). This test simulates a
// hypothetical future caller that violates that invariant (e.g., a new
// pipeline step that calls Channel.Send from a goroutine separate from
// the session relay). With the internal mu added in deflate.go the
// race-detector run stays clean; without it, the dict mutations would
// trigger a WARNING: DATA RACE on go test -race.
func TestDeflateState_ConcurrentCompressDecompress_RaceFree(t *testing.T) {
	params := deflateParams{enabled: true, contextTakeover: true, windowBits: 15}
	ds := newDeflateState(params)
	defer ds.close()

	// Prime the dictionary with one round-trip so subsequent operations
	// touch the populated dict path inside both compress and decompress.
	plain := []byte("priming payload for the LZ77 sliding window")
	primed, err := ds.compress(plain, maxFramePayloadSize)
	if err != nil {
		t.Fatalf("prime compress: %v", err)
	}
	if _, err := ds.decompress(primed, maxFramePayloadSize); err != nil {
		t.Fatalf("prime decompress: %v", err)
	}

	// This is a race-detector probe. Per-call return values from
	// compress/decompress are intentionally NOT asserted: interleaved
	// goroutines will sometimes produce LZ77-desync errors because the
	// dict each call captures is no longer the dict in effect when its
	// peer call runs. The signal we care about is (a) no race-detector
	// hit and (b) no panic propagating out of the goroutines — both are
	// surfaced by `go test -race` alone (a race aborts; a panic crashes
	// the test). We therefore discard both errors and the channel.
	const goroutines = 4
	const iters = 25
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if id%2 == 0 {
					_, _ = ds.compress(plain, maxFramePayloadSize)
					continue
				}
				out, cerr := ds.compress(plain, maxFramePayloadSize)
				if cerr != nil {
					continue
				}
				_, _ = ds.decompress(out, maxFramePayloadSize)
			}
		}(g)
	}
	wg.Wait()
}
