package ws

import (
	"bytes"
	"compress/flate"
	"fmt"
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
