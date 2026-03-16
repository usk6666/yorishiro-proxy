package ws

import (
	"bytes"
	"compress/flate"
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
