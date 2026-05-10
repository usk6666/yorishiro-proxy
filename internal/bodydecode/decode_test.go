package bodydecode

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const samplePlaintext = "the quick brown fox jumps over the lazy dog 1234567890"

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// deflateBytes produces the spec-compliant HTTP deflate form: zlib-wrapped
// (RFC 1950) DEFLATE. This is what nginx/Apache/IIS/Cloudflare etc. emit
// under Content-Encoding: deflate.
func deflateBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// rawDeflateBytes produces non-spec-compliant raw DEFLATE (RFC 1951) without
// the zlib header. A small population of legacy senders (notably old IIS)
// emit this under Content-Encoding: deflate, so the decoder must fall back.
func rawDeflateBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func brotliBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

func zstdBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

func TestDecode_RoundTripCodecs(t *testing.T) {
	plain := []byte(samplePlaintext)
	// header is the Content-Encoding string passed to Decode; wantApplied is
	// the codec name Decode should report. They differ for x-gzip (normalized
	// to "gzip") and for the deflate raw-fallback case (still reported as
	// "deflate" because that is the wire-observed codec name).
	cases := []struct {
		name        string
		header      string
		body        []byte
		wantApplied string
	}{
		{"gzip", "gzip", gzipBytes(t, plain), "gzip"},
		{"x-gzip", "x-gzip", gzipBytes(t, plain), "gzip"},
		{"deflate-zlib", "deflate", deflateBytes(t, plain), "deflate"},
		{"deflate-raw-fallback", "deflate", rawDeflateBytes(t, plain), "deflate"},
		{"br", "br", brotliBytes(t, plain), "br"},
		{"zstd", "zstd", zstdBytes(t, plain), "zstd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, applied, anom := Decode(tc.body, tc.header, DefaultMaxDecodedSize)
			if anom != nil {
				t.Fatalf("unexpected anomaly: %+v", anom)
			}
			if applied != tc.wantApplied {
				t.Fatalf("applied = %q, want %q", applied, tc.wantApplied)
			}
			if !bytes.Equal(out, plain) {
				t.Fatalf("decoded mismatch: got %q want %q", out, plain)
			}
		})
	}
}

func TestDecode_IdentityAndEmpty(t *testing.T) {
	plain := []byte(samplePlaintext)
	cases := []struct {
		name        string
		body        []byte
		encoding    string
		wantOut     []byte
		wantApplied string
	}{
		{"empty encoding header", plain, "", plain, ""},
		{"identity", plain, "identity", plain, ""},
		{"identity uppercase", plain, "IDENTITY", plain, ""},
		{"identity with whitespace", plain, "  identity  ", plain, ""},
		{"empty body", []byte{}, "gzip", []byte{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, applied, anom := Decode(tc.body, tc.encoding, DefaultMaxDecodedSize)
			if anom != nil {
				t.Fatalf("unexpected anomaly: %+v", anom)
			}
			if applied != tc.wantApplied {
				t.Fatalf("applied = %q, want %q", applied, tc.wantApplied)
			}
			if !bytes.Equal(out, tc.wantOut) {
				t.Fatalf("out mismatch: got %q want %q", out, tc.wantOut)
			}
		})
	}
}

func TestDecode_UnknownEncoding(t *testing.T) {
	body := []byte("not actually compressed")
	out, applied, anom := Decode(body, "snappy", DefaultMaxDecodedSize)
	if anom == nil {
		t.Fatalf("expected anomaly, got nil")
	}
	if anom.Type != AnomalyUnknownEncoding {
		t.Fatalf("anomaly type = %q, want %q", anom.Type, AnomalyUnknownEncoding)
	}
	if applied != "" {
		t.Fatalf("applied = %q, want empty", applied)
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("expected original body unchanged on anomaly")
	}
}

func TestDecode_Malformed(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{"gzip header", "gzip", []byte{0xff, 0xff, 0xff, 0xff}},
		{"gzip truncated", "gzip", gzipBytes(t, []byte("payload"))[:5]},
		{"zstd header", "zstd", []byte{0x00, 0x00, 0x00, 0x00, 0x00}},
		{"deflate corrupt", "deflate", []byte{0xff, 0xff, 0xff}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, applied, anom := Decode(tc.body, tc.encoding, DefaultMaxDecodedSize)
			if anom == nil {
				t.Fatalf("expected anomaly, got nil")
			}
			if anom.Type != AnomalyMalformed {
				t.Fatalf("anomaly type = %q, want %q", anom.Type, AnomalyMalformed)
			}
			if applied != "" {
				t.Fatalf("applied = %q, want empty", applied)
			}
			if !bytes.Equal(out, tc.body) {
				t.Fatalf("expected original body unchanged on anomaly")
			}
		})
	}
}

func TestDecode_SizeExceeded(t *testing.T) {
	// Compress a payload larger than the cap to force a size_exceeded anomaly.
	const cap = 1024
	plain := bytes.Repeat([]byte("A"), cap*4)
	body := gzipBytes(t, plain)

	out, applied, anom := Decode(body, "gzip", cap)
	if anom == nil {
		t.Fatalf("expected anomaly, got nil")
	}
	if anom.Type != AnomalySizeExceeded {
		t.Fatalf("anomaly type = %q, want %q", anom.Type, AnomalySizeExceeded)
	}
	if applied != "" {
		t.Fatalf("applied = %q, want empty", applied)
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("expected original body unchanged on anomaly")
	}
}

// TestDecode_SizeExceededDeflateRawFallback locks in the size cap on the
// raw-DEFLATE fallback branch of decodeDeflate. The shared readCapped helper
// makes this structurally guaranteed alongside the zlib path, but covering
// the fallback explicitly prevents future refactors from quietly losing the
// cap on legacy non-zlib senders.
func TestDecode_SizeExceededDeflateRawFallback(t *testing.T) {
	const cap = 1024
	plain := bytes.Repeat([]byte("A"), cap*4)
	body := rawDeflateBytes(t, plain)

	out, applied, anom := Decode(body, "deflate", cap)
	if anom == nil {
		t.Fatalf("expected anomaly, got nil")
	}
	if anom.Type != AnomalySizeExceeded {
		t.Fatalf("anomaly type = %q, want %q", anom.Type, AnomalySizeExceeded)
	}
	if applied != "" {
		t.Fatalf("applied = %q, want empty", applied)
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("expected original body unchanged on anomaly")
	}
}

func TestDecode_ChainRejected(t *testing.T) {
	body := gzipBytes(t, []byte(samplePlaintext))
	out, applied, anom := Decode(body, "gzip, br", DefaultMaxDecodedSize)
	if anom == nil {
		t.Fatalf("expected anomaly, got nil")
	}
	if anom.Type != AnomalyChainRejected {
		t.Fatalf("anomaly type = %q, want %q", anom.Type, AnomalyChainRejected)
	}
	if applied != "" {
		t.Fatalf("applied = %q, want empty", applied)
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("expected original body unchanged on anomaly")
	}
}

func TestDecode_DisabledCap(t *testing.T) {
	// maxSize <= 0 disables the cap.
	plain := bytes.Repeat([]byte("A"), 8<<20) // 8 MiB plaintext
	body := gzipBytes(t, plain)

	out, applied, anom := Decode(body, "gzip", 0)
	if anom != nil {
		t.Fatalf("unexpected anomaly: %+v", anom)
	}
	if applied != "gzip" {
		t.Fatalf("applied = %q, want gzip", applied)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("decoded mismatch")
	}
}
