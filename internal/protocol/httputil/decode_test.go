package httputil

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	gohttp "net/http"
	"testing"
)

func gzipCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func deflateCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const testMaxSize int64 = 10 << 20 // 10 MB for tests

func TestDecompressBody(t *testing.T) {
	original := []byte(`{"message":"hello world"}`)

	tests := []struct {
		name            string
		body            []byte
		contentEncoding string
		want            []byte
		wantErr         bool
	}{
		{
			name:            "empty encoding returns as-is",
			body:            original,
			contentEncoding: "",
			want:            original,
		},
		{
			name:            "identity returns as-is",
			body:            original,
			contentEncoding: "identity",
			want:            original,
		},
		{
			name:            "gzip decompresses",
			body:            gzipCompress(t, original),
			contentEncoding: "gzip",
			want:            original,
		},
		{
			name:            "x-gzip decompresses",
			body:            gzipCompress(t, original),
			contentEncoding: "x-gzip",
			want:            original,
		},
		{
			name:            "deflate decompresses",
			body:            deflateCompress(t, original),
			contentEncoding: "deflate",
			want:            original,
		},
		{
			name:            "case insensitive encoding",
			body:            gzipCompress(t, original),
			contentEncoding: "Gzip",
			want:            original,
		},
		{
			name:            "whitespace trimmed",
			body:            gzipCompress(t, original),
			contentEncoding: " gzip ",
			want:            original,
		},
		{
			name:            "unsupported encoding returns original with error",
			body:            original,
			contentEncoding: "br",
			want:            original,
			wantErr:         true,
		},
		{
			name:            "corrupted gzip returns original with error",
			body:            []byte("not gzip data"),
			contentEncoding: "gzip",
			want:            []byte("not gzip data"),
			wantErr:         true,
		},
		{
			name:            "empty body returns empty",
			body:            nil,
			contentEncoding: "gzip",
			want:            nil,
		},
		{
			name:            "empty body slice returns empty",
			body:            []byte{},
			contentEncoding: "gzip",
			want:            []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecompressBody(tt.body, tt.contentEncoding, testMaxSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecompressBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("DecompressBody() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecompressBody_MaxSizeTruncation(t *testing.T) {
	// Create data larger than the limit.
	const maxSize int64 = 100
	bigData := bytes.Repeat([]byte("A"), 200)
	compressed := gzipCompress(t, bigData)

	got, err := DecompressBody(compressed, "gzip", maxSize)
	if err != nil {
		t.Fatalf("DecompressBody() unexpected error: %v", err)
	}
	if int64(len(got)) != maxSize {
		t.Errorf("DecompressBody() len = %d, want %d (truncated to maxSize)", len(got), maxSize)
	}
}

func TestRecordingHeaders(t *testing.T) {
	t.Run("decompressed strips Content-Encoding and updates Content-Length", func(t *testing.T) {
		original := gohttp.Header{
			"Content-Encoding": {"gzip"},
			"Content-Length":   {"42"},
			"Content-Type":    {"application/json"},
		}
		got := RecordingHeaders(original, true, 100)

		if v := got.Get("Content-Encoding"); v != "" {
			t.Errorf("Content-Encoding should be removed, got %q", v)
		}
		if v := got.Get("Content-Length"); v != "100" {
			t.Errorf("Content-Length = %q, want %q", v, "100")
		}
		if v := got.Get("Content-Type"); v != "application/json" {
			t.Errorf("Content-Type = %q, want %q", v, "application/json")
		}

		// Original headers must not be modified.
		if v := original.Get("Content-Encoding"); v != "gzip" {
			t.Errorf("original Content-Encoding modified: got %q", v)
		}
	})

	t.Run("not decompressed keeps headers as-is", func(t *testing.T) {
		original := gohttp.Header{
			"Content-Encoding": {"gzip"},
			"Content-Length":   {"42"},
		}
		got := RecordingHeaders(original, false, 100)

		if v := got.Get("Content-Encoding"); v != "gzip" {
			t.Errorf("Content-Encoding = %q, want %q", v, "gzip")
		}
		if v := got.Get("Content-Length"); v != "42" {
			t.Errorf("Content-Length = %q, want %q", v, "42")
		}
	})
}
