// Package httputil provides shared HTTP utilities used across protocol handlers.
package httputil

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	gohttp "net/http"
	"strconv"
	"strings"
)

// DecompressBody decompresses an HTTP response body based on the Content-Encoding
// header value. Supported encodings: gzip, deflate, x-gzip.
// Brotli (br) and zstd are not currently supported; the original body is returned
// with an error for unsupported encodings.
// Stacked/chained Content-Encoding values (e.g., "gzip, deflate") are not
// supported and fall back to returning the original body.
//
// maxSize limits the decompressed output size to prevent decompression bombs
// (CWE-409). If the decompressed data exceeds maxSize, only maxSize bytes are
// returned (callers can detect truncation by comparing against maxSize).
//
// Returns the decompressed body and a nil error on success.
// If contentEncoding is empty or "identity", the body is returned as-is.
// If the encoding is unsupported or decompression fails, the original body is
// returned along with an error describing the failure. This allows callers to
// fall back to storing the compressed body.
func DecompressBody(body []byte, contentEncoding string, maxSize int64) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	encoding := strings.TrimSpace(strings.ToLower(contentEncoding))
	if encoding == "" || encoding == "identity" {
		return body, nil
	}

	switch encoding {
	case "gzip", "x-gzip":
		return decompressGzip(body, maxSize)
	case "deflate":
		return decompressDeflate(body, maxSize)
	default:
		return body, fmt.Errorf("unsupported Content-Encoding: %s", encoding)
	}
}

// RecordingHeaders returns a shallow copy of the response headers suitable for
// flow recording. When the body has been decompressed, Content-Encoding is
// removed and Content-Length is updated to reflect the decoded body size.
func RecordingHeaders(original gohttp.Header, decompressed bool, bodyLen int) gohttp.Header {
	headers := original.Clone()
	if decompressed {
		headers.Del("Content-Encoding")
		headers.Set("Content-Length", strconv.Itoa(bodyLen))
	}
	return headers
}

func decompressGzip(body []byte, maxSize int64) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body, fmt.Errorf("gzip reader: %w", err)
	}
	defer r.Close()

	decoded, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return body, fmt.Errorf("gzip decompress: %w", err)
	}
	if int64(len(decoded)) > maxSize {
		decoded = decoded[:maxSize]
	}
	return decoded, nil
}

func decompressDeflate(body []byte, maxSize int64) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(body))
	defer r.Close()

	decoded, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return body, fmt.Errorf("deflate decompress: %w", err)
	}
	if int64(len(decoded)) > maxSize {
		decoded = decoded[:maxSize]
	}
	return decoded, nil
}
