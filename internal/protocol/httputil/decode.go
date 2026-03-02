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
//
// Returns the decompressed body and a nil error on success.
// If contentEncoding is empty or "identity", the body is returned as-is.
// If the encoding is unsupported or decompression fails, the original body is
// returned along with an error describing the failure. This allows callers to
// fall back to storing the compressed body.
func DecompressBody(body []byte, contentEncoding string) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	encoding := strings.TrimSpace(strings.ToLower(contentEncoding))
	if encoding == "" || encoding == "identity" {
		return body, nil
	}

	switch encoding {
	case "gzip", "x-gzip":
		return decompressGzip(body)
	case "deflate":
		return decompressDeflate(body)
	default:
		return body, fmt.Errorf("unsupported Content-Encoding: %s", encoding)
	}
}

// RecordingHeaders returns a shallow copy of the response headers suitable for
// session recording. When the body has been decompressed, Content-Encoding is
// removed and Content-Length is updated to reflect the decoded body size.
func RecordingHeaders(original gohttp.Header, decompressed bool, bodyLen int) gohttp.Header {
	headers := original.Clone()
	if decompressed {
		headers.Del("Content-Encoding")
		headers.Set("Content-Length", strconv.Itoa(bodyLen))
	}
	return headers
}

func decompressGzip(body []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body, fmt.Errorf("gzip reader: %w", err)
	}
	defer r.Close()

	decoded, err := io.ReadAll(r)
	if err != nil {
		return body, fmt.Errorf("gzip decompress: %w", err)
	}
	return decoded, nil
}

func decompressDeflate(body []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(body))
	defer r.Close()

	decoded, err := io.ReadAll(r)
	if err != nil {
		return body, fmt.Errorf("deflate decompress: %w", err)
	}
	return decoded, nil
}
