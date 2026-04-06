package grpcweb

import (
	"bytes"
	"fmt"
	"io"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
)

// WireEncoding specifies the gRPC-Web wire format for request encoding.
type WireEncoding int

const (
	// WireEncodingBinary sends gRPC-Web frames as raw binary
	// (Content-Type: application/grpc-web).
	WireEncodingBinary WireEncoding = iota

	// WireEncodingBase64 encodes gRPC-Web frames as base64
	// (Content-Type: application/grpc-web-text).
	WireEncodingBase64
)

// BuildRequest constructs a parser.RawRequest for a gRPC-Web request from
// the given method, URL, headers, frames, and wire encoding.
//
// For WireEncodingBinary, the frames are encoded as raw binary in the body.
// For WireEncodingBase64, the frames are first encoded as binary, then
// base64-encoded for the grpc-web-text wire format.
//
// The returned RawRequest is compatible with UpstreamRouter.RoundTrip().
func BuildRequest(method, rawURL string, headers parser.RawHeaders, frames []Frame, encoding WireEncoding) (*parser.RawRequest, error) {
	if method == "" {
		return nil, fmt.Errorf("method is required")
	}
	if rawURL == "" {
		return nil, fmt.Errorf("url is required")
	}

	// Encode frames into binary body.
	var bodyBuf bytes.Buffer
	for _, f := range frames {
		encoded := EncodeFrame(f.IsTrailer, f.Compressed, f.Payload)
		bodyBuf.Write(encoded)
	}

	bodyBytes := bodyBuf.Bytes()

	// For base64 encoding, wrap the binary body.
	if encoding == WireEncodingBase64 {
		bodyBytes = EncodeBase64Body(bodyBytes)
	}

	// Build headers clone, ensuring Content-Length is set correctly.
	h := headers.Clone()
	h.Del("Content-Length")
	h.Del("Transfer-Encoding")
	if len(bodyBytes) > 0 {
		h.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	}

	// Ensure Host header from URL if not present.
	// Extract host from rawURL for the Host header.
	// We parse just enough to get the host portion.
	host := extractHostFromURL(rawURL)
	if h.Get("Host") == "" && host != "" {
		h = append(parser.RawHeaders{{Name: "Host", Value: host}}, h...)
	}

	// Build request URI (path+query portion).
	requestURI := extractRequestURI(rawURL)

	var body io.Reader
	if len(bodyBytes) > 0 {
		body = bytes.NewReader(bodyBytes)
	}

	return &parser.RawRequest{
		Method:     method,
		RequestURI: requestURI,
		Proto:      "HTTP/1.1",
		Headers:    h,
		Body:       body,
	}, nil
}

// extractHostFromURL extracts the host:port from a URL string.
func extractHostFromURL(rawURL string) string {
	// Skip scheme.
	after := rawURL
	if idx := indexOf(after, "://"); idx >= 0 {
		after = after[idx+3:]
	}
	// Strip path.
	if idx := indexByte(after, '/'); idx >= 0 {
		after = after[:idx]
	}
	// Strip userinfo.
	if idx := indexByte(after, '@'); idx >= 0 {
		after = after[idx+1:]
	}
	return after
}

// extractRequestURI extracts the path?query portion from a URL string.
func extractRequestURI(rawURL string) string {
	// Skip scheme.
	after := rawURL
	if idx := indexOf(after, "://"); idx >= 0 {
		after = after[idx+3:]
	}
	// Find path start.
	if idx := indexByte(after, '/'); idx >= 0 {
		return after[idx:]
	}
	return "/"
}

// indexOf returns the index of sep in s, or -1 if not found.
func indexOf(s, sep string) int {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

// indexByte returns the index of the first occurrence of c in s, or -1.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
