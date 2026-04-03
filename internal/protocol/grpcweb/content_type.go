package grpcweb

import (
	"strings"
)

// IsGRPCWebContentType reports whether the given Content-Type value indicates
// a gRPC-Web request or response. It matches both binary and base64-encoded
// variants, including subtype suffixes (+proto, +json) and optional parameters
// (e.g., charset).
func IsGRPCWebContentType(ct string) bool {
	mediaType := extractMediaType(ct)
	return isGRPCWebBinary(mediaType) || isGRPCWebText(mediaType)
}

// IsBase64Encoded reports whether the given Content-Type value indicates
// a base64-encoded gRPC-Web body (the "-text" variants).
func IsBase64Encoded(ct string) bool {
	mediaType := extractMediaType(ct)
	return isGRPCWebText(mediaType)
}

// extractMediaType returns the media type portion of a Content-Type header
// value, stripping any parameters (e.g., "; charset=utf-8") and converting
// to lowercase for comparison.
func extractMediaType(ct string) string {
	// Strip parameters after semicolon.
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	return strings.TrimSpace(strings.ToLower(ct))
}

// isGRPCWebBinary reports whether the media type is a binary gRPC-Web type.
func isGRPCWebBinary(mediaType string) bool {
	return mediaType == "application/grpc-web" ||
		strings.HasPrefix(mediaType, "application/grpc-web+")
}

// isGRPCWebText reports whether the media type is a base64-encoded gRPC-Web type.
func isGRPCWebText(mediaType string) bool {
	return mediaType == "application/grpc-web-text" ||
		strings.HasPrefix(mediaType, "application/grpc-web-text+")
}
