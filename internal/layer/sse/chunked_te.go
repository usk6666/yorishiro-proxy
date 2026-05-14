package sse

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// IsHTTPMessageChunked reports whether env's typed *envelope.HTTPMessage
// declares Transfer-Encoding: chunked on the wire. The check is
// case-insensitive on the header name and tolerates multi-token values
// (e.g. "gzip, chunked") per RFC 9112 §6.1.
//
// This helper exists so the SSE upgrade orchestrator can re-wrap event
// bytes in chunked framing when the pre-swap HTTP response advertised
// chunked TE — without reaching into HTTP/1.x parser internals.
//
// Returns false when env is nil, env.Message is not *HTTPMessage, or no
// chunked token is present.
func IsHTTPMessageChunked(env *envelope.Envelope) bool {
	if env == nil {
		return false
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok || msg == nil {
		return false
	}
	for _, kv := range msg.Headers {
		if !strings.EqualFold(kv.Name, "Transfer-Encoding") {
			continue
		}
		if hasChunkedToken(kv.Value) {
			return true
		}
	}
	return false
}

// hasChunkedToken reports whether v contains a "chunked" coding token.
// Comparison is case-insensitive; tokens are comma-separated per
// RFC 9112 §6.1.
func hasChunkedToken(v string) bool {
	for _, tok := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "chunked") {
			return true
		}
	}
	return false
}
