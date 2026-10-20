package http1

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// EncodeWireBytes re-encodes env.Message into HTTP/1.x wire-form bytes for
// use by pipeline.RecordStep as the modified variant's RawBytes.
//
// The encoder prefers raw-first patching when env.Opaque carries the original
// parser.RawRequest / parser.RawResponse (the normal Pipeline flow): the
// raw header block is edited via applyHeaderPatch so unmodified headers
// preserve their original OWS (Optional Whitespace), matching exactly what
// channel.sendRequestOpaque / sendResponseOpaque would emit.
//
// When env.Opaque is absent (for example a Resend path constructing a fresh
// Envelope), the encoder falls back to synthetic serialization using
// serializeRequestLine + serializeHeaders (request) or serializeStatusLine +
// serializeHeaders (response).
//
// Body handling:
//   - When env.Message.Body is non-nil, it is appended after the header block
//     and, for a changed body, Content-Length is re-stamped on the serialized
//     headers (matching channel.sendRequest/ResponseOpaque behavior).
//   - When env.Message.BodyBuffer is non-nil, the buffer's bytes are
//     materialized via BodyBuffer.Bytes and appended after the header block.
//     Content-Length is re-stamped from BodyBuffer.Len() when the body changed.
//   - When both are nil, the encoder returns header-only bytes with no
//     partial marker (e.g. GET with no payload).
//
// EncodeWireBytes is pure: it does not mutate env, env.Message, env.Opaque,
// or any cached RawHeaders. The raw headers list on opaque.rawReq/rawResp
// is cloned before patching.
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("http1: EncodeWireBytes: nil envelope")
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, fmt.Errorf("http1: EncodeWireBytes: requires *HTTPMessage, got %T", env.Message)
	}

	opaque, _ := env.Opaque.(*opaqueHTTP1)
	switch env.Direction {
	case envelope.Send:
		if opaque != nil && opaque.rawReq != nil {
			return encodeRequestOpaque(msg, opaque)
		}
		return encodeRequestSynthetic(msg)
	case envelope.Receive:
		if opaque != nil && opaque.rawResp != nil {
			return encodeResponseOpaque(msg, opaque)
		}
		return encodeResponseSynthetic(msg)
	default:
		return nil, fmt.Errorf("http1: EncodeWireBytes: unknown direction %d", env.Direction)
	}
}

// encodeRequestOpaque renders a request header block via raw-first patching,
// preserving OWS on unmodified headers. Body handling mirrors
// channel.sendRequestOpaque.
//
// USK-1148: the header section comes from opaqueRequestHead, the same
// function the channel writes with, so a rewritten request line (and any
// header / framing change) is recorded exactly as sent.
//
// USK-769: when the upstream wire used chunked Transfer-Encoding and the
// captured RawBody fits in MaxRawCaptureSize, the encoder re-emits RawBody
// (chunk framing intact) verbatim. When the body has been mutated — or the
// chunked RawBody overflowed the capture cap — the encoder falls back to
// TE→CL rewrite + Body / BodyBuffer assembly.
//
// USK-772: when the captured RawBody was disk-spilled, the encoder reads the
// disk-backed bodybuf via Bytes(ctx) and stitches header + body. The encoder
// runs in pipeline.RecordStep, where context.Background is acceptable for
// the synchronous Bytes call (no incoming ctx flows here).
func encodeRequestOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) ([]byte, error) {
	head, d := opaqueRequestHead(msg, opaque)
	if d.zeroCopy {
		head = bytes.Clone(head)
	}
	if d.useRawBody {
		return appendRawBody(head, opaque.rawReq.RawBody, opaque.rawReq.RawBodyBuffer)
	}
	return assembleWithBody(head, msg)
}

// encodeResponseOpaque is the response-side twin of encodeRequestOpaque.
func encodeResponseOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) ([]byte, error) {
	head, d := opaqueResponseHead(msg, opaque)
	if d.zeroCopy {
		head = bytes.Clone(head)
	}
	if d.useRawBody {
		return appendRawBody(head, opaque.rawResp.RawBody, opaque.rawResp.RawBodyBuffer)
	}
	return assembleWithBody(head, msg)
}

// appendRawBody concatenates headerBytes and the wire body bytes. When
// rawBodyBuffer is non-nil (USK-772 disk-spill), bytes are materialized via
// Bytes(ctx); otherwise rawBody (memory) is used directly. Used by the
// !bodyChanged branch of the opaque encoders so the chunk framing in
// rawBody is preserved on the wire.
func appendRawBody(headerBytes, rawBody []byte, rawBodyBuffer *bodybuf.BodyBuffer) ([]byte, error) {
	if rawBodyBuffer != nil {
		body, err := rawBodyBuffer.Bytes(context.Background())
		if err != nil {
			return nil, fmt.Errorf("http1: wireencode read raw body buffer: %w", err)
		}
		out := make([]byte, 0, len(headerBytes)+len(body))
		out = append(out, headerBytes...)
		out = append(out, body...)
		return out, nil
	}
	out := make([]byte, 0, len(headerBytes)+len(rawBody))
	out = append(out, headerBytes...)
	out = append(out, rawBody...)
	return out, nil
}

// encodeRequestSynthetic renders a request without reference to any original
// parser output. This path runs when env.Opaque is nil (e.g. Resend).
func encodeRequestSynthetic(msg *envelope.HTTPMessage) ([]byte, error) {
	var buf bytes.Buffer

	requestURI := msg.Path
	if msg.RawQuery != "" {
		requestURI += "?" + msg.RawQuery
	}
	if requestURI == "" {
		requestURI = "/"
	}
	method := msg.Method
	if method == "" {
		method = "GET"
	}
	_ = serializeRequestLine(&buf, method, requestURI, "HTTP/1.1")

	headers := kvToRawHeaders(msg.Headers)
	if headers.Get("Content-Length") == "" {
		switch {
		case msg.Body != nil:
			headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		}
	}
	_ = serializeHeaders(&buf, headers)
	return appendBody(buf.Bytes(), msg)
}

// encodeResponseSynthetic is the response-side twin of encodeRequestSynthetic.
func encodeResponseSynthetic(msg *envelope.HTTPMessage) ([]byte, error) {
	var buf bytes.Buffer

	status := ""
	if msg.StatusReason != "" {
		status = fmt.Sprintf("%d %s", msg.Status, msg.StatusReason)
	}
	_ = serializeStatusLine(&buf, "HTTP/1.1", status, msg.Status)

	headers := kvToRawHeaders(msg.Headers)
	if headers.Get("Content-Length") == "" {
		switch {
		case msg.Body != nil:
			headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		}
	}
	_ = serializeHeaders(&buf, headers)
	return appendBody(buf.Bytes(), msg)
}

// assembleWithBody appends the message body to headerBytes.
//
// When msg.Body is non-nil, the concatenated header+body bytes are returned.
// When msg.BodyBuffer is non-nil, the buffer is materialized via
// BodyBuffer.Bytes and appended. When both are nil (e.g. GET with no
// payload), headerBytes is returned unchanged.
func assembleWithBody(headerBytes []byte, msg *envelope.HTTPMessage) ([]byte, error) {
	return appendBody(headerBytes, msg)
}

// appendBody materializes msg.Body or msg.BodyBuffer after headerBytes.
// Separate helper so both opaque and synthetic paths share the same logic.
func appendBody(headerBytes []byte, msg *envelope.HTTPMessage) ([]byte, error) {
	if msg.Body != nil {
		out := make([]byte, 0, len(headerBytes)+len(msg.Body))
		out = append(out, headerBytes...)
		out = append(out, msg.Body...)
		return out, nil
	}
	if msg.BodyBuffer != nil {
		bodyBytes, err := msg.BodyBuffer.Bytes(context.Background())
		if err != nil {
			return nil, fmt.Errorf("http1: wireencode materialize body: %w", err)
		}
		out := make([]byte, 0, len(headerBytes)+len(bodyBytes))
		out = append(out, headerBytes...)
		out = append(out, bodyBytes...)
		return out, nil
	}
	// No body (e.g. GET with no payload): header-only, no partial marker.
	return headerBytes, nil
}
