package http1

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
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
func encodeRequestOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) ([]byte, error) {
	rawReq := cloneRawRequest(opaque.rawReq)

	headersChanged := !kvEqual(msg.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(msg, opaque)

	if headersChanged {
		rawReq.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawReq.Headers)
	}
	if bodyChanged {
		rawReq.Headers.Del("Transfer-Encoding")
		switch {
		case msg.Body != nil:
			rawReq.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			rawReq.Headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		default:
			rawReq.Headers.Set("Content-Length", "0")
		}
	}

	headerBytes := serializeRequestHeader(rawReq)
	return assembleWithBody(headerBytes, msg)
}

// encodeResponseOpaque is the response-side twin of encodeRequestOpaque.
func encodeResponseOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) ([]byte, error) {
	rawResp := cloneRawResponse(opaque.rawResp)

	headersChanged := !kvEqual(msg.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(msg, opaque)

	if headersChanged {
		rawResp.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawResp.Headers)
	}
	if bodyChanged {
		rawResp.Headers.Del("Transfer-Encoding")
		switch {
		case msg.Body != nil:
			rawResp.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			rawResp.Headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		default:
			rawResp.Headers.Set("Content-Length", "0")
		}
	}

	headerBytes := serializeResponseHeader(rawResp)
	return assembleWithBody(headerBytes, msg)
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

// cloneRawRequest returns a deep-enough copy of r so that header patching in
// EncodeWireBytes does not mutate the opaque state stored on the envelope.
// Body is intentionally not copied: it is an io.Reader owned elsewhere and
// this encoder never consumes it.
func cloneRawRequest(r *parser.RawRequest) *parser.RawRequest {
	return &parser.RawRequest{
		Method:     r.Method,
		RequestURI: r.RequestURI,
		Proto:      r.Proto,
		Headers:    r.Headers.Clone(),
		Body:       r.Body,
		RawBytes:   r.RawBytes,
		Anomalies:  r.Anomalies,
		Close:      r.Close,
		Truncated:  r.Truncated,
	}
}

// cloneRawResponse is the response-side twin of cloneRawRequest.
func cloneRawResponse(r *parser.RawResponse) *parser.RawResponse {
	return &parser.RawResponse{
		Proto:      r.Proto,
		StatusCode: r.StatusCode,
		Status:     r.Status,
		Headers:    r.Headers.Clone(),
		Body:       r.Body,
		RawBytes:   r.RawBytes,
		Anomalies:  r.Anomalies,
		Truncated:  r.Truncated,
	}
}
