package http1

import (
	"bytes"
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
//   - When env.Message.Body is nil but a passthrough body is still active
//     (opaque.bodyReader is non-nil), the body cannot be re-read offline
//     without mutating the live stream — the encoder returns the header-only
//     bytes together with pipeline.ErrPartialWireBytes so RecordStep can tag
//     Metadata["wire_bytes"] = "partial".
//
// EncodeWireBytes is pure: it does not mutate env, env.Message, env.Opaque,
// or any cached RawHeaders. The raw headers list on opaque.rawReq/rawResp
// is cloned before patching.
//
// Callers upstream (pipeline.RecordStep) interpret
// envelope.ErrPartialWireBytes to mean "the returned bytes are a partial
// reconstruction" and tag flow metadata accordingly.
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
		return encodeRequestSynthetic(msg), nil
	case envelope.Receive:
		if opaque != nil && opaque.rawResp != nil {
			return encodeResponseOpaque(msg, opaque)
		}
		return encodeResponseSynthetic(msg), nil
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
	bodyChanged := isBodyChanged(msg.Body, opaque)

	if headersChanged {
		rawReq.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawReq.Headers)
	}
	if bodyChanged && msg.Body != nil {
		rawReq.Headers.Del("Transfer-Encoding")
		rawReq.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
	}

	headerBytes := serializeRequestHeader(rawReq)
	return assembleWithBody(headerBytes, msg, opaque)
}

// encodeResponseOpaque is the response-side twin of encodeRequestOpaque.
func encodeResponseOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) ([]byte, error) {
	rawResp := cloneRawResponse(opaque.rawResp)

	headersChanged := !kvEqual(msg.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(msg.Body, opaque)

	if headersChanged {
		rawResp.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawResp.Headers)
	}
	if bodyChanged && msg.Body != nil {
		rawResp.Headers.Del("Transfer-Encoding")
		rawResp.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
	}

	headerBytes := serializeResponseHeader(rawResp)
	return assembleWithBody(headerBytes, msg, opaque)
}

// encodeRequestSynthetic renders a request without reference to any original
// parser output. This path runs when env.Opaque is nil (e.g. Resend).
func encodeRequestSynthetic(msg *envelope.HTTPMessage) []byte {
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
	if msg.Body != nil && headers.Get("Content-Length") == "" {
		headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
	}
	_ = serializeHeaders(&buf, headers)
	if msg.Body != nil {
		buf.Write(msg.Body)
	}
	return buf.Bytes()
}

// encodeResponseSynthetic is the response-side twin of encodeRequestSynthetic.
func encodeResponseSynthetic(msg *envelope.HTTPMessage) []byte {
	var buf bytes.Buffer

	status := ""
	if msg.StatusReason != "" {
		status = fmt.Sprintf("%d %s", msg.Status, msg.StatusReason)
	}
	_ = serializeStatusLine(&buf, "HTTP/1.1", status, msg.Status)

	headers := kvToRawHeaders(msg.Headers)
	if msg.Body != nil && headers.Get("Content-Length") == "" {
		headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
	}
	_ = serializeHeaders(&buf, headers)
	if msg.Body != nil {
		buf.Write(msg.Body)
	}
	return buf.Bytes()
}

// assembleWithBody appends the message body to headerBytes where possible.
//
// When msg.Body is non-nil (buffered mode), the concatenated header+body
// bytes are returned with no partial marker. When msg.Body is nil and a
// passthrough bodyReader is still live on opaque, the body cannot be
// replayed offline without disturbing the real channel.Send path;
// returning headerBytes together with pipeline.ErrPartialWireBytes signals
// to RecordStep that the modified variant's RawBytes is a partial
// reconstruction.
func assembleWithBody(headerBytes []byte, msg *envelope.HTTPMessage, opaque *opaqueHTTP1) ([]byte, error) {
	if msg.Body != nil {
		out := make([]byte, 0, len(headerBytes)+len(msg.Body))
		out = append(out, headerBytes...)
		out = append(out, msg.Body...)
		return out, nil
	}
	if opaque != nil && opaque.bodyReader != nil {
		// Passthrough body is still live on the real channel; not replayable
		// here. Return header-only bytes + partial marker.
		return headerBytes, envelope.ErrPartialWireBytes
	}
	// No body at all (e.g. GET request with no payload).
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
