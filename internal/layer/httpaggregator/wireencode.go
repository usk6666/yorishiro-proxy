package httpaggregator

import (
	"bytes"
	"context"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// defaultEncoderTableSize is the HPACK dynamic table size used by the
// offline re-encoder.
const defaultEncoderTableSize uint32 = 4096

// EncodeWireBytes re-encodes an aggregated HTTPMessage envelope into
// HTTP/2 wire-form frames for use by pipeline.RecordStep as the modified
// variant's RawBytes. Moved from internal/layer/http2 as part of USK-637
// because the aggregator now owns the full HTTPMessage envelope surface
// for HTTP/2 traffic.
//
// The encoder emits HEADERS (+ CONTINUATION*) then DATA* then trailer
// HEADERS. The stream identifier on emitted frames is always 1 — the live
// stream id is meaningless for an offline capture. HPACK state is a
// freshly-allocated encoder (4096-byte table); emitted bytes are HPACK-
// valid but differ from the live writer's output due to independent
// dynamic-table histories.
//
// EncodeWireBytes is pure: no mutation of env/msg, no network I/O.
// BodyBuffer.Bytes is read through its independent read handle so this
// call is safe to run concurrently with a live write path.
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("httpaggregator: EncodeWireBytes: nil envelope")
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, fmt.Errorf("httpaggregator: EncodeWireBytes: requires *HTTPMessage, got %T", env.Message)
	}

	bodyBytes, err := resolveBodyForEncode(msg)
	if err != nil {
		return nil, err
	}

	// Build the HPACK field list from the HTTPMessage. Direction selects
	// request-vs-response pseudo-headers. Lowercase header names per
	// RFC 9113 §8.2.1; anomaly surfacing is on the receive side.
	headers := buildHeaderFieldsFromMessage(env, msg)
	trailers := buildTrailerFieldsFromMessage(msg.Trailers)

	hasBody := len(bodyBytes) > 0
	hasTrailers := len(trailers) > 0
	headersEndStream := !hasBody && !hasTrailers

	enc := hpack.NewEncoder(defaultEncoderTableSize, true)
	headerBlock := enc.Encode(headers)

	var buf bytes.Buffer
	wr := frame.NewWriter(&buf)
	const encodeStreamID uint32 = 1
	maxFrameSize := wr.MaxFrameSize()

	if err := writeHeaderBlockEncoded(wr, encodeStreamID, headerBlock, headersEndStream, maxFrameSize); err != nil {
		return nil, fmt.Errorf("httpaggregator: EncodeWireBytes: write header block: %w", err)
	}

	if hasBody {
		if err := writeBodyBuffered(wr, encodeStreamID, bodyBytes, !hasTrailers, int(maxFrameSize)); err != nil {
			return nil, fmt.Errorf("httpaggregator: EncodeWireBytes: write body: %w", err)
		}
	}

	if hasTrailers {
		trailerBlock := enc.Encode(trailers)
		if err := writeHeaderBlockEncoded(wr, encodeStreamID, trailerBlock, true, maxFrameSize); err != nil {
			return nil, fmt.Errorf("httpaggregator: EncodeWireBytes: write trailer block: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// resolveBodyForEncode flattens msg.Body or msg.BodyBuffer into an
// in-memory []byte for offline DATA frame encoding.
func resolveBodyForEncode(msg *envelope.HTTPMessage) ([]byte, error) {
	if msg.Body != nil {
		return msg.Body, nil
	}
	if msg.BodyBuffer != nil {
		b, err := msg.BodyBuffer.Bytes(context.Background())
		if err != nil {
			return nil, fmt.Errorf("httpaggregator: EncodeWireBytes materialize body: %w", err)
		}
		return b, nil
	}
	return nil, nil
}

// buildHeaderFieldsFromMessage re-uses the Layer's event-based encoder via
// a synthetic H2HeadersEvent so pseudo-header selection stays in one place.
func buildHeaderFieldsFromMessage(env *envelope.Envelope, msg *envelope.HTTPMessage) []hpack.HeaderField {
	evt := &http2.H2HeadersEvent{
		Method:       msg.Method,
		Scheme:       msg.Scheme,
		Authority:    msg.Authority,
		Path:         msg.Path,
		RawQuery:     msg.RawQuery,
		Status:       msg.Status,
		StatusReason: msg.StatusReason,
		Headers:      msg.Headers,
	}
	return http2.BuildHeaderFieldsFromEvent(env, evt)
}

// buildTrailerFieldsFromMessage converts HTTPMessage.Trailers to lowercase
// hpack.HeaderField entries. Pseudo-headers in trailers are invalid per
// RFC 9113 §8.1 and are dropped (anomaly surfacing is the receive-side
// responsibility).
func buildTrailerFieldsFromMessage(trailers []envelope.KeyValue) []hpack.HeaderField {
	if len(trailers) == 0 {
		return nil
	}
	out := make([]hpack.HeaderField, 0, len(trailers))
	for _, kv := range trailers {
		if len(kv.Name) > 0 && kv.Name[0] == ':' {
			continue
		}
		out = append(out, hpack.HeaderField{
			Name:  lowerASCII(kv.Name),
			Value: kv.Value,
		})
	}
	return out
}

// writeHeaderBlockEncoded splits a pre-encoded HPACK block across HEADERS
// + CONTINUATION frames according to maxFrameSize.
func writeHeaderBlockEncoded(wr *frame.Writer, streamID uint32, encoded []byte, endStream bool, maxFrameSize uint32) error {
	if maxFrameSize == 0 {
		maxFrameSize = frame.DefaultMaxFrameSize
	}
	if uint32(len(encoded)) <= maxFrameSize {
		return wr.WriteHeaders(streamID, endStream, true, encoded)
	}
	first := encoded[:maxFrameSize]
	rest := encoded[maxFrameSize:]
	if err := wr.WriteHeaders(streamID, endStream, false, first); err != nil {
		return err
	}
	for len(rest) > int(maxFrameSize) {
		if err := wr.WriteContinuation(streamID, false, rest[:maxFrameSize]); err != nil {
			return err
		}
		rest = rest[maxFrameSize:]
	}
	return wr.WriteContinuation(streamID, true, rest)
}

// writeBodyBuffered writes a fully-buffered body as DATA frames. When
// endStreamOnLast is true, END_STREAM is placed on the final frame.
func writeBodyBuffered(wr *frame.Writer, streamID uint32, body []byte, endStreamOnLast bool, maxFrameSize int) error {
	if maxFrameSize <= 0 {
		maxFrameSize = int(frame.DefaultMaxFrameSize)
	}
	for len(body) > 0 {
		n := maxFrameSize
		if n > len(body) {
			n = len(body)
		}
		chunk := body[:n]
		body = body[n:]
		endStream := endStreamOnLast && len(body) == 0
		if err := wr.WriteData(streamID, endStream, chunk); err != nil {
			return err
		}
	}
	return nil
}

// lowerASCII returns s with ASCII uppercase letters lowered.
func lowerASCII(s string) string {
	// Fast path: already lowercase.
	needs := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
