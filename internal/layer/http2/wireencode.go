package http2

import (
	"bytes"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// defaultEncoderTableSize is the HPACK dynamic table size used by the
// offline re-encoder. RFC 7541 §4.2 defines 4096 as the default
// SETTINGS_HEADER_TABLE_SIZE and every live connection starts here until a
// peer SETTINGS frame negotiates otherwise.
const defaultEncoderTableSize uint32 = 4096

// EncodeWireBytes re-encodes env.Message into HTTP/2 wire-form frames for
// use by pipeline.RecordStep as the modified variant's RawBytes.
//
// The encoder mirrors the logic of the connection writer's
// handleWriteMessage path: HEADERS (+ CONTINUATION fragmentation if needed)
// over the encoded header block, followed by DATA frames carrying the body,
// followed by a trailer HEADERS frame when msg.Trailers is non-empty. The
// stream identifier on the emitted frames is always 1 — the live stream id
// is meaningless for an offline capture embedded in a flow record, and the
// decoder only needs the bytes to round-trip through hpack.
//
// HPACK state caveat: this function uses a freshly-allocated hpack.Encoder
// with the default dynamic table size (4096 bytes, per RFC 7541 §4.2)
// rather than reusing the connection's encoder goroutine. As a result, the
// emitted header block indices differ from the bytes the real connection
// writer would have produced — the two encoders have different dynamic
// table histories. The emitted header block is, however, HPACK-valid and
// semantically equivalent: it decodes to the same (name, value) sequence
// a live hpack.Decoder would recover from the real wire bytes. Tests and
// analysts must therefore assert semantic content (via hpack.Decoder) and
// not byte-identity against the live wire capture.
//
// Body handling:
//   - When msg.Body is non-nil it is serialized directly into DATA frames
//     using the default MaxFrameSize (16 KiB).
//   - When msg.Body is nil and msg.BodyStream is non-nil (HTTP/2 passthrough
//     mode), the stream cannot be replayed offline without disturbing the
//     live channel — the encoder returns the header-block-only bytes
//     together with envelope.ErrPartialWireBytes so RecordStep can tag
//     Metadata["wire_bytes"] = "partial".
//
// No flow-control accounting occurs: this is an offline re-encode, not a
// wire write. END_STREAM is placed on the last frame emitted (trailer
// HEADERS when trailers present, else the last DATA, else the initial
// HEADERS when the message has no body).
//
// EncodeWireBytes is pure: it does not consult the live Layer's
// hpack.Encoder / frame.Writer and does not mutate env or env.Message.
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("http2: EncodeWireBytes: nil envelope")
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, fmt.Errorf("http2: EncodeWireBytes: requires *HTTPMessage, got %T", env.Message)
	}

	headers := buildHeaderFields(env, msg)
	trailers, _ := buildTrailerFields(msg.Trailers)

	hasBody := len(msg.Body) > 0
	hasTrailers := len(trailers) > 0
	streamStillOpen := msg.Body == nil && msg.BodyStream != nil
	headersEndStream := !hasBody && !hasTrailers && !streamStillOpen

	enc := hpack.NewEncoder(defaultEncoderTableSize, true)
	headerBlock := enc.Encode(headers)

	var buf bytes.Buffer
	wr := frame.NewWriter(&buf)
	const encodeStreamID uint32 = 1
	maxFrameSize := wr.MaxFrameSize()

	if err := writeHeaderBlockEncoded(wr, encodeStreamID, headerBlock, headersEndStream, maxFrameSize); err != nil {
		return nil, fmt.Errorf("http2: EncodeWireBytes: write header block: %w", err)
	}

	if hasBody {
		if err := writeBodyBuffered(wr, encodeStreamID, msg.Body, !hasTrailers, int(maxFrameSize)); err != nil {
			return nil, fmt.Errorf("http2: EncodeWireBytes: write body: %w", err)
		}
	}

	if hasTrailers {
		trailerBlock := enc.Encode(trailers)
		if err := writeHeaderBlockEncoded(wr, encodeStreamID, trailerBlock, true, maxFrameSize); err != nil {
			return nil, fmt.Errorf("http2: EncodeWireBytes: write trailer block: %w", err)
		}
	}

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())

	if streamStillOpen {
		// Passthrough body was not included; signal partial wire bytes.
		return out, envelope.ErrPartialWireBytes
	}
	return out, nil
}

// writeHeaderBlockEncoded writes a HEADERS (+ CONTINUATION) sequence for the
// given pre-encoded block, fragmenting at maxFrameSize.
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
