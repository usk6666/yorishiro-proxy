package grpcweb

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// Sentinel errors returned by the gRPC-Web body parser. Wrapped via
// fmt.Errorf("...: %w", sentinel) so callers can use errors.Is to classify
// recoverable wire-format failures versus security caps. Recoverable
// failures map to envelope.AnomalyType values in the Channel; security caps
// (oversize LPM, etc.) intentionally do NOT have a sentinel and continue to
// surface as *layer.StreamError.
var (
	// ErrMalformedBase64 wraps a base64 decode failure on a grpc-web-text
	// body. See envelope.AnomalyMalformedGRPCWebBase64.
	ErrMalformedBase64 = errors.New("malformed grpc-web base64")

	// ErrMalformedLPM wraps any length-prefixed message framing failure:
	// incomplete header, invalid flags byte, or incomplete payload. See
	// envelope.AnomalyMalformedGRPCWebLPM.
	ErrMalformedLPM = errors.New("malformed grpc-web LPM")

	// ErrMalformedTrailer wraps a failure to parse the embedded trailer
	// frame's text payload. See envelope.AnomalyMalformedGRPCWebTrailer.
	ErrMalformedTrailer = errors.New("malformed grpc-web trailer")
)

// frameHeaderSize is the size of the gRPC-Web Length-Prefixed Message header.
const frameHeaderSize = 5

// trailerFlagBit is the MSB of the flags byte, indicating a trailer frame.
const trailerFlagBit = 0x80

// compressedFlagBit is bit 0 of the flags byte, indicating compression.
const compressedFlagBit = 0x01

// Frame represents a parsed gRPC-Web Length-Prefixed Message.
// Unlike standard gRPC frames, gRPC-Web frames may be trailer frames
// identified by the MSB of the flags byte.
type Frame struct {
	// IsTrailer indicates whether this is an embedded trailer frame
	// (flags byte has MSB set, i.e., 0x80).
	IsTrailer bool

	// Compressed indicates whether the payload is compressed.
	// When true, the payload should be decompressed according to the
	// grpc-encoding header.
	Compressed bool

	// Payload is the raw bytes of the frame.
	// For data frames, this contains protobuf (or JSON) message bytes.
	// For trailer frames, this contains key-value text
	// ("grpc-status: 0\r\ngrpc-message: OK\r\n").
	Payload []byte
}

// ParseResult holds the result of parsing gRPC-Web frames, separating
// data frames from trailer frames.
type ParseResult struct {
	// DataFrames contains all non-trailer frames in wire order.
	DataFrames []*Frame

	// TrailerFrame is the embedded trailer frame, if present.
	// gRPC-Web responses typically have exactly one trailer frame at the end.
	TrailerFrame *Frame

	// Trailers contains the parsed trailer key-value pairs, if a trailer
	// frame was present. Keys are preserved in their original casing.
	Trailers map[string]string
}

// DecodeBody decodes a gRPC-Web response body. If isBase64 is true, the body
// is base64-decoded before frame parsing. It returns the parsed frames
// separated into data and trailer frames.
//
// DecodeBody uses the default LPM cap (config.MaxGRPCMessageSize); callers
// that need a configurable cap (e.g. the gRPC-Web Channel applying a
// per-Channel Option) should use DecodeBodyWithMaxMessageSize.
func DecodeBody(data []byte, isBase64 bool) (*ParseResult, error) {
	return DecodeBodyWithMaxMessageSize(data, isBase64, config.MaxGRPCMessageSize)
}

// DecodeBodyWithMaxMessageSize is like DecodeBody but uses the supplied
// per-LPM cap for wire-side validation. maxMessageSize=0 falls back to
// config.MaxGRPCMessageSize so this remains drop-in compatible with the
// non-configurable variant.
func DecodeBodyWithMaxMessageSize(data []byte, isBase64 bool, maxMessageSize uint32) (*ParseResult, error) {
	if maxMessageSize == 0 {
		maxMessageSize = config.MaxGRPCMessageSize
	}
	if isBase64 {
		decoded, err := decodeBase64(data)
		if err != nil {
			return nil, fmt.Errorf("decode grpc-web base64 body: %w: %v", ErrMalformedBase64, err)
		}
		data = decoded
	}

	return readAllFrames(data, maxMessageSize)
}

// ReadAllFrames reads all gRPC-Web Length-Prefixed Messages from the given
// binary data. Unlike the standard gRPC ReadAllFrames, this function
// recognizes trailer frames (flags byte MSB set).
// If the data is empty, it returns an empty ParseResult with no error.
//
// maxMessageSize bounds the declared LPM length (CWE-400 mitigation).
func readAllFrames(data []byte, maxMessageSize uint32) (*ParseResult, error) {
	result := &ParseResult{}

	if len(data) == 0 {
		return result, nil
	}

	offset := 0
	for offset < len(data) {
		remaining := len(data) - offset
		if remaining < frameHeaderSize {
			return result, fmt.Errorf("%w: incomplete frame header: %d bytes remaining", ErrMalformedLPM, remaining)
		}

		flags := data[offset]
		isTrailer := flags&trailerFlagBit != 0
		compressed := flags&compressedFlagBit != 0

		// Validate that only known flag bits are set.
		// Known bits: bit 0 (compressed) and bit 7 (trailer).
		if flags & ^byte(trailerFlagBit|compressedFlagBit) != 0 {
			return result, fmt.Errorf("%w: invalid flags byte: 0x%02x", ErrMalformedLPM, flags)
		}

		length := binary.BigEndian.Uint32(data[offset+1 : offset+5])
		if length > maxMessageSize {
			// Security cap (CWE-400). Intentionally NOT wrapped with
			// ErrMalformedLPM — oversize is a DoS-defense termination,
			// not a wire-format observability signal.
			return result, fmt.Errorf("grpc-web message too large: %d > %d", length, maxMessageSize)
		}

		offset += frameHeaderSize

		if uint32(len(data)-offset) < length {
			return result, fmt.Errorf("%w: incomplete payload: want %d bytes, have %d", ErrMalformedLPM, length, len(data)-offset)
		}

		payload := make([]byte, length)
		copy(payload, data[offset:offset+int(length)])

		frame := &Frame{
			IsTrailer:  isTrailer,
			Compressed: compressed,
			Payload:    payload,
		}

		if isTrailer {
			result.TrailerFrame = frame
			trailers, err := ParseTrailers(payload)
			if err != nil {
				return result, fmt.Errorf("%w: %v", ErrMalformedTrailer, err)
			}
			result.Trailers = trailers
		} else {
			result.DataFrames = append(result.DataFrames, frame)
		}

		offset += int(length)
	}

	return result, nil
}

// decodeBase64 decodes base64-encoded gRPC-Web data. It handles both
// standard and padded base64.
func decodeBase64(data []byte) ([]byte, error) {
	// gRPC-Web text format uses standard base64 encoding (RFC 4648).
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		// Try without padding for robustness — some implementations
		// omit trailing '=' padding.
		decoded, err2 := base64.RawStdEncoding.DecodeString(string(data))
		if err2 != nil {
			return nil, err // Return the original error.
		}
		return decoded, nil
	}
	return decoded, nil
}

// EncodeFrame encodes a gRPC-Web frame into bytes.
// This is primarily used for testing.
func EncodeFrame(isTrailer, compressed bool, payload []byte) []byte {
	buf := make([]byte, frameHeaderSize+len(payload))
	var flags byte
	if isTrailer {
		flags |= trailerFlagBit
	}
	if compressed {
		flags |= compressedFlagBit
	}
	buf[0] = flags
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}

// EncodeBase64Body encodes binary gRPC-Web frames into base64 for
// the grpc-web-text wire format. This is primarily used for testing.
func EncodeBase64Body(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)
	return []byte(encoded)
}
