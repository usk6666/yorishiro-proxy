package grpc

import (
	"encoding/binary"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// EncodeWireBytes re-encodes env.Message into gRPC wire-form bytes for use
// by pipeline.RecordStep as the modified variant's RawBytes.
//
// Per-message-type behavior:
//
//   - *envelope.GRPCStartMessage → returns (nil, nil). gRPC HEADERS live in
//     the underlying HTTP/2 layer's HPACK block; this Layer cannot re-render
//     the HPACK frame in isolation. RecordStep tags the variant
//     wire_bytes="unavailable".
//
//   - *envelope.GRPCEndMessage → returns (nil, nil). gRPC trailer-HEADERS
//     are likewise HPACK-encoded by the HTTP/2 layer. (Diverges from the
//     grpc-web encoder, where End is an LPM trailer frame, not an HPACK
//     trailer block.)
//
//   - *envelope.GRPCDataMessage → re-encodes one Length-Prefixed Message
//     frame: 5-byte prefix (1 compressed-flag byte + 4 BE length bytes)
//     followed by the payload. The pure end-marker shape
//     (Payload==nil && WireLength==0 && !Compressed && EndStream=true)
//     yields a non-nil empty byte slice — faithful to the wire reality
//     "this envelope contributed zero LPM bytes" (matches the empty H2
//     DATA payload sendData emits for the same shape).
//
//   - When m.Compressed=true, the encoder returns (nil, nil) fail-soft:
//     bit-exact re-compression requires the negotiated grpc-encoding which
//     lives on per-channel directionState and is intentionally not
//     accessible from a pure encoder. RecordStep tags wire_bytes=
//     "unavailable"; the original variant retains the actual compressed
//     bytes via the Pipeline's zero-copy path.
//
//   - Any other Message type → hard error (registry mis-wiring).
//
// EncodeWireBytes is pure: it does not mutate env, env.Message, env.Opaque,
// or any per-channel state; it does no I/O.
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("grpc: EncodeWireBytes: nil envelope")
	}
	if env.Message == nil {
		return nil, fmt.Errorf("grpc: EncodeWireBytes: nil Message")
	}

	switch m := env.Message.(type) {
	case *envelope.GRPCStartMessage:
		return nil, nil

	case *envelope.GRPCEndMessage:
		return nil, nil

	case *envelope.GRPCDataMessage:
		// Pure end-marker: empty H2 DATA payload + END_STREAM=1 on the wire.
		// Return a non-nil zero-length slice so RecordStep records the
		// modified variant with empty RawBytes (no "unavailable" tag).
		if m.Payload == nil && m.WireLength == 0 && !m.Compressed && m.EndStream {
			return []byte{}, nil
		}
		// Compressed payload: bit-exact re-compression requires the
		// negotiated grpc-encoding which is intentionally not exposed to
		// the encoder. Fail-soft.
		if m.Compressed {
			return nil, nil
		}
		// Uncompressed LPM: rebuild prefix + payload from struct fields.
		// WireLength is intentionally derived from len(m.Payload) — the
		// analyst-edited Payload is the source of truth; an analyst that
		// kept the old WireLength after editing Payload would emit wire
		// bytes the peer would reject.
		out := make([]byte, lpmPrefixLen+len(m.Payload))
		// out[0] = 0 (compressed-flag) — already zero from make.
		binary.BigEndian.PutUint32(out[1:5], uint32(len(m.Payload)))
		copy(out[lpmPrefixLen:], m.Payload)
		return out, nil

	default:
		return nil, fmt.Errorf("grpc: EncodeWireBytes: requires *GRPC{Start,Data,End}Message, got %T", env.Message)
	}
}
