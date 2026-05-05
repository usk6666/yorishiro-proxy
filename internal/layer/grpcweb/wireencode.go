package grpcweb

import (
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// EncodeWireBytes re-encodes env.Message into gRPC-Web wire-form bytes for
// use by pipeline.RecordStep as the modified variant's RawBytes.
//
// The encoder consults env.Opaque (an *opaqueGRPCWeb populated by
// refillFromHTTPMessage) for the wire-format signal (binary vs base64) and
// the negotiated grpc-encoding. Pipeline Steps must not type-assert on
// Opaque (RFC §3.1) — only this same-package WireEncoder does.
//
// Per-message-type behavior:
//
//   - *envelope.GRPCStartMessage → returns (nil, nil). gRPC-Web Start
//     metadata lives on HTTP headers owned by the inner HTTP/1.x or HTTP/2
//     Layer; this Layer cannot re-render the HTTP header block from a
//     GRPCStartMessage in isolation. RecordStep receives a nil byte slice
//     which causes Metadata["wire_bytes"] = "unavailable" — the analyst
//     sees the modified Start row with HTTP-headers-not-recordable
//     semantics, which is the correct contract for grpc-web.
//
//   - *envelope.GRPCDataMessage → re-encodes one Length-Prefixed Message
//     frame from m.Payload (re-compressing if m.Compressed=true) and, when
//     the wire format is base64, base64-wraps the single frame.
//
//   - *envelope.GRPCEndMessage → re-encodes one trailer LPM frame from
//     status/message/details/trailers, applying base64 wrap when needed.
//
//   - any other Message type → error.
//
// When env.Opaque is missing (e.g. Resend constructs a fresh Envelope),
// GRPC* Message types fall back to (nil, nil) — fail-soft per the
// bytechunk wireencode precedent — so RecordStep tags the modified
// variant as "unavailable" instead of crashing the pipeline.
//
// Production datapath registration is added in the N8/N9 proxy assembly
// issue. This implementation lives here so the integration tests in this
// package can register it directly (USK-661).
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("grpcweb: EncodeWireBytes: nil envelope")
	}
	if env.Message == nil {
		return nil, fmt.Errorf("grpcweb: EncodeWireBytes: nil Message")
	}

	opaque, _ := env.Opaque.(*opaqueGRPCWeb)

	switch m := env.Message.(type) {
	case *envelope.GRPCStartMessage:
		// HTTP headers are owned by the inner Layer; nothing to re-render
		// here. nil bytes signal "unavailable" to RecordStep, which is the
		// correct semantic for grpc-web Start variants.
		return nil, nil

	case *envelope.GRPCDataMessage:
		if opaque == nil {
			// Fail-soft on missing opaque (e.g. Resend path). RecordStep
			// will tag wire_bytes="unavailable".
			return nil, nil
		}
		wirePayload := m.Payload
		if m.Compressed {
			compressed, err := compressPayload(wirePayload, opaque.encoding)
			if err != nil {
				return nil, fmt.Errorf("grpcweb: EncodeWireBytes: %w", err)
			}
			wirePayload = compressed
		}
		frame := EncodeFrame(false, m.Compressed, wirePayload)
		if opaque.wireBase64 {
			return EncodeBase64Body(frame), nil
		}
		return frame, nil

	case *envelope.GRPCEndMessage:
		if opaque == nil {
			return nil, nil
		}
		trailerPayload := encodeTrailerPayload(m)
		frame := EncodeFrame(true, false, trailerPayload)
		if opaque.wireBase64 {
			return EncodeBase64Body(frame), nil
		}
		return frame, nil

	default:
		return nil, fmt.Errorf("grpcweb: EncodeWireBytes: requires *GRPC{Start,Data,End}Message, got %T", env.Message)
	}
}
