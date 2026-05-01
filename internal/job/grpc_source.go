package job

import (
	"context"
	"io"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// GRPCResendSource is an EnvelopeSource that yields the envelope sequence
// describing one full gRPC RPC: GRPCStartMessage → GRPCDataMessage* →
// (optional) GRPCEndMessage → io.EOF. Subsequent Next calls return io.EOF.
//
// The shape diverges from HTTPResendSource / WSResendSource (single-envelope
// one-shots) because gRPC has multi-event RPC semantics: the RPC lifecycle
// requires an opening HEADERS frame, one or more LPM-framed DATA messages,
// and either an END_STREAM bit on the trailing DATA or an explicit trailer
// HEADERS block. The job runner iterates Next() until io.EOF, sending each
// envelope through the same Layer.Send path resend_grpc uses inline.
//
// The source is one-shot and immutable: the caller supplies a fully
// resolved GRPCResendSpec describing the RPC, and the source emits the
// envelopes in send order. fuzz_grpc (USK-679) is the primary downstream
// consumer; resend_grpc itself builds the envelopes inline because it
// also needs to pre-encode wire bytes for the WireEncoderRegistry.
type GRPCResendSource struct {
	streamID string
	connID   string

	start    *envelope.GRPCStartMessage
	startRaw []byte
	dataMsgs []GRPCResendDataPart
	end      *envelope.GRPCEndMessage // nil = terminate via END_STREAM on last Data
	endRaw   []byte                   // optional pre-encoded wire bytes for End

	emitted int // 0 = next emits Start; then Start+1..Start+len(dataMsgs) = Data; then End if present; then EOF
}

// GRPCResendDataPart describes one length-prefixed message (LPM) on the
// gRPC Send-direction stream. Compressed flips the LPM compression byte;
// when Compressed=true the caller is responsible for ensuring the
// associated GRPCStartMessage's Encoding field is non-empty (the gRPC
// Layer rejects compressed=true with an unsupported encoding via
// *layer.StreamError on Send).
//
// Payload is always the decompressed bytes; the Layer handles compression
// against the negotiated grpc-encoding cached on directionState. Raw, when
// non-empty, is used as the synthesised envelope's Envelope.Raw and the
// Layer's sendData prefers it verbatim (5-byte LPM prefix + payload bytes
// included).
//
// EndStream marks the LPM as the request-side terminator. When the end
// envelope is present (GRPCEndMessage), all GRPCResendDataParts must have
// EndStream=false so the trailer HEADERS frame carries the END_STREAM
// signal. When the end envelope is absent, exactly the last
// GRPCResendDataPart should have EndStream=true.
type GRPCResendDataPart struct {
	Payload    []byte
	Compressed bool
	WireLength uint32 // optional: length of compressed payload on the wire; 0 = derived from len(Payload)
	EndStream  bool
	Raw        []byte // optional pre-encoded wire bytes (5-byte prefix + payload)
}

// GRPCResendSpec is the complete description of one resend RPC. Every
// field is owned by the caller; the source does not deep-copy on Next, so
// callers must not mutate slices after passing them in. RawBytes seeds
// Envelope.Raw on each direction's envelope so RecordStep records the
// pre-computed wire form when the resend handler has already encoded it.
type GRPCResendSpec struct {
	Start    *envelope.GRPCStartMessage
	StartRaw []byte // optional pre-encoded HEADERS wire bytes; usually empty (HPACK is per-connection-stateful)
	Data     []GRPCResendDataPart
	End      *envelope.GRPCEndMessage // nil = terminate via END_STREAM on last Data
	EndRaw   []byte                   // optional pre-encoded trailer HEADERS wire bytes; usually empty
}

// NewGRPCResendSource builds a one-shot multi-envelope source. streamID
// is stamped on every produced envelope (RecordStep keys the new Stream
// row off it). connID populates EnvelopeContext.ConnID so pluginv2
// transaction-state lookups (USK-670) and downstream Pipeline Steps see
// consistent values across the RPC's envelopes.
//
// The source rejects an empty Data list at construction time: an RPC
// with zero DATA frames is not a well-formed gRPC interaction. Callers
// that genuinely need a HEADERS-only stream should not use this source.
func NewGRPCResendSource(streamID, connID string, spec GRPCResendSpec) *GRPCResendSource {
	return &GRPCResendSource{
		streamID: streamID,
		connID:   connID,
		start:    spec.Start,
		startRaw: spec.StartRaw,
		dataMsgs: spec.Data,
		end:      spec.End,
		endRaw:   spec.EndRaw,
	}
}

// Next emits envelopes in order: Start (sequence 0), each Data (sequence
// 1..N), optional End (sequence N+1). Returns io.EOF once the sequence
// is exhausted. The returned envelope's Direction is always Send; the
// caller's Layer.Send path drives wire encoding.
func (s *GRPCResendSource) Next(_ context.Context) (*envelope.Envelope, error) {
	dataCount := len(s.dataMsgs)
	endIndex := 1 + dataCount
	totalEnvelopes := endIndex
	if s.end != nil {
		totalEnvelopes++
	}

	if s.emitted >= totalEnvelopes {
		return nil, io.EOF
	}

	pos := s.emitted
	s.emitted++

	switch {
	case pos == 0:
		return s.startEnvelope(), nil
	case pos < endIndex:
		return s.dataEnvelope(pos - 1), nil
	default:
		return s.endEnvelope(pos), nil
	}
}

func (s *GRPCResendSource) startEnvelope() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  s.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       s.startRaw,
		Message:   s.start,
		Context: envelope.EnvelopeContext{
			ConnID: s.connID,
		},
	}
}

func (s *GRPCResendSource) dataEnvelope(idx int) *envelope.Envelope {
	d := s.dataMsgs[idx]
	wireLen := d.WireLength
	if wireLen == 0 {
		wireLen = uint32(len(d.Payload))
	}
	return &envelope.Envelope{
		StreamID:  s.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  idx + 1,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       d.Raw,
		Message: &envelope.GRPCDataMessage{
			Service:    s.start.Service,
			Method:     s.start.Method,
			Compressed: d.Compressed,
			WireLength: wireLen,
			Payload:    d.Payload,
			EndStream:  d.EndStream,
		},
		Context: envelope.EnvelopeContext{
			ConnID: s.connID,
		},
	}
}

func (s *GRPCResendSource) endEnvelope(sequence int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  s.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  sequence,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       s.endRaw,
		Message:   s.end,
		Context: envelope.EnvelopeContext{
			ConnID: s.connID,
		},
	}
}
