package ws

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// EncodeWireBytes re-encodes env.Message into one WebSocket frame's wire
// bytes for use by pipeline.RecordStep as the modified variant's RawBytes.
//
// Behavior:
//
//   - Mask is taken verbatim from msg.Masked + msg.Mask. The encoder does
//     NOT regenerate a fresh random mask key (channel.Send does, on the
//     live wire path; the encoder is for variant-record snapshots, which
//     are allowed to differ from a hypothetical re-Send).
//
//   - Close frames reconstruct payload from CloseCode + CloseReason when
//     either is set; otherwise msg.Payload is used verbatim. Mirrors
//     channel.buildSendPayload.
//
//   - RSV1 = msg.Compressed only when compression succeeds (currently
//     never, see below). RSV2/RSV3 are always 0, matching channel.Send.
//
//   - When msg.Compressed=true the encoder returns (nil, nil) fail-soft:
//     deflateState.compress mutates the per-direction LZ77 dictionary,
//     which would corrupt live channel state; allocating a fresh
//     deflateState would not match the peer's compressor history; and
//     emitting RSV1=0 with plain payload would lie about the wire shape.
//     RecordStep tags wire_bytes="unavailable"; the original compressed
//     bytes are preserved on the unmodified variant.
//
// EncodeWireBytes is pure: it does not mutate env, env.Message, or
// env.Opaque; it does no I/O. Direction-agnostic — Role is irrelevant
// because mask/payload come from the WSMessage fields.
func EncodeWireBytes(env *envelope.Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("ws: EncodeWireBytes: nil envelope")
	}
	if env.Message == nil {
		return nil, fmt.Errorf("ws: EncodeWireBytes: nil Message")
	}
	msg, ok := env.Message.(*envelope.WSMessage)
	if !ok {
		return nil, fmt.Errorf("ws: EncodeWireBytes: requires *WSMessage, got %T", env.Message)
	}

	if msg.Compressed {
		return nil, nil
	}

	payload := buildSendPayloadFromMessage(msg)

	frame := &Frame{
		Fin:     msg.Fin,
		Opcode:  byte(msg.Opcode),
		Masked:  msg.Masked,
		MaskKey: msg.Mask,
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		return nil, fmt.Errorf("ws: EncodeWireBytes: %w", err)
	}
	return buf.Bytes(), nil
}

// buildSendPayloadFromMessage mirrors channel.buildSendPayload: for Close
// frames prefer CloseCode+CloseReason when either is set; otherwise return
// Payload verbatim.
func buildSendPayloadFromMessage(msg *envelope.WSMessage) []byte {
	if msg.Opcode != envelope.WSClose {
		return msg.Payload
	}
	if msg.CloseCode == 0 && msg.CloseReason == "" {
		return msg.Payload
	}
	out := make([]byte, 2+len(msg.CloseReason))
	binary.BigEndian.PutUint16(out[:2], msg.CloseCode)
	copy(out[2:], msg.CloseReason)
	return out
}
