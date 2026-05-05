package ws

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// NewResendWireEncoder returns a wire-byte encoder closure for use by the
// resend_ws MCP tool's Pipeline (PluginStepPost + RecordStep). It differs
// from EncodeWireBytes in one way: when the supplied envelope's
// WSMessage has Compressed=true, the closure actually compresses the
// payload into permessage-deflate wire form using a throwaway
// deflateState, rather than failing-soft like EncodeWireBytes does on
// the live wire path.
//
// Why split the encoder? EncodeWireBytes can't safely re-compress on
// the live wire path because (*deflateState).compress mutates the per-
// direction LZ77 dictionary; allocating a fresh deflateState there
// would not match the peer's compressor history. The resend pipeline,
// in contrast, owns its own dictionary that is thrown away after one
// frame, so re-compression is sound and produces faithful wire bytes
// for RecordStep's variant snapshots.
//
// Mask handling matches EncodeWireBytes: the WSMessage.Mask field is
// taken verbatim. The live Layer.Send for RoleClient regenerates a
// fresh per-frame mask at write time per RFC 6455 §5.3, so the recorded
// Raw is allowed to differ from the live wire mask — the encoder
// produces variant-snapshot bytes, not a byte-for-byte capture of the
// live wire.
//
// extensionHeader is the server-negotiated Sec-WebSocket-Extensions
// value (the 101 response value, authoritative per RFC 7692). When
// empty, the closure assumes no compression was negotiated; passing a
// Compressed=true WSMessage with an empty extensionHeader returns an
// error rather than silently emitting an uncompressed frame.
//
// The closure is safe to register on a pipeline.WireEncoderRegistry.
func NewResendWireEncoder(extensionHeader string) func(*envelope.Envelope) ([]byte, error) {
	return func(env *envelope.Envelope) ([]byte, error) {
		if env == nil {
			return nil, errors.New("ws: NewResendWireEncoder: nil envelope")
		}
		if env.Message == nil {
			return nil, errors.New("ws: NewResendWireEncoder: nil Message")
		}
		msg, ok := env.Message.(*envelope.WSMessage)
		if !ok {
			return nil, fmt.Errorf("ws: NewResendWireEncoder: requires *WSMessage, got %T", env.Message)
		}
		if !msg.Compressed {
			return EncodeWireBytes(env)
		}

		client, _ := parseDeflateExtension(extensionHeader)
		if !client.enabled {
			return nil, errors.New("ws: NewResendWireEncoder: compressed=true but extension header did not negotiate client deflate")
		}
		ds := newDeflateState(client)
		// Build the wire payload first (Close frames reconstruct from
		// CloseCode + CloseReason; other opcodes use Payload verbatim).
		payload := buildSendPayloadFromMessage(msg)
		compressed, err := ds.compress(payload, maxFramePayloadSize)
		if err != nil {
			return nil, fmt.Errorf("ws: NewResendWireEncoder: deflate compress: %w", err)
		}
		frame := &Frame{
			Fin:     msg.Fin,
			RSV1:    true,
			Opcode:  byte(msg.Opcode),
			Masked:  msg.Masked,
			MaskKey: msg.Mask,
			Payload: compressed,
		}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, frame); err != nil {
			return nil, fmt.Errorf("ws: NewResendWireEncoder: %w", err)
		}
		return buf.Bytes(), nil
	}
}
