package envelope

// WSOpcode identifies a WebSocket frame opcode (RFC 6455 §5.2).
type WSOpcode uint8

// WebSocket opcodes defined by RFC 6455.
const (
	WSContinuation WSOpcode = 0x0
	WSText         WSOpcode = 0x1
	WSBinary       WSOpcode = 0x2
	WSClose        WSOpcode = 0x8
	WSPing         WSOpcode = 0x9
	WSPong         WSOpcode = 0xA
)

// WSMessage represents one WebSocket frame. See RFC-001 section 3.2.2.
//
// Frame-per-Envelope: control frames (Ping/Pong/Close) and continuation
// frames each produce their own Envelope. The Layer does not coalesce
// fragmented messages at this level.
type WSMessage struct {
	// Opcode is the WebSocket frame opcode.
	Opcode WSOpcode

	// Fin indicates the final fragment of a message.
	Fin bool

	// Masked indicates whether the frame payload was masked on the wire
	// (true for client-to-server frames per RFC 6455).
	Masked bool

	// Mask holds the 4-byte masking key when Masked is true.
	Mask [4]byte

	// Payload is the unmasked frame payload.
	Payload []byte

	// CloseCode carries the RFC 6455 status code for Close frames.
	// Zero for non-Close frames.
	CloseCode uint16

	// CloseReason carries the optional UTF-8 reason for Close frames.
	CloseReason string

	// Compressed indicates the frame was sent with the per-message-deflate
	// extension RSV1 bit (RFC 7692).
	Compressed bool
}

// Protocol returns ProtocolWebSocket.
func (m *WSMessage) Protocol() Protocol { return ProtocolWebSocket }

// CloneMessage returns a deep copy of the WSMessage. The Mask array and
// all scalar fields are copied by value; Payload is deep-copied.
func (m *WSMessage) CloneMessage() Message {
	return &WSMessage{
		Opcode:      m.Opcode,
		Fin:         m.Fin,
		Masked:      m.Masked,
		Mask:        m.Mask,
		Payload:     cloneBytes(m.Payload),
		CloseCode:   m.CloseCode,
		CloseReason: m.CloseReason,
		Compressed:  m.Compressed,
	}
}
