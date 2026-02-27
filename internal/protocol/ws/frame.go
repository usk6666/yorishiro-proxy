// Package ws implements a WebSocket frame parser and bidirectional relay
// for proxying WebSocket connections. It handles RFC 6455 frame parsing,
// masking/unmasking, fragmentation, and control frame processing.
package ws

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WebSocket opcodes as defined in RFC 6455 Section 11.8.
const (
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

// maxControlPayloadSize is the maximum payload size for control frames (125 bytes per RFC 6455).
const maxControlPayloadSize = 125

// maxFramePayloadSize limits the maximum payload size to prevent memory exhaustion.
// WebSocket frames can theoretically be up to 2^63 bytes; we cap at 16MB.
const maxFramePayloadSize = 16 << 20 // 16MB

// Frame represents a parsed WebSocket frame.
type Frame struct {
	// Fin indicates whether this is the final fragment in a message.
	Fin bool
	// RSV1, RSV2, RSV3 are reserved bits (must be 0 unless an extension defines them).
	RSV1 bool
	RSV2 bool
	RSV3 bool
	// Opcode identifies the frame type (text, binary, close, ping, pong, continuation).
	Opcode byte
	// Masked indicates whether the payload is masked (client-to-server frames must be masked).
	Masked bool
	// MaskKey is the 4-byte masking key (only present if Masked is true).
	MaskKey [4]byte
	// Payload is the (unmasked) frame payload data.
	Payload []byte
}

// IsControl returns true if the frame is a control frame (Close, Ping, or Pong).
func (f *Frame) IsControl() bool {
	return f.Opcode >= OpcodeClose
}

// ReadFrame reads a single WebSocket frame from r.
// If the frame is masked, the payload is automatically unmasked.
func ReadFrame(r io.Reader) (*Frame, error) {
	// Read the first 2 bytes: FIN, RSV1-3, Opcode, MASK, Payload length.
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}

	f := &Frame{
		Fin:    header[0]&0x80 != 0,
		RSV1:   header[0]&0x40 != 0,
		RSV2:   header[0]&0x20 != 0,
		RSV3:   header[0]&0x10 != 0,
		Opcode: header[0] & 0x0F,
		Masked: header[1]&0x80 != 0,
	}

	// Parse payload length (7 bits, 7+16 bits, or 7+64 bits).
	payloadLen := uint64(header[1] & 0x7F)
	switch {
	case payloadLen == 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, fmt.Errorf("read extended payload length (16-bit): %w", err)
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
	case payloadLen == 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, fmt.Errorf("read extended payload length (64-bit): %w", err)
		}
		payloadLen = binary.BigEndian.Uint64(ext[:])
		// MSB must be 0 per RFC 6455 Section 5.2.
		if payloadLen>>63 != 0 {
			return nil, fmt.Errorf("invalid frame: payload length MSB is set")
		}
	}

	// Validate control frame constraints.
	if f.IsControl() {
		if payloadLen > maxControlPayloadSize {
			return nil, fmt.Errorf("control frame payload too large: %d > %d", payloadLen, maxControlPayloadSize)
		}
		if !f.Fin {
			return nil, fmt.Errorf("control frame must not be fragmented")
		}
	}

	// Guard against excessive memory allocation.
	if payloadLen > maxFramePayloadSize {
		return nil, fmt.Errorf("frame payload too large: %d > %d", payloadLen, maxFramePayloadSize)
	}

	// Read masking key if present.
	if f.Masked {
		if _, err := io.ReadFull(r, f.MaskKey[:]); err != nil {
			return nil, fmt.Errorf("read mask key: %w", err)
		}
	}

	// Read payload.
	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
		// Unmask the payload if masked.
		if f.Masked {
			maskPayload(f.MaskKey, f.Payload)
		}
	}

	return f, nil
}

// WriteFrame serializes a WebSocket frame and writes it to w.
// If the frame's Masked field is true, the payload is masked with MaskKey before writing.
// The payload in the Frame struct is not modified; masking is applied to a copy.
func WriteFrame(w io.Writer, f *Frame) error {
	// First byte: FIN, RSV1-3, Opcode.
	var b0 byte
	if f.Fin {
		b0 |= 0x80
	}
	if f.RSV1 {
		b0 |= 0x40
	}
	if f.RSV2 {
		b0 |= 0x20
	}
	if f.RSV3 {
		b0 |= 0x10
	}
	b0 |= f.Opcode & 0x0F

	// Second byte: MASK, Payload length.
	payloadLen := len(f.Payload)
	var header []byte

	switch {
	case payloadLen <= 125:
		header = make([]byte, 2)
		header[0] = b0
		header[1] = byte(payloadLen)
	case payloadLen <= 65535:
		header = make([]byte, 4)
		header[0] = b0
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(payloadLen))
	default:
		header = make([]byte, 10)
		header[0] = b0
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(payloadLen))
	}

	if f.Masked {
		header[1] |= 0x80
	}

	// Write header.
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}

	// Write mask key if masked.
	if f.Masked {
		if _, err := w.Write(f.MaskKey[:]); err != nil {
			return fmt.Errorf("write mask key: %w", err)
		}
	}

	// Write payload (masked if needed).
	if payloadLen > 0 {
		if f.Masked {
			// Apply mask to a copy so the original payload is not modified.
			masked := make([]byte, payloadLen)
			copy(masked, f.Payload)
			maskPayload(f.MaskKey, masked)
			if _, err := w.Write(masked); err != nil {
				return fmt.Errorf("write masked payload: %w", err)
			}
		} else {
			if _, err := w.Write(f.Payload); err != nil {
				return fmt.Errorf("write payload: %w", err)
			}
		}
	}

	return nil
}

// maskPayload applies the WebSocket masking algorithm (XOR with rotating key).
// This operation is its own inverse: applying it twice restores the original data.
func maskPayload(key [4]byte, data []byte) {
	for i := range data {
		data[i] ^= key[i%4]
	}
}

// OpcodeString returns a human-readable name for the given opcode.
func OpcodeString(opcode byte) string {
	switch opcode {
	case OpcodeContinuation:
		return "continuation"
	case OpcodeText:
		return "text"
	case OpcodeBinary:
		return "binary"
	case OpcodeClose:
		return "close"
	case OpcodePing:
		return "ping"
	case OpcodePong:
		return "pong"
	default:
		return fmt.Sprintf("unknown(0x%x)", opcode)
	}
}
