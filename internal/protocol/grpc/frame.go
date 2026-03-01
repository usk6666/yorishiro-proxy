// Package grpc implements gRPC protocol handling for the yorishiro-proxy.
// It parses gRPC Length-Prefixed Messages over HTTP/2 and records gRPC
// sessions (unary and streaming RPCs) to the session store.
//
// gRPC uses HTTP/2 as its transport and frames messages with a 5-byte header:
//
//	1 byte:  Compressed-Flag (0 = uncompressed, 1 = compressed)
//	4 bytes: Message-Length (big-endian uint32)
//	N bytes: Protocol Buffers payload
//
// See: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
package grpc

import (
	"encoding/binary"
	"fmt"
	"io"
)

// frameHeaderSize is the size of the gRPC Length-Prefixed Message header.
const frameHeaderSize = 5

// maxMessageSize limits the maximum gRPC message payload to prevent memory
// exhaustion from malicious or malformed messages.
const maxMessageSize = 16 << 20 // 16MB

// Frame represents a parsed gRPC Length-Prefixed Message.
type Frame struct {
	// Compressed indicates whether the payload is compressed.
	// When true, the payload should be decompressed according to the
	// grpc-encoding header (e.g., gzip, deflate).
	Compressed bool
	// Payload is the raw Protocol Buffers message bytes.
	// If Compressed is true, this contains the compressed data.
	Payload []byte
}

// ReadFrame reads a single gRPC Length-Prefixed Message from r.
// It returns the parsed frame or an error if the data is malformed
// or the reader fails. Returns io.EOF if the reader is at EOF before
// any bytes are read.
func ReadFrame(r io.Reader) (*Frame, error) {
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read grpc frame header: %w", err)
	}

	compressed := header[0] != 0
	if header[0] > 1 {
		return nil, fmt.Errorf("invalid grpc compressed flag: %d", header[0])
	}

	length := binary.BigEndian.Uint32(header[1:5])
	if length > maxMessageSize {
		return nil, fmt.Errorf("grpc message too large: %d > %d", length, maxMessageSize)
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read grpc payload (%d bytes): %w", length, err)
		}
	}

	return &Frame{
		Compressed: compressed,
		Payload:    payload,
	}, nil
}

// ReadAllFrames reads all gRPC Length-Prefixed Messages from the given data.
// It returns the list of parsed frames. If the data is empty, it returns
// nil with no error. If the data contains a partial frame, an error is returned.
func ReadAllFrames(data []byte) ([]*Frame, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var frames []*Frame
	offset := 0

	for offset < len(data) {
		remaining := len(data) - offset
		if remaining < frameHeaderSize {
			return frames, fmt.Errorf("incomplete grpc frame header: %d bytes remaining", remaining)
		}

		compressed := data[offset] != 0
		if data[offset] > 1 {
			return frames, fmt.Errorf("invalid grpc compressed flag: %d", data[offset])
		}

		length := binary.BigEndian.Uint32(data[offset+1 : offset+5])
		if length > maxMessageSize {
			return frames, fmt.Errorf("grpc message too large: %d > %d", length, maxMessageSize)
		}

		offset += frameHeaderSize

		if uint32(len(data)-offset) < length {
			return frames, fmt.Errorf("incomplete grpc payload: want %d bytes, have %d", length, len(data)-offset)
		}

		payload := make([]byte, length)
		copy(payload, data[offset:offset+int(length)])

		frames = append(frames, &Frame{
			Compressed: compressed,
			Payload:    payload,
		})

		offset += int(length)
	}

	return frames, nil
}

// EncodeFrame encodes a gRPC Length-Prefixed Message into bytes.
// This is primarily used for testing.
func EncodeFrame(compressed bool, payload []byte) []byte {
	buf := make([]byte, frameHeaderSize+len(payload))
	if compressed {
		buf[0] = 1
	}
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload)))
	copy(buf[5:], payload)
	return buf
}
