package protobuf

import (
	"encoding/binary"
	"fmt"
)

// Frame represents a single gRPC frame with a 5-byte header:
// [compressed:1 byte][length:4 bytes big-endian][payload]
type Frame struct {
	// Compressed indicates whether the payload is compressed.
	// 0 = uncompressed, 1 = compressed.
	Compressed byte
	// Payload is the raw protobuf message bytes (after decompression if applicable).
	Payload []byte
}

// ParseFrames splits gRPC wire data into individual frames.
// Each frame has a 5-byte header: [compressed:1][length:4][payload:length].
func ParseFrames(data []byte) ([]Frame, error) {
	var frames []Frame
	offset := 0

	for offset < len(data) {
		if len(data)-offset < 5 {
			return nil, fmt.Errorf("grpc frame: incomplete header at offset %d: need 5 bytes, have %d", offset, len(data)-offset)
		}

		compressed := data[offset]
		length := binary.BigEndian.Uint32(data[offset+1 : offset+5])
		offset += 5

		if uint32(len(data)-offset) < length {
			return nil, fmt.Errorf("grpc frame: payload truncated at offset %d: need %d bytes, have %d", offset, length, len(data)-offset)
		}

		payload := make([]byte, length)
		copy(payload, data[offset:offset+int(length)])
		offset += int(length)

		frames = append(frames, Frame{
			Compressed: compressed,
			Payload:    payload,
		})
	}

	return frames, nil
}

// ParseFrame parses a single gRPC frame from data.
// Returns the frame and the number of bytes consumed.
func ParseFrame(data []byte) (Frame, int, error) {
	if len(data) < 5 {
		return Frame{}, 0, fmt.Errorf("grpc frame: incomplete header: need 5 bytes, have %d", len(data))
	}

	compressed := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	total := 5 + int(length)
	if len(data) < total {
		return Frame{}, 0, fmt.Errorf("grpc frame: payload truncated: need %d bytes, have %d", length, len(data)-5)
	}

	payload := make([]byte, length)
	copy(payload, data[5:total])

	return Frame{
		Compressed: compressed,
		Payload:    payload,
	}, total, nil
}

// BuildFrame serializes a single gRPC frame to wire format.
func BuildFrame(f Frame) []byte {
	buf := make([]byte, 5+len(f.Payload))
	buf[0] = f.Compressed
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(f.Payload)))
	copy(buf[5:], f.Payload)
	return buf
}

// BuildFrames serializes multiple gRPC frames to wire format.
func BuildFrames(frames []Frame) []byte {
	var total int
	for _, f := range frames {
		total += 5 + len(f.Payload)
	}
	buf := make([]byte, 0, total)
	for _, f := range frames {
		buf = append(buf, BuildFrame(f)...)
	}
	return buf
}
