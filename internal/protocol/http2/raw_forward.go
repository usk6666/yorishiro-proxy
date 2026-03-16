package http2

import (
	"encoding/binary"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
)

// rewriteRawFrameStreamIDs rewrites the stream ID in all HTTP/2 frames within
// rawBytes to the given newStreamID. It returns a copy of the raw bytes with
// stream IDs rewritten, whether any frame contains END_STREAM, and any error.
//
// This is used for raw mode forwarding where intercepted frames from the client
// need to be sent on a newly allocated upstream stream. The frame headers are
// parsed minimally (9-byte header) to locate and rewrite stream ID fields.
//
// Frames with stream ID 0 (connection-level frames like SETTINGS, PING) are
// not rewritten, as they are not stream-specific.
func rewriteRawFrameStreamIDs(rawBytes []byte, newStreamID uint32) ([]byte, bool, error) {
	if len(rawBytes) == 0 {
		return nil, false, nil
	}

	result := make([]byte, len(rawBytes))
	copy(result, rawBytes)

	hasEndStream := false
	offset := 0

	for offset < len(result) {
		if offset+frame.HeaderSize > len(result) {
			return nil, false, fmt.Errorf("truncated frame header at offset %d", offset)
		}

		// Parse the 9-byte frame header.
		payloadLen := uint32(result[offset])<<16 | uint32(result[offset+1])<<8 | uint32(result[offset+2])
		frameType := frame.Type(result[offset+3])
		flags := frame.Flags(result[offset+4])
		streamID := binary.BigEndian.Uint32(result[offset+5:offset+9]) & 0x7FFFFFFF

		totalFrameSize := frame.HeaderSize + int(payloadLen)
		if offset+totalFrameSize > len(result) {
			return nil, false, fmt.Errorf("truncated frame payload at offset %d: need %d bytes, have %d",
				offset, totalFrameSize, len(result)-offset)
		}

		// Rewrite stream ID if it's not a connection-level frame (stream ID != 0).
		if streamID != 0 {
			binary.BigEndian.PutUint32(result[offset+5:offset+9], newStreamID&0x7FFFFFFF)
		}

		// Check for END_STREAM flag on DATA or HEADERS frames.
		if (frameType == frame.TypeData || frameType == frame.TypeHeaders) && flags.Has(frame.FlagEndStream) {
			hasEndStream = true
		}

		offset += totalFrameSize
	}

	return result, hasEndStream, nil
}
