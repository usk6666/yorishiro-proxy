package http2

import (
	"context"
	"fmt"
	"strconv"
)

// rawFramesContextKey is the context key for passing raw frame bytes from
// clientConn.dispatchStream to handleStream.
type rawFramesContextKey struct{}

// contextWithRawFrames stores raw frame bytes in the context.
func contextWithRawFrames(ctx context.Context, frames [][]byte) context.Context {
	return context.WithValue(ctx, rawFramesContextKey{}, frames)
}

// rawFramesFromContext retrieves raw frame bytes from the context.
// Returns nil if no raw frames are stored.
func rawFramesFromContext(ctx context.Context) [][]byte {
	v, _ := ctx.Value(rawFramesContextKey{}).([][]byte)
	return v
}

// joinRawFrames concatenates multiple raw frame byte slices into a single
// contiguous byte slice. This is used to store all HTTP/2 frames for a
// request or response in Message.RawBytes. Each frame's raw bytes are
// appended in order, preserving the wire format.
//
// Returns nil if frames is nil or empty.
func joinRawFrames(frames [][]byte) []byte {
	if len(frames) == 0 {
		return nil
	}

	totalLen := 0
	for _, f := range frames {
		totalLen += len(f)
	}
	if totalLen == 0 {
		return nil
	}

	result := make([]byte, 0, totalLen)
	for _, f := range frames {
		result = append(result, f...)
	}
	return result
}

// buildFrameMetadata creates metadata entries describing the raw frame
// composition of an HTTP/2 message. This metadata enables downstream tools
// to understand the frame-level structure without parsing RawBytes.
//
// The returned map contains:
//   - "h2_frame_count": number of frames
//   - "h2_total_wire_bytes": total bytes across all frames
//
// If existing is non-nil, the frame metadata is merged into it (existing
// keys take precedence). Otherwise a new map is returned.
//
// Returns nil if frames is nil or empty.
func buildFrameMetadata(frames [][]byte, existing map[string]string) map[string]string {
	if len(frames) == 0 {
		return existing
	}

	totalBytes := 0
	for _, f := range frames {
		totalBytes += len(f)
	}

	if existing == nil {
		existing = make(map[string]string, 2)
	}
	// Only set if not already present (existing keys take precedence).
	if _, ok := existing["h2_frame_count"]; !ok {
		existing["h2_frame_count"] = strconv.Itoa(len(frames))
	}
	if _, ok := existing["h2_total_wire_bytes"]; !ok {
		existing["h2_total_wire_bytes"] = fmt.Sprintf("%d", totalBytes)
	}
	return existing
}
