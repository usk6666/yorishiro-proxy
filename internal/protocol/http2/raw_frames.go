package http2

import (
	"context"
	"strconv"
)

// maxRawCaptureSize limits the size of raw frame bytes captured per message.
// This prevents excessive memory use for very large HTTP/2 streams and is
// consistent with the HTTP/1.x limit in internal/protocol/http/handler.go.
const maxRawCaptureSize = 2 << 20 // 2MB

// rawFramesContextKey is the context key for passing raw frame bytes from
// clientConn.dispatchStream to handleStream.
type rawFramesContextKey struct{}

// endStreamChContextKey is the context key for passing the END_STREAM signal
// channel from clientConn.dispatchStreamWithBody to handlers.
type endStreamChContextKey struct{}

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

// contextWithEndStreamCh stores the END_STREAM signal channel in the context.
func contextWithEndStreamCh(ctx context.Context, ch chan struct{}) context.Context {
	return context.WithValue(ctx, endStreamChContextKey{}, ch)
}

// endStreamChFromContext retrieves the END_STREAM signal channel from the context.
// Returns nil if no channel is stored (e.g. HEADERS had END_STREAM set).
func endStreamChFromContext(ctx context.Context) <-chan struct{} {
	v, _ := ctx.Value(endStreamChContextKey{}).(<-chan struct{})
	if v != nil {
		return v
	}
	// Also try the writable channel type, since we store chan struct{}.
	w, _ := ctx.Value(endStreamChContextKey{}).(chan struct{})
	return w
}

// joinRawFrames concatenates multiple raw frame byte slices into a single
// contiguous byte slice. This is used to store all HTTP/2 frames for a
// request or response in Message.RawBytes. Each frame's raw bytes are
// appended in order, preserving the wire format.
//
// The total size is capped at maxRawCaptureSize (2 MB). If the combined
// frames exceed this limit, the result is truncated and a trailing
// truncation indicator is not appended (callers should check
// buildFrameMetadata for "h2_truncated" = "true").
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

	capSize := totalLen
	if capSize > maxRawCaptureSize {
		capSize = maxRawCaptureSize
	}

	result := make([]byte, 0, capSize)
	for _, f := range frames {
		if len(result)+len(f) > maxRawCaptureSize {
			remaining := maxRawCaptureSize - len(result)
			if remaining > 0 {
				result = append(result, f[:remaining]...)
			}
			break
		}
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
//   - "h2_truncated": "true" if total wire bytes exceed maxRawCaptureSize
//
// If existing is non-nil, the frame metadata is merged into it (existing
// keys take precedence). Otherwise a new map is returned.
//
// Returns existing unchanged if frames is nil or empty. When both frames
// and existing are nil, returns nil.
func buildFrameMetadata(frames [][]byte, existing map[string]string) map[string]string {
	if len(frames) == 0 {
		return existing
	}

	totalBytes := 0
	for _, f := range frames {
		totalBytes += len(f)
	}

	if existing == nil {
		existing = make(map[string]string, 3)
	}
	// Only set if not already present (existing keys take precedence).
	if _, ok := existing["h2_frame_count"]; !ok {
		existing["h2_frame_count"] = strconv.Itoa(len(frames))
	}
	if _, ok := existing["h2_total_wire_bytes"]; !ok {
		existing["h2_total_wire_bytes"] = strconv.Itoa(totalBytes)
	}
	if totalBytes > maxRawCaptureSize {
		if _, ok := existing["h2_truncated"]; !ok {
			existing["h2_truncated"] = "true"
		}
	}
	return existing
}
