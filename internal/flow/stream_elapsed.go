package flow

import (
	"context"
	"time"
)

// StreamElapsed returns time.Since(Stream.Timestamp) for the Stream
// identified by streamID, or zero on any lookup failure / nil reader /
// nil Stream / zero Timestamp / non-positive elapsed time (clock skew).
//
// The zero return is the documented "only non-zero fields are applied"
// sentinel for StreamUpdate.Duration, so a miss leaves the Stream's
// existing Duration untouched when the result is fed straight into
// UpdateStream. Stream.Timestamp is stamped by the pipeline RecordStep
// when it creates the Stream from the first envelope, so the result is
// the elapsed time from the first recorded envelope to the call.
//
// Shared by the live data path's OnComplete hook (proxybuild) and the
// MCP resend / fuzz Stream finalizer so both record Duration the same way.
func StreamElapsed(ctx context.Context, r StreamReader, streamID string) time.Duration {
	if r == nil {
		return 0
	}
	st, err := r.GetStream(ctx, streamID)
	if err != nil || st == nil || st.Timestamp.IsZero() {
		return 0
	}
	d := time.Since(st.Timestamp)
	if d <= 0 {
		return 0
	}
	return d
}
