package httputil

import "time"

// RoundTripTiming holds per-phase timing data captured during a round trip.
type RoundTripTiming struct {
	// WroteRequest is the time when the request was fully written.
	WroteRequest time.Time
	// GotFirstByte is the time when the first response byte was received.
	GotFirstByte time.Time
}

// ComputeTiming calculates send/wait/receive timing in milliseconds from
// httptrace timestamps. Returns nil pointers for any phase that cannot be
// computed (e.g., if the trace callback was not called). Negative durations
// (e.g., from clock skew) are clamped to zero.
func ComputeTiming(sendStart time.Time, timing *RoundTripTiming, receiveEnd time.Time) (sendMs, waitMs, receiveMs *int64) {
	if timing == nil {
		return nil, nil, nil
	}
	if !timing.WroteRequest.IsZero() {
		v := timing.WroteRequest.Sub(sendStart).Milliseconds()
		if v < 0 {
			v = 0
		}
		sendMs = &v
	}
	if !timing.WroteRequest.IsZero() && !timing.GotFirstByte.IsZero() {
		v := timing.GotFirstByte.Sub(timing.WroteRequest).Milliseconds()
		if v < 0 {
			v = 0
		}
		waitMs = &v
	}
	if !timing.GotFirstByte.IsZero() {
		v := receiveEnd.Sub(timing.GotFirstByte).Milliseconds()
		if v < 0 {
			v = 0
		}
		receiveMs = &v
	}
	return sendMs, waitMs, receiveMs
}
