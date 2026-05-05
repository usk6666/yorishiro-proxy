package transport

import (
	"sync"
	"time"
)

// RoundTripTiming holds per-phase timing data captured during a round trip.
// The fields are protected by a mutex because httptrace callbacks may fire
// on a different goroutine than the one calling ComputeTiming — especially
// for HTTP/2 where WroteRequest can be called after RoundTrip returns.
type RoundTripTiming struct {
	mu           sync.Mutex
	wroteRequest time.Time
	gotFirstByte time.Time
}

// SetWroteRequest records the time when the request was fully written.
// Safe for concurrent use.
func (t *RoundTripTiming) SetWroteRequest(ts time.Time) {
	t.mu.Lock()
	t.wroteRequest = ts
	t.mu.Unlock()
}

// SetGotFirstByte records the time when the first response byte was received.
// Safe for concurrent use.
func (t *RoundTripTiming) SetGotFirstByte(ts time.Time) {
	t.mu.Lock()
	t.gotFirstByte = ts
	t.mu.Unlock()
}

// snapshot returns a copy of the timing fields under the lock.
func (t *RoundTripTiming) snapshot() (wroteRequest, gotFirstByte time.Time) {
	t.mu.Lock()
	wroteRequest = t.wroteRequest
	gotFirstByte = t.gotFirstByte
	t.mu.Unlock()
	return
}

// ComputeTiming calculates send/wait/receive timing in milliseconds from
// httptrace timestamps. Returns nil pointers for any phase that cannot be
// computed (e.g., if the trace callback was not called). Negative durations
// (e.g., from clock skew) are clamped to zero.
func ComputeTiming(sendStart time.Time, timing *RoundTripTiming, receiveEnd time.Time) (sendMs, waitMs, receiveMs *int64) {
	if timing == nil {
		return nil, nil, nil
	}
	wroteRequest, gotFirstByte := timing.snapshot()
	if !wroteRequest.IsZero() {
		v := wroteRequest.Sub(sendStart).Milliseconds()
		if v < 0 {
			v = 0
		}
		sendMs = &v
	}
	if !wroteRequest.IsZero() && !gotFirstByte.IsZero() {
		v := gotFirstByte.Sub(wroteRequest).Milliseconds()
		if v < 0 {
			v = 0
		}
		waitMs = &v
	}
	if !gotFirstByte.IsZero() {
		v := receiveEnd.Sub(gotFirstByte).Milliseconds()
		if v < 0 {
			v = 0
		}
		receiveMs = &v
	}
	return sendMs, waitMs, receiveMs
}
