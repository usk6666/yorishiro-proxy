package transport

import (
	"testing"
	"time"
)

func TestComputeTiming(t *testing.T) {
	tests := []struct {
		name      string
		sendStart time.Time
		timing    *RoundTripTiming
		recvEnd   time.Time
		wantSend  *int64
		wantWait  *int64
		wantRecv  *int64
	}{
		{
			name:      "nil timing returns all nil",
			sendStart: time.Now(),
			timing:    nil,
			recvEnd:   time.Now(),
			wantSend:  nil,
			wantWait:  nil,
			wantRecv:  nil,
		},
		{
			name:      "all timestamps present",
			sendStart: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			timing: func() *RoundTripTiming {
				t := &RoundTripTiming{}
				t.SetWroteRequest(time.Date(2025, 1, 1, 0, 0, 0, 10*int(time.Millisecond), time.UTC))
				t.SetGotFirstByte(time.Date(2025, 1, 1, 0, 0, 0, 60*int(time.Millisecond), time.UTC))
				return t
			}(),
			recvEnd:  time.Date(2025, 1, 1, 0, 0, 0, 90*int(time.Millisecond), time.UTC),
			wantSend: ptrInt64(10),
			wantWait: ptrInt64(50),
			wantRecv: ptrInt64(30),
		},
		{
			name:      "zero wroteRequest",
			sendStart: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			timing: func() *RoundTripTiming {
				t := &RoundTripTiming{}
				t.SetGotFirstByte(time.Date(2025, 1, 1, 0, 0, 0, 60*int(time.Millisecond), time.UTC))
				return t
			}(),
			recvEnd:  time.Date(2025, 1, 1, 0, 0, 0, 90*int(time.Millisecond), time.UTC),
			wantSend: nil,
			wantWait: nil,
			wantRecv: ptrInt64(30),
		},
		{
			name:      "zero gotFirstByte",
			sendStart: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			timing: func() *RoundTripTiming {
				t := &RoundTripTiming{}
				t.SetWroteRequest(time.Date(2025, 1, 1, 0, 0, 0, 10*int(time.Millisecond), time.UTC))
				return t
			}(),
			recvEnd:  time.Date(2025, 1, 1, 0, 0, 0, 90*int(time.Millisecond), time.UTC),
			wantSend: ptrInt64(10),
			wantWait: nil,
			wantRecv: nil,
		},
		{
			name:      "negative durations clamped to zero",
			sendStart: time.Date(2025, 1, 1, 0, 0, 0, 100*int(time.Millisecond), time.UTC),
			timing: func() *RoundTripTiming {
				t := &RoundTripTiming{}
				t.SetWroteRequest(time.Date(2025, 1, 1, 0, 0, 0, 50*int(time.Millisecond), time.UTC))
				t.SetGotFirstByte(time.Date(2025, 1, 1, 0, 0, 0, 30*int(time.Millisecond), time.UTC))
				return t
			}(),
			recvEnd:  time.Date(2025, 1, 1, 0, 0, 0, 20*int(time.Millisecond), time.UTC),
			wantSend: ptrInt64(0),
			wantWait: ptrInt64(0),
			wantRecv: ptrInt64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSend, gotWait, gotRecv := ComputeTiming(tt.sendStart, tt.timing, tt.recvEnd)
			checkInt64Ptr(t, "sendMs", gotSend, tt.wantSend)
			checkInt64Ptr(t, "waitMs", gotWait, tt.wantWait)
			checkInt64Ptr(t, "receiveMs", gotRecv, tt.wantRecv)
		})
	}
}

func ptrInt64(v int64) *int64 { return &v }

func checkInt64Ptr(t *testing.T, name string, got, want *int64) {
	t.Helper()
	if got == nil && want == nil {
		return
	}
	if got == nil {
		t.Errorf("%s = nil, want %d", name, *want)
		return
	}
	if want == nil {
		t.Errorf("%s = %d, want nil", name, *got)
		return
	}
	if *got != *want {
		t.Errorf("%s = %d, want %d", name, *got, *want)
	}
}
