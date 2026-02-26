package fuzzer

import (
	"testing"
)

func TestNewOverloadMonitor_Disabled(t *testing.T) {
	tests := []struct {
		name       string
		threshold  int
		multiplier float64
	}{
		{"both zero", 0, 0},
		{"both negative", -1, -1},
		{"threshold negative, multiplier zero", -1, 0},
		{"threshold zero, multiplier negative", 0, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewOverloadMonitor(tt.threshold, tt.multiplier, 10)
			if m != nil {
				t.Error("expected nil monitor when both detection methods are disabled")
			}
		})
	}
}

func TestNewOverloadMonitor_DefaultWindow(t *testing.T) {
	m := NewOverloadMonitor(1000, 0, 0)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}
	if m.windowSize != 10 {
		t.Errorf("windowSize = %d, want 10 (default)", m.windowSize)
	}
}

func TestOverloadMonitor_AbsoluteThreshold(t *testing.T) {
	m := NewOverloadMonitor(100, 0, 3)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}

	// Fill baseline window (3 samples): median = 50
	for _, v := range []int{40, 50, 60} {
		if m.Record(v) {
			t.Error("should not trigger during baseline window")
		}
	}

	// Next window — not yet exceeding threshold.
	// median of {70, 80, 90} = 80 < 100
	for _, v := range []int{70, 80, 90} {
		if m.Record(v) {
			t.Errorf("should not trigger with median 80 < threshold 100, value=%d", v)
		}
	}

	// Now exceed threshold.
	// After recording 110, 120, 130 the window is {110, 120, 130}, median = 120 > 100
	for _, v := range []int{110, 120} {
		m.Record(v)
	}
	if !m.Record(130) {
		t.Error("should trigger when median 120 > threshold 100")
	}
}

func TestOverloadMonitor_BaselineMultiplier(t *testing.T) {
	m := NewOverloadMonitor(0, 2.0, 3)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}

	// Fill baseline: {100, 100, 100}, median = 100
	for i := 0; i < 3; i++ {
		if m.Record(100) {
			t.Error("should not trigger during baseline")
		}
	}

	// Window with median = 150 < 100*2.0 = 200: no trigger
	for _, v := range []int{140, 150, 160} {
		if m.Record(v) {
			t.Error("should not trigger with median 150 < 200")
		}
	}

	// Window with median = 210 > 200: trigger
	for _, v := range []int{200, 210} {
		m.Record(v)
	}
	if !m.Record(220) {
		t.Error("should trigger with median 210 > baseline*2.0 = 200")
	}
}

func TestOverloadMonitor_CombinedOR(t *testing.T) {
	// Both methods enabled: threshold=500, multiplier=3.0, window=3
	m := NewOverloadMonitor(500, 3.0, 3)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}

	// Baseline: {100, 100, 100}, median = 100
	for i := 0; i < 3; i++ {
		m.Record(100)
	}

	// Trigger via multiplier (median 310 > 100*3.0=300) but NOT threshold (310 < 500)
	for _, v := range []int{300, 310} {
		m.Record(v)
	}
	if !m.Record(320) {
		t.Error("should trigger via baseline multiplier: 310 > 300")
	}
}

func TestOverloadMonitor_NoTriggerWithinLimits(t *testing.T) {
	m := NewOverloadMonitor(1000, 5.0, 5)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}

	// Baseline: 5 samples of 100
	for i := 0; i < 5; i++ {
		if m.Record(100) {
			t.Error("should not trigger during baseline")
		}
	}

	// Stay within limits: median ~ 200, threshold=1000, baseline*5=500
	for i := 0; i < 20; i++ {
		if m.Record(200) {
			t.Error("should not trigger with median 200 < min(1000, 500)")
		}
	}
}

func TestOverloadMonitor_InsufficientSamples(t *testing.T) {
	m := NewOverloadMonitor(50, 0, 10)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}

	// Should not trigger until we have enough samples for baseline + at least one window
	for i := 0; i < 9; i++ {
		if m.Record(1000) { // Even huge values
			t.Error("should not trigger before baseline window is filled")
		}
	}
}

func TestOverloadMonitor_EvenWindowSize(t *testing.T) {
	// Even window size: median is average of two middle elements
	m := NewOverloadMonitor(150, 0, 4)
	if m == nil {
		t.Fatal("expected non-nil monitor")
	}

	// Baseline: {100, 200, 300, 400} sorted = {100, 200, 300, 400}, median = (200+300)/2 = 250
	for _, v := range []int{100, 200, 300, 400} {
		if m.Record(v) {
			t.Error("should not trigger during baseline")
		}
	}

	// Next window should check against threshold 150
	// {160, 160, 160, 160} sorted, median = 160 > 150
	for _, v := range []int{160, 160, 160} {
		m.Record(v)
	}
	if !m.Record(160) {
		t.Error("should trigger with median 160 > threshold 150")
	}
}

func TestCheckStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		stopCodes  []int
		want       bool
	}{
		{"match", 503, []int{500, 502, 503}, true},
		{"no match", 200, []int{500, 502, 503}, false},
		{"empty stop list", 503, nil, false},
		{"zero status", 0, []int{503}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkStatusCode(tt.statusCode, tt.stopCodes)
			if got != tt.want {
				t.Errorf("checkStatusCode(%d, %v) = %v, want %v", tt.statusCode, tt.stopCodes, got, tt.want)
			}
		})
	}
}
