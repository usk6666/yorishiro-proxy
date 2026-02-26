package fuzzer

import (
	"sort"
	"sync"
)

// StopCondition holds the configuration for automatic job stopping.
type StopCondition struct {
	// StatusCodes stops the job when any of these HTTP status codes is received.
	StatusCodes []int `json:"status_codes,omitempty"`
	// ErrorCount stops the job when the cumulative error count reaches this value.
	ErrorCount int `json:"error_count,omitempty"`
	// LatencyThresholdMs is the absolute latency threshold in milliseconds.
	// If the sliding window median exceeds this value, the job is stopped.
	LatencyThresholdMs int `json:"latency_threshold_ms,omitempty"`
	// LatencyBaselineMultiplier is the multiplier applied to the baseline median.
	// If the current median exceeds baseline * multiplier, the job is stopped.
	LatencyBaselineMultiplier float64 `json:"latency_baseline_multiplier,omitempty"`
	// LatencyWindow is the number of recent requests used for the sliding window.
	// Defaults to 10 if either latency parameter is set.
	LatencyWindow int `json:"latency_window,omitempty"`
}

// OverloadMonitor tracks response latencies and detects overload conditions
// using a sliding window median approach with absolute threshold and baseline
// multiplier detection, combined with OR logic.
type OverloadMonitor struct {
	mu sync.Mutex

	// Configuration.
	thresholdMs        int
	baselineMultiplier float64
	windowSize         int

	// Ring buffer for latency samples (milliseconds).
	samples []int
	count   int // total number of samples recorded (may exceed windowSize)
	writeAt int // next write position in ring buffer

	// Baseline median (computed from the first windowSize samples).
	baselineMedian float64
	baselineReady  bool
}

// NewOverloadMonitor creates a new OverloadMonitor with the given configuration.
// Returns nil if both latency detection methods are disabled (thresholdMs <= 0
// and baselineMultiplier <= 0).
func NewOverloadMonitor(thresholdMs int, baselineMultiplier float64, windowSize int) *OverloadMonitor {
	if thresholdMs <= 0 && baselineMultiplier <= 0 {
		return nil
	}
	if windowSize <= 0 {
		windowSize = 10
	}
	return &OverloadMonitor{
		thresholdMs:        thresholdMs,
		baselineMultiplier: baselineMultiplier,
		windowSize:         windowSize,
		samples:            make([]int, windowSize),
	}
}

// Record adds a latency sample (in milliseconds) and returns true if an
// overload condition is detected. The caller should stop the job if true.
func (m *OverloadMonitor) Record(latencyMs int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Write into ring buffer.
	m.samples[m.writeAt] = latencyMs
	m.writeAt = (m.writeAt + 1) % m.windowSize
	m.count++

	// Not enough samples to compute median yet.
	if m.count < m.windowSize {
		return false
	}

	// Compute the baseline on the first full window.
	if !m.baselineReady {
		m.baselineMedian = m.computeMedian()
		m.baselineReady = true
		// Don't trigger on the baseline window itself.
		return false
	}

	currentMedian := m.computeMedian()

	// Absolute threshold check.
	if m.thresholdMs > 0 && currentMedian > float64(m.thresholdMs) {
		return true
	}

	// Baseline multiplier check.
	if m.baselineMultiplier > 0 && m.baselineMedian > 0 && currentMedian > m.baselineMedian*m.baselineMultiplier {
		return true
	}

	return false
}

// computeMedian returns the median of the current ring buffer contents.
// Must be called with mu held. Assumes the buffer is full (count >= windowSize).
func (m *OverloadMonitor) computeMedian() float64 {
	sorted := make([]int, m.windowSize)
	copy(sorted, m.samples)
	sort.Ints(sorted)

	n := m.windowSize
	if n%2 == 0 {
		return float64(sorted[n/2-1]+sorted[n/2]) / 2.0
	}
	return float64(sorted[n/2])
}

// checkStatusCode returns true if the given status code is in the stop list.
func checkStatusCode(statusCode int, stopCodes []int) bool {
	for _, c := range stopCodes {
		if statusCode == c {
			return true
		}
	}
	return false
}
