package proxybuild

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"syscall"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// h1MetricsStub is a layer.Channel test double that returns a caller-
// configured error from Send and io.EOF from Next. Used by the metrics
// unit tests so each emit point can be exercised in isolation without
// staging a real TLS handshake.
type h1MetricsStub struct {
	mu      sync.Mutex
	sendErr error
	closed  chan struct{}
	once    sync.Once
}

func (s *h1MetricsStub) StreamID() string { return "stub" }
func (s *h1MetricsStub) Next(_ context.Context) (*envelope.Envelope, error) {
	return nil, io.EOF
}
func (s *h1MetricsStub) Send(_ context.Context, _ *envelope.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendErr
}
func (s *h1MetricsStub) Close() error {
	s.once.Do(func() {
		s.closed = make(chan struct{})
		close(s.closed)
	})
	return nil
}
func (s *h1MetricsStub) Closed() <-chan struct{} {
	s.once.Do(func() {
		s.closed = make(chan struct{})
	})
	return s.closed
}
func (s *h1MetricsStub) Err() error { return io.EOF }

func newSendEnv() *envelope.Envelope {
	return &envelope.Envelope{
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/", Authority: "example.com"},
	}
}

// TestH1Metrics_NewIsZero asserts a fresh counter set returns the
// zero snapshot.
func TestH1Metrics_NewIsZero(t *testing.T) {
	t.Parallel()
	m := NewH1UpstreamMetrics()
	snap := m.Snapshot()
	if snap != (H1UpstreamMetricsSnapshot{}) {
		t.Errorf("NewH1UpstreamMetrics: snapshot = %+v, want zero", snap)
	}
}

// TestH1Metrics_NilSafe asserts every emit method short-circuits on
// a nil receiver. Production callers do not check for nil — the
// emit-site doc-comment promises nil-safety.
func TestH1Metrics_NilSafe(t *testing.T) {
	t.Parallel()
	var m *H1UpstreamMetrics // nil pointer
	// All emit methods must not panic on nil. Snapshot returns the
	// zero value.
	m.incStaleDetectedHealthcheck()
	m.incWriteEpipe()
	m.incRedialHealthcheck()
	m.incRedialWriteEpipe()
	m.incRedialFailedHealthcheck()
	m.incRedialFailedWriteEpipe()
	m.incReplaySuccess()
	m.incReplayFailNonidempotent()
	m.incReplayFailBodyConsumed()
	m.incReplayFailRedial()
	m.incReplayFailRedialReplay()
	m.observeChainGeneration(5)
	m.releaseChainGeneration(5)
	snap := m.Snapshot()
	if snap != (H1UpstreamMetricsSnapshot{}) {
		t.Errorf("nil-receiver Snapshot: %+v, want zero", snap)
	}
}

// TestH1Metrics_DirectIncrements asserts each emit helper increments
// the corresponding atomic.Int64 exactly once. This pins the
// 1:1-emit-to-counter mapping the design review schema documents.
func TestH1Metrics_DirectIncrements(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		emit func(*H1UpstreamMetrics)
		want func(H1UpstreamMetricsSnapshot) int64
	}{
		{
			name: "stale_detected_healthcheck",
			emit: (*H1UpstreamMetrics).incStaleDetectedHealthcheck,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.StaleDetectedHealthcheck },
		},
		{
			name: "write_epipe",
			emit: (*H1UpstreamMetrics).incWriteEpipe,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.WriteEpipe },
		},
		{
			name: "redial_healthcheck",
			emit: (*H1UpstreamMetrics).incRedialHealthcheck,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.RedialHealthcheck },
		},
		{
			name: "redial_write_epipe",
			emit: (*H1UpstreamMetrics).incRedialWriteEpipe,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.RedialWriteEpipe },
		},
		{
			name: "redial_failed_healthcheck",
			emit: (*H1UpstreamMetrics).incRedialFailedHealthcheck,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.RedialFailedHealthcheck },
		},
		{
			name: "redial_failed_write_epipe",
			emit: (*H1UpstreamMetrics).incRedialFailedWriteEpipe,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.RedialFailedWriteEpipe },
		},
		{
			name: "replay_success",
			emit: (*H1UpstreamMetrics).incReplaySuccess,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.ReplaySuccess },
		},
		{
			name: "replay_fail_nonidempotent",
			emit: (*H1UpstreamMetrics).incReplayFailNonidempotent,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.ReplayFailNonidempotent },
		},
		{
			name: "replay_fail_body_consumed",
			emit: (*H1UpstreamMetrics).incReplayFailBodyConsumed,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.ReplayFailBodyConsumed },
		},
		{
			name: "replay_fail_redial",
			emit: (*H1UpstreamMetrics).incReplayFailRedial,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.ReplayFailRedial },
		},
		{
			name: "replay_fail_redial_replay",
			emit: (*H1UpstreamMetrics).incReplayFailRedialReplay,
			want: func(s H1UpstreamMetricsSnapshot) int64 { return s.ReplayFailRedialReplay },
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewH1UpstreamMetrics()
			tc.emit(m)
			tc.emit(m)
			snap := m.Snapshot()
			if got := tc.want(snap); got != 2 {
				t.Errorf("%s after 2 increments = %d, want 2", tc.name, got)
			}
		})
	}
}

// TestH1Metrics_ChainGeneration asserts the gauge family: observe
// increments Live and updates Max; release decrements Live but does
// not touch Max. Max records the high-water mark across the lifetime.
func TestH1Metrics_ChainGeneration(t *testing.T) {
	t.Parallel()
	m := NewH1UpstreamMetrics()

	// First chain redials twice -> generations 1, 2.
	m.observeChainGeneration(1)
	m.observeChainGeneration(2)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 2 || snap.ChainGenerationMax != 2 {
		t.Errorf("after 2 observes (1,2): live=%d max=%d, want live=2 max=2",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// Second chain redials thrice -> generations 1, 2, 3.
	m.observeChainGeneration(1)
	m.observeChainGeneration(2)
	m.observeChainGeneration(3)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 5 || snap.ChainGenerationMax != 3 {
		t.Errorf("after second chain (1,2,3): live=%d max=%d, want live=5 max=3",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// First chain closes (released gen=2). Live drops by 2; max
	// stays at 3.
	m.releaseChainGeneration(2)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 3 || snap.ChainGenerationMax != 3 {
		t.Errorf("after release(2): live=%d max=%d, want live=3 max=3",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// Second chain closes (released gen=3). Live -> 0, max stays.
	m.releaseChainGeneration(3)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 0 || snap.ChainGenerationMax != 3 {
		t.Errorf("after release(3): live=%d max=%d, want live=0 max=3",
			snap.ChainGenerationLive, snap.ChainGenerationMax)
	}

	// release(0) is a no-op.
	m.releaseChainGeneration(0)
	if snap := m.Snapshot(); snap.ChainGenerationLive != 0 {
		t.Errorf("release(0): live=%d, want 0", snap.ChainGenerationLive)
	}
}

// TestH1Retry_Metrics_WriteEpipe_NonReplaySafe_Header asserts the
// retry wrapper increments writeEpipe + replayFailNonidempotent when
// the inner returns a header-stage non-replay-safe stale error
// (typically POST). The wrapper must NOT call chain.Redial.
func TestH1Retry_Metrics_WriteEpipe_NonReplaySafe_Header(t *testing.T) {
	t.Parallel()
	m := NewH1UpstreamMetrics()
	chain := &h1Chain{metrics: m} // dummy chain — Redial must not fire
	stale := &http1.StaleUpstreamError{
		Underlying: syscall.EPIPE,
		ReplaySafe: false,
		Stage:      "header",
	}
	stub := &h1MetricsStub{sendErr: stale}
	wrapper := newRetryingUpstreamChannel(stub, chain, func(c layer.Channel) layer.Channel { return c },
		discardLogger(), "127.0.0.1:0", m)

	err := wrapper.Send(context.Background(), newSendEnv())
	if err == nil {
		t.Fatal("Send: got nil, want StaleUpstreamError surfaced")
	}
	snap := m.Snapshot()
	if snap.WriteEpipe != 1 {
		t.Errorf("write_epipe = %d, want 1", snap.WriteEpipe)
	}
	if snap.ReplayFailNonidempotent != 1 {
		t.Errorf("replay_fail_nonidempotent = %d, want 1", snap.ReplayFailNonidempotent)
	}
	// No redial was attempted -> no redial counters fired.
	if snap.RedialHealthcheck != 0 || snap.RedialWriteEpipe != 0 ||
		snap.RedialFailedHealthcheck != 0 || snap.RedialFailedWriteEpipe != 0 {
		t.Errorf("non-replay-safe path should not increment redial counters; got snap=%+v", snap)
	}
	if snap.ReplaySuccess != 0 {
		t.Errorf("replay_success = %d, want 0", snap.ReplaySuccess)
	}
}

// TestH1Retry_Metrics_WriteEpipe_NonReplaySafe_Body asserts the
// body-stage non-replay-safe path increments replayFailBodyConsumed
// (a body already streamed cannot be replayed).
func TestH1Retry_Metrics_WriteEpipe_NonReplaySafe_Body(t *testing.T) {
	t.Parallel()
	m := NewH1UpstreamMetrics()
	chain := &h1Chain{metrics: m}
	stale := &http1.StaleUpstreamError{
		Underlying: syscall.EPIPE,
		ReplaySafe: false,
		Stage:      "body",
	}
	stub := &h1MetricsStub{sendErr: stale}
	wrapper := newRetryingUpstreamChannel(stub, chain, func(c layer.Channel) layer.Channel { return c },
		discardLogger(), "127.0.0.1:0", m)

	err := wrapper.Send(context.Background(), newSendEnv())
	if err == nil {
		t.Fatal("Send: got nil, want StaleUpstreamError surfaced")
	}
	snap := m.Snapshot()
	if snap.WriteEpipe != 1 {
		t.Errorf("write_epipe = %d, want 1", snap.WriteEpipe)
	}
	if snap.ReplayFailBodyConsumed != 1 {
		t.Errorf("replay_fail_body_consumed = %d, want 1", snap.ReplayFailBodyConsumed)
	}
	if snap.ReplayFailNonidempotent != 0 {
		t.Errorf("replay_fail_nonidempotent = %d, want 0 (Stage=body should NOT count as header)",
			snap.ReplayFailNonidempotent)
	}
}

// TestH1Retry_Metrics_NonStaleError_NoCount asserts that a non-stale
// error from the inner does NOT increment any retry counter. The
// wrapper surfaces the error verbatim; no replay decision is made.
func TestH1Retry_Metrics_NonStaleError_NoCount(t *testing.T) {
	t.Parallel()
	m := NewH1UpstreamMetrics()
	chain := &h1Chain{metrics: m}
	stub := &h1MetricsStub{sendErr: errors.New("synthetic-non-stale")}
	wrapper := newRetryingUpstreamChannel(stub, chain, func(c layer.Channel) layer.Channel { return c },
		discardLogger(), "127.0.0.1:0", m)

	err := wrapper.Send(context.Background(), newSendEnv())
	if err == nil {
		t.Fatal("Send: got nil, want synthetic error")
	}
	snap := m.Snapshot()
	if snap != (H1UpstreamMetricsSnapshot{}) {
		t.Errorf("non-stale error should not increment any counter; got snap=%+v", snap)
	}
}

// TestH1Retry_Metrics_BudgetExhausted asserts a SECOND retry attempt
// (after the first replay consumed the one-shot budget) does NOT
// increment write_epipe or any redial counter. The first attempt
// already fired all the counters; the second is surfaced verbatim.
//
// We force the budget consumed by pre-setting wrapper.retried, then
// drive a fresh ReplaySafe=true stale error and assert the wrapper
// returns it verbatim without further counter activity.
func TestH1Retry_Metrics_BudgetExhausted(t *testing.T) {
	t.Parallel()
	m := NewH1UpstreamMetrics()
	chain := &h1Chain{metrics: m}
	stale := &http1.StaleUpstreamError{
		Underlying: syscall.EPIPE,
		ReplaySafe: true,
		Stage:      "header",
	}
	stub := &h1MetricsStub{sendErr: stale}
	wrapper := newRetryingUpstreamChannel(stub, chain, func(c layer.Channel) layer.Channel { return c },
		discardLogger(), "127.0.0.1:0", m)
	// Consume the budget.
	wrapper.retried.Store(true)

	err := wrapper.Send(context.Background(), newSendEnv())
	if err == nil {
		t.Fatal("Send: got nil, want stale verbatim after budget exhaustion")
	}
	snap := m.Snapshot()
	// write_epipe still fires (it counts every observed stale, not
	// every "retry attempted"). But redial/replay-success counters
	// stay zero — the budget gate short-circuited before any redial
	// or replay attempt.
	if snap.WriteEpipe != 1 {
		t.Errorf("write_epipe = %d, want 1 (every stale is observed)", snap.WriteEpipe)
	}
	if snap.RedialWriteEpipe != 0 {
		t.Errorf("redial_write_epipe = %d, want 0 (budget consumed before Redial)",
			snap.RedialWriteEpipe)
	}
	if snap.ReplaySuccess != 0 || snap.ReplayFailRedial != 0 || snap.ReplayFailRedialReplay != 0 {
		t.Errorf("replay counters fired after budget exhaustion: %+v", snap)
	}
}

// TestH1Chain_Metrics_HealthcheckPass asserts the happy-path
// EnsureFresh (HealthCheck nil) increments NO counters.
func TestH1Chain_Metrics_HealthcheckPass(t *testing.T) {
	t.Parallel()
	_, server := testTCPPair(t)
	defer server.Close()

	initial := http1.New(server, "stream-pass", envelope.Receive)
	defer initial.Close()

	m := NewH1UpstreamMetrics()
	chain := newH1Chain(initial, "example.com:443", nil, discardLogger(), m)
	defer chain.closeAll()

	got, err := chain.EnsureFresh(context.Background())
	if err != nil {
		t.Fatalf("EnsureFresh: %v", err)
	}
	if got != initial {
		t.Errorf("EnsureFresh returned a new Layer on alive conn")
	}
	if snap := m.Snapshot(); snap != (H1UpstreamMetricsSnapshot{}) {
		t.Errorf("alive-conn EnsureFresh should not increment counters; snap=%+v", snap)
	}
}

// TestH1Chain_Metrics_EnsureFreshDialFail asserts that when the
// current Layer is stale AND the dial cannot succeed (nil cfg +
// invalid target), the stale_detected and redial_failed counters
// both fire. The stale Layer is NOT closed in this branch — the
// next EnsureFresh retries cleanly.
func TestH1Chain_Metrics_EnsureFreshDialFail(t *testing.T) {
	t.Parallel()
	client, server := testTCPPair(t)

	initial := http1.New(server, "stream-fail", envelope.Receive)
	defer initial.Close()

	// Close peer so HealthCheck observes stale.
	_ = client.Close()

	m := NewH1UpstreamMetrics()
	chain := newH1Chain(initial, "127.0.0.1:1", nil, discardLogger(), m) // nil cfg trips defensive guard
	defer chain.closeAll()

	// Poll until HealthCheck flips to stale.
	var err error
	for i := 0; i < 200; i++ {
		_, err = chain.EnsureFresh(context.Background())
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("EnsureFresh on stale + nil-cfg: never observed dial failure")
	}
	snap := m.Snapshot()
	if snap.StaleDetectedHealthcheck < 1 {
		t.Errorf("stale_detected_healthcheck = %d, want >= 1", snap.StaleDetectedHealthcheck)
	}
	if snap.RedialFailedHealthcheck < 1 {
		t.Errorf("redial_failed_healthcheck = %d, want >= 1", snap.RedialFailedHealthcheck)
	}
	// Successful redial did NOT fire.
	if snap.RedialHealthcheck != 0 {
		t.Errorf("redial_healthcheck = %d, want 0 on dial-failure path", snap.RedialHealthcheck)
	}
}

// TestH1Chain_Metrics_CloseAllReleasesGauge asserts closeAll
// decrements chainGenerationLive by this chain's contribution but
// leaves chainGenerationMax intact. Multi-chain scoping is exercised
// by manually injecting a second chain's contribution into the same
// metrics struct.
func TestH1Chain_Metrics_CloseAllReleasesGauge(t *testing.T) {
	t.Parallel()
	_, server := testTCPPair(t)

	initial := http1.New(server, "stream-close-gauge", envelope.Receive)
	// Don't defer initial.Close() — chain.closeAll handles it.

	m := NewH1UpstreamMetrics()
	chain := newH1Chain(initial, "example.com:443", nil, discardLogger(), m)

	// Simulate 2 successful redials by directly bumping the gauge
	// under c.mu (avoids needing a working dial).
	chain.mu.Lock()
	chain.liveGen = 2
	chain.mu.Unlock()
	m.observeChainGeneration(1)
	m.observeChainGeneration(2)
	// Add a second chain's contribution to verify isolation.
	m.observeChainGeneration(1)

	beforeMax := m.Snapshot().ChainGenerationMax
	beforeLive := m.Snapshot().ChainGenerationLive
	if beforeLive != 3 || beforeMax != 2 {
		t.Fatalf("setup: live=%d max=%d, want live=3 max=2", beforeLive, beforeMax)
	}

	chain.closeAll()

	snap := m.Snapshot()
	if snap.ChainGenerationLive != 1 {
		t.Errorf("closeAll: live=%d, want 1 (second chain's contribution remains)",
			snap.ChainGenerationLive)
	}
	if snap.ChainGenerationMax != 2 {
		t.Errorf("closeAll: max=%d, want 2 (Max never decreases)", snap.ChainGenerationMax)
	}
}

// discardLogger returns a slog.Logger that drops every record so unit
// tests don't spew metrics-emit logs into the test output. The same
// pattern is used by other proxybuild unit tests that exercise
// Debug/Warn paths.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
