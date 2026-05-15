//go:build e2e

// Package ws_test (file: intercept_hold_timeout_protocol_override_integration_test.go)
// is the USK-855 smoke-tier regression guard. It wires the full HTTP/1 → WS
// upgrade harness with a catch-all intercept rule, configures a short
// per-protocol WS hold timeout below the global, and confirms the
// auto_release fires under the per-protocol budget before the global
// timeout would have done so.
//
// This is the merge-gate evidence that the per-protocol override path is
// wired all the way through HoldQueue.Hold; without it, a regression
// could silently revert WS holds to the 5-minute global default and
// reintroduce the USK-851 Fly.io-edge friction.
package ws_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// TestWSIntercept_HoldTimeout_PerProtocolOverride_AutoRelease asserts
// that a held WS frame is auto-released by the per-protocol override
// timer (1500ms) and NOT the global timer (60s). The held envelope is
// observable in the queue immediately after the frame arrives; the test
// then waits for the queue to drain via the timer (no operator Release).
//
// Acceptance:
//   - queue.Len() == 0 within 3 seconds (override is 1500ms);
//   - holdQueue.ProtocolOverrideResolved(ws).Timeout == 1500ms;
//   - no operator-side Release was called.
func TestWSIntercept_HoldTimeout_PerProtocolOverride_AutoRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientA, clientB := pipePairUSK851(t)
	upstreamA, upstreamB := pipePairUSK851(t)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
		_ = upstreamA.Close()
		_ = upstreamB.Close()
	})

	stack := connector.NewConnectionStack("usk855-conn")
	clientLayer := http1.New(clientB, "client-stream", envelope.Send)
	upstreamLayer := http1.New(upstreamA, "upstream-stream", envelope.Receive)
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)
	t.Cleanup(func() { _ = stack.Close() })

	store := &tagCapturingStore{}

	wsEngine := wsrules.NewInterceptEngine()
	wsEngine.SetRules([]wsrules.InterceptRule{{
		ID:        "usk855-catch-all",
		Enabled:   true,
		Direction: wsrules.DirectionBoth,
	}})
	holdQueue := common.NewHoldQueue()
	// Global 60s — would mask a regression if the override path stopped
	// applying. Per-protocol 1500ms — must fire before the global.
	holdQueue.SetTimeout(60 * time.Second)
	holdQueue.SetProtocolTimeout(envelope.ProtocolWebSocket, 1500*time.Millisecond)
	releaseTracker := common.NewReleaseTracker()

	if got, _ := holdQueue.ProtocolOverrideResolved(envelope.ProtocolWebSocket); got != 1500*time.Millisecond {
		t.Fatalf("ProtocolOverrideResolved(ws).Timeout = %v, want 1500ms (test setup invariant)", got)
	}

	logger := slog.Default()
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(nil, nil, nil, logger),
		pipeline.NewTransformStep(nil, nil, nil, nil),
		pipeline.NewInterceptStep(nil, wsEngine, nil, nil, holdQueue, nil, logger),
		pipeline.NewRecordStep(store, logger),
		session.NewUpgradeStep(),
	}
	p := pipeline.New(steps...)

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		ch, ok := <-upstreamLayer.Channels()
		if !ok || ch == nil {
			return nil, errors.New("upstream Channels closed before yielding")
		}
		return ch, nil
	}

	sessionDone := make(chan struct{})
	var sessionErr error
	var once sync.Once
	opts := session.SessionOptions{
		InterceptReleaseTracker: releaseTracker,
	}

	go func() {
		defer close(sessionDone)
		err := session.RunStackSession(ctx, stack, dial, p, opts)
		once.Do(func() { sessionErr = err })
	}()

	doWSUpgradeHandshakeUSK851(t, ctx, clientA, upstreamB, stack)

	// Client sends a single text frame; the rule holds it.
	writeMaskedTextFrame(t, clientA, []byte("usk855-payload"))

	// Wait for the held entry to appear so we know the timer is armed.
	_ = waitForHeldEntry(t, holdQueue, 3*time.Second)

	// Wait for the queue to drain via the per-protocol timer. The
	// auto_release path removes the entry from the queue before
	// returning the action to the holding goroutine, so observing
	// Len() == 0 within (1500ms + small margin) is the regression
	// signal we want.
	drainDeadline := time.Now().Add(3 * time.Second) // 2x the override budget
	for time.Now().Before(drainDeadline) {
		if holdQueue.Len() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if holdQueue.Len() != 0 {
		t.Fatalf("queue not drained within per-protocol budget: still %d entries; per-protocol override did not fire", holdQueue.Len())
	}

	// Clean up: close pipes so the session loop unwinds. The session
	// completion is not strictly required for the assertion but we
	// still wait so leaked goroutines fail the test under -race.
	_ = clientA.Close()
	_ = upstreamB.Close()
	select {
	case <-sessionDone:
	case <-time.After(5 * time.Second):
		t.Logf("session did not terminate within 5s; err=%v", sessionErr)
	}
}
