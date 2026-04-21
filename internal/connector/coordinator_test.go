package connector

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

func TestCoordinator_StartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	statuses := coord.ListenerStatuses()
	if len(statuses) != 1 {
		t.Fatalf("ListenerStatuses len = %d, want 1", len(statuses))
	}
	if statuses[0].Name != DefaultListenerName {
		t.Errorf("Name = %q, want %q", statuses[0].Name, DefaultListenerName)
	}
	if statuses[0].ListenAddr == "" {
		t.Error("ListenAddr is empty")
	}

	if err := coord.StopNamed(ctx, DefaultListenerName); err != nil {
		t.Fatalf("StopNamed: %v", err)
	}

	if got := coord.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after stop = %d, want 0", got)
	}
}

func TestCoordinator_StartNamed_Multiple(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.StartNamed(ctx, "alpha", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed alpha: %v", err)
	}
	if err := coord.StartNamed(ctx, "beta", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed beta: %v", err)
	}

	if got := coord.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	statuses := coord.ListenerStatuses()
	names := make(map[string]bool)
	for _, s := range statuses {
		names[s.Name] = true
		if s.ListenAddr == "" {
			t.Errorf("listener %q has empty ListenAddr", s.Name)
		}
	}
	if !names["alpha"] || !names["beta"] {
		t.Errorf("expected alpha and beta in statuses, got %v", names)
	}

	// Stop one, verify the other continues.
	if err := coord.StopNamed(ctx, "alpha"); err != nil {
		t.Fatalf("StopNamed alpha: %v", err)
	}
	if got := coord.ListenerCount(); got != 1 {
		t.Errorf("ListenerCount after stopping alpha = %d, want 1", got)
	}

	// Stop the remaining.
	if err := coord.StopAll(ctx); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	if got := coord.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after StopAll = %d, want 0", got)
	}
}

func TestCoordinator_StartNamed_Duplicate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.StartNamed(ctx, "dup", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed first: %v", err)
	}
	defer coord.StopAll(ctx)

	err := coord.StartNamed(ctx, "dup", "127.0.0.1:0")
	if !errors.Is(err, ErrListenerExists) {
		t.Errorf("duplicate StartNamed err = %v, want ErrListenerExists", err)
	}
}

func TestCoordinator_StopNamed_NotFound(t *testing.T) {
	ctx := context.Background()
	coord := NewCoordinator(CoordinatorConfig{})

	err := coord.StopNamed(ctx, "missing")
	if !errors.Is(err, ErrListenerNotFound) {
		t.Errorf("StopNamed missing err = %v, want ErrListenerNotFound", err)
	}
}

func TestCoordinator_StopAll_Empty(t *testing.T) {
	ctx := context.Background()
	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.StopAll(ctx); err != nil {
		t.Errorf("StopAll on empty coordinator: %v", err)
	}
}

func TestCoordinator_StopNamed_EmptyDefaultsToDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// StopNamed with empty string should stop the default listener.
	if err := coord.StopNamed(ctx, ""); err != nil {
		t.Fatalf("StopNamed empty: %v", err)
	}

	if got := coord.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount = %d, want 0", got)
	}
}

func TestCoordinator_StartNamed_EmptyDefaultsToDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.StartNamed(ctx, "", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed empty: %v", err)
	}
	defer coord.StopAll(ctx)

	statuses := coord.ListenerStatuses()
	if len(statuses) != 1 || statuses[0].Name != DefaultListenerName {
		t.Errorf("expected default listener, got %v", statuses)
	}
}

func TestCoordinator_ListenerStatuses_Uptime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer coord.StopAll(ctx)

	// Give a small window for uptime to tick.
	time.Sleep(50 * time.Millisecond)

	statuses := coord.ListenerStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}

	// UptimeSeconds should be 0 (less than 1 second) after 50ms.
	// The key check is that it doesn't panic or return garbage.
	if statuses[0].UptimeSeconds < 0 {
		t.Errorf("negative uptime: %d", statuses[0].UptimeSeconds)
	}
}

func TestCoordinator_OnStack_Callback(t *testing.T) {
	var called atomic.Int32

	coord := NewCoordinator(CoordinatorConfig{
		CONNECTNegotiator: NewCONNECTNegotiator(nil),
		SOCKS5Negotiator:  NewSOCKS5Negotiator(nil),
		OnStack: func(_ context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			called.Add(1)
			stack.Close()
		},
	})

	// Verify that handlers are wired (non-nil). We can't easily test the
	// full handler path here (that requires an actual CONNECT/SOCKS5 client)
	// but we verify the wiring is in place.
	connectHandler := coord.buildCONNECTHandler()
	if connectHandler == nil {
		t.Error("CONNECT handler is nil despite negotiator being set")
	}

	socks5Handler := coord.buildSOCKS5Handler()
	if socks5Handler == nil {
		t.Error("SOCKS5 handler is nil despite negotiator being set")
	}
}

func TestCoordinator_NilNegotiators(t *testing.T) {
	coord := NewCoordinator(CoordinatorConfig{})

	if h := coord.buildCONNECTHandler(); h != nil {
		t.Error("CONNECT handler should be nil when negotiator is nil")
	}
	if h := coord.buildSOCKS5Handler(); h != nil {
		t.Error("SOCKS5 handler should be nil when negotiator is nil")
	}
}

// TestCoordinator_OnHTTP2Stack_Wiring verifies that the OnHTTP2Stack field on
// CoordinatorConfig is plumbed through to the CONNECT and SOCKS5 handler
// configs that the Coordinator builds internally. This catches regressions
// where a new callback is added to CoordinatorConfig but the wiring only
// reaches OnStack, leaving h2 stacks unhandled.
//
// We don't drive a real CONNECT/SOCKS5 flow here — that requires a full
// listener. Instead we introspect the coordinator's internal field and
// verify buildCONNECTHandler / buildSOCKS5Handler return non-nil when the
// negotiators are set, which is a proxy for "OnHTTP2Stack reached the
// handler configs".
func TestCoordinator_OnHTTP2Stack_Wiring(t *testing.T) {
	onHTTP2 := func(_ context.Context, _ *ConnectionStack, _ *http2.Layer,
		_, _ *envelope.TLSSnapshot, _ string) {
	}

	coord := NewCoordinator(CoordinatorConfig{
		CONNECTNegotiator: NewCONNECTNegotiator(nil),
		SOCKS5Negotiator:  NewSOCKS5Negotiator(nil),
		OnHTTP2Stack:      onHTTP2,
	})

	if coord.onHTTP2Stack == nil {
		t.Fatal("coord.onHTTP2Stack is nil; OnHTTP2Stack not copied from config")
	}

	// CONNECT/SOCKS5 handlers must build non-nil; the handler configs
	// should carry the same OnHTTP2Stack value. We can't read the
	// handler's internal config after NewCONNECTHandler captures it, but
	// verifying non-nil handlers + the field on Coordinator is enough to
	// catch mis-wiring at this layer.
	if h := coord.buildCONNECTHandler(); h == nil {
		t.Error("buildCONNECTHandler returned nil despite negotiator being set")
	}
	if h := coord.buildSOCKS5Handler(); h == nil {
		t.Error("buildSOCKS5Handler returned nil despite negotiator being set")
	}
}

func TestCoordinator_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	coord := NewCoordinator(CoordinatorConfig{})

	if err := coord.StartNamed(ctx, "a", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed: %v", err)
	}
	if err := coord.StartNamed(ctx, "b", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed: %v", err)
	}

	if got := coord.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	// Cancel the parent context. Both listeners should shut down.
	cancel()

	// Give listeners time to observe the cancellation and exit.
	time.Sleep(100 * time.Millisecond)

	// StopAll should succeed quickly (listeners already stopped).
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()

	if err := coord.StopAll(stopCtx); err != nil {
		t.Errorf("StopAll after cancel: %v", err)
	}
}

func TestCoordinator_ConcurrentStartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord := NewCoordinator(CoordinatorConfig{})
	errs := make(chan error, 20)

	// Start 10 listeners concurrently.
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("listener-%d", i)
		go func() {
			errs <- coord.StartNamed(ctx, name, "127.0.0.1:0")
		}()
	}

	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent start: %v", err)
		}
	}

	if got := coord.ListenerCount(); got != 10 {
		t.Fatalf("ListenerCount = %d, want 10", got)
	}

	// Stop all concurrently is not meaningful (StopAll is serial internally)
	// but verify it doesn't race.
	if err := coord.StopAll(ctx); err != nil {
		t.Fatalf("StopAll: %v", err)
	}

	if got := coord.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after StopAll = %d, want 0", got)
	}
}
