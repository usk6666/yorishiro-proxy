package proxy_test

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- MaxConnections getter tests ---

func TestManager_MaxConnections_DefaultWhenNotSet(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// When no explicit value is set, should return default (128).
	if got := manager.MaxConnections(); got != 128 {
		t.Errorf("MaxConnections = %d, want 128 (default)", got)
	}
}

func TestManager_MaxConnections_ConfiguredBeforeStart(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	manager.SetMaxConnections(500)

	// Should return the configured value even before start.
	if got := manager.MaxConnections(); got != 500 {
		t.Errorf("MaxConnections = %d, want 500", got)
	}
}

func TestManager_MaxConnections_ReflectsRunningListener(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	manager.SetMaxConnections(512)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	// When running, should reflect the listener's value.
	if got := manager.MaxConnections(); got != 512 {
		t.Errorf("MaxConnections while running = %d, want 512", got)
	}

	// Dynamic change should propagate.
	manager.SetMaxConnections(2048)
	if got := manager.MaxConnections(); got != 2048 {
		t.Errorf("MaxConnections after dynamic change = %d, want 2048", got)
	}
}

// --- PeekTimeout getter tests ---

func TestManager_PeekTimeout_DefaultWhenNotSet(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// When no explicit value is set, should return default (30s).
	if got := manager.PeekTimeout(); got != 30*time.Second {
		t.Errorf("PeekTimeout = %v, want 30s (default)", got)
	}
}

func TestManager_PeekTimeout_ConfiguredBeforeStart(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	manager.SetPeekTimeout(15 * time.Second)

	if got := manager.PeekTimeout(); got != 15*time.Second {
		t.Errorf("PeekTimeout = %v, want 15s", got)
	}
}

func TestManager_PeekTimeout_ReflectsRunningListener(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	manager.SetPeekTimeout(5 * time.Second)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	// When running, should reflect the listener's value.
	if got := manager.PeekTimeout(); got != 5*time.Second {
		t.Errorf("PeekTimeout while running = %v, want 5s", got)
	}

	// Dynamic change should propagate.
	manager.SetPeekTimeout(10 * time.Second)
	if got := manager.PeekTimeout(); got != 10*time.Second {
		t.Errorf("PeekTimeout after dynamic change = %v, want 10s", got)
	}
}

// --- SetPeekTimeout / SetMaxConnections propagation tests ---

func TestManager_SetPeekTimeout_PropagatesWhenNotRunning(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// Set before start should persist for when proxy starts later.
	manager.SetPeekTimeout(10 * time.Second)
	if got := manager.PeekTimeout(); got != 10*time.Second {
		t.Errorf("PeekTimeout = %v, want 10s", got)
	}
}

func TestManager_SetMaxConnections_PropagatesWhenNotRunning(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// Set before start should persist for when proxy starts later.
	manager.SetMaxConnections(256)
	if got := manager.MaxConnections(); got != 256 {
		t.Errorf("MaxConnections = %d, want 256", got)
	}
}
