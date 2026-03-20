package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// stubDetector is a minimal ProtocolDetector for testing.
type stubDetector struct{}

func (d *stubDetector) Detect(_ []byte) proxy.ProtocolHandler { return nil }

func TestManager_StartStop_Lifecycle(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// Initially not running.
	running, addr := manager.Status()
	if running {
		t.Error("expected not running initially")
	}
	if addr != "" {
		t.Errorf("expected empty addr, got %q", addr)
	}

	// Start on a random port.
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Should be running now.
	running, addr = manager.Status()
	if !running {
		t.Error("expected running after Start")
	}
	if addr == "" {
		t.Error("expected non-empty addr after Start")
	}

	// Verify the address is actually listening.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("could not connect to proxy addr %s: %v", addr, err)
	}
	conn.Close()

	// Stop.
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Should not be running.
	running, addr = manager.Status()
	if running {
		t.Error("expected not running after Stop")
	}
	if addr != "" {
		t.Errorf("expected empty addr after Stop, got %q", addr)
	}
}

func TestManager_DoubleStart_Error(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	// Second start should fail.
	err := manager.Start(ctx, "127.0.0.1:0")
	if err == nil {
		t.Fatal("expected error on double Start")
	}
	if err != proxy.ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning, got %v", err)
	}
}

func TestManager_StopWhenNotRunning_Error(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	err := manager.Stop(context.Background())
	if err == nil {
		t.Fatal("expected error on Stop when not running")
	}
	if err != proxy.ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}
}

func TestManager_StopAfterStop_Error(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("first Stop: %v", err)
	}

	// Second stop should fail.
	err := manager.Stop(ctx)
	if err == nil {
		t.Fatal("expected error on second Stop")
	}
	if err != proxy.ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}
}

func TestManager_StartWithRandomPort(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// Start with a random port to verify the manager correctly reports
	// the actual listen address assigned by the OS.
	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	running, addr := manager.Status()
	if !running {
		t.Error("expected running after Start")
	}
	if addr == "" {
		t.Error("expected non-empty addr")
	}
}

func TestManager_RestartAfterStop(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	// First start.
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	_, addr1 := manager.Status()

	// Stop.
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Restart on a different random port.
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	defer manager.Stop(context.Background())

	running, addr2 := manager.Status()
	if !running {
		t.Error("expected running after restart")
	}
	if addr2 == "" {
		t.Error("expected non-empty addr after restart")
	}

	// Addresses should generally differ since ports are random.
	t.Logf("first addr: %s, second addr: %s", addr1, addr2)
}

func TestManager_StartWithInvalidAddr(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// Use an invalid address format.
	err := manager.Start(context.Background(), "invalid-address-no-port")
	if err == nil {
		manager.Stop(context.Background())
		t.Fatal("expected error for invalid address")
	}

	// Should still be not running after failed start.
	running, _ := manager.Status()
	if running {
		t.Error("expected not running after failed Start")
	}
}

func TestManager_StopWithCancelledContext(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Create an already-cancelled context for Stop.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := manager.Stop(cancelCtx)
	// The stop might succeed quickly if the listener shuts down fast enough,
	// or it might fail with context cancelled. Either is acceptable.
	if err != nil {
		t.Logf("Stop with cancelled context returned error (expected): %v", err)
	}

	// Ensure we can clean up properly.
	running, _ := manager.Status()
	if running {
		manager.Stop(context.Background())
	}
}

func TestManager_ActiveConnections_NotRunning(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	if got := manager.ActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections when not running = %d, want 0", got)
	}
}

func TestManager_ActiveConnections_Running(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	// No active connections should exist immediately after starting.
	if got := manager.ActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections after start = %d, want 0", got)
	}
}

func TestManager_Uptime_NotRunning(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	if got := manager.Uptime(); got != 0 {
		t.Errorf("Uptime when not running = %v, want 0", got)
	}
}

func TestManager_Uptime_Running(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	// Uptime should be positive when running.
	time.Sleep(50 * time.Millisecond)
	uptime := manager.Uptime()
	if uptime <= 0 {
		t.Errorf("Uptime = %v, want > 0", uptime)
	}
	if uptime > 5*time.Second {
		t.Errorf("Uptime = %v, unexpectedly large", uptime)
	}
}

func TestManager_Uptime_AfterStop(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Uptime should be 0 after stopping.
	if got := manager.Uptime(); got != 0 {
		t.Errorf("Uptime after stop = %v, want 0", got)
	}
}

func TestManager_ConcurrentStatus(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	// Call Status concurrently to verify thread safety.
	done := make(chan struct{})
	for range 10 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 100 {
				manager.Status()
			}
		}()
	}
	for range 10 {
		<-done
	}
}

// newTestForwardParams creates TCPForwardParams for testing with a raw protocol config.
func newTestForwardParams(handler proxy.ProtocolHandler, targets map[string]string) proxy.TCPForwardParams {
	forwards := make(map[string]*config.ForwardConfig, len(targets))
	for port, target := range targets {
		forwards[port] = &config.ForwardConfig{Target: target, Protocol: "raw"}
	}
	return proxy.TCPForwardParams{
		Forwards: forwards,
		Handler:  handler,
	}
}

func TestManager_StartTCPForwards(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	handler := &echoHandler{}
	params := newTestForwardParams(handler, map[string]string{
		"0": "127.0.0.1:9999", // port 0 = random
	})

	if err := manager.StartTCPForwards(ctx, params); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	// Verify forward addrs are populated.
	addrs := manager.TCPForwardAddrs()
	if addrs == nil {
		t.Fatal("expected non-nil TCPForwardAddrs")
	}
	if _, ok := addrs["0"]; !ok {
		t.Error("expected addrs to contain port '0'")
	}
}

func TestManager_StartTCPForwards_NotRunning(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	handler := &echoHandler{}
	params := newTestForwardParams(handler, map[string]string{
		"0": "127.0.0.1:9999",
	})

	err := manager.StartTCPForwards(context.Background(), params)
	if err == nil {
		t.Fatal("expected error when not running")
	}
	if err != proxy.ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}
}

func TestManager_StartTCPForwards_Connectable(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	handler := &echoHandler{}
	params := newTestForwardParams(handler, map[string]string{
		"0": "127.0.0.1:9999",
	})

	if err := manager.StartTCPForwards(ctx, params); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	// Get the actual address and connect.
	addrs := manager.TCPForwardAddrs()
	addr := addrs["0"]
	if addr == "" {
		t.Fatal("expected non-empty forward address")
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tcp forward: %v", err)
	}
	conn.Close()
}

func TestManager_StopCleansUpTCPForwards(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	handler := &echoHandler{}
	params := newTestForwardParams(handler, map[string]string{
		"0": "127.0.0.1:9999",
	})

	if err := manager.StartTCPForwards(ctx, params); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	// Stop should clean up TCP forwards.
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// TCPForwardAddrs should be nil after stop.
	if got := manager.TCPForwardAddrs(); got != nil {
		t.Errorf("TCPForwardAddrs after stop = %v, want nil", got)
	}
}

func TestManager_TCPForwardAddrs_NotRunning(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	if got := manager.TCPForwardAddrs(); got != nil {
		t.Errorf("TCPForwardAddrs when not running = %v, want nil", got)
	}
}

// --- Multi-listener (Named) tests ---

func TestManager_StartNamed_MultipleListeners(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	// Start multiple listeners with different names.
	if err := manager.StartNamed(ctx, "http", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed(http): %v", err)
	}
	if err := manager.StartNamed(ctx, "grpc", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed(grpc): %v", err)
	}
	if err := manager.StartNamed(ctx, "tcp", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed(tcp): %v", err)
	}
	defer manager.StopAll(context.Background())

	// All should be running.
	if got := manager.ListenerCount(); got != 3 {
		t.Errorf("ListenerCount = %d, want 3", got)
	}

	statuses := manager.ListenerStatuses()
	if len(statuses) != 3 {
		t.Fatalf("ListenerStatuses len = %d, want 3", len(statuses))
	}

	// Verify each listener has a unique address.
	addrs := make(map[string]bool)
	for _, st := range statuses {
		if st.ListenAddr == "" {
			t.Errorf("listener %q has empty address", st.Name)
		}
		if addrs[st.ListenAddr] {
			t.Errorf("duplicate address %q for listener %q", st.ListenAddr, st.Name)
		}
		addrs[st.ListenAddr] = true
	}

	// Verify each listener is actually accepting connections.
	for _, st := range statuses {
		conn, err := net.DialTimeout("tcp", st.ListenAddr, 2*time.Second)
		if err != nil {
			t.Errorf("could not connect to listener %q at %s: %v", st.Name, st.ListenAddr, err)
			continue
		}
		conn.Close()
	}
}

func TestManager_StartNamed_DuplicateName_Error(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	if err := manager.StartNamed(ctx, "mylistener", "127.0.0.1:0"); err != nil {
		t.Fatalf("first StartNamed: %v", err)
	}
	defer manager.StopAll(context.Background())

	// Duplicate name should fail.
	err := manager.StartNamed(ctx, "mylistener", "127.0.0.1:0")
	if err == nil {
		t.Fatal("expected error on duplicate name")
	}
	if !containsError(err, proxy.ErrListenerExists) {
		t.Errorf("expected ErrListenerExists, got %v", err)
	}
}

func TestManager_StartNamed_DefaultName_BackwardCompat(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	// Start using Start() (which uses "default" name).
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.StopAll(context.Background())

	// StartNamed with "default" should fail with ErrAlreadyRunning.
	err := manager.StartNamed(ctx, proxy.DefaultListenerName, "127.0.0.1:0")
	if err != proxy.ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning, got %v", err)
	}

	// StartNamed with empty name should also fail (defaults to "default").
	err = manager.StartNamed(ctx, "", "127.0.0.1:0")
	if err != proxy.ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning for empty name, got %v", err)
	}

	// Status should show the default listener.
	running, addr := manager.Status()
	if !running {
		t.Error("expected running")
	}
	if addr == "" {
		t.Error("expected non-empty addr")
	}
}

func TestManager_StopNamed_Individual(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	if err := manager.StartNamed(ctx, "listener-a", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed(a): %v", err)
	}
	if err := manager.StartNamed(ctx, "listener-b", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed(b): %v", err)
	}
	defer manager.StopAll(context.Background())

	if got := manager.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	// Stop one listener.
	if err := manager.StopNamed(ctx, "listener-a"); err != nil {
		t.Fatalf("StopNamed(a): %v", err)
	}

	// Only listener-b should remain.
	if got := manager.ListenerCount(); got != 1 {
		t.Fatalf("ListenerCount after stop = %d, want 1", got)
	}

	statuses := manager.ListenerStatuses()
	if len(statuses) != 1 || statuses[0].Name != "listener-b" {
		t.Errorf("expected only listener-b remaining, got %v", statuses)
	}
}

func TestManager_StopNamed_NotFound(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// Stopping a non-existent named listener should return ErrListenerNotFound.
	err := manager.StopNamed(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent listener")
	}
	if !containsError(err, proxy.ErrListenerNotFound) {
		t.Errorf("expected ErrListenerNotFound, got %v", err)
	}
}

func TestManager_StopNamed_DefaultBackwardCompat(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// StopNamed with "default" when not running should return ErrNotRunning.
	err := manager.StopNamed(context.Background(), proxy.DefaultListenerName)
	if err != proxy.ErrNotRunning {
		t.Errorf("expected ErrNotRunning for default, got %v", err)
	}

	// StopNamed with empty name should also return ErrNotRunning (defaults to "default").
	err = manager.StopNamed(context.Background(), "")
	if err != proxy.ErrNotRunning {
		t.Errorf("expected ErrNotRunning for empty name, got %v", err)
	}
}

func TestManager_StopAll(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	// Start multiple listeners.
	names := []string{"a", "b", "c"}
	addrs := make(map[string]string)
	for _, name := range names {
		if err := manager.StartNamed(ctx, name, "127.0.0.1:0"); err != nil {
			t.Fatalf("StartNamed(%s): %v", name, err)
		}
	}

	// Record addresses for later verification.
	for _, st := range manager.ListenerStatuses() {
		addrs[st.Name] = st.ListenAddr
	}

	if got := manager.ListenerCount(); got != 3 {
		t.Fatalf("ListenerCount = %d, want 3", got)
	}

	// StopAll should stop everything.
	if err := manager.StopAll(ctx); err != nil {
		t.Fatalf("StopAll: %v", err)
	}

	if got := manager.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after StopAll = %d, want 0", got)
	}

	// All addresses should be unreachable.
	for name, addr := range addrs {
		var lastOK bool
		for i := 0; i < 10; i++ {
			conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err != nil {
				lastOK = false
				break
			}
			conn.Close()
			lastOK = true
			time.Sleep(50 * time.Millisecond)
		}
		if lastOK {
			t.Errorf("listener %q at %s still accepting after StopAll", name, addr)
		}
	}
}

func TestManager_StopAll_NoListeners(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	// StopAll with no listeners should not error.
	if err := manager.StopAll(context.Background()); err != nil {
		t.Errorf("StopAll with no listeners: %v", err)
	}
}

func TestManager_ListenerStatuses_Empty(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	if got := manager.ListenerStatuses(); got != nil {
		t.Errorf("ListenerStatuses when empty = %v, want nil", got)
	}
}

func TestManager_ListenerStatuses_Uptime(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.StartNamed(ctx, "test", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed: %v", err)
	}
	defer manager.StopAll(context.Background())

	time.Sleep(50 * time.Millisecond)

	statuses := manager.ListenerStatuses()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds = %d, want >= 0", statuses[0].UptimeSeconds)
	}
}

func TestManager_ListenerCount(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	if got := manager.ListenerCount(); got != 0 {
		t.Errorf("initial ListenerCount = %d, want 0", got)
	}

	manager.StartNamed(ctx, "a", "127.0.0.1:0")
	if got := manager.ListenerCount(); got != 1 {
		t.Errorf("ListenerCount after 1 start = %d, want 1", got)
	}

	manager.StartNamed(ctx, "b", "127.0.0.1:0")
	if got := manager.ListenerCount(); got != 2 {
		t.Errorf("ListenerCount after 2 starts = %d, want 2", got)
	}

	manager.StopNamed(ctx, "a")
	if got := manager.ListenerCount(); got != 1 {
		t.Errorf("ListenerCount after 1 stop = %d, want 1", got)
	}

	manager.StopAll(ctx)
	if got := manager.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after StopAll = %d, want 0", got)
	}
}

func TestManager_ActiveConnections_MultipleListeners(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	manager.StartNamed(ctx, "a", "127.0.0.1:0")
	manager.StartNamed(ctx, "b", "127.0.0.1:0")
	defer manager.StopAll(context.Background())

	// Should be 0 with no active connections.
	if got := manager.ActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections = %d, want 0", got)
	}
}

func TestManager_SetPeekTimeout_AppliesAllListeners(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	manager.StartNamed(ctx, "a", "127.0.0.1:0")
	manager.StartNamed(ctx, "b", "127.0.0.1:0")
	defer manager.StopAll(context.Background())

	// Set a new peek timeout.
	newTimeout := 5 * time.Second
	manager.SetPeekTimeout(newTimeout)

	// PeekTimeout should reflect the new value.
	if got := manager.PeekTimeout(); got != newTimeout {
		t.Errorf("PeekTimeout = %v, want %v", got, newTimeout)
	}
}

func TestManager_SetMaxConnections_AppliesAllListeners(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	manager.StartNamed(ctx, "a", "127.0.0.1:0")
	manager.StartNamed(ctx, "b", "127.0.0.1:0")
	defer manager.StopAll(context.Background())

	// Set a new max connections.
	manager.SetMaxConnections(500)

	// MaxConnections should reflect the new value.
	if got := manager.MaxConnections(); got != 500 {
		t.Errorf("MaxConnections = %d, want 500", got)
	}
}

func TestManager_MixedNamedAndDefault(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()

	// Start using the backward-compatible Start() method.
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Also start a named listener.
	if err := manager.StartNamed(ctx, "grpc", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed: %v", err)
	}

	// Both should be running.
	if got := manager.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	// Status() should report the default listener.
	running, addr := manager.Status()
	if !running {
		t.Error("Status() expected running")
	}
	if addr == "" {
		t.Error("Status() expected non-empty addr")
	}

	// Stop the default listener using Stop().
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Default should be stopped but grpc should still be running.
	running, _ = manager.Status()
	if running {
		t.Error("default should not be running after Stop")
	}
	if got := manager.ListenerCount(); got != 1 {
		t.Fatalf("ListenerCount = %d, want 1", got)
	}

	manager.StopAll(ctx)
}

func TestManager_StartNamed_EmptyName_DefaultsToDefault(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.StartNamed(ctx, "", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed empty: %v", err)
	}
	defer manager.StopAll(context.Background())

	// Should report as "default" listener.
	running, addr := manager.Status()
	if !running {
		t.Error("expected running")
	}
	if addr == "" {
		t.Error("expected non-empty addr")
	}
}

func TestManager_ConcurrentStartNamed(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	defer manager.StopAll(context.Background())

	// Start multiple listeners concurrently.
	done := make(chan error, 5)
	for i := range 5 {
		name := fmt.Sprintf("listener-%d", i)
		go func() {
			done <- manager.StartNamed(ctx, name, "127.0.0.1:0")
		}()
	}

	var errors []error
	for range 5 {
		if err := <-done; err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		t.Errorf("unexpected errors during concurrent start: %v", errors)
	}

	if got := manager.ListenerCount(); got != 5 {
		t.Errorf("ListenerCount = %d, want 5", got)
	}
}

// containsError checks if err wraps target using errors.Is.
func containsError(err, target error) bool {
	return errors.Is(err, target)
}

// echoHandler is a simple protocol handler that echoes data for testing.
type echoHandler struct{}

func (h *echoHandler) Name() string         { return "echo" }
func (h *echoHandler) Detect(_ []byte) bool { return true }
func (h *echoHandler) Handle(_ context.Context, conn net.Conn) error {
	_, err := io.Copy(conn, conn)
	return err
}
