package proxy_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// stubDetector is a minimal ProtocolDetector for testing.
type stubDetector struct{}

func (d *stubDetector) Detect(_ []byte) proxy.ProtocolHandler { return nil }

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestManager_StartStop_Lifecycle(t *testing.T) {
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	if got := manager.ActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections when not running = %d, want 0", got)
	}
}

func TestManager_ActiveConnections_Running(t *testing.T) {
	logger := newTestLogger()
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
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	if got := manager.Uptime(); got != 0 {
		t.Errorf("Uptime when not running = %v, want 0", got)
	}
}

func TestManager_Uptime_Running(t *testing.T) {
	logger := newTestLogger()
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
	logger := newTestLogger()
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
	logger := newTestLogger()
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

func TestManager_StartTCPForwards(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	handler := &echoHandler{}
	forwards := map[string]string{
		"0": "127.0.0.1:9999", // port 0 = random
	}

	if err := manager.StartTCPForwards(ctx, forwards, handler); err != nil {
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
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	handler := &echoHandler{}
	forwards := map[string]string{
		"0": "127.0.0.1:9999",
	}

	err := manager.StartTCPForwards(context.Background(), forwards, handler)
	if err == nil {
		t.Fatal("expected error when not running")
	}
	if err != proxy.ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got %v", err)
	}
}

func TestManager_StartTCPForwards_Connectable(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer manager.Stop(context.Background())

	handler := &echoHandler{}
	forwards := map[string]string{
		"0": "127.0.0.1:9999",
	}

	if err := manager.StartTCPForwards(ctx, forwards, handler); err != nil {
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
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	if err := manager.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	handler := &echoHandler{}
	forwards := map[string]string{
		"0": "127.0.0.1:9999",
	}

	if err := manager.StartTCPForwards(ctx, forwards, handler); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	// Get the forward address before stopping.
	addrs := manager.TCPForwardAddrs()
	fwdAddr := addrs["0"]

	// Stop should clean up TCP forwards.
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// TCPForwardAddrs should be nil after stop.
	if got := manager.TCPForwardAddrs(); got != nil {
		t.Errorf("TCPForwardAddrs after stop = %v, want nil", got)
	}

	// The forward listener should no longer be accepting connections.
	conn, err := net.DialTimeout("tcp", fwdAddr, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Error("expected dial to fail after stop, but it succeeded")
	}
}

func TestManager_TCPForwardAddrs_NotRunning(t *testing.T) {
	logger := newTestLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	if got := manager.TCPForwardAddrs(); got != nil {
		t.Errorf("TCPForwardAddrs when not running = %v, want nil", got)
	}
}

// echoHandler is a simple protocol handler that echoes data for testing.
type echoHandler struct{}

func (h *echoHandler) Name() string          { return "echo" }
func (h *echoHandler) Detect(_ []byte) bool   { return true }
func (h *echoHandler) Handle(_ context.Context, conn net.Conn) error {
	_, err := io.Copy(conn, conn)
	return err
}
