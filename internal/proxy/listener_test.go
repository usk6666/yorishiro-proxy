package proxy_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// slowHandler is a ProtocolHandler that blocks for a configured duration.
type slowHandler struct {
	delay   time.Duration
	handled atomic.Int32
	entered atomic.Int32
	name    string
}

func (h *slowHandler) Name() string        { return h.name }
func (h *slowHandler) Detect(_ []byte) bool { return true }

func (h *slowHandler) Handle(_ context.Context, conn net.Conn) error {
	h.entered.Add(1)
	defer conn.Close()
	time.Sleep(h.delay)
	h.handled.Add(1)
	return nil
}

// slowDetector always returns the same slowHandler.
type slowDetector struct {
	handler proxy.ProtocolHandler
}

func (d *slowDetector) Detect(_ []byte) proxy.ProtocolHandler {
	return d.handler
}

func dialAndSend(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	// Send enough bytes so Peek(16) succeeds.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	return conn
}

// waitForEntered polls until handler.entered reaches the target count.
func waitForEntered(handler *slowHandler, target int32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for handler.entered.Load() < target && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return handler.entered.Load() >= target
}

func TestListener_GracefulShutdown_WaitsForHandlers(t *testing.T) {
	handler := &slowHandler{delay: 300 * time.Millisecond, name: "slow"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   newTestLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	conn := dialAndSend(t, listener.Addr())
	defer conn.Close()

	if !waitForEntered(handler, 1, 2*time.Second) {
		t.Fatal("handler was never entered")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	if handler.handled.Load() != 1 {
		t.Errorf("handled = %d, want 1", handler.handled.Load())
	}
}

func TestListener_GracefulShutdown_EmptyDrain(t *testing.T) {
	handler := &slowHandler{delay: time.Second, name: "slow"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   newTestLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return promptly on empty drain")
	}
}

func TestListener_MultipleConnections_AllDrain(t *testing.T) {
	handler := &slowHandler{delay: 200 * time.Millisecond, name: "slow"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   newTestLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	const numConns = 5
	conns := make([]net.Conn, numConns)
	for i := range numConns {
		conns[i] = dialAndSend(t, listener.Addr())
		defer conns[i].Close()
	}

	if !waitForEntered(handler, numConns, 2*time.Second) {
		t.Fatalf("only %d/%d handlers entered", handler.entered.Load(), numConns)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	if got := handler.handled.Load(); got != numConns {
		t.Errorf("handled = %d, want %d", got, numConns)
	}
}

func TestListener_Semaphore_RejectsAtCapacity(t *testing.T) {
	handler := &slowHandler{delay: 500 * time.Millisecond, name: "slow"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Logger:         newTestLogger(),
		MaxConnections: 2,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	// Fill both slots.
	conn1 := dialAndSend(t, listener.Addr())
	defer conn1.Close()
	conn2 := dialAndSend(t, listener.Addr())
	defer conn2.Close()

	if !waitForEntered(handler, 2, 2*time.Second) {
		t.Fatalf("only %d/2 handlers entered", handler.entered.Load())
	}

	// Third connection should be rejected (closed by server).
	conn3, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn3.Close()

	// Send data so the server can process the connection.
	conn3.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))

	// The server should close the connection because semaphore is full.
	buf := make([]byte, 1)
	conn3.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn3.Read(buf)
	if err == nil {
		t.Fatal("expected error reading from rejected connection")
	}

	// Only 2 handlers should have been entered (third was rejected).
	if handler.entered.Load() != 2 {
		t.Errorf("handler entered = %d, want 2", handler.entered.Load())
	}
}

func TestListener_Semaphore_ReleasesSlot(t *testing.T) {
	handler := &slowHandler{delay: 100 * time.Millisecond, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Logger:         newTestLogger(),
		MaxConnections: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	// First connection occupies the single slot.
	conn1 := dialAndSend(t, listener.Addr())
	defer conn1.Close()

	if !waitForEntered(handler, 1, 2*time.Second) {
		t.Fatal("first handler was never entered")
	}

	// Wait for the first handler to complete and release the slot.
	deadline := time.Now().Add(2 * time.Second)
	for handler.handled.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if handler.handled.Load() < 1 {
		t.Fatal("first handler never completed")
	}

	// Second connection should now be accepted.
	conn2 := dialAndSend(t, listener.Addr())
	defer conn2.Close()

	if !waitForEntered(handler, 2, 2*time.Second) {
		t.Fatalf("second handler was never entered, entered = %d", handler.entered.Load())
	}
}

func TestListener_PeekTimeout_DisconnectsSlowClient(t *testing.T) {
	handler := &slowHandler{delay: 0, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      newTestLogger(),
		PeekTimeout: 200 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Start(ctx)
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	// Connect but send no data — should be disconnected by peek timeout.
	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for the connection to be closed by the server.
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected error reading from timed-out connection")
	}

	// Handler should never have been entered (peek failed).
	if handler.entered.Load() != 0 {
		t.Errorf("handler entered = %d, want 0", handler.entered.Load())
	}
}
