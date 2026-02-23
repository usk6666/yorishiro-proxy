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
	logger := newTestLogger()
	listener := proxy.NewListener("127.0.0.1:0", detector, logger)

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

	// Establish a connection that will be handled slowly.
	conn := dialAndSend(t, listener.Addr())
	defer conn.Close()

	// Wait for the handler goroutine to actually enter Handle.
	if !waitForEntered(handler, 1, 2*time.Second) {
		t.Fatal("handler was never entered")
	}

	// Cancel context to trigger shutdown.
	cancel()

	// Start() should block until the slow handler completes.
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	// Verify handler completed.
	if handler.handled.Load() != 1 {
		t.Errorf("handled = %d, want 1", handler.handled.Load())
	}
}

func TestListener_GracefulShutdown_EmptyDrain(t *testing.T) {
	handler := &slowHandler{delay: time.Second, name: "slow"}
	detector := &slowDetector{handler: handler}
	logger := newTestLogger()
	listener := proxy.NewListener("127.0.0.1:0", detector, logger)

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

	// Cancel immediately with no active connections.
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
	logger := newTestLogger()
	listener := proxy.NewListener("127.0.0.1:0", detector, logger)

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

	// Establish multiple connections.
	const numConns = 5
	conns := make([]net.Conn, numConns)
	for i := range numConns {
		conns[i] = dialAndSend(t, listener.Addr())
		defer conns[i].Close()
	}

	// Wait for all handlers to enter Handle.
	if !waitForEntered(handler, numConns, 2*time.Second) {
		t.Fatalf("only %d/%d handlers entered", handler.entered.Load(), numConns)
	}

	// Cancel context.
	cancel()

	// Wait for Start to return.
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	// All handlers should have completed.
	if got := handler.handled.Load(); got != numConns {
		t.Errorf("handled = %d, want %d", got, numConns)
	}
}
