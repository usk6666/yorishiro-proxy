package proxy_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// --- SetMaxConnections tests ---

func TestListener_SetMaxConnections_ResizesCapacity(t *testing.T) {
	// Start with max 2, then resize to 4 while running.
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

	// Verify initial max.
	if got := listener.MaxConnections(); got != 2 {
		t.Errorf("initial MaxConnections = %d, want 2", got)
	}

	// Resize to 4.
	listener.SetMaxConnections(4)
	if got := listener.MaxConnections(); got != 4 {
		t.Errorf("after resize MaxConnections = %d, want 4", got)
	}

	// Open 3 connections — should all be accepted (would have been rejected with limit 2).
	conns := make([]net.Conn, 3)
	for i := range conns {
		conns[i] = dialAndSend(t, listener.Addr())
		defer conns[i].Close()
	}

	if !waitForEntered(handler, 3, 2*time.Second) {
		t.Fatalf("only %d/3 handlers entered after resize", handler.entered.Load())
	}
}

func TestListener_SetMaxConnections_IgnoresNonPositive(t *testing.T) {
	handler := &slowHandler{delay: time.Millisecond, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Logger:         newTestLogger(),
		MaxConnections: 10,
	})

	// Setting to 0 or negative should be ignored.
	listener.SetMaxConnections(0)
	if got := listener.MaxConnections(); got != 10 {
		t.Errorf("after SetMaxConnections(0) = %d, want 10", got)
	}

	listener.SetMaxConnections(-5)
	if got := listener.MaxConnections(); got != 10 {
		t.Errorf("after SetMaxConnections(-5) = %d, want 10", got)
	}
}

func TestListener_SetMaxConnections_DefaultMaxConnections(t *testing.T) {
	handler := &slowHandler{delay: time.Millisecond, name: "fast"}
	detector := &slowDetector{handler: handler}
	// MaxConnections=0 should default to 1024.
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   newTestLogger(),
	})

	if got := listener.MaxConnections(); got != 1024 {
		t.Errorf("default MaxConnections = %d, want 1024", got)
	}
}

// --- SetPeekTimeout tests ---

func TestListener_SetPeekTimeout_UpdatesTimeout(t *testing.T) {
	handler := &slowHandler{delay: time.Millisecond, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      newTestLogger(),
		PeekTimeout: 500 * time.Millisecond,
	})

	// Verify initial value.
	if got := listener.PeekTimeout(); got != 500*time.Millisecond {
		t.Errorf("initial PeekTimeout = %v, want 500ms", got)
	}

	// Update to new value.
	listener.SetPeekTimeout(2 * time.Second)
	if got := listener.PeekTimeout(); got != 2*time.Second {
		t.Errorf("after SetPeekTimeout = %v, want 2s", got)
	}
}

func TestListener_SetPeekTimeout_IgnoresNonPositive(t *testing.T) {
	handler := &slowHandler{delay: time.Millisecond, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      newTestLogger(),
		PeekTimeout: 500 * time.Millisecond,
	})

	listener.SetPeekTimeout(0)
	if got := listener.PeekTimeout(); got != 500*time.Millisecond {
		t.Errorf("after SetPeekTimeout(0) = %v, want 500ms", got)
	}

	listener.SetPeekTimeout(-1 * time.Second)
	if got := listener.PeekTimeout(); got != 500*time.Millisecond {
		t.Errorf("after SetPeekTimeout(-1s) = %v, want 500ms", got)
	}
}

func TestListener_PeekTimeout_DefaultValue(t *testing.T) {
	handler := &slowHandler{delay: time.Millisecond, name: "fast"}
	detector := &slowDetector{handler: handler}
	// PeekTimeout=0 should default to 30s.
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   newTestLogger(),
	})

	if got := listener.PeekTimeout(); got != 30*time.Second {
		t.Errorf("default PeekTimeout = %v, want 30s", got)
	}
}

func TestListener_SetPeekTimeout_TakesEffectOnNewConnections(t *testing.T) {
	handler := &slowHandler{delay: 0, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      newTestLogger(),
		PeekTimeout: 30 * time.Second, // Long initial timeout.
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

	// Set a very short peek timeout.
	listener.SetPeekTimeout(200 * time.Millisecond)

	// Connect but send no data — should be disconnected by the new short timeout.
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

	// Handler should never have been entered (peek timed out).
	if handler.entered.Load() != 0 {
		t.Errorf("handler entered = %d, want 0", handler.entered.Load())
	}
}
