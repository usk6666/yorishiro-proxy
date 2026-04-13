package connector

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestFullListener creates a FullListener bound to localhost:0 for testing.
// The caller must cancel ctx to shut down.
func newTestFullListener(t *testing.T, cfg FullListenerConfig) *FullListener {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.PeekTimeout == 0 {
		cfg.PeekTimeout = 5 * time.Second
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 10
	}
	return NewFullListener(cfg)
}

// startFullListener starts a FullListener in a goroutine and waits for ready.
func startFullListener(t *testing.T, ctx context.Context, fl *FullListener) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("FullListener.Start failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("FullListener.Ready timed out")
	}
}

func TestFullListener_AcceptAndDetect_CONNECT(t *testing.T) {
	var handled atomic.Bool

	fl := newTestFullListener(t, FullListenerConfig{
		OnCONNECT: func(ctx context.Context, pc *PeekConn) error {
			handled.Store(true)
			// Verify context is enriched
			if ConnIDFromContext(ctx) == "" {
				t.Error("expected ConnID in context")
			}
			if ClientAddrFromContext(ctx) == "" {
				t.Error("expected ClientAddr in context")
			}
			if ListenerNameFromContext(ctx) == "" {
				t.Error("expected ListenerName in context")
			}
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	// Connect and send a CONNECT request prefix
	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n"))
	conn.Close()

	// Wait for handler to fire
	deadline := time.After(3 * time.Second)
	for !handled.Load() {
		select {
		case <-deadline:
			t.Fatal("handler was not invoked within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestFullListener_AcceptAndDetect_SOCKS5(t *testing.T) {
	var handled atomic.Bool

	fl := newTestFullListener(t, FullListenerConfig{
		OnSOCKS5: func(ctx context.Context, pc *PeekConn) error {
			handled.Store(true)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// SOCKS5 greeting: version 0x05, 1 auth method, NO_AUTH
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	conn.Close()

	deadline := time.After(3 * time.Second)
	for !handled.Load() {
		select {
		case <-deadline:
			t.Fatal("handler was not invoked within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestFullListener_AcceptAndDetect_HTTP1(t *testing.T) {
	var handled atomic.Bool

	fl := newTestFullListener(t, FullListenerConfig{
		OnHTTP1: func(ctx context.Context, pc *PeekConn) error {
			handled.Store(true)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	conn.Close()

	deadline := time.After(3 * time.Second)
	for !handled.Load() {
		select {
		case <-deadline:
			t.Fatal("handler was not invoked within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestFullListener_AcceptAndDetect_HTTP2(t *testing.T) {
	var handled atomic.Bool

	fl := newTestFullListener(t, FullListenerConfig{
		OnHTTP2: func(ctx context.Context, pc *PeekConn) error {
			handled.Store(true)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// HTTP/2 connection preface
	_, _ = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	conn.Close()

	deadline := time.After(3 * time.Second)
	for !handled.Load() {
		select {
		case <-deadline:
			t.Fatal("handler was not invoked within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestFullListener_AcceptAndDetect_TCP(t *testing.T) {
	var handled atomic.Bool

	fl := newTestFullListener(t, FullListenerConfig{
		OnTCP: func(ctx context.Context, pc *PeekConn) error {
			handled.Store(true)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Binary data that doesn't match any known protocol
	_, _ = conn.Write([]byte{0xFF, 0xFE, 0xFD, 0xFC})
	conn.Close()

	deadline := time.After(3 * time.Second)
	for !handled.Load() {
		select {
		case <-deadline:
			t.Fatal("handler was not invoked within timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestFullListener_MaxConnections(t *testing.T) {
	const maxConns = 2
	var (
		mu       sync.Mutex
		handling int
		maxSeen  int
		barrier  = make(chan struct{})
	)

	fl := newTestFullListener(t, FullListenerConfig{
		MaxConnections: maxConns,
		OnTCP: func(ctx context.Context, pc *PeekConn) error {
			mu.Lock()
			handling++
			if handling > maxSeen {
				maxSeen = handling
			}
			mu.Unlock()

			// Block until test signals release
			<-barrier

			mu.Lock()
			handling--
			mu.Unlock()
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	// Open maxConns connections that will block in the handler
	conns := make([]net.Conn, maxConns)
	for i := range conns {
		c, err := net.Dial("tcp", fl.Addr())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		_, _ = c.Write([]byte{0xFF}) // trigger TCP detection
		conns[i] = c
	}

	// Wait for all handlers to be active
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		h := handling
		mu.Unlock()
		if h >= maxConns {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d/%d handlers active", h, maxConns)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	if fl.ActiveConnections() != maxConns {
		t.Errorf("ActiveConnections = %d, want %d", fl.ActiveConnections(), maxConns)
	}

	// The next connection should be rejected at capacity
	rejectedConn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial rejected: %v", err)
	}
	// The server should close this connection without processing
	_, _ = rejectedConn.Write([]byte{0xFF})
	buf := make([]byte, 1)
	_ = rejectedConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := rejectedConn.Read(buf)
	if readErr == nil {
		t.Error("expected rejected connection to be closed")
	}
	rejectedConn.Close()

	// Release blocked handlers
	close(barrier)
	for _, c := range conns {
		c.Close()
	}

	// Wait for all handlers to finish
	deadline = time.After(3 * time.Second)
	for fl.ActiveConnections() > 0 {
		select {
		case <-deadline:
			t.Fatalf("handlers did not drain, active=%d", fl.ActiveConnections())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestFullListener_PeekTimeout(t *testing.T) {
	var closedWithoutHandler atomic.Bool

	fl := newTestFullListener(t, FullListenerConfig{
		PeekTimeout: 200 * time.Millisecond,
		OnCONNECT: func(ctx context.Context, pc *PeekConn) error {
			// Should not be reached — the client sends nothing
			t.Error("handler should not be invoked for slow client")
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	// Connect but don't send any data — should be timed out by peek deadline
	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for the connection to be closed by the listener
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr != nil {
		closedWithoutHandler.Store(true)
	}

	if !closedWithoutHandler.Load() {
		t.Error("expected peek timeout to close the connection")
	}
}

func TestFullListener_GracefulShutdown(t *testing.T) {
	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})

	fl := newTestFullListener(t, FullListenerConfig{
		OnTCP: func(ctx context.Context, pc *PeekConn) error {
			close(handlerStarted)
			// Simulate a long-running handler
			<-ctx.Done()
			close(handlerDone)
			return ctx.Err()
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	startCh := make(chan error, 1)
	go func() {
		startCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-startCh:
		t.Fatalf("Start failed: %v", err)
	}

	// Open a connection and wait for handler to start
	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte{0xFF})

	select {
	case <-handlerStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not start")
	}

	// Cancel context — should trigger graceful shutdown
	cancel()

	// Handler should be notified via ctx.Done()
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish after context cancel")
	}

	// Start should return nil (graceful shutdown)
	select {
	case err := <-startCh:
		if err != nil {
			t.Fatalf("Start returned error on graceful shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after shutdown")
	}

	conn.Close()
}

func TestFullListener_NoHandler_ClosesConnection(t *testing.T) {
	// No handlers configured — connection should be closed gracefully
	fl := newTestFullListener(t, FullListenerConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n"))

	// Connection should be closed by the listener (no handler)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Error("expected connection to be closed when no handler is configured")
	}
	conn.Close()
}

func TestFullListener_Ready(t *testing.T) {
	fl := newTestFullListener(t, FullListenerConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Before Start, Ready channel should not be closed
	select {
	case <-fl.Ready():
		t.Fatal("Ready should not be closed before Start")
	default:
	}

	startFullListener(t, ctx, fl)

	// After Start completes, Ready is closed
	select {
	case <-fl.Ready():
	default:
		t.Fatal("Ready should be closed after Start")
	}
}

func TestFullListener_DefaultConfig(t *testing.T) {
	fl := NewFullListener(FullListenerConfig{
		Addr: "127.0.0.1:0",
	})

	if fl.name != "default" {
		t.Errorf("name = %q, want %q", fl.name, "default")
	}
	if fl.PeekTimeout() != DefaultPeekTimeout {
		t.Errorf("PeekTimeout = %v, want %v", fl.PeekTimeout(), DefaultPeekTimeout)
	}
	if fl.MaxConnections() != DefaultMaxConnections {
		t.Errorf("MaxConnections = %d, want %d", fl.MaxConnections(), DefaultMaxConnections)
	}
}

func TestFullListener_SetMaxConnections(t *testing.T) {
	fl := NewFullListener(FullListenerConfig{
		Addr:           "127.0.0.1:0",
		MaxConnections: 10,
	})

	if fl.MaxConnections() != 10 {
		t.Fatalf("MaxConnections = %d, want 10", fl.MaxConnections())
	}

	fl.SetMaxConnections(50)
	if fl.MaxConnections() != 50 {
		t.Errorf("MaxConnections after Set = %d, want 50", fl.MaxConnections())
	}

	// Non-positive values are ignored
	fl.SetMaxConnections(0)
	if fl.MaxConnections() != 50 {
		t.Errorf("MaxConnections after Set(0) = %d, want 50", fl.MaxConnections())
	}
	fl.SetMaxConnections(-1)
	if fl.MaxConnections() != 50 {
		t.Errorf("MaxConnections after Set(-1) = %d, want 50", fl.MaxConnections())
	}
}

func TestFullListener_SetPeekTimeout(t *testing.T) {
	fl := NewFullListener(FullListenerConfig{
		Addr:        "127.0.0.1:0",
		PeekTimeout: 5 * time.Second,
	})

	if fl.PeekTimeout() != 5*time.Second {
		t.Fatalf("PeekTimeout = %v, want 5s", fl.PeekTimeout())
	}

	fl.SetPeekTimeout(10 * time.Second)
	if fl.PeekTimeout() != 10*time.Second {
		t.Errorf("PeekTimeout after Set = %v, want 10s", fl.PeekTimeout())
	}

	// Non-positive values are ignored
	fl.SetPeekTimeout(0)
	if fl.PeekTimeout() != 10*time.Second {
		t.Errorf("PeekTimeout after Set(0) = %v, want 10s", fl.PeekTimeout())
	}
}

func TestFullListener_Addr(t *testing.T) {
	fl := newTestFullListener(t, FullListenerConfig{})

	// Before Start, Addr is empty
	if addr := fl.Addr(); addr != "" {
		t.Errorf("Addr before Start = %q, want empty", addr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	// After Start, Addr is non-empty
	addr := fl.Addr()
	if addr == "" {
		t.Error("Addr after Start should be non-empty")
	}

	// Should be a valid host:port
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Errorf("Addr %q is not valid host:port: %v", addr, err)
	}
}

func TestFullListener_MultipleProtocols(t *testing.T) {
	var (
		connectCount atomic.Int32
		socks5Count  atomic.Int32
		http1Count   atomic.Int32
		tcpCount     atomic.Int32
	)

	fl := newTestFullListener(t, FullListenerConfig{
		OnCONNECT: func(ctx context.Context, pc *PeekConn) error {
			connectCount.Add(1)
			return nil
		},
		OnSOCKS5: func(ctx context.Context, pc *PeekConn) error {
			socks5Count.Add(1)
			return nil
		},
		OnHTTP1: func(ctx context.Context, pc *PeekConn) error {
			http1Count.Add(1)
			return nil
		},
		OnTCP: func(ctx context.Context, pc *PeekConn) error {
			tcpCount.Add(1)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	addr := fl.Addr()
	sends := []struct {
		data []byte
		name string
	}{
		{[]byte("CONNECT example.com:443 HTTP/1.1\r\n"), "CONNECT"},
		{[]byte{0x05, 0x01, 0x00}, "SOCKS5"},
		{[]byte("GET / HTTP/1.1\r\n"), "HTTP/1.x"},
		{[]byte{0xFF, 0xFE}, "TCP"},
	}

	for _, s := range sends {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial for %s: %v", s.name, err)
		}
		_, _ = conn.Write(s.data)
		conn.Close()
	}

	// Wait for all handlers to complete
	deadline := time.After(5 * time.Second)
	for {
		total := connectCount.Load() + socks5Count.Load() + http1Count.Load() + tcpCount.Load()
		if total >= 4 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("handlers did not all fire: CONNECT=%d SOCKS5=%d HTTP1=%d TCP=%d",
				connectCount.Load(), socks5Count.Load(), http1Count.Load(), tcpCount.Load())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	if v := connectCount.Load(); v != 1 {
		t.Errorf("CONNECT count = %d, want 1", v)
	}
	if v := socks5Count.Load(); v != 1 {
		t.Errorf("SOCKS5 count = %d, want 1", v)
	}
	if v := http1Count.Load(); v != 1 {
		t.Errorf("HTTP1 count = %d, want 1", v)
	}
	if v := tcpCount.Load(); v != 1 {
		t.Errorf("TCP count = %d, want 1", v)
	}
}

func TestFullListener_HandlerError_Logged(t *testing.T) {
	var handled atomic.Bool

	fl := newTestFullListener(t, FullListenerConfig{
		OnTCP: func(ctx context.Context, pc *PeekConn) error {
			handled.Store(true)
			return fmt.Errorf("intentional test error")
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte{0xFF})
	conn.Close()

	deadline := time.After(3 * time.Second)
	for !handled.Load() {
		select {
		case <-deadline:
			t.Fatal("handler was not invoked")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	// If we got here, the handler error was handled gracefully
	// (not panicked, connection cleaned up)
}

func TestFullListener_ListenerName_InContext(t *testing.T) {
	const customName = "test-listener"
	var gotName string
	var done = make(chan struct{})

	fl := newTestFullListener(t, FullListenerConfig{
		Name: customName,
		OnTCP: func(ctx context.Context, pc *PeekConn) error {
			gotName = ListenerNameFromContext(ctx)
			close(done)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFullListener(t, ctx, fl)

	conn, err := net.Dial("tcp", fl.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte{0xFF})
	conn.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler not invoked")
	}

	if gotName != customName {
		t.Errorf("ListenerName = %q, want %q", gotName, customName)
	}
}
