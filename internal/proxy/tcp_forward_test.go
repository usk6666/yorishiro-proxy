package proxy_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// echoHandler is defined in manager_test.go

func TestTCPForwardListener_StartStop(t *testing.T) {
	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Logger:  testutil.DiscardLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	// Wait for the listener to be ready.
	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	addr := fl.Addr()
	if addr == "" {
		t.Fatal("expected non-empty address after Start")
	}

	// Verify we can connect.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	// Write data and verify echo.
	testData := []byte("hello tcp forward")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	conn.Close()

	// Stop the listener.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Start to return")
	}
}

func TestTCPForwardListener_InvalidAddr(t *testing.T) {
	handler := &echoHandler{}

	// Use an invalid address that will fail to bind.
	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "192.0.2.1:0",
		Handler: handler,
		Logger:  testutil.DiscardLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := fl.Start(ctx)
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestTCPForwardListener_AddrBeforeStart(t *testing.T) {
	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Logger:  testutil.DiscardLogger(),
	})

	// Addr should be empty before Start.
	if addr := fl.Addr(); addr != "" {
		t.Errorf("Addr before Start = %q, want empty", addr)
	}
}

func TestTCPForwardListener_MultipleConnections(t *testing.T) {
	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Logger:  testutil.DiscardLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	addr := fl.Addr()

	// Open multiple concurrent connections, verify echo, and close each.
	const numConns = 5
	for i := range numConns {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}

		testData := []byte("test data")
		if _, err := conn.Write(testData); err != nil {
			conn.Close()
			t.Fatalf("write %d: %v", i, err)
		}

		buf := make([]byte, len(testData))
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			t.Fatalf("read %d: %v", i, err)
		}

		if string(buf) != string(testData) {
			t.Errorf("conn %d echo mismatch: got %q, want %q", i, buf, testData)
		}

		conn.Close()
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_ConnectionLimit(t *testing.T) {
	handler := &slowHandler{delay: 500 * time.Millisecond, name: "slow"}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:           "127.0.0.1:0",
		Handler:        handler,
		Logger:         testutil.DiscardLogger(),
		MaxConnections: 2,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	addr := fl.Addr()

	// Open 2 connections (max).
	var conns []net.Conn
	for i := range 2 {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, conn)
	}

	// Give time for connections to be accepted.
	time.Sleep(50 * time.Millisecond)

	if got := fl.ActiveConnections(); got != 2 {
		t.Errorf("ActiveConnections = %d, want 2", got)
	}

	// Third connection should be accepted at TCP level but rejected by the listener.
	conn3, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		// Dial itself failed — connection limit is enforced at the OS/listener level.
		// This is acceptable; the limit is working.
		t.Logf("dial was rejected directly (connection limit enforced at dial): %v", err)
	} else {
		// The connection was accepted at TCP level; verify the server closes it.
		conn3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 1)
		_, readErr := conn3.Read(buf)
		if readErr == nil {
			t.Error("expected connection to be closed by server when at capacity")
		}
		conn3.Close()
	}

	// Clean up.
	for _, c := range conns {
		c.Close()
	}
	cancel()
	<-errCh
}

func TestTCPForwardListener_ForwardTarget_InContext(t *testing.T) {
	// Verify that the forwarding target is injected into the context.
	targetCh := make(chan string, 1)
	handler := &contextCapturingHandler{
		extractFunc: proxy.ForwardTargetFromContext,
		resultCh:    targetCh,
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Logger:  testutil.DiscardLogger(),
		Config:  &config.ForwardConfig{Target: "api.example.com:50051", Protocol: "raw"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	select {
	case got := <-targetCh:
		if got != "api.example.com:50051" {
			t.Errorf("ForwardTarget = %q, want %q", got, "api.example.com:50051")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for context capture")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_AutoMode_WithDetector(t *testing.T) {
	// Verify that "auto" mode uses the detector.
	nameCh := make(chan string, 1)
	httpHandler := &namedHandler{name: "HTTP/1.x"}
	httpHandler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		nameCh <- "HTTP/1.x"
		return nil
	}

	detector := &staticDetector{handler: httpHandler}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:     "127.0.0.1:0",
		Handler:  &echoHandler{}, // fallback
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
		Config:   &config.ForwardConfig{Target: "example.com:80", Protocol: "auto"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Write some data so peek can succeed.
	conn.Write([]byte("GET / HTTP/1.1\r\n"))
	conn.Close()

	select {
	case got := <-nameCh:
		if got != "HTTP/1.x" {
			t.Errorf("handler = %q, want HTTP/1.x", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler dispatch")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_RawMode_SkipsDetector(t *testing.T) {
	// Verify that "raw" mode skips the detector and uses the fallback handler directly.
	nameCh := make(chan string, 1)
	fallback := &namedHandler{name: "raw-fallback"}
	fallback.handleFunc = func(ctx context.Context, conn net.Conn) error {
		nameCh <- "raw-fallback"
		return nil
	}

	detector := &staticDetector{handler: &namedHandler{name: "should-not-be-used"}}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:     "127.0.0.1:0",
		Handler:  fallback,
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
		Config:   &config.ForwardConfig{Target: "example.com:80", Protocol: "raw"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fl.Start(ctx)
	}()

	select {
	case <-fl.Ready():
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	}

	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	select {
	case got := <-nameCh:
		if got != "raw-fallback" {
			t.Errorf("handler = %q, want raw-fallback", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler dispatch")
	}

	cancel()
	<-errCh
}

// slowHandler is defined in listener_test.go

// contextCapturingHandler calls extractFunc on the context and sends the result to resultCh.
type contextCapturingHandler struct {
	extractFunc func(context.Context) (string, bool)
	resultCh    chan string
}

func (h *contextCapturingHandler) Name() string         { return "ctx-capture" }
func (h *contextCapturingHandler) Detect(_ []byte) bool { return true }
func (h *contextCapturingHandler) Handle(ctx context.Context, _ net.Conn) error {
	val, _ := h.extractFunc(ctx)
	h.resultCh <- val
	return nil
}

// namedHandler is a configurable handler for testing protocol dispatch.
type namedHandler struct {
	name       string
	handleFunc func(context.Context, net.Conn) error
}

func (h *namedHandler) Name() string         { return h.name }
func (h *namedHandler) Detect(_ []byte) bool { return true }
func (h *namedHandler) Handle(ctx context.Context, conn net.Conn) error {
	if h.handleFunc != nil {
		return h.handleFunc(ctx, conn)
	}
	return nil
}

// staticDetector always returns the configured handler.
type staticDetector struct {
	handler proxy.ProtocolHandler
}

func (d *staticDetector) Detect(_ []byte) proxy.ProtocolHandler {
	return d.handler
}
