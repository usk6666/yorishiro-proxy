package proxy_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// slowHandler is a ProtocolHandler that blocks for a configured duration.
type slowHandler struct {
	delay   time.Duration
	handled atomic.Int32
	entered atomic.Int32
	name    string
}

func (h *slowHandler) Name() string         { return h.name }
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
		Logger:   testutil.DiscardLogger(),
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
		Logger:   testutil.DiscardLogger(),
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
		Logger:   testutil.DiscardLogger(),
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
		Logger:         testutil.DiscardLogger(),
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
		Logger:         testutil.DiscardLogger(),
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

func TestListener_ActiveConnections_NoSemaphore(t *testing.T) {
	// With MaxConnections < 0 (or not set), sem is nil-equivalent but default applies.
	// Default is 1024 so sem will always be non-nil. Test with a configured value.
	handler := &slowHandler{delay: 500 * time.Millisecond, name: "slow"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Logger:         testutil.DiscardLogger(),
		MaxConnections: 10,
	})

	// Before starting, ActiveConnections should be 0.
	if got := listener.ActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections before start = %d, want 0", got)
	}

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

	// Still 0 with no connections.
	if got := listener.ActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections with no conns = %d, want 0", got)
	}

	// Open 2 connections.
	conn1 := dialAndSend(t, listener.Addr())
	defer conn1.Close()
	conn2 := dialAndSend(t, listener.Addr())
	defer conn2.Close()

	if !waitForEntered(handler, 2, 2*time.Second) {
		t.Fatalf("only %d/2 handlers entered", handler.entered.Load())
	}

	active := listener.ActiveConnections()
	if active != 2 {
		t.Errorf("ActiveConnections = %d, want 2", active)
	}
}

func TestListener_SetMaxConnections_RejectsAfterReduction(t *testing.T) {
	handler := &slowHandler{delay: 2 * time.Second, name: "slow"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Logger:         testutil.DiscardLogger(),
		MaxConnections: 10,
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

	// Open 3 connections (within the limit of 10).
	conns := make([]net.Conn, 3)
	for i := range conns {
		conns[i] = dialAndSend(t, listener.Addr())
		defer conns[i].Close()
	}

	if !waitForEntered(handler, 3, 2*time.Second) {
		t.Fatalf("only %d/3 handlers entered", handler.entered.Load())
	}

	// Verify 3 active connections.
	if got := listener.ActiveConnections(); got != 3 {
		t.Fatalf("ActiveConnections = %d, want 3", got)
	}

	// Reduce the limit below the current active count.
	listener.SetMaxConnections(2)

	if got := listener.MaxConnections(); got != 2 {
		t.Fatalf("MaxConnections = %d, want 2", got)
	}

	// New connection should be rejected because activeConns (3) > new limit (2).
	rejConn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rejConn.Close()

	rejConn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))

	buf := make([]byte, 1)
	rejConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = rejConn.Read(buf)
	if err == nil {
		t.Fatal("expected error reading from rejected connection after limit reduction")
	}

	// Only the original 3 handlers should have been entered.
	if got := handler.entered.Load(); got != 3 {
		t.Errorf("handler entered = %d, want 3", got)
	}
}

func TestListener_SetMaxConnections_IgnoresInvalid(t *testing.T) {
	handler := &slowHandler{delay: 0, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Logger:         testutil.DiscardLogger(),
		MaxConnections: 5,
	})

	// Zero and negative values should be ignored.
	listener.SetMaxConnections(0)
	if got := listener.MaxConnections(); got != 5 {
		t.Errorf("MaxConnections after SetMaxConnections(0) = %d, want 5", got)
	}

	listener.SetMaxConnections(-1)
	if got := listener.MaxConnections(); got != 5 {
		t.Errorf("MaxConnections after SetMaxConnections(-1) = %d, want 5", got)
	}

	// Positive values should be accepted.
	listener.SetMaxConnections(10)
	if got := listener.MaxConnections(); got != 10 {
		t.Errorf("MaxConnections after SetMaxConnections(10) = %d, want 10", got)
	}
}

func TestListener_PeekTimeout_DisconnectsSlowClient(t *testing.T) {
	handler := &slowHandler{delay: 0, name: "fast"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      testutil.DiscardLogger(),
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

// socks5Handler is a ProtocolHandler that detects SOCKS5 from the first byte.
type socks5Handler struct {
	entered atomic.Int32
}

func (h *socks5Handler) Name() string { return "SOCKS5" }
func (h *socks5Handler) Detect(peek []byte) bool {
	return len(peek) >= 1 && peek[0] == 0x05
}
func (h *socks5Handler) Handle(_ context.Context, conn net.Conn) error {
	h.entered.Add(1)
	defer conn.Close()
	return nil
}

// httpHandler is a ProtocolHandler that detects HTTP from a method prefix.
type httpHandler struct {
	entered atomic.Int32
}

func (h *httpHandler) Name() string { return "HTTP" }
func (h *httpHandler) Detect(peek []byte) bool {
	return len(peek) >= 4 && string(peek[:4]) == "GET "
}
func (h *httpHandler) Handle(_ context.Context, conn net.Conn) error {
	h.entered.Add(1)
	defer conn.Close()
	return nil
}

// catchAllHandler is a ProtocolHandler whose Detect always returns true,
// simulating the raw TCP fallback handler.
type catchAllHandler struct {
	entered atomic.Int32
}

func (h *catchAllHandler) Name() string { return "TCP" }
func (h *catchAllHandler) Detect(_ []byte) bool {
	return true
}
func (h *catchAllHandler) Handle(_ context.Context, conn net.Conn) error {
	h.entered.Add(1)
	defer conn.Close()
	return nil
}

// multiDetector returns the first handler whose Detect returns true.
type multiDetector struct {
	handlers []proxy.ProtocolHandler
}

func (d *multiDetector) Detect(peek []byte) proxy.ProtocolHandler {
	for _, h := range d.handlers {
		if h.Detect(peek) {
			return h
		}
	}
	return nil
}

func TestListener_TwoStagePeek_SOCKS5DetectedQuickly(t *testing.T) {
	socks := &socks5Handler{}
	http := &httpHandler{}
	detector := &multiDetector{handlers: []proxy.ProtocolHandler{socks, http}}

	// Use a long peek timeout to verify that SOCKS5 does NOT wait for it.
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      testutil.DiscardLogger(),
		PeekTimeout: 10 * time.Second,
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

	// Send a SOCKS5 client greeting (3 bytes, fewer than peekSize=16).
	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting: version=0x05, nmethods=1, method=0x00 (NO AUTH)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write socks5 greeting: %v", err)
	}

	// The handler should be entered quickly (well under peek timeout).
	start := time.Now()
	deadline := time.Now().Add(2 * time.Second)
	for socks.entered.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(start)

	if socks.entered.Load() != 1 {
		t.Fatal("SOCKS5 handler was never entered")
	}

	// Must complete in well under 1 second (the peek timeout is 10s).
	if elapsed > 1*time.Second {
		t.Errorf("SOCKS5 detection took %v, expected < 1s (peek_timeout=10s)", elapsed)
	}
}

func TestListener_TwoStagePeek_HTTPStillWorks(t *testing.T) {
	socks := &socks5Handler{}
	http := &httpHandler{}
	detector := &multiDetector{handlers: []proxy.ProtocolHandler{socks, http}}

	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      testutil.DiscardLogger(),
		PeekTimeout: 5 * time.Second,
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

	// Send a full HTTP request (more than peekSize bytes).
	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for http.entered.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if http.entered.Load() != 1 {
		t.Fatal("HTTP handler was never entered")
	}
	if socks.entered.Load() != 0 {
		t.Errorf("SOCKS5 handler entered = %d, want 0", socks.entered.Load())
	}
}

func TestListener_TwoStagePeek_NoMatch(t *testing.T) {
	socks := &socks5Handler{}
	http := &httpHandler{}
	detector := &multiDetector{handlers: []proxy.ProtocolHandler{socks, http}}

	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      testutil.DiscardLogger(),
		PeekTimeout: 500 * time.Millisecond,
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

	// Send unrecognized data (not SOCKS5, not HTTP).
	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0xFF, 0xFE, 0xFD, 0xFC}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Connection should be closed (no handler matched).
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected error reading from connection with no matching handler")
	}

	if socks.entered.Load() != 0 {
		t.Errorf("SOCKS5 handler entered = %d, want 0", socks.entered.Load())
	}
	if http.entered.Load() != 0 {
		t.Errorf("HTTP handler entered = %d, want 0", http.entered.Load())
	}
}

func TestListener_TwoStagePeek_QuickMatchSkipsFullPeek(t *testing.T) {
	// Verify that when the first-stage peek matches, the handler is dispatched
	// without waiting for more bytes. We do this by sending only 1 byte
	// (SOCKS5 version) and verifying the handler is entered promptly.
	socks := &socks5Handler{}
	detector := &multiDetector{handlers: []proxy.ProtocolHandler{socks}}

	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      testutil.DiscardLogger(),
		PeekTimeout: 10 * time.Second,
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

	// Send only 1 byte: SOCKS5 version.
	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05}); err != nil {
		t.Fatalf("write: %v", err)
	}

	start := time.Now()
	deadline := time.Now().Add(2 * time.Second)
	for socks.entered.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(start)

	if socks.entered.Load() != 1 {
		t.Fatal("SOCKS5 handler was never entered with single byte")
	}

	if elapsed > 1*time.Second {
		t.Errorf("single-byte SOCKS5 detection took %v, expected < 1s", elapsed)
	}
}

func TestListener_TwoStagePeek_PartialHTTPFallsThrough(t *testing.T) {
	// Send just "G" (1 byte) which doesn't match SOCKS5 (0x05) or HTTP ("GET ").
	// After full peek timeout with only 1 byte available beyond the quick peek,
	// the handler should not match.
	http := &httpHandler{}
	detector := &multiDetector{handlers: []proxy.ProtocolHandler{http}}

	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      testutil.DiscardLogger(),
		PeekTimeout: 500 * time.Millisecond,
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

	// Send only "G" — not enough for HTTP detection ("GET " needs 4 bytes).
	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("G")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Connection should be closed after peek timeout (no handler matched).
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected error reading from connection with partial HTTP data")
	}

	if http.entered.Load() != 0 {
		t.Errorf("HTTP handler entered = %d, want 0 (only 1 byte sent)", http.entered.Load())
	}
}

func TestListener_TwoStagePeek_CatchAllDoesNotShortCircuitHTTP(t *testing.T) {
	// Regression test for S-1: a catch-all handler (raw TCP) whose Detect
	// always returns true must not prevent HTTP detection on stage 2.
	// Production handler order: http, socks5, tcp (catch-all last).
	httpH := &httpHandler{}
	socks := &socks5Handler{}
	catchAll := &catchAllHandler{}
	detector := &multiDetector{handlers: []proxy.ProtocolHandler{httpH, socks, catchAll}}

	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      testutil.DiscardLogger(),
		PeekTimeout: 5 * time.Second,
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

	// Send a full HTTP request — more than peekSize bytes arrive in one write.
	conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for httpH.entered.Load() < 1 && catchAll.entered.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if httpH.entered.Load() != 1 {
		t.Errorf("HTTP handler entered = %d, want 1", httpH.entered.Load())
	}
	if catchAll.entered.Load() != 0 {
		t.Errorf("catch-all handler entered = %d, want 0 (HTTP should take priority)", catchAll.entered.Load())
	}
}
