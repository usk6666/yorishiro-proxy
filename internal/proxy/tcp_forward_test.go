package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
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

// newTestCAAndIssuer creates a test CA and Issuer for TLS tests.
func newTestCAAndIssuer(t *testing.T) (*cert.CA, *cert.Issuer, *x509.CertPool) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	return ca, issuer, pool
}

func TestTCPForwardListener_TLS_Termination(t *testing.T) {
	// Verify that when TLS=true, the listener terminates TLS and passes
	// cleartext to the handler.
	_, issuer, certPool := newTestCAAndIssuer(t)

	handlerCalled := make(chan string, 1)
	handler := &namedHandler{name: "test-handler"}
	handler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		// Read data from the cleartext connection.
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		handlerCalled <- string(buf[:n])
		return nil
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config:  &config.ForwardConfig{Target: "example.com:443", Protocol: "raw", TLS: true},
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

	// Connect with TLS.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			RootCAs:    certPool,
			ServerName: "example.com",
		},
	)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}

	// Send data through the TLS connection.
	testData := "hello-tls"
	if _, err := tlsConn.Write([]byte(testData)); err != nil {
		t.Fatalf("write: %v", err)
	}
	tlsConn.Close()

	select {
	case got := <-handlerCalled:
		if got != testData {
			t.Errorf("handler received %q, want %q", got, testData)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler to receive data")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_CertificateHostname(t *testing.T) {
	// Verify that the MITM certificate is issued for the target hostname.
	_, issuer, certPool := newTestCAAndIssuer(t)

	certHostCh := make(chan string, 1)
	handler := &namedHandler{name: "test-handler"}
	handler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		return nil
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config:  &config.ForwardConfig{Target: "api.example.com:50051", Protocol: "raw", TLS: true},
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

	// Connect with TLS, verify peer certificate.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			RootCAs:    certPool,
			ServerName: "api.example.com",
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
					certHostCh <- verifiedChains[0][0].Subject.CommonName
				}
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	tlsConn.Close()

	select {
	case cn := <-certHostCh:
		if cn != "api.example.com" {
			t.Errorf("certificate CN = %q, want %q", cn, "api.example.com")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for certificate verification")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_SNIOverride(t *testing.T) {
	// When client sends SNI different from the target hostname, the certificate
	// should use the SNI value.
	_, issuer, certPool := newTestCAAndIssuer(t)

	handler := &namedHandler{name: "test-handler"}
	handler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		return nil
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config:  &config.ForwardConfig{Target: "default.example.com:443", Protocol: "raw", TLS: true},
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

	// Connect with a different SNI.
	sniCertCh := make(chan string, 1)
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			RootCAs:    certPool,
			ServerName: "override.example.com",
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
					sniCertCh <- verifiedChains[0][0].Subject.CommonName
				}
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	tlsConn.Close()

	select {
	case cn := <-sniCertCh:
		if cn != "override.example.com" {
			t.Errorf("certificate CN = %q, want %q (SNI override)", cn, "override.example.com")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for certificate verification")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_NoClientHello_FallbackCleartext(t *testing.T) {
	// When TLS=true but client sends non-TLS data, the connection should
	// fall back to cleartext handling.
	_, issuer, _ := newTestCAAndIssuer(t)

	handlerCalled := make(chan string, 1)
	handler := &namedHandler{name: "test-handler"}
	handler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		handlerCalled <- string(buf[:n])
		return nil
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config:  &config.ForwardConfig{Target: "example.com:443", Protocol: "raw", TLS: true},
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

	// Connect with plain TCP (no TLS).
	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	testData := "plain-data"
	if _, err := conn.Write([]byte(testData)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	select {
	case got := <-handlerCalled:
		if got != testData {
			t.Errorf("handler received %q, want %q", got, testData)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler to receive data")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_False_NoTermination(t *testing.T) {
	// When TLS=false (default), no TLS termination should occur even if
	// the client sends TLS data. The raw handler should receive the TLS bytes.
	handler := &namedHandler{name: "raw-handler"}
	gotCh := make(chan []byte, 1)
	handler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		gotCh <- buf[:n]
		return nil
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Logger:  testutil.DiscardLogger(),
		Config:  &config.ForwardConfig{Target: "example.com:443", Protocol: "raw", TLS: false},
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

	// Send fake TLS-like bytes (0x16, 0x03 prefix).
	fakeData := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if _, err := conn.Write(fakeData); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	select {
	case got := <-gotCh:
		// Handler should receive the raw bytes, not decrypted.
		if got[0] != 0x16 || got[1] != 0x03 {
			t.Errorf("handler received unexpected first bytes: %x", got[:2])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_NoIssuer(t *testing.T) {
	// When TLS=true but no issuer is configured, the connection should be closed.
	handler := &namedHandler{name: "test-handler"}
	handler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		return nil
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  nil, // No issuer
		Logger:  testutil.DiscardLogger(),
		Config:  &config.ForwardConfig{Target: "example.com:443", Protocol: "raw", TLS: true},
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

	// Send a TLS ClientHello-like data.
	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte{0x16, 0x03})

	// Connection should be closed by the proxy since no issuer is available.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Error("expected connection to be closed when no issuer configured")
	}
	conn.Close()

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_AutoMode(t *testing.T) {
	// Verify TLS termination works with auto protocol detection.
	_, issuer, certPool := newTestCAAndIssuer(t)

	handlerCalled := make(chan string, 1)
	httpHandler := &namedHandler{name: "HTTP/1.x"}
	httpHandler.handleFunc = func(ctx context.Context, conn net.Conn) error {
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		handlerCalled <- string(buf[:n])
		return nil
	}

	detector := &staticDetector{handler: httpHandler}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:     "127.0.0.1:0",
		Handler:  &echoHandler{}, // fallback
		Detector: detector,
		Issuer:   issuer,
		Logger:   testutil.DiscardLogger(),
		Config:   &config.ForwardConfig{Target: "example.com:443", Protocol: "auto", TLS: true},
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

	// Connect with TLS and send HTTP-like data.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			RootCAs:    certPool,
			ServerName: "example.com",
		},
	)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}

	httpReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("write: %v", err)
	}
	tlsConn.Close()

	select {
	case got := <-handlerCalled:
		if len(got) == 0 {
			t.Error("handler received empty data")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler")
	}

	cancel()
	<-errCh
}
