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

func newTestCAAndIssuer(t *testing.T) (*cert.CA, *cert.Issuer) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	issuer := cert.NewIssuer(ca)
	return ca, issuer
}

func TestTCPForwardListener_TLS_MITM_EchoHandler(t *testing.T) {
	ca, issuer := newTestCAAndIssuer(t)

	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "echo.example.com:443",
			Protocol: "raw",
			TLS:      true,
		},
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

	// Create a TLS client that trusts the test CA.
	caCert, _ := ca.SigningPair()
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			ServerName: "echo.example.com",
			RootCAs:    certPool,
		},
	)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer tlsConn.Close()

	// Verify the MITM certificate CN matches the target hostname.
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn != "echo.example.com" {
		t.Errorf("certificate CN = %q, want %q", cn, "echo.example.com")
	}

	// Verify data flows through TLS tunnel by writing and reading echo.
	// Use a goroutine for the write side to avoid deadlock with io.Copy.
	testData := []byte("hello tls mitm")
	writeDone := make(chan error, 1)
	go func() {
		_, werr := tlsConn.Write(testData)
		if werr != nil {
			writeDone <- werr
			return
		}
		// Close the write side to signal EOF so io.Copy returns.
		tlsConn.CloseWrite()
		writeDone <- nil
	}()

	buf, readErr := io.ReadAll(tlsConn)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}

	if werr := <-writeDone; werr != nil {
		t.Fatalf("write: %v", werr)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf, testData)
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_MITM_SNIDiffersFromTarget(t *testing.T) {
	ca, issuer := newTestCAAndIssuer(t)

	handler := &echoHandler{}

	// Use a closed localhost port as target to avoid DNS resolution and
	// connection timeout when the handler attempts to dial upstream.
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, unreachablePort, _ := net.SplitHostPort(tmpLn.Addr().String())
	tmpLn.Close()

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "127.0.0.1:" + unreachablePort,
			Protocol: "raw",
			TLS:      true,
		},
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

	caCert, _ := ca.SigningPair()
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	// Connect with a different SNI than the target hostname.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			ServerName: "different.example.com",
			RootCAs:    certPool,
		},
	)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer tlsConn.Close()

	// Certificate should use the SNI value, not the target.
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn != "different.example.com" {
		t.Errorf("certificate CN = %q, want %q (should match SNI)", cn, "different.example.com")
	}

	tlsConn.Close()
	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		// Listener may take a moment to shut down.
	}
}

func TestTCPForwardListener_TLS_False_NoTermination(t *testing.T) {
	// When TLS is false, the connection should be passed through as-is
	// (no TLS termination). The echo handler should see raw bytes.
	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Logger:  testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "example.com:80",
			Protocol: "raw",
			TLS:      false,
		},
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

	// Plain TCP connection should work without TLS.
	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	testData := []byte("plaintext data")
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

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_NonTLSClient_GracefulFallback(t *testing.T) {
	// When TLS is true but the client sends non-TLS data, the connection
	// should gracefully fall back to cleartext processing.
	handler := &echoHandler{}
	_, issuer := newTestCAAndIssuer(t)

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "example.com:443",
			Protocol: "raw",
			TLS:      true,
		},
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

	// Send plaintext data to a TLS-configured port.
	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	testData := []byte("not TLS data")
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

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_NoIssuer_ClosesConnection(t *testing.T) {
	// When TLS is true but no issuer is configured, the connection should be closed.
	handlerCalled := make(chan struct{}, 1)
	handler := &namedHandler{
		name: "test",
		handleFunc: func(_ context.Context, _ net.Conn) error {
			handlerCalled <- struct{}{}
			return nil
		},
	}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  nil, // no issuer
		Logger:  testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "example.com:443",
			Protocol: "raw",
			TLS:      true,
		},
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

	// Send TLS ClientHello bytes.
	conn, err := net.DialTimeout("tcp", fl.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Write a minimal TLS ClientHello header.
	conn.Write([]byte{0x16, 0x03, 0x01})
	conn.Close()

	// Handler should NOT be called (connection should be dropped).
	select {
	case <-handlerCalled:
		t.Error("handler should not have been called when issuer is nil")
	case <-time.After(200 * time.Millisecond):
		// Expected: handler was not called.
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_MITM_AutoProtocolDetection(t *testing.T) {
	// Verify that after TLS termination, auto protocol detection
	// can identify the cleartext protocol.
	ca, issuer := newTestCAAndIssuer(t)

	handlerCalled := make(chan string, 1)
	httpHandler := &namedHandler{name: "HTTP/1.x"}
	httpHandler.handleFunc = func(_ context.Context, conn net.Conn) error {
		handlerCalled <- "HTTP/1.x"
		return nil
	}

	detector := &staticDetector{handler: httpHandler}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:     "127.0.0.1:0",
		Handler:  &echoHandler{}, // fallback
		Detector: detector,
		Issuer:   issuer,
		Logger:   testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "api.example.com:443",
			Protocol: "auto",
			TLS:      true,
		},
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

	caCert, _ := ca.SigningPair()
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			ServerName: "api.example.com",
			RootCAs:    certPool,
		},
	)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}

	// Write HTTP-like data after TLS handshake.
	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"))
	tlsConn.Close()

	select {
	case got := <-handlerCalled:
		if got != "HTTP/1.x" {
			t.Errorf("handler = %q, want HTTP/1.x", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler dispatch after TLS termination")
	}

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_MITM_ALPN(t *testing.T) {
	ca, issuer := newTestCAAndIssuer(t)

	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "h2.example.com:443",
			Protocol: "raw",
			TLS:      true,
		},
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

	caCert, _ := ca.SigningPair()
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	// Connect requesting h2 via ALPN.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			ServerName: "h2.example.com",
			RootCAs:    certPool,
			NextProtos: []string{"h2", "http/1.1"},
		},
	)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer tlsConn.Close()

	// Verify ALPN negotiation.
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN = %q, want %q", state.NegotiatedProtocol, "h2")
	}

	// Close connection before cancel to unblock echoHandler's io.Copy.
	tlsConn.Close()

	cancel()
	<-errCh
}

func TestTCPForwardListener_TLS_MITM_IPAddress_Target(t *testing.T) {
	// When target is an IP address, certificate should use IP SAN.
	ca, issuer := newTestCAAndIssuer(t)

	handler := &echoHandler{}

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: handler,
		Issuer:  issuer,
		Logger:  testutil.DiscardLogger(),
		Config: &config.ForwardConfig{
			Target:   "127.0.0.1:8443",
			Protocol: "raw",
			TLS:      true,
		},
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

	caCert, _ := ca.SigningPair()
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	// Connect without SNI (IP address connection).
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fl.Addr(),
		&tls.Config{
			// No ServerName — mimics IP-based connection.
			// Use InsecureSkipVerify since IP cert verification
			// needs manual checking.
			InsecureSkipVerify: true,
		},
	)
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	cert := state.PeerCertificates[0]
	if cn := cert.Subject.CommonName; cn != "127.0.0.1" {
		t.Errorf("certificate CN = %q, want %q", cn, "127.0.0.1")
	}

	// Verify IP SAN is set (not DNS SAN) for IP-based targets.
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("certificate IPAddresses = %v, want to contain 127.0.0.1", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("certificate DNSNames = %v, want empty for IP target", cert.DNSNames)
	}

	cancel()
	<-errCh
}
