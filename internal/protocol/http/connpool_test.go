package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// connpoolMockTLSTransport implements httputil.TLSTransport for testing.
type connpoolMockTLSTransport struct {
	alpn    string
	err     error
	called  bool
	gotName string
}

func (m *connpoolMockTLSTransport) TLSConnect(_ context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	m.called = true
	m.gotName = serverName
	if m.err != nil {
		return nil, "", m.err
	}
	return conn, m.alpn, nil
}

// generateTestTLSConfig creates a self-signed TLS config for testing.
func generateTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
}

func TestConnPool_Get_DirectPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	pool := &ConnPool{
		DialTimeout: 5 * time.Second,
	}
	defer pool.Close()

	ctx := context.Background()
	result, err := pool.Get(ctx, ln.Addr().String(), false, "")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer result.Conn.Close()

	if result.ALPN != "" {
		t.Errorf("ALPN = %q, want empty for plaintext", result.ALPN)
	}
	if result.ConnectDuration <= 0 {
		t.Errorf("ConnectDuration = %v, want > 0", result.ConnectDuration)
	}
}

func TestConnPool_Get_DirectTLS(t *testing.T) {
	tlsCfg := generateTestTLSConfig(t)

	// Use a raw TCP listener; do server-side TLS handshake in the goroutine.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Perform server-side TLS handshake.
		tlsConn := tls.Server(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		// Keep connection open until the client closes.
		buf := make([]byte, 1)
		tlsConn.Read(buf)
	}()

	pool := &ConnPool{
		TLSTransport: &httputil.StandardTransport{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		},
		DialTimeout: 5 * time.Second,
	}
	defer pool.Close()

	ctx := context.Background()
	result, err := pool.Get(ctx, ln.Addr().String(), true, "localhost")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer result.Conn.Close()

	if result.ALPN != "http/1.1" {
		t.Errorf("ALPN = %q, want %q", result.ALPN, "http/1.1")
	}
	if result.ConnectDuration <= 0 {
		t.Errorf("ConnectDuration = %v, want > 0", result.ConnectDuration)
	}
}

func TestConnPool_Get_TLSError(t *testing.T) {
	mockTLS := &connpoolMockTLSTransport{
		err: fmt.Errorf("tls handshake failed"),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	pool := &ConnPool{
		TLSTransport: mockTLS,
		DialTimeout:  5 * time.Second,
	}

	ctx := context.Background()
	_, err = pool.Get(ctx, ln.Addr().String(), true, "example.com")
	if err == nil {
		t.Fatal("Get() expected error for TLS failure")
	}
	if !strings.Contains(err.Error(), "tls handshake failed") {
		t.Errorf("error = %v, want to contain 'tls handshake failed'", err)
	}
	if !mockTLS.called {
		t.Error("TLSTransport.TLSConnect was not called")
	}
	if mockTLS.gotName != "example.com" {
		t.Errorf("TLSConnect serverName = %q, want %q", mockTLS.gotName, "example.com")
	}
}

func TestConnPool_Get_DialFailure(t *testing.T) {
	pool := &ConnPool{
		DialTimeout: 100 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Use a non-routable address to trigger a dial failure.
	_, err := pool.Get(ctx, "192.0.2.1:1", false, "")
	if err == nil {
		t.Fatal("Get() expected error for unreachable address")
	}
}

func TestConnPool_Get_UpstreamProxy(t *testing.T) {
	// Start a minimal HTTP CONNECT proxy.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	// Start a target server.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()

	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go handleTestCONNECTProxy(conn, targetLn.Addr().String())
		}
	}()

	proxyURL, _ := url.Parse("http://" + proxyLn.Addr().String())
	pool := &ConnPool{
		UpstreamProxy: proxyURL,
		DialTimeout:   5 * time.Second,
	}

	ctx := context.Background()
	result, err := pool.Get(ctx, targetLn.Addr().String(), false, "")
	if err != nil {
		t.Fatalf("Get() via upstream proxy error = %v", err)
	}
	defer result.Conn.Close()
}

func TestConnPool_effectiveTLSTransport_Default(t *testing.T) {
	pool := &ConnPool{}
	transport := pool.effectiveTLSTransport()
	if transport == nil {
		t.Fatal("effectiveTLSTransport returned nil")
	}
	st, ok := transport.(*httputil.StandardTransport)
	if !ok {
		t.Fatalf("default transport type = %T, want *httputil.StandardTransport", transport)
	}
	if !st.InsecureSkipVerify {
		t.Error("default transport should have InsecureSkipVerify=true")
	}
}

func TestConnPool_effectiveTLSTransport_Custom(t *testing.T) {
	custom := &connpoolMockTLSTransport{}
	pool := &ConnPool{TLSTransport: custom}
	transport := pool.effectiveTLSTransport()
	if transport != custom {
		t.Error("effectiveTLSTransport should return custom transport when set")
	}
}

func TestConnPool_Close_NoOp(t *testing.T) {
	pool := &ConnPool{}
	// Should not panic.
	pool.Close()
}

func TestConnPool_Get_ConnectionLeak(t *testing.T) {
	var accepted []net.Conn
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted = append(accepted, conn)
		}
	}()

	pool := &ConnPool{DialTimeout: 2 * time.Second}
	ctx := context.Background()

	const numConns = 5
	for i := 0; i < numConns; i++ {
		result, err := pool.Get(ctx, ln.Addr().String(), false, "")
		if err != nil {
			t.Fatalf("Get() iteration %d error = %v", i, err)
		}
		result.Conn.Close()
	}

	// Close the listener so the accept goroutine exits, then wait.
	ln.Close()
	<-acceptDone

	if len(accepted) != numConns {
		t.Errorf("accepted %d connections, want %d", len(accepted), numConns)
	}
	for _, c := range accepted {
		c.Close()
	}
}

// handleTestCONNECTProxy is a minimal HTTP CONNECT proxy for testing.
func handleTestCONNECTProxy(conn net.Conn, targetAddr string) {
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	req := string(buf[:n])
	if !strings.HasPrefix(req, "CONNECT ") {
		return
	}

	// Establish connection to target.
	target, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy.
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			target.Write(buf[:n])
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := target.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()
	<-done
}
