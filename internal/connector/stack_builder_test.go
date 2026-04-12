package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestBuildConnectionStack_RawPassthrough(t *testing.T) {
	// --- Setup: upstream TLS server that echoes data ---
	serverCfg, err := newSelfSignedTLSConfig("target.example.com")
	if err != nil {
		t.Fatal(err)
	}

	upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	// --- Setup: CA + Issuer for MITM ---
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	// --- Setup: Config with raw_passthrough for the upstream target ---
	target := upstreamLn.Addr().String()
	proxyCfg := &config.ProxyConfig{
		RawPassthroughHosts: []string{target},
	}

	buildCfg := &BuildConfig{
		ProxyConfig:        proxyCfg,
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	// Use a TCP listener instead of net.Pipe to avoid TLS handshake
	// deadlocks (net.Pipe has zero buffering).
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	// Run BuildConnectionStack in a goroutine. It accepts on the server
	// side of the connection and performs TLS MITM + upstream dial.
	type buildResult struct {
		stack *ConnectionStack
		err   error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, err := clientLn.Accept()
		if err != nil {
			resultCh <- buildResult{nil, err}
			return
		}
		stack, _, err := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack, err}
	}()

	// Client-side: connect and perform TLS handshake with the proxy (MITM).
	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	// Extract the host from target to match the MITM cert.
	host, _, _ := net.SplitHostPort(target)

	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Certificate())

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName:         host,
		RootCAs:            certPool,
		InsecureSkipVerify: true, //nolint:gosec // test: MITM cert for IP
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	// Wait for BuildConnectionStack to complete.
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("BuildConnectionStack: %v", result.err)
	}

	stack := result.stack
	if stack == nil {
		t.Fatal("expected non-nil stack")
	}
	defer stack.Close()

	if stack.ConnID == "" {
		t.Error("expected non-empty ConnID")
	}

	if stack.ClientTopmost() == nil {
		t.Error("expected non-nil client topmost layer")
	}
	if stack.UpstreamTopmost() == nil {
		t.Error("expected non-nil upstream topmost layer")
	}
}

func TestBuildConnectionStack_HTTPMITMStack(t *testing.T) {
	// --- Setup: upstream TLS server that speaks HTTP/1.x ---
	serverCfg, err := newSelfSignedTLSConfig("target.example.com")
	if err != nil {
		t.Fatal(err)
	}

	upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Minimal HTTP/1.x server: read until \r\n\r\n, respond 200 OK.
		buf := make([]byte, 4096)
		for n := 0; n < len(buf); {
			nn, err := conn.Read(buf[n:])
			if err != nil {
				return
			}
			n += nn
			if bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
				break
			}
		}
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		conn.Write([]byte(resp))
	}()

	// --- Setup: CA + Issuer for MITM ---
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	// --- Setup: Config WITHOUT raw_passthrough (default = HTTP MITM) ---
	target := upstreamLn.Addr().String()
	proxyCfg := &config.ProxyConfig{} // empty = no raw_passthrough hosts

	buildCfg := &BuildConfig{
		ProxyConfig:        proxyCfg,
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	// Use a TCP listener to avoid TLS handshake deadlocks (net.Pipe is zero-buffered).
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	type buildResult struct {
		stack *ConnectionStack
		snap  *envelope.TLSSnapshot
		err   error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, err := clientLn.Accept()
		if err != nil {
			resultCh <- buildResult{nil, nil, err}
			return
		}
		stack, snap, err := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack, snap, err}
	}()

	// Client-side: connect and perform TLS handshake with the proxy (MITM).
	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	host, _, _ := net.SplitHostPort(target)

	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Certificate())

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName:         host,
		RootCAs:            certPool,
		InsecureSkipVerify: true, //nolint:gosec // test: MITM cert for IP
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	// Wait for BuildConnectionStack to complete.
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("BuildConnectionStack: %v", result.err)
	}

	stack := result.stack
	if stack == nil {
		t.Fatal("expected non-nil stack")
	}
	defer stack.Close()

	if stack.ConnID == "" {
		t.Error("expected non-empty ConnID")
	}

	if stack.ClientTopmost() == nil {
		t.Error("expected non-nil client topmost layer")
	}
	if stack.UpstreamTopmost() == nil {
		t.Error("expected non-nil upstream topmost layer")
	}

	// Verify the client-side layer produces a Channel.
	clientCh := stack.ClientTopmost().Channels()
	ch, ok := <-clientCh
	if !ok || ch == nil {
		t.Error("expected client layer to produce a Channel")
	}

	// Verify the upstream-side layer produces a Channel.
	upstreamCh := stack.UpstreamTopmost().Channels()
	uch, ok := <-upstreamCh
	if !ok || uch == nil {
		t.Error("expected upstream layer to produce a Channel")
	}

	// Verify TLSSnapshot is populated.
	if result.snap == nil {
		t.Fatal("expected non-nil TLSSnapshot")
	}
	if result.snap.Version == 0 {
		t.Error("expected non-zero TLS version in snapshot")
	}
}

func TestBuildConnectionStack_NilConfig(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	_, _, err := BuildConnectionStack(context.Background(), proxyConn, "example.com:443", nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}
