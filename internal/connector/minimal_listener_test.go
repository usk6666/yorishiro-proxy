package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestMinimalListener_CONNECT_RawPassthrough(t *testing.T) {
	// --- Setup: upstream TLS echo server ---
	serverCfg, err := newSelfSignedTLSConfig("target.local")
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

	// --- Setup: CA + Issuer ---
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	target := upstreamLn.Addr().String()

	// --- Setup: MinimalListener ---
	var stackReceived *ConnectionStack
	var stackTarget string
	var stackMu sync.Mutex
	stackDone := make(chan struct{})

	mlCfg := MinimalListenerConfig{
		BuildConfig: &BuildConfig{
			ProxyConfig: &config.ProxyConfig{
				RawPassthroughHosts: []string{target},
			},
			Issuer:             issuer,
			InsecureSkipVerify: true,
		},
		OnStack: func(_ context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, tgt string) {
			stackMu.Lock()
			stackReceived = stack
			stackTarget = tgt
			stackMu.Unlock()
			close(stackDone)
		},
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ml := NewMinimalListenerFromListener(proxyLn, mlCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ml.Serve(ctx)
	defer ml.Close()

	// --- Client: send CONNECT, then TLS handshake ---
	clientConn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer clientConn.Close()

	// Send CONNECT request.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := clientConn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read 200 response.
	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp := string(buf[:n])
	if resp != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		t.Fatalf("unexpected CONNECT response: %q", resp)
	}

	// TLS handshake through the MITM proxy. Use InsecureSkipVerify because
	// the CONNECT target is an IP address, and the MITM cert is issued for
	// that IP (not "target.local").
	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake through proxy: %v", err)
	}

	// Wait for OnStack callback.
	select {
	case <-stackDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for OnStack callback")
	}

	stackMu.Lock()
	defer stackMu.Unlock()

	if stackReceived == nil {
		t.Fatal("expected OnStack to be called with non-nil stack")
	}
	defer stackReceived.Close()

	if stackTarget != target {
		t.Errorf("OnStack target = %q, want %q", stackTarget, target)
	}

	if stackReceived.ClientTopmost() == nil {
		t.Error("expected non-nil client topmost layer")
	}
	if stackReceived.UpstreamTopmost() == nil {
		t.Error("expected non-nil upstream topmost layer")
	}
}

func TestMinimalListener_NonCONNECT_ClosesConnection(t *testing.T) {
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	mlCfg := MinimalListenerConfig{
		BuildConfig: &BuildConfig{
			ProxyConfig: &config.ProxyConfig{},
			Issuer:      issuer,
		},
		OnStack: func(_ context.Context, _ *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			t.Error("OnStack should not be called for non-CONNECT")
		},
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ml := NewMinimalListenerFromListener(proxyLn, mlCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ml.Serve(ctx)
	defer ml.Close()

	// Send a non-CONNECT request.
	clientConn, err := net.DialTimeout("tcp", proxyLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The proxy should close the connection after failing to parse CONNECT.
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	_, err = clientConn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed after non-CONNECT request")
	}
}
