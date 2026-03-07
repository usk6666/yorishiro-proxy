//go:build e2e

package proxy_test

import (
	"context"
	"fmt"
	"net"
	gohttp "net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startProxyWithTimeouts creates a proxy with configurable peek and request timeouts.
// This allows tests to use short timeouts (e.g. 200ms) for fast timeout verification.
func startProxyWithTimeouts(
	t *testing.T,
	ctx context.Context,
	store flow.Store,
	peekTimeout time.Duration,
	requestTimeout time.Duration,
	issuer *cert.Issuer,
) (*proxy.Listener, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	if requestTimeout > 0 {
		httpHandler.SetRequestTimeout(requestTimeout)
	}
	detector := protocol.NewDetector(httpHandler)

	cfg := proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	}
	if peekTimeout > 0 {
		cfg.PeekTimeout = peekTimeout
	}

	listener := proxy.NewListener(cfg)
	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener, proxyCancel
}

func TestIntegration_TimeoutIdleConnection(t *testing.T) {
	// TCP connection with no data sent should be closed by the peek timeout.
	const peekTimeout = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxyWithTimeouts(t, ctx, store, peekTimeout, 0, nil)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	// Connect but send nothing.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Set a generous deadline on our read so the test doesn't hang indefinitely.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	start := time.Now()

	// Read should return EOF or error when the proxy closes the connection
	// due to the peek timeout.
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected connection to be closed by proxy, but Read succeeded")
	}

	// The connection should be closed within a reasonable margin of the peek timeout.
	// Allow up to 3x the timeout for scheduling jitter.
	maxExpected := peekTimeout * 3
	if elapsed > maxExpected {
		t.Errorf("connection closed after %v, expected within %v of peek timeout %v",
			elapsed, maxExpected, peekTimeout)
	}

	// Verify at least the timeout duration has elapsed.
	if elapsed < peekTimeout/2 {
		t.Errorf("connection closed too early (%v), peek timeout is %v",
			elapsed, peekTimeout)
	}
}

func TestIntegration_TimeoutPartialHTTPHeaders(t *testing.T) {
	// Sending partial HTTP headers (without the terminating blank line) should
	// trigger the request timeout.
	const requestTimeout = 200 * time.Millisecond
	// Use a longer peek timeout so we pass protocol detection successfully.
	const peekTimeout = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxyWithTimeouts(t, ctx, store, peekTimeout, requestTimeout, nil)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "request line only without CRLF termination",
			payload: "GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1",
		},
		{
			name:    "headers with single CRLF no blank line",
			payload: "GET http://127.0.0.1/test HTTP/1.1\r\nHost: 127.0.0.1\r\n",
		},
		{
			// Enough data to pass peek (16 bytes) but the HTTP request
			// line is not terminated, so ReadRequest blocks.
			name:    "long partial request line without CRLF",
			payload: "GET http://127.0.0.1/verylongpath HTTP/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			// Send partial headers to get past protocol detection (peek),
			// but do not complete the request.
			if _, err := conn.Write([]byte(tt.payload)); err != nil {
				t.Fatalf("write partial request: %v", err)
			}

			start := time.Now()

			// The proxy should close the connection after the request timeout.
			buf := make([]byte, 4096)
			_, err = conn.Read(buf)
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("expected connection to be closed by proxy, but Read succeeded")
			}

			// Allow generous margin for scheduling jitter.
			maxExpected := requestTimeout * 5
			if elapsed > maxExpected {
				t.Errorf("connection closed after %v, expected within %v of request timeout %v",
					elapsed, maxExpected, requestTimeout)
			}
		})
	}

	// Verify the proxy is still alive after the timeout tests.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy not accepting connections after timeout tests: %v", err)
	}
	conn.Close()
}

func TestIntegration_TimeoutKeepAliveIdle(t *testing.T) {
	// After completing a valid request on a keep-alive connection, the proxy should
	// close the connection if no follow-up request arrives within the request timeout.
	const requestTimeout = 300 * time.Millisecond
	const peekTimeout = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start a simple upstream HTTP server.
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			w.WriteHeader(gohttp.StatusOK)
			fmt.Fprintf(w, "ok")
		}),
	}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxyWithTimeouts(t, ctx, store, peekTimeout, requestTimeout, nil)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	// Send a valid HTTP request (keep-alive by default in HTTP/1.1).
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	validReq := fmt.Sprintf(
		"GET http://%s/first HTTP/1.1\r\nHost: %s\r\n\r\n",
		upstreamAddr, upstreamAddr,
	)
	if _, err := conn.Write([]byte(validReq)); err != nil {
		t.Fatalf("write first request: %v", err)
	}

	// Read the response to the first request.
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	response := string(respBuf[:n])
	if !strings.Contains(response, "200") {
		t.Fatalf("expected 200 OK, got: %q", response)
	}

	// Now wait without sending a second request. The proxy should close the
	// connection after the request timeout.
	start := time.Now()

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected connection to be closed by proxy after keep-alive idle timeout")
	}

	// The connection should be closed within a reasonable margin of the request timeout.
	maxExpected := requestTimeout * 5
	if elapsed > maxExpected {
		t.Errorf("keep-alive connection closed after %v, expected within %v of request timeout %v",
			elapsed, maxExpected, requestTimeout)
	}

	if elapsed < requestTimeout/2 {
		t.Errorf("keep-alive connection closed too early (%v), request timeout is %v",
			elapsed, requestTimeout)
	}
}

func TestIntegration_TimeoutSlowTLSHandshake(t *testing.T) {
	// After a CONNECT tunnel is established, if the client sends garbage
	// instead of a valid TLS ClientHello, the TLS handshake should fail
	// and the proxy should close the connection quickly.
	const peekTimeout = 5 * time.Second
	const requestTimeout = 300 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Generate test CA for TLS MITM.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	listener, proxyCancel := startProxyWithTimeouts(t, ctx, store, peekTimeout, requestTimeout, issuer)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	// Send a CONNECT request, receive 200, then send garbage instead of TLS ClientHello.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	// Read the 200 Connection Established response.
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	response := string(respBuf[:n])
	if !strings.Contains(response, "200") {
		t.Fatalf("expected 200 Connection Established, got: %q", response)
	}

	// Send garbage data instead of a valid TLS ClientHello.
	// This will cause the TLS handshake to fail immediately with a parse error.
	garbage := []byte("THIS IS NOT A TLS HANDSHAKE\r\n")
	if _, err := conn.Write(garbage); err != nil {
		t.Fatalf("write garbage after CONNECT: %v", err)
	}

	start := time.Now()

	// Wait for the proxy to close the connection after the failed handshake.
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected connection to be closed by proxy after invalid TLS handshake data")
	}

	// The handshake should fail nearly immediately since we sent garbage.
	maxExpected := 2 * time.Second
	if elapsed > maxExpected {
		t.Errorf("connection with garbage TLS data closed after %v, expected within %v",
			elapsed, maxExpected)
	}
}

func TestIntegration_TimeoutStallAfterCONNECT(t *testing.T) {
	// After a CONNECT tunnel is established, if the client does nothing
	// (no TLS handshake, no data), the proxy should eventually close the
	// connection. We use a short proxy context to cancel the stalled handshake.
	const peekTimeout = 5 * time.Second
	const requestTimeout = 300 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Generate test CA for TLS MITM.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	// Use a short-lived proxy context so the stalled handshake is cancelled quickly.
	proxyTimeout := 1 * time.Second
	proxyCtx, proxyCtxCancel := context.WithTimeout(ctx, proxyTimeout)
	defer proxyCtxCancel()

	listener, proxyCancel := startProxyWithTimeouts(t, proxyCtx, store, peekTimeout, requestTimeout, issuer)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	// Send a CONNECT request, receive 200, then do nothing.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	// Read the 200 Connection Established response.
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	response := string(respBuf[:n])
	if !strings.Contains(response, "200") {
		t.Fatalf("expected 200 Connection Established, got: %q", response)
	}

	// Do NOT send anything. Wait for the proxy to close the connection
	// when its context is cancelled.
	start := time.Now()

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected connection to be closed by proxy after context cancellation")
	}

	// The proxy context has a 1-second timeout, so the connection should close
	// within a generous margin of that.
	maxExpected := proxyTimeout * 3
	if elapsed > maxExpected {
		t.Errorf("stalled TLS connection closed after %v, expected within %v of proxy timeout %v",
			elapsed, maxExpected, proxyTimeout)
	}
}

func TestIntegration_TimeoutProxyStillHealthy(t *testing.T) {
	// After multiple timeout scenarios, the proxy should still accept and
	// correctly handle new valid requests.
	const peekTimeout = 200 * time.Millisecond
	const requestTimeout = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream HTTP server.
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			w.WriteHeader(gohttp.StatusOK)
			fmt.Fprintf(w, "healthy")
		}),
	}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxyWithTimeouts(t, ctx, store, peekTimeout, requestTimeout, nil)
	defer proxyCancel()

	proxyAddr := listener.Addr()

	// Scenario 1: idle connection (peek timeout).
	idleConn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy for idle conn: %v", err)
	}
	idleConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	idleConn.Read(buf) // Wait for timeout close.
	idleConn.Close()

	// Scenario 2: partial headers (request timeout).
	partialConn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy for partial conn: %v", err)
	}
	partialConn.Write([]byte("GET http://127.0.0.1/slow HTTP/1.1\r\nHost: 127.0.0.1\r\n"))
	partialConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	partialConn.Read(buf) // Wait for timeout close.
	partialConn.Close()

	// Scenario 3: valid request should succeed after the above timeouts.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy not accepting connections after timeouts: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	validReq := fmt.Sprintf(
		"GET http://%s/health HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstreamAddr, upstreamAddr,
	)
	if _, err := conn.Write([]byte(validReq)); err != nil {
		t.Fatalf("write valid request: %v", err)
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil && n == 0 {
		t.Fatalf("proxy did not respond to valid request after timeout scenarios: %v", err)
	}

	response := string(respBuf[:n])
	if !strings.Contains(response, "200") {
		t.Errorf("expected 200 OK, got: %q", response)
	}
	if !strings.Contains(response, "healthy") {
		t.Errorf("expected body 'healthy', got: %q", response)
	}
}
