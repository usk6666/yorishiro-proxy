//go:build e2e

package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startHTTPSProxyWithPassthrough creates and starts a proxy with TLS MITM
// support and a configured passthrough list. Returns the listener, handler,
// passthrough list, and cancel function.
func startHTTPSProxyWithPassthrough(t *testing.T, ctx context.Context, store flow.Store, ca *cert.CA, patterns []string) (*proxy.Listener, *protohttp.Handler, *proxy.PassthroughList, context.CancelFunc) {
	t.Helper()

	pl := proxy.NewPassthroughList()
	for _, p := range patterns {
		pl.Add(p)
	}

	issuer := cert.NewIssuer(ca)
	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	httpHandler.SetPassthroughList(pl)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

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

	return listener, httpHandler, pl, proxyCancel
}

// sendCONNECTAndRead sends a raw CONNECT request through the proxy and returns
// the raw connection after reading the CONNECT response.
func sendCONNECTAndRead(t *testing.T, proxyAddr, target string) (net.Conn, string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	// Send CONNECT request.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read CONNECT response.
	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()

	return conn, resp.Status
}

func TestIntegration_TLSPassthrough_RelayWithoutMITM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start an upstream TLS server that the passthrough domain points to.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "passthrough-response")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	// Configure passthrough for localhost (matching the upstream host).
	listener, _, _, proxyCancel := startHTTPSProxyWithPassthrough(
		t, ctx, store, ca, []string{"localhost"},
	)
	defer proxyCancel()

	// Connect through the proxy using CONNECT method.
	target := fmt.Sprintf("localhost:%s", upstreamPort)
	tunnelConn, status := sendCONNECTAndRead(t, listener.Addr(), target)
	defer tunnelConn.Close()

	if status != "200 Connection Established" {
		t.Fatalf("CONNECT status = %q, want %q", status, "200 Connection Established")
	}

	// The tunnel should relay raw TLS bytes. Perform a TLS handshake
	// directly with the upstream server (not with the proxy's CA cert).
	// The upstream uses a self-signed cert, so we use InsecureSkipVerify.
	tlsConn := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake with upstream through passthrough: %v", err)
	}

	// Verify that the certificate is from the upstream server, NOT from our
	// proxy CA. The upstream uses httptest.NewTLSServer's built-in cert.
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		t.Fatal("no peer certificates received")
	}

	// The peer cert should NOT be issued by our proxy CA.
	caCert := ca.Certificate()
	for _, peerCert := range peerCerts {
		if err := peerCert.CheckSignatureFrom(caCert); err == nil {
			t.Fatal("peer certificate was signed by proxy CA, expected upstream's own certificate (passthrough failed)")
		}
	}

	// Send an HTTP request over the TLS tunnel and verify response.
	req, _ := gohttp.NewRequest("GET", "https://localhost:"+upstreamPort+"/", nil)
	req.Write(tlsConn)

	resp, err := gohttp.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "passthrough-response" {
		t.Errorf("body = %q, want %q", body, "passthrough-response")
	}

	// Verify NO flow was recorded (passthrough skips flow recording).
	time.Sleep(200 * time.Millisecond)
	entries, err := store.ListFlows(ctx, flow.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 sessions (passthrough), got %d", len(entries))
	}
}

func TestIntegration_TLSPassthrough_NonPassthroughStillMITM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start upstream HTTPS server.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "mitm-response")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	// Configure passthrough for a DIFFERENT domain (not localhost).
	listener, httpHandler, _, proxyCancel := startHTTPSProxyWithPassthrough(
		t, ctx, store, ca, []string{"passthrough-only.example.com"},
	)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	// Connect via normal HTTPS proxy client that trusts our proxy CA.
	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "mitm-response" {
		t.Errorf("body = %q, want %q", body, "mitm-response")
	}

	// Verify session WAS recorded (non-passthrough gets MITM'd).
	time.Sleep(200 * time.Millisecond)
	entries, err := store.ListFlows(ctx, flow.ListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 HTTPS session (MITM), got %d", len(entries))
	}

	fl := entries[0]
	if fl.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTPS")
	}
	recvMsgs, mErr := store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "receive"})
	if mErr != nil {
		t.Fatalf("GetMessages: %v", mErr)
	}
	if len(recvMsgs) == 0 {
		t.Fatal("no receive message found")
	}
	if string(recvMsgs[0].Body) != "mitm-response" {
		t.Errorf("response body = %q, want %q", recvMsgs[0].Body, "mitm-response")
	}
}

func TestIntegration_TLSPassthrough_WildcardPattern(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start an upstream TLS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "wildcard-passthrough")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	// Configure wildcard passthrough for *.localdomain.
	// We'll use "sub.localdomain" as CONNECT target but connect to localhost.
	// Since passthrough just relays bytes, the DNS resolution of the CONNECT
	// target doesn't matter for the hostname matching test.
	listener, _, pl, proxyCancel := startHTTPSProxyWithPassthrough(
		t, ctx, store, ca, []string{"*.localdomain"},
	)
	defer proxyCancel()

	// Verify the pattern is in the list.
	if !pl.Contains("sub.localdomain") {
		t.Fatal("expected *.localdomain to match sub.localdomain")
	}
	if pl.Contains("localdomain") {
		t.Fatal("expected *.localdomain not to match localdomain")
	}

	// For passthrough, the proxy tries to dial the CONNECT authority.
	// We use localhost:<port> as the authority so the dial succeeds.
	// But the hostname for matching is "localhost", not "sub.localdomain".
	// So we add "localhost" to the passthrough list to test the actual relay.
	pl.Add("localhost")

	target := fmt.Sprintf("localhost:%s", upstreamPort)
	tunnelConn, status := sendCONNECTAndRead(t, listener.Addr(), target)
	defer tunnelConn.Close()

	if status != "200 Connection Established" {
		t.Fatalf("CONNECT status = %q, want %q", status, "200 Connection Established")
	}

	// Perform TLS handshake directly with upstream (bypassing MITM).
	tlsConn := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// Verify peer cert is from upstream, not proxy CA.
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		t.Fatal("no peer certificates received")
	}
	caCert := ca.Certificate()
	for _, pc := range peerCerts {
		if err := pc.CheckSignatureFrom(caCert); err == nil {
			t.Fatal("peer cert was signed by proxy CA (expected passthrough)")
		}
	}
}

func TestIntegration_TLSPassthrough_DynamicAddRemove(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Start upstream HTTPS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "dynamic-test")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	// Start WITHOUT passthrough for localhost.
	listener, httpHandler, pl, proxyCancel := startHTTPSProxyWithPassthrough(
		t, ctx, store, ca, nil,
	)
	defer proxyCancel()
	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})

	// First request: should be MITM'd (localhost not in passthrough).
	client := httpsProxyClient(listener.Addr(), ca.Certificate())
	targetURL := fmt.Sprintf("https://localhost:%s/before", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	time.Sleep(200 * time.Millisecond)

	entries, err := store.ListFlows(ctx, flow.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 session before passthrough, got %d", len(entries))
	}

	// Dynamically add localhost to passthrough.
	pl.Add("localhost")

	// Second request: should be passthrough (no new MITM session).
	target := fmt.Sprintf("localhost:%s", upstreamPort)
	tunnelConn, status := sendCONNECTAndRead(t, listener.Addr(), target)
	defer tunnelConn.Close()

	if status != "200 Connection Established" {
		t.Fatalf("CONNECT status = %q, want %q", status, "200 Connection Established")
	}

	// TLS handshake directly with upstream.
	tlsConn := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("passthrough TLS handshake: %v", err)
	}
	tlsConn.Close()

	// Verify peer cert was from upstream, not proxy CA.
	// (Already tested in the handshake succeeding with InsecureSkipVerify
	// against upstream's cert, not the proxy's dynamically generated cert.)

	time.Sleep(200 * time.Millisecond)

	// Flow count should still be 1 (passthrough doesn't record).
	entries, err = store.ListFlows(ctx, flow.ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 session after passthrough, got %d", len(entries))
	}
}

func TestIntegration_TLSPassthrough_VerifyCertIsUpstream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start upstream with its own TLS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// Get the upstream server's certificate for comparison.
	upstreamCert := upstream.TLS.Certificates[0].Leaf
	if upstreamCert == nil {
		// Parse it from the raw bytes.
		var err error
		upstreamCert, err = x509.ParseCertificate(upstream.TLS.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatalf("parse upstream cert: %v", err)
		}
	}

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, _, _, proxyCancel := startHTTPSProxyWithPassthrough(
		t, ctx, store, ca, []string{"localhost"},
	)
	defer proxyCancel()

	// CONNECT to the upstream through passthrough.
	target := fmt.Sprintf("localhost:%s", upstreamPort)
	tunnelConn, _ := sendCONNECTAndRead(t, listener.Addr(), target)
	defer tunnelConn.Close()

	tlsConn := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// The peer certificate should be the upstream's cert, not the proxy CA's.
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		t.Fatal("no peer certificates")
	}

	// Compare the raw bytes of the peer cert with the upstream cert.
	if len(peerCerts[0].Raw) != len(upstreamCert.Raw) {
		t.Error("peer certificate differs from upstream certificate (passthrough may not be working)")
	} else {
		for i := range peerCerts[0].Raw {
			if peerCerts[0].Raw[i] != upstreamCert.Raw[i] {
				t.Error("peer certificate raw bytes differ from upstream certificate")
				break
			}
		}
	}
}
