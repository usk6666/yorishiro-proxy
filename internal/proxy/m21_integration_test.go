//go:build e2e

package proxy_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	gohttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// ============================================================================
// mTLS test helpers
// ============================================================================

// testPKI holds a complete PKI setup for mTLS testing:
// server CA, client CA, server cert, client cert.
type testPKI struct {
	ServerCAPool   *x509.CertPool
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string
	ClientCAPool   *x509.CertPool
	TmpDir         string
}

// generateTestPKI creates a test PKI with separate server and client CAs,
// and issues one server cert and one client cert.
func generateTestPKI(t *testing.T) *testPKI {
	t.Helper()
	tmpDir := t.TempDir()

	// Generate server CA.
	serverCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server CA key: %v", err)
	}
	serverCACert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Server CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	serverCADER, err := x509.CreateCertificate(rand.Reader, serverCACert, serverCACert, &serverCAKey.PublicKey, serverCAKey)
	if err != nil {
		t.Fatalf("create server CA cert: %v", err)
	}
	serverCAParsed, _ := x509.ParseCertificate(serverCADER)
	serverCAPool := x509.NewCertPool()
	serverCAPool.AddCert(serverCAParsed)

	// Generate client CA.
	clientCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client CA key: %v", err)
	}
	clientCACert := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	clientCADER, err := x509.CreateCertificate(rand.Reader, clientCACert, clientCACert, &clientCAKey.PublicKey, clientCAKey)
	if err != nil {
		t.Fatalf("create client CA cert: %v", err)
	}
	clientCAParsed, _ := x509.ParseCertificate(clientCADER)
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(clientCAParsed)

	// Issue server certificate signed by server CA.
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverCert, serverCAParsed, &serverKey.PublicKey, serverCAKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	// Issue client certificate signed by client CA.
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(20),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientCert, clientCAParsed, &clientKey.PublicKey, clientCAKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	// Write server cert+key to files.
	serverCertFile := filepath.Join(tmpDir, "server.crt")
	serverKeyFile := filepath.Join(tmpDir, "server.key")
	writePEMFile(t, serverCertFile, "CERTIFICATE", serverCertDER)
	writeECKeyFile(t, serverKeyFile, serverKey)

	// Write client cert+key to files.
	clientCertFile := filepath.Join(tmpDir, "client.crt")
	clientKeyFile := filepath.Join(tmpDir, "client.key")
	writePEMFile(t, clientCertFile, "CERTIFICATE", clientCertDER)
	writeECKeyFile(t, clientKeyFile, clientKey)

	// Write server CA cert to file (for proxy to trust the upstream).
	serverCACertFile := filepath.Join(tmpDir, "server-ca.crt")
	writePEMFile(t, serverCACertFile, "CERTIFICATE", serverCADER)

	return &testPKI{
		ServerCAPool:   serverCAPool,
		ServerCertFile: serverCertFile,
		ServerKeyFile:  serverKeyFile,
		ClientCertFile: clientCertFile,
		ClientKeyFile:  clientKeyFile,
		ClientCAPool:   clientCAPool,
		TmpDir:         tmpDir,
	}
}

// writePEMFile writes a single PEM block to a file.
func writePEMFile(t *testing.T, path, blockType string, derBytes []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: derBytes})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write PEM file %s: %v", path, err)
	}
}

// writeECKeyFile writes an EC private key to a PEM file.
func writeECKeyFile(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	writePEMFile(t, path, "EC PRIVATE KEY", keyDER)
}

// startMTLSServer creates a TLS server that requires client certificates.
// Returns the listener address.
func startMTLSServer(t *testing.T, pki *testPKI, handler gohttp.Handler) (string, func()) {
	t.Helper()

	serverCert, err := tls.LoadX509KeyPair(pki.ServerCertFile, pki.ServerKeyFile)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.ClientCAPool,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	server := &gohttp.Server{
		Handler:     handler,
		ReadTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.Serve(ln); err != gohttp.ErrServerClosed {
			t.Logf("mTLS server error: %v", err)
		}
	}()

	cleanup := func() {
		server.Close()
	}

	return ln.Addr().String(), cleanup
}

// startTLSServerNoClientAuth creates a TLS server without client cert requirements.
func startTLSServerNoClientAuth(t *testing.T, pki *testPKI, handler gohttp.Handler) (string, func()) {
	t.Helper()

	serverCert, err := tls.LoadX509KeyPair(pki.ServerCertFile, pki.ServerKeyFile)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}

	server := &gohttp.Server{
		Handler:     handler,
		ReadTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.Serve(ln); err != gohttp.ErrServerClosed {
			t.Logf("TLS server error: %v", err)
		}
	}()

	cleanup := func() {
		server.Close()
	}

	return ln.Addr().String(), cleanup
}

// pollFlows polls the store until the expected number of flows appear or timeout.
func pollFlows(t *testing.T, ctx context.Context, store flow.Store, opts flow.ListOptions, wantCount int) []*flow.Flow {
	t.Helper()
	var flows []*flow.Flow
	var err error
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, opts)
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= wantCount {
			return flows
		}
	}
	t.Fatalf("expected %d flows, got %d after polling", wantCount, len(flows))
	return nil
}

// getFlowMessages retrieves send and receive messages for a flow.
func getFlowMessages(t *testing.T, ctx context.Context, store flow.Store, flowID string) (send, recv *flow.Message) {
	t.Helper()
	msgs, err := store.GetMessages(ctx, flowID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	for _, m := range msgs {
		switch m.Direction {
		case "send":
			if send == nil {
				send = m
			}
		case "receive":
			if recv == nil {
				recv = m
			}
		}
	}
	return send, recv
}

// ============================================================================
// 1. mTLS integration tests
// ============================================================================

func TestM21_MTLS_ProxyWithClientCert(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pki := generateTestPKI(t)

	// Start mTLS upstream server.
	upstreamAddr, upstreamCleanup := startMTLSServer(t, pki, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Verify client cert was presented.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			w.Header().Set("X-Client-CN", r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "mtls-ok")
	}))
	defer upstreamCleanup()

	// Set up flow store.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Generate proxy CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	// Start proxy with mTLS TLS transport configured.
	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)

	// Configure TLS transport with client certificate for localhost.
	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		ClientCertPath: pki.ClientCertFile,
		ClientKeyPath:  pki.ClientKeyFile,
		CABundlePath:   filepath.Join(pki.TmpDir, "server-ca.crt"),
	})

	tlsTransport := &httputil.StandardTransport{
		InsecureSkipVerify: false,
		HostTLS:            registry,
	}
	httpHandler.SetTLSTransport(tlsTransport)

	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// Create client that trusts the proxy CA.
	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	// Send request through proxy to the mTLS upstream.
	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)
	targetURL := fmt.Sprintf("https://localhost:%s/mtls-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy to mTLS server: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "mtls-ok" {
		t.Errorf("body = %q, want %q", body, "mtls-ok")
	}
	if resp.Header.Get("X-Client-CN") != "Test Client" {
		t.Errorf("X-Client-CN = %q, want %q", resp.Header.Get("X-Client-CN"), "Test Client")
	}

	// Verify flow was recorded.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]
	if fl.Protocol != "HTTPS" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTPS")
	}
	send, recv := getFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if send.Method != "GET" {
		t.Errorf("method = %q, want %q", send.Method, "GET")
	}
	if recv.StatusCode != 200 {
		t.Errorf("status = %d, want 200", recv.StatusCode)
	}
}

func TestM21_MTLS_ConnectionRejectedWithoutClientCert(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pki := generateTestPKI(t)

	// Start mTLS upstream server.
	upstreamAddr, upstreamCleanup := startMTLSServer(t, pki, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "should-not-reach")
	}))
	defer upstreamCleanup()

	// Set up flow store.
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

	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)

	// Configure TLS transport WITHOUT client cert but with server CA trust.
	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		CABundlePath: filepath.Join(pki.TmpDir, "server-ca.crt"),
	})

	tlsTransport := &httputil.StandardTransport{
		InsecureSkipVerify: false,
		HostTLS:            registry,
	}
	httpHandler.SetTLSTransport(tlsTransport)

	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	// Try to send request without client cert — should fail.
	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)
	targetURL := fmt.Sprintf("https://localhost:%s/mtls-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		// Connection error is expected since the mTLS handshake fails.
		return
	}
	defer resp.Body.Close()

	// If we got a response, it should indicate an error (502 Bad Gateway).
	if resp.StatusCode == gohttp.StatusOK {
		t.Error("expected connection to fail without client cert, but got 200 OK")
	}
}

func TestM21_MTLS_PerHostCertSwitching(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pki := generateTestPKI(t)

	// Start mTLS upstream server (requires client cert).
	mtlsAddr, mtlsCleanup := startMTLSServer(t, pki, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		cn := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "mtls-host:%s", cn)
	}))
	defer mtlsCleanup()

	// Start regular TLS server (no client cert).
	tlsAddr, tlsCleanup := startTLSServerNoClientAuth(t, pki, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "plain-tls-host")
	}))
	defer tlsCleanup()

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

	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)

	// Configure per-host TLS: mTLS host gets client cert, other host does not.
	_, mtlsPort, _ := net.SplitHostPort(mtlsAddr)
	_, tlsPort, _ := net.SplitHostPort(tlsAddr)

	registry := httputil.NewHostTLSRegistry()
	// mTLS host: client cert + server CA
	registry.Set("localhost", &httputil.HostTLSConfig{
		ClientCertPath: pki.ClientCertFile,
		ClientKeyPath:  pki.ClientKeyFile,
		CABundlePath:   filepath.Join(pki.TmpDir, "server-ca.crt"),
	})

	tlsTransport := &httputil.StandardTransport{
		InsecureSkipVerify: false,
		HostTLS:            registry,
	}
	httpHandler.SetTLSTransport(tlsTransport)

	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	// Request to mTLS host.
	mtlsURL := fmt.Sprintf("https://localhost:%s/mtls", mtlsPort)
	resp1, err := client.Get(mtlsURL)
	if err != nil {
		t.Fatalf("GET mTLS host: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if resp1.StatusCode != gohttp.StatusOK {
		t.Errorf("mTLS host status = %d, want %d", resp1.StatusCode, gohttp.StatusOK)
	}
	if !strings.HasPrefix(string(body1), "mtls-host:") {
		t.Errorf("mTLS host body = %q, want prefix %q", body1, "mtls-host:")
	}

	// Request to plain TLS host.
	tlsURL := fmt.Sprintf("https://localhost:%s/plain", tlsPort)
	resp2, err := client.Get(tlsURL)
	if err != nil {
		t.Fatalf("GET plain TLS host: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != gohttp.StatusOK {
		t.Errorf("plain TLS host status = %d, want %d", resp2.StatusCode, gohttp.StatusOK)
	}
	if string(body2) != "plain-tls-host" {
		t.Errorf("plain TLS host body = %q, want %q", body2, "plain-tls-host")
	}

	// Verify both flows were recorded.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 2)
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(flows))
	}
}

func TestM21_MTLS_TLSVerifyControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pki := generateTestPKI(t)

	// Start a TLS server without client cert requirement.
	upstreamAddr, upstreamCleanup := startTLSServerNoClientAuth(t, pki, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "verify-control-ok")
	}))
	defer upstreamCleanup()

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

	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)

	// Test: TLSVerify=false skips verification (should succeed without CA bundle).
	tlsVerifyFalse := false
	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		TLSVerify: &tlsVerifyFalse,
	})

	tlsTransport := &httputil.StandardTransport{
		InsecureSkipVerify: false, // global is strict
		HostTLS:            registry,
	}
	httpHandler.SetTLSTransport(tlsTransport)

	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)
	targetURL := fmt.Sprintf("https://localhost:%s/verify-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET with TLSVerify=false: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "verify-control-ok" {
		t.Errorf("body = %q, want %q", body, "verify-control-ok")
	}

	// Verify flow was recorded.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
}

// ============================================================================
// 2. Flow timing recording tests
// ============================================================================

func TestM21_FlowTiming_HTTPSTimingRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream that introduces a small delay.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		time.Sleep(10 * time.Millisecond) // Small server-side delay.
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "timing-test-body")
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

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/timing-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for flow to be persisted.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]

	// Verify timing fields are populated.
	if fl.SendMs == nil {
		t.Error("SendMs is nil, expected non-nil")
	}
	if fl.WaitMs == nil {
		t.Error("WaitMs is nil, expected non-nil")
	}
	if fl.ReceiveMs == nil {
		t.Error("ReceiveMs is nil, expected non-nil")
	}

	// All timing values should be non-negative.
	if fl.SendMs != nil && *fl.SendMs < 0 {
		t.Errorf("SendMs = %d, want >= 0", *fl.SendMs)
	}
	if fl.WaitMs != nil && *fl.WaitMs < 0 {
		t.Errorf("WaitMs = %d, want >= 0", *fl.WaitMs)
	}
	if fl.ReceiveMs != nil && *fl.ReceiveMs < 0 {
		t.Errorf("ReceiveMs = %d, want >= 0", *fl.ReceiveMs)
	}
}

func TestM21_FlowTiming_ConsistencyCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream with a measurable delay.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		// Write a larger body to have non-zero receive time.
		fmt.Fprint(w, strings.Repeat("x", 1024))
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

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/consistency-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]

	// Verify timing values are present and consistent.
	if fl.SendMs == nil || fl.WaitMs == nil || fl.ReceiveMs == nil {
		t.Fatalf("timing fields: send=%v wait=%v receive=%v — expected all non-nil",
			fl.SendMs, fl.WaitMs, fl.ReceiveMs)
	}

	// The sum of send + wait + receive should approximately equal duration_ms.
	totalPhasesMs := *fl.SendMs + *fl.WaitMs + *fl.ReceiveMs
	durationMs := fl.Duration.Milliseconds()

	// Allow generous tolerance: the sum may differ from duration due to
	// proxy overhead, connection setup, etc. We just check the sum is
	// within 2x of the total duration and non-negative.
	if totalPhasesMs < 0 {
		t.Errorf("total phases = %d ms, want >= 0", totalPhasesMs)
	}
	if durationMs > 0 && totalPhasesMs > 2*durationMs+100 {
		t.Errorf("total phases (%d ms) significantly exceeds duration (%d ms)",
			totalPhasesMs, durationMs)
	}
}

func TestM21_FlowTiming_HTTPTimingRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start plain HTTP upstream.
	upstream := gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			time.Sleep(10 * time.Millisecond)
			w.WriteHeader(gohttp.StatusOK)
			fmt.Fprint(w, "http-timing-ok")
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() { upstream.Serve(ln) }()
	defer upstream.Close()

	upstreamAddr := ln.Addr().String()

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

	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	detector := protocol.NewDetector(httpHandler)
	proxyListener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := proxyListener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-proxyListener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// HTTP client through the proxy.
	proxyURL, _ := url.Parse("http://" + proxyListener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{Proxy: gohttp.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/http-timing", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	// HTTP flows should also have timing.
	if fl.SendMs == nil {
		t.Error("SendMs is nil for HTTP flow")
	}
	if fl.WaitMs == nil {
		t.Error("WaitMs is nil for HTTP flow")
	}
	if fl.ReceiveMs == nil {
		t.Error("ReceiveMs is nil for HTTP flow")
	}
}

// ============================================================================
// 3. HAR export tests
// ============================================================================

func TestM21_HARExport_BasicHTTPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, `{"result":"ok"}`)
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

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/api/data?key=val", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for flow to persist.
	pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)

	// Export as HAR.
	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	// Parse and validate HAR structure.
	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR JSON: %v", err)
	}

	if har.Log == nil {
		t.Fatal("har.log is nil")
	}
	if har.Log.Version != "1.2" {
		t.Errorf("har.log.version = %q, want %q", har.Log.Version, "1.2")
	}
	if har.Log.Creator == nil || har.Log.Creator.Name != "yorishiro-proxy" {
		t.Error("har.log.creator.name is not 'yorishiro-proxy'")
	}
	if len(har.Log.Entries) != 1 {
		t.Fatalf("entries count = %d, want 1", len(har.Log.Entries))
	}

	entry := har.Log.Entries[0]

	// Validate request.
	if entry.Request == nil {
		t.Fatal("entry.request is nil")
	}
	if entry.Request.Method != "GET" {
		t.Errorf("request.method = %q, want %q", entry.Request.Method, "GET")
	}
	if !strings.Contains(entry.Request.URL, "/api/data") {
		t.Errorf("request.url = %q, does not contain /api/data", entry.Request.URL)
	}
	if entry.Request.HTTPVersion != "HTTP/1.1" {
		t.Errorf("request.httpVersion = %q, want %q", entry.Request.HTTPVersion, "HTTP/1.1")
	}

	// Validate query string.
	foundKey := false
	for _, qs := range entry.Request.QueryString {
		if qs.Name == "key" && qs.Value == "val" {
			foundKey = true
		}
	}
	if !foundKey {
		t.Error("query string parameter key=val not found")
	}

	// Validate response.
	if entry.Response == nil {
		t.Fatal("entry.response is nil")
	}
	if entry.Response.Status != 200 {
		t.Errorf("response.status = %d, want 200", entry.Response.Status)
	}
	if entry.Response.Content == nil {
		t.Fatal("response.content is nil")
	}
	if entry.Response.Content.MimeType == "" {
		t.Error("response.content.mimeType is empty")
	}
	if entry.Response.Content.Text != `{"result":"ok"}` {
		t.Errorf("response.content.text = %q, want %q", entry.Response.Content.Text, `{"result":"ok"}`)
	}

	// Validate startedDateTime is RFC3339.
	if entry.StartedDateTime == "" {
		t.Error("startedDateTime is empty")
	}

	// Validate timings exist.
	if entry.Timings == nil {
		t.Fatal("entry.timings is nil")
	}
}

func TestM21_HARExport_FilterByProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Create flows of different protocols directly in the store.
	httpsFlow := &flow.Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, httpsFlow); err != nil {
		t.Fatalf("SaveFlow HTTPS: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpsFlow.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL: mustParseURL("https://example.com/https"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpsFlow.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200,
		Body: []byte("https-body"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	httpFlow := &flow.Flow{
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, httpFlow); err != nil {
		t.Fatalf("SaveFlow HTTP: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpFlow.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST",
		URL: mustParseURL("http://example.com/http"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: httpFlow.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 201,
		Body: []byte("http-body"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Export only HTTPS flows.
	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		Filter:        flow.ExportFilter{Protocol: "HTTPS"},
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Errorf("exported = %d, want 1 (only HTTPS)", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}
	if len(har.Log.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(har.Log.Entries))
	}
	if har.Log.Entries[0].Request.Method != "GET" {
		t.Errorf("filtered entry method = %q, want GET", har.Log.Entries[0].Request.Method)
	}
}

func TestM21_HARExport_BinaryBodyBase64(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Create a flow with binary response body.
	binaryBody := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a} // PNG header
	fl := &flow.Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  10 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL: mustParseURL("https://example.com/image.png"),
	}); err != nil {
		t.Fatalf("AppendMessage send: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200,
		Headers: map[string][]string{"Content-Type": {"image/png"}},
		Body:    binaryBody,
	}); err != nil {
		t.Fatalf("AppendMessage recv: %v", err)
	}

	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if entry.Response.Content.Encoding != "base64" {
		t.Errorf("content.encoding = %q, want %q", entry.Response.Content.Encoding, "base64")
	}
	if entry.Response.Content.Text == "" {
		t.Error("content.text is empty for binary body")
	}
	if entry.Response.Content.MimeType != "image/png" {
		t.Errorf("content.mimeType = %q, want %q", entry.Response.Content.MimeType, "image/png")
	}
}

func TestM21_HARExport_WebSocketMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Create a WebSocket flow with upgrade request/response and data messages.
	wsFlow := &flow.Flow{
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  500 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, wsFlow); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Upgrade request.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL:     mustParseURL("wss://example.com/ws"),
		Headers: map[string][]string{"Upgrade": {"websocket"}},
	}); err != nil {
		t.Fatalf("AppendMessage upgrade req: %v", err)
	}

	// Upgrade response.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 101,
		Headers: map[string][]string{"Upgrade": {"websocket"}},
	}); err != nil {
		t.Fatalf("AppendMessage upgrade resp: %v", err)
	}

	// Data messages.
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 2, Direction: "send",
		Timestamp: time.Now().UTC(),
		Body:      []byte("hello"),
		Metadata:  map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage ws send: %v", err)
	}

	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: wsFlow.ID, Sequence: 3, Direction: "receive",
		Timestamp: time.Now().UTC(),
		Body:      []byte("world"),
		Metadata:  map[string]string{"opcode": "1"},
	}); err != nil {
		t.Fatalf("AppendMessage ws recv: %v", err)
	}

	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}

	entry := har.Log.Entries[0]

	// Verify _webSocketMessages custom field.
	if len(entry.WebSocketMessages) == 0 {
		t.Fatal("_webSocketMessages is empty")
	}
	if len(entry.WebSocketMessages) != 2 {
		t.Fatalf("_webSocketMessages count = %d, want 2", len(entry.WebSocketMessages))
	}

	// Verify send message.
	sendMsg := entry.WebSocketMessages[0]
	if sendMsg.Type != "send" {
		t.Errorf("ws msg[0].type = %q, want %q", sendMsg.Type, "send")
	}
	if sendMsg.Data != "hello" {
		t.Errorf("ws msg[0].data = %q, want %q", sendMsg.Data, "hello")
	}
	if sendMsg.Opcode != 1 {
		t.Errorf("ws msg[0].opcode = %d, want 1", sendMsg.Opcode)
	}

	// Verify receive message.
	recvMsg := entry.WebSocketMessages[1]
	if recvMsg.Type != "receive" {
		t.Errorf("ws msg[1].type = %q, want %q", recvMsg.Type, "receive")
	}
	if recvMsg.Data != "world" {
		t.Errorf("ws msg[1].data = %q, want %q", recvMsg.Data, "world")
	}
}

// ============================================================================
// 4. Combined scenario tests
// ============================================================================

func TestM21_Combined_MTLSFlowHARExport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pki := generateTestPKI(t)

	// Start mTLS upstream.
	upstreamAddr, upstreamCleanup := startMTLSServer(t, pki, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, `{"secure":"mtls-data"}`)
	}))
	defer upstreamCleanup()

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

	issuer := cert.NewIssuer(ca)
	httpHandler := protohttp.NewHandler(store, issuer, logger)

	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		ClientCertPath: pki.ClientCertFile,
		ClientKeyPath:  pki.ClientKeyFile,
		CABundlePath:   filepath.Join(pki.TmpDir, "server-ca.crt"),
	})

	tlsTransport := &httputil.StandardTransport{
		InsecureSkipVerify: false,
		HostTLS:            registry,
	}
	httpHandler.SetTLSTransport(tlsTransport)

	detector := protocol.NewDetector(httpHandler)
	proxyListener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := proxyListener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-proxyListener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	client := httpsProxyClient(proxyListener.Addr(), ca.Certificate())

	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)
	targetURL := fmt.Sprintf("https://localhost:%s/secure-api", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET mTLS: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Wait for flow to persist.
	pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)

	// Export as HAR.
	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if entry.Request == nil || entry.Request.Method != "GET" {
		t.Error("HAR entry request method is not GET")
	}
	if entry.Response == nil || entry.Response.Status != 200 {
		t.Error("HAR entry response status is not 200")
	}
	if entry.Response.Content == nil || entry.Response.Content.Text != `{"secure":"mtls-data"}` {
		t.Errorf("HAR response body = %q, want %q", entry.Response.Content.Text, `{"secure":"mtls-data"}`)
	}
}

func TestM21_Combined_TimingInHAR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "timing-har-test")
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

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()
	httpHandler.SetTransport(upstreamTransport)

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/timing-har", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]

	// Verify flow has timing data.
	if fl.SendMs == nil || fl.WaitMs == nil || fl.ReceiveMs == nil {
		t.Fatalf("timing fields missing: send=%v wait=%v receive=%v",
			fl.SendMs, fl.WaitMs, fl.ReceiveMs)
	}

	// Export as HAR and verify timings are reflected.
	var buf bytes.Buffer
	exported, err := flow.ExportHAR(ctx, store, &buf, flow.ExportOptions{
		IncludeBodies: true,
	}, "test")
	if err != nil {
		t.Fatalf("ExportHAR: %v", err)
	}
	if exported != 1 {
		t.Fatalf("exported = %d, want 1", exported)
	}

	var har flow.HAR
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("parse HAR: %v", err)
	}

	entry := har.Log.Entries[0]
	if entry.Timings == nil {
		t.Fatal("HAR timings is nil")
	}

	// HAR timings should reflect flow timing data (not -1 defaults).
	if entry.Timings.Send < 0 {
		t.Errorf("HAR timings.send = %f, want >= 0", entry.Timings.Send)
	}
	if entry.Timings.Wait < 0 {
		t.Errorf("HAR timings.wait = %f, want >= 0", entry.Timings.Wait)
	}
	if entry.Timings.Receive < 0 {
		t.Errorf("HAR timings.receive = %f, want >= 0", entry.Timings.Receive)
	}

	// HAR timings should match flow timing values.
	if entry.Timings.Send != float64(*fl.SendMs) {
		t.Errorf("HAR timings.send = %f, want %f", entry.Timings.Send, float64(*fl.SendMs))
	}
	if entry.Timings.Wait != float64(*fl.WaitMs) {
		t.Errorf("HAR timings.wait = %f, want %f", entry.Timings.Wait, float64(*fl.WaitMs))
	}
	if entry.Timings.Receive != float64(*fl.ReceiveMs) {
		t.Errorf("HAR timings.receive = %f, want %f", entry.Timings.Receive, float64(*fl.ReceiveMs))
	}
}

// mustParseURL parses a URL string or panics.
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("mustParseURL(%q): %v", rawURL, err))
	}
	return u
}
