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
	ServerCAPool     *x509.CertPool
	ServerCertFile   string
	ServerKeyFile    string
	ServerCACertFile string
	ClientCertFile   string
	ClientKeyFile    string
	ClientCAPool     *x509.CertPool
	TmpDir           string
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
		ServerCAPool:     serverCAPool,
		ServerCertFile:   serverCertFile,
		ServerKeyFile:    serverKeyFile,
		ServerCACertFile: serverCACertFile,
		ClientCertFile:   clientCertFile,
		ClientKeyFile:    clientKeyFile,
		ClientCAPool:     clientCAPool,
		TmpDir:           tmpDir,
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

// startMTLSProxy creates an HTTPS proxy with a pre-configured HostTLSRegistry
// and returns the listener, handler, and a cancel function.
// It blocks until the proxy is ready to accept connections.
func startMTLSProxy(t *testing.T, ctx context.Context, store flow.Store, ca *cert.CA, registry *httputil.HostTLSRegistry) (*proxy.Listener, *protohttp.Handler, context.CancelFunc) {
	t.Helper()

	issuer := cert.NewIssuer(ca)
	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, issuer, logger)

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

	return listener, httpHandler, proxyCancel
}

// ============================================================================
// mTLS integration tests
// ============================================================================

func TestMTLS_ProxyWithClientCert(t *testing.T) {
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

	// Configure TLS transport with client certificate for localhost.
	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		ClientCertPath: pki.ClientCertFile,
		ClientKeyPath:  pki.ClientKeyFile,
		CABundlePath:   pki.ServerCACertFile,
	})

	listener, _, proxyCancel := startMTLSProxy(t, ctx, store, ca, registry)
	defer proxyCancel()

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

func TestMTLS_ConnectionRejectedWithoutClientCert(t *testing.T) {
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

	// Configure TLS transport WITHOUT client cert but with server CA trust.
	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		CABundlePath: pki.ServerCACertFile,
	})

	listener, _, proxyCancel := startMTLSProxy(t, ctx, store, ca, registry)
	defer proxyCancel()

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

func TestMTLS_PerHostCertSwitching(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pki := generateTestPKI(t)

	// Start mTLS upstream server (requires client cert).
	// Both servers share the same server cert which has DNSNames=["localhost"]
	// and IPAddresses=[127.0.0.1]. We address the mTLS server via "127.0.0.1"
	// and the plain TLS server via "localhost" so that HostTLSRegistry
	// differentiates them by hostname.
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

	// Configure per-host TLS using different hostnames:
	// "127.0.0.1" → mTLS server (with client cert + server CA)
	// "localhost"  → plain TLS server (server CA only, no client cert)
	_, mtlsPort, _ := net.SplitHostPort(mtlsAddr)
	_, tlsPort, _ := net.SplitHostPort(tlsAddr)

	registry := httputil.NewHostTLSRegistry()
	registry.Set("127.0.0.1", &httputil.HostTLSConfig{
		ClientCertPath: pki.ClientCertFile,
		ClientKeyPath:  pki.ClientKeyFile,
		CABundlePath:   pki.ServerCACertFile,
	})
	registry.Set("localhost", &httputil.HostTLSConfig{
		CABundlePath: pki.ServerCACertFile,
	})

	listener, _, proxyCancel := startMTLSProxy(t, ctx, store, ca, registry)
	defer proxyCancel()

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	// Request to mTLS host via 127.0.0.1 — should present client cert.
	mtlsURL := fmt.Sprintf("https://127.0.0.1:%s/mtls", mtlsPort)
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

	// Request to plain TLS host via localhost — should NOT present client cert.
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

func TestMTLS_TLSVerifyControl(t *testing.T) {
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

	// Test: TLSVerify=false skips verification (should succeed without CA bundle).
	tlsVerifyFalse := false
	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		TLSVerify: &tlsVerifyFalse,
	})

	listener, _, proxyCancel := startMTLSProxy(t, ctx, store, ca, registry)
	defer proxyCancel()

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

func TestMTLS_FlowHARExport(t *testing.T) {
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

	registry := httputil.NewHostTLSRegistry()
	registry.Set("localhost", &httputil.HostTLSConfig{
		ClientCertPath: pki.ClientCertFile,
		ClientKeyPath:  pki.ClientKeyFile,
		CABundlePath:   pki.ServerCACertFile,
	})

	proxyListener, _, proxyCancel := startMTLSProxy(t, ctx, store, ca, registry)
	defer proxyCancel()

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
