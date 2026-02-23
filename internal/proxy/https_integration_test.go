package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/katashiro-proxy/internal/protocol/http"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// startHTTPSProxy creates and starts a proxy with TLS MITM support.
// It returns the listener, the HTTP handler (for transport configuration),
// and a cancel function for cleanup.
func startHTTPSProxy(t *testing.T, ctx context.Context, store session.Store, ca *cert.CA) (*proxy.Listener, *protohttp.Handler, context.CancelFunc) {
	t.Helper()

	issuer := cert.NewIssuer(ca)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener("127.0.0.1:0", detector, logger)

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

	return listener, httpHandler, proxyCancel
}

// httpsProxyClient creates an HTTP client configured to use the proxy for
// CONNECT tunneling and trust the given CA certificate for TLS verification.
func httpsProxyClient(proxyAddr string, caCert *x509.Certificate) *gohttp.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 5 * time.Second,
	}
}

// newTestUpstreamHTTPS creates a test HTTPS server and returns the server
// along with a transport configured to trust the test server's certificate.
// The transport should be injected into the proxy handler via SetTransport
// so the proxy can connect to the test upstream.
func newTestUpstreamHTTPS(handler gohttp.Handler) (*httptest.Server, *gohttp.Transport) {
	server := httptest.NewTLSServer(handler)
	transport := &gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return server, transport
}

func TestIntegration_HTTPSGET(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start upstream HTTPS server.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "upstream-https")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from https upstream")
	}))
	defer upstream.Close()

	// Extract port from upstream server.
	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// Create temporary SQLite database.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Generate test CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	// Start proxy with HTTPS MITM support.
	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()

	// Configure the proxy's upstream transport to trust the test server.
	httpHandler.SetTransport(upstreamTransport)

	// Create client that trusts the proxy's CA.
	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	// Send HTTPS GET request through the proxy.
	targetURL := fmt.Sprintf("https://localhost:%s/test-path", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from https upstream" {
		t.Errorf("body = %q, want %q", body, "hello from https upstream")
	}
	if resp.Header.Get("X-Test") != "upstream-https" {
		t.Errorf("X-Test header = %q, want %q", resp.Header.Get("X-Test"), "upstream-https")
	}

	// Wait for session to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Verify session was recorded.
	entries, err := store.List(ctx, session.ListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 HTTPS session, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Request.Method != "GET" {
		t.Errorf("session method = %q, want %q", entry.Request.Method, "GET")
	}
	if entry.Protocol != "HTTPS" {
		t.Errorf("session protocol = %q, want %q", entry.Protocol, "HTTPS")
	}
	if entry.Request.URL == nil || entry.Request.URL.Scheme != "https" {
		scheme := ""
		if entry.Request.URL != nil {
			scheme = entry.Request.URL.Scheme
		}
		t.Errorf("session URL scheme = %q, want %q", scheme, "https")
	}
	if entry.Request.URL == nil || entry.Request.URL.Path != "/test-path" {
		path := ""
		if entry.Request.URL != nil {
			path = entry.Request.URL.Path
		}
		t.Errorf("session URL path = %q, want %q", path, "/test-path")
	}
	if entry.Response.StatusCode != 200 {
		t.Errorf("session status = %d, want %d", entry.Response.StatusCode, 200)
	}
	if string(entry.Response.Body) != "hello from https upstream" {
		t.Errorf("session response body = %q, want %q", entry.Response.Body, "hello from https upstream")
	}
}

func TestIntegration_HTTPSPOST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start upstream HTTPS server that echoes the request body.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "received: %s", body)
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
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

	// Send HTTPS POST request with JSON body.
	reqBody := `{"key":"value","number":42}`
	targetURL := fmt.Sprintf("https://localhost:%s/api/data", upstreamPort)
	resp, err := client.Post(targetURL, "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("HTTPS POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusCreated)
	}
	expectedBody := "received: " + reqBody
	if string(body) != expectedBody {
		t.Errorf("body = %q, want %q", body, expectedBody)
	}

	// Wait for session to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Verify session was recorded.
	entries, err := store.List(ctx, session.ListOptions{Method: "POST", Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 POST session, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Request.Method != "POST" {
		t.Errorf("session method = %q, want %q", entry.Request.Method, "POST")
	}
	if entry.Protocol != "HTTPS" {
		t.Errorf("session protocol = %q, want %q", entry.Protocol, "HTTPS")
	}
	if entry.Request.URL == nil || entry.Request.URL.Scheme != "https" {
		t.Errorf("session URL scheme = %q, want %q", entry.Request.URL.Scheme, "https")
	}
	if entry.Request.URL == nil || entry.Request.URL.Path != "/api/data" {
		t.Errorf("session URL path = %q, want %q", entry.Request.URL.Path, "/api/data")
	}
	if string(entry.Request.Body) != reqBody {
		t.Errorf("session request body = %q, want %q", entry.Request.Body, reqBody)
	}
	if entry.Response.StatusCode != 201 {
		t.Errorf("session response status = %d, want %d", entry.Response.StatusCode, 201)
	}
	if string(entry.Response.Body) != expectedBody {
		t.Errorf("session response body = %q, want %q", entry.Response.Body, expectedBody)
	}
}

func TestIntegration_HTTPSSessionRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start upstream HTTPS server with custom headers.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Custom-Response", "custom-value")
		w.Header().Set("X-Request-Path", r.URL.Path)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "session-test-body")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
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

	// Send request with query parameters.
	targetURL := fmt.Sprintf("https://localhost:%s/session/check?q=test&page=1", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET through proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for session to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Verify detailed session recording.
	entries, err := store.List(ctx, session.ListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 session, got %d", len(entries))
	}

	entry := entries[0]

	// Protocol must be HTTPS.
	if entry.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", entry.Protocol, "HTTPS")
	}

	// URL must have https scheme.
	if entry.Request.URL == nil {
		t.Fatal("request URL is nil")
	}
	if entry.Request.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", entry.Request.URL.Scheme, "https")
	}

	// URL path must match.
	if entry.Request.URL.Path != "/session/check" {
		t.Errorf("URL path = %q, want %q", entry.Request.URL.Path, "/session/check")
	}

	// Query parameters must be preserved.
	if entry.Request.URL.RawQuery != "q=test&page=1" {
		t.Errorf("URL query = %q, want %q", entry.Request.URL.RawQuery, "q=test&page=1")
	}

	// Host must contain localhost.
	if !strings.Contains(entry.Request.URL.Host, "localhost") {
		t.Errorf("URL host = %q, does not contain %q", entry.Request.URL.Host, "localhost")
	}

	// Decrypted response body must be recorded.
	if string(entry.Response.Body) != "session-test-body" {
		t.Errorf("response body = %q, want %q", entry.Response.Body, "session-test-body")
	}

	// Response headers must be recorded (decrypted).
	if gohttp.Header(entry.Response.Headers).Get("X-Custom-Response") != "custom-value" {
		t.Errorf("response header X-Custom-Response = %q, want %q",
			gohttp.Header(entry.Response.Headers).Get("X-Custom-Response"), "custom-value")
	}

	// Duration must be positive.
	if entry.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Duration)
	}

	// ID must be assigned.
	if entry.ID == "" {
		t.Error("session ID is empty")
	}
}

func TestIntegration_HTTPSKeepAlive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var mu sync.Mutex
	requestCount := 0
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		mu.Lock()
		requestCount++
		count := requestCount
		mu.Unlock()
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "response-%d", count)
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
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

	// Send multiple HTTPS requests over the same connection (keep-alive).
	// Go's http.Client reuses connections by default.
	for i := 1; i <= 3; i++ {
		targetURL := fmt.Sprintf("https://localhost:%s/path-%d", upstreamPort, i)
		resp, err := client.Get(targetURL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		expectedBody := fmt.Sprintf("response-%d", i)
		if string(body) != expectedBody {
			t.Errorf("request %d body = %q, want %q", i, body, expectedBody)
		}
	}

	// Wait for sessions to be persisted.
	time.Sleep(300 * time.Millisecond)

	// Verify all 3 sessions were recorded.
	entries, err := store.List(ctx, session.ListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 HTTPS sessions, got %d", len(entries))
	}

	// Verify each session has correct protocol and unique paths.
	// Note: entries are ordered by timestamp DESC, so we check all have HTTPS protocol.
	paths := make(map[string]bool)
	for _, entry := range entries {
		if entry.Protocol != "HTTPS" {
			t.Errorf("session protocol = %q, want %q", entry.Protocol, "HTTPS")
		}
		if entry.Request.URL == nil {
			t.Error("request URL is nil")
			continue
		}
		if entry.Request.URL.Scheme != "https" {
			t.Errorf("URL scheme = %q, want %q", entry.Request.URL.Scheme, "https")
		}
		paths[entry.Request.URL.Path] = true
	}

	// Verify all 3 unique paths were recorded.
	for i := 1; i <= 3; i++ {
		expectedPath := fmt.Sprintf("/path-%d", i)
		if !paths[expectedPath] {
			t.Errorf("missing session for path %q", expectedPath)
		}
	}
}

func TestIntegration_HTTPSMultipleHosts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start two separate upstream HTTPS servers to simulate different hosts.
	upstream1, _ := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "host1-response")
	}))
	defer upstream1.Close()

	upstream2, _ := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "host2-response")
	}))
	defer upstream2.Close()

	_, port1, _ := net.SplitHostPort(upstream1.Listener.Addr().String())
	_, port2, _ := net.SplitHostPort(upstream2.Listener.Addr().String())

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := session.NewSQLiteStore(ctx, dbPath, logger)
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

	// Use InsecureSkipVerify for upstream connections since both test
	// servers use self-signed certificates.
	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	client := httpsProxyClient(listener.Addr(), ca.Certificate())

	// Send HTTPS request to first "host" (localhost:port1).
	url1 := fmt.Sprintf("https://localhost:%s/host1-path", port1)
	resp1, err := client.Get(url1)
	if err != nil {
		t.Fatalf("GET to host1: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if string(body1) != "host1-response" {
		t.Errorf("host1 body = %q, want %q", body1, "host1-response")
	}

	// Send HTTPS request to second "host" (localhost:port2).
	url2 := fmt.Sprintf("https://localhost:%s/host2-path", port2)
	resp2, err := client.Get(url2)
	if err != nil {
		t.Fatalf("GET to host2: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if string(body2) != "host2-response" {
		t.Errorf("host2 body = %q, want %q", body2, "host2-response")
	}

	// Wait for sessions to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Verify both sessions were recorded with different hosts.
	entries, err := store.List(ctx, session.ListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 HTTPS sessions, got %d", len(entries))
	}

	// Verify sessions have different host:port values.
	hosts := make(map[string]bool)
	for _, entry := range entries {
		if entry.Request.URL == nil {
			t.Error("request URL is nil")
			continue
		}
		hosts[entry.Request.URL.Host] = true
		if entry.Protocol != "HTTPS" {
			t.Errorf("protocol = %q, want %q", entry.Protocol, "HTTPS")
		}
		if entry.Request.URL.Scheme != "https" {
			t.Errorf("URL scheme = %q, want %q", entry.Request.URL.Scheme, "https")
		}
	}

	expectedHost1 := "localhost:" + port1
	expectedHost2 := "localhost:" + port2
	if !hosts[expectedHost1] {
		t.Errorf("missing session for host %q, got hosts %v", expectedHost1, hosts)
	}
	if !hosts[expectedHost2] {
		t.Errorf("missing session for host %q, got hosts %v", expectedHost2, hosts)
	}
}
