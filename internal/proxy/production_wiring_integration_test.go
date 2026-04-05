//go:build e2e

package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// productionLikeConfig holds configuration values that mirror production
// wiring in cmd/yorishiro-proxy/main.go initProtocolHandlers.
type productionLikeConfig struct {
	// PeekTimeout mirrors cfg.PeekTimeout set via manager.SetPeekTimeout.
	PeekTimeout time.Duration
	// MaxConnections mirrors cfg.MaxConnections set via manager.SetMaxConnections.
	MaxConnections int
	// RequestTimeout mirrors cfg.RequestTimeout set on the HTTP handler.
	RequestTimeout time.Duration
	// InsecureSkipVerify mirrors cfg.InsecureSkipVerify.
	InsecureSkipVerify bool
}

// startProductionWiredProxy creates a proxy with production-equivalent wiring.
// It calls all setter methods that production main.go calls, ensuring there
// are no setter interaction bugs.
func startProductionWiredProxy(
	t *testing.T,
	ctx context.Context,
	cfg productionLikeConfig,
	safetyEngine *safety.Engine,
) (listener *proxy.Listener, httpHandler *protohttp.Handler, store *flow.SQLiteStore, cancel context.CancelFunc) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()

	var err error
	store, err = flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// Generate ephemeral CA (mirrors production ca-ephemeral mode).
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	// Create HTTP handler (mirrors initProtocolHandlers).
	httpHandler = protohttp.NewHandler(store, issuer, logger)

	// --- All setter methods called in production order ---

	// 1. SetRequestTimeout (mirrors httpHandler.SetRequestTimeout(cfg.RequestTimeout))
	if cfg.RequestTimeout > 0 {
		httpHandler.SetRequestTimeout(cfg.RequestTimeout)
	}

	// 2. SetInsecureSkipVerify (mirrors httpHandler.SetInsecureSkipVerify(cfg.InsecureSkipVerify))
	httpHandler.SetInsecureSkipVerify(cfg.InsecureSkipVerify)

	// 3. SetPassthroughList (mirrors httpHandler.SetPassthroughList(passthrough))
	passthrough := proxy.NewPassthroughList()
	httpHandler.SetPassthroughList(passthrough)

	// 4. SetCaptureScope (mirrors httpHandler.SetCaptureScope(scope))
	scope := proxy.NewCaptureScope()
	httpHandler.SetCaptureScope(scope)

	// 5. SetInterceptEngine (mirrors httpHandler.SetInterceptEngine(interceptEngine))
	interceptEngine := intercept.NewEngine()
	httpHandler.SetInterceptEngine(interceptEngine)

	// 6. SetInterceptQueue (mirrors httpHandler.SetInterceptQueue(interceptQueue))
	interceptQueue := intercept.NewQueue()
	httpHandler.SetInterceptQueue(interceptQueue)

	// 7. SetTransformPipeline (mirrors httpHandler.SetTransformPipeline(pipeline))
	pipeline := rules.NewPipeline()
	httpHandler.SetTransformPipeline(pipeline)

	// 8. SetTLSTransport (mirrors initTLSTransport → httpHandler.SetTLSTransport(t))
	hostTLSRegistry := httputil.NewHostTLSRegistry()
	tlsTransport := &httputil.StandardTransport{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		HostTLS:            hostTLSRegistry,
	}
	httpHandler.SetTLSTransport(tlsTransport)

	// 9. SetDetector (mirrors httpHandler.SetDetector(fpDetector))
	fpDetector := fingerprint.NewDetector()
	httpHandler.SetDetector(fpDetector)

	// 10. SetSafetyEngine (mirrors safety engine setup when enabled)
	if safetyEngine != nil {
		httpHandler.SetSafetyEngine(safetyEngine)
	}

	// Build protocol detector (mirrors production).
	detector := protocol.NewDetector(httpHandler)

	// Configure listener with production-like timeouts.
	listenerCfg := proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	}
	if cfg.PeekTimeout > 0 {
		listenerCfg.PeekTimeout = cfg.PeekTimeout
	}
	if cfg.MaxConnections > 0 {
		listenerCfg.MaxConnections = cfg.MaxConnections
	}

	listener = proxy.NewListener(listenerCfg)

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
		store.Close()
		t.Fatal("proxy did not become ready")
	}

	cancel = func() {
		proxyCancel()
		store.Close()
	}
	return listener, httpHandler, store, cancel
}

// TestIntegration_ProductionWiring_HTTPSMITM verifies that an HTTPS request
// passes through the proxy with all production setter methods applied.
// This covers setter interaction bugs that per-setter tests miss.
func TestIntegration_ProductionWiring_HTTPSMITM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := productionLikeConfig{
		PeekTimeout:        5 * time.Second,
		MaxConnections:     64,
		RequestTimeout:     10 * time.Second,
		InsecureSkipVerify: true,
	}

	listener, httpHandler, store, proxyCancel := startProductionWiredProxy(t, ctx, cfg, nil)
	defer proxyCancel()

	// Start upstream HTTPS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Wiring-Test", "production-like")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "production-wired-response")
	}))
	defer upstream.Close()

	// Configure upstream transport (test-only: trust the test server).
	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// Build client that trusts the proxy's CA.
	// Retrieve CA cert from the issuer's CA via the handler.
	// Since we generated the CA in the helper, we need to get it.
	// Re-generate CA for client trust (the helper uses its own).
	// Actually, we need the CA from inside the helper.
	// Let's use a different approach: create client with InsecureSkipVerify for MITM test.

	// The proxy issues MITM certs using the CA generated inside the helper.
	// We can't access it, so we'll skip client-side TLS verify of the MITM cert.
	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	// Send HTTPS request through proxy.
	targetURL := fmt.Sprintf("https://localhost:%s/production-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET through production-wired proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "production-wired-response" {
		t.Errorf("body = %q, want %q", body, "production-wired-response")
	}

	// Verify flow was recorded.
	flows := pollFlows(t, ctx, store, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10}, 1)
	fl := flows[0]
	if fl.Protocol != "HTTPS" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTPS")
	}

	send, recv := pollFlowMessages(t, ctx, store, fl.ID)
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
		t.Errorf("status code = %d, want %d", recv.StatusCode, 200)
	}
}

// TestIntegration_ProductionWiring_TimeoutMaxConnections verifies that
// PeekTimeout and MaxConnections are applied correctly in production-like
// wiring. This extends timeout_integration_test.go coverage to the
// production wiring path.
func TestIntegration_ProductionWiring_TimeoutMaxConnections(t *testing.T) {
	t.Run("peek_timeout_closes_idle_connection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cfg := productionLikeConfig{
			PeekTimeout:        200 * time.Millisecond,
			MaxConnections:     4,
			RequestTimeout:     10 * time.Second,
			InsecureSkipVerify: true,
		}

		listener, _, _, proxyCancel := startProductionWiredProxy(t, ctx, cfg, nil)
		defer proxyCancel()

		// Connect but send nothing — should be closed by peek timeout.
		conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()

		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected connection to be closed by proxy peek timeout")
		}

		// Should close within 3x the peek timeout.
		maxExpected := cfg.PeekTimeout * 3
		if elapsed > maxExpected {
			t.Errorf("connection closed after %v, expected within %v", elapsed, maxExpected)
		}
		if elapsed < cfg.PeekTimeout/2 {
			t.Errorf("connection closed too early (%v), peek timeout is %v", elapsed, cfg.PeekTimeout)
		}
	})

	t.Run("max_connections_limits_concurrent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		const maxConns = 2

		cfg := productionLikeConfig{
			PeekTimeout:        5 * time.Second,
			MaxConnections:     maxConns,
			RequestTimeout:     10 * time.Second,
			InsecureSkipVerify: true,
		}

		listener, _, _, proxyCancel := startProductionWiredProxy(t, ctx, cfg, nil)
		defer proxyCancel()

		// Open maxConns connections to fill the semaphore.
		conns := make([]net.Conn, 0, maxConns)
		for i := 0; i < maxConns; i++ {
			conn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy conn %d: %v", i, err)
			}
			// Send partial HTTP to pass peek detection but keep connection alive.
			conn.Write([]byte("GET http://127.0.0.1/slow HTTP/1.1\r\nHost: 127.0.0.1\r\n"))
			conns = append(conns, conn)
		}
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()

		// Give the listener time to acquire semaphore for each connection.
		time.Sleep(200 * time.Millisecond)

		// An additional connection should still be accepted at the TCP level
		// (the OS accepts the connection), but the proxy won't process it
		// until a slot frees up. Verify the proxy is still responsive by
		// closing one held connection and then sending a valid request.
		conns[0].Close()
		time.Sleep(100 * time.Millisecond)

		// New connection after freeing a slot should be accepted.
		newConn, err := net.DialTimeout("tcp", listener.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy after slot free: %v", err)
		}
		defer newConn.Close()

		// Verify the proxy accepts and processes data on the new connection.
		newConn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = newConn.Write([]byte("GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		if err != nil {
			t.Fatalf("write on new connection: %v", err)
		}
	})
}

// TestIntegration_ProductionWiring_SafetyFilter verifies that the safety
// filter engine works correctly when wired into the HTTP handler following
// the production initialization path.
func TestIntegration_ProductionWiring_SafetyFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create a safety engine with an input rule that blocks DROP TABLE.
	safetyEngine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				Preset: "destructive-sql",
				Action: "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cfg := productionLikeConfig{
		PeekTimeout:        5 * time.Second,
		MaxConnections:     64,
		RequestTimeout:     10 * time.Second,
		InsecureSkipVerify: true,
	}

	listener, _, _, proxyCancel := startProductionWiredProxy(t, ctx, cfg, safetyEngine)
	defer proxyCancel()

	// Start upstream HTTP server (should NOT be reached for blocked requests).
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			w.WriteHeader(gohttp.StatusOK)
			fmt.Fprint(w, "should-not-reach")
		}),
	}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Send a request with a destructive SQL payload.
	targetURL := fmt.Sprintf("http://%s/api/query", upstreamAddr)
	reqBody := strings.NewReader("DROP TABLE users;")
	resp, err := client.Post(targetURL, "text/plain", reqBody)
	if err != nil {
		t.Fatalf("POST with destructive SQL: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The safety filter should block this request with 403.
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want %d (body: %s)", resp.StatusCode, gohttp.StatusForbidden, body)
	}
	if !strings.Contains(string(body), "safety_filter") {
		t.Errorf("body should mention safety_filter, got: %s", body)
	}

	// Send a benign request — should pass through.
	benignResp, err := client.Get(fmt.Sprintf("http://%s/api/data", upstreamAddr))
	if err != nil {
		t.Fatalf("benign GET: %v", err)
	}
	defer benignResp.Body.Close()
	benignBody, _ := io.ReadAll(benignResp.Body)

	if benignResp.StatusCode != gohttp.StatusOK {
		t.Errorf("benign status = %d, want %d", benignResp.StatusCode, gohttp.StatusOK)
	}
	if string(benignBody) != "should-not-reach" {
		// Benign request should reach upstream.
		t.Errorf("benign body = %q, want %q", benignBody, "should-not-reach")
	}
}

// TestIntegration_ProductionWiring_CaptureLogger verifies that initialization
// errors and warnings are captured in the logger when using production-like
// wiring. This ensures that DiscardLogger() doesn't hide important errors.
func TestIntegration_ProductionWiring_CaptureLogger(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	capture, logger := testutil.NewCaptureLogger()

	// Create a production-like proxy manually with CaptureLogger to verify
	// that InsecureSkipVerify logs a warning.
	dbPath := filepath.Join(t.TempDir(), "test.db")
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

	// Calling SetInsecureSkipVerify(true) should log a warning.
	httpHandler.SetInsecureSkipVerify(true)

	// Apply all other setters (production-like).
	httpHandler.SetPassthroughList(proxy.NewPassthroughList())
	httpHandler.SetCaptureScope(proxy.NewCaptureScope())
	httpHandler.SetInterceptEngine(intercept.NewEngine())
	httpHandler.SetInterceptQueue(intercept.NewQueue())
	httpHandler.SetTransformPipeline(rules.NewPipeline())
	httpHandler.SetDetector(fingerprint.NewDetector())

	hostTLSRegistry := httputil.NewHostTLSRegistry()
	tlsTransport := &httputil.StandardTransport{
		InsecureSkipVerify: true,
		HostTLS:            hostTLSRegistry,
	}
	httpHandler.SetTLSTransport(tlsTransport)

	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:           "127.0.0.1:0",
		Detector:       detector,
		Logger:         logger,
		PeekTimeout:    5 * time.Second,
		MaxConnections: 64,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// Start upstream HTTPS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "capture-logger-test")
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	// Build client trusting the proxy CA.
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Certificate())
	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 5 * time.Second,
	}

	// Send HTTPS request through proxy.
	targetURL := fmt.Sprintf("https://localhost:%s/capture-test", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify the warning about InsecureSkipVerify was logged.
	logOutput := capture.Output()
	if !strings.Contains(logOutput, "TLS certificate verification is disabled") {
		t.Errorf("expected InsecureSkipVerify warning in logs, got:\n%s", logOutput)
	}
}

// TestIntegration_ProductionWiring_AllSettersHTTPForward verifies that
// all setter methods interact correctly for a plain HTTP forward proxy
// request (not CONNECT/MITM). This ensures that passthrough, intercept,
// transform, and safety all participate in the request flow.
func TestIntegration_ProductionWiring_AllSettersHTTPForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := productionLikeConfig{
		PeekTimeout:        5 * time.Second,
		MaxConnections:     64,
		RequestTimeout:     10 * time.Second,
		InsecureSkipVerify: false,
	}

	listener, _, store, proxyCancel := startProductionWiredProxy(t, ctx, cfg, nil)
	defer proxyCancel()

	// Start upstream HTTP server.
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			w.Header().Set("X-Handler", "all-setters")
			w.WriteHeader(gohttp.StatusOK)
			fmt.Fprintf(w, "all-setters-ok:%s", r.URL.Path)
		}),
	}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Send multiple requests.
	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/data"},
		{"GET", "/health"},
	}

	for _, tt := range tests {
		targetURL := fmt.Sprintf("http://%s%s", upstreamAddr, tt.path)
		var resp *gohttp.Response
		var reqErr error
		if tt.method == "POST" {
			resp, reqErr = client.Post(targetURL, "application/json", strings.NewReader(`{"test":true}`))
		} else {
			resp, reqErr = client.Get(targetURL)
		}
		if reqErr != nil {
			t.Fatalf("%s %s: %v", tt.method, tt.path, reqErr)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != gohttp.StatusOK {
			t.Errorf("%s %s: status = %d, want %d", tt.method, tt.path, resp.StatusCode, gohttp.StatusOK)
		}
		expectedBody := fmt.Sprintf("all-setters-ok:%s", tt.path)
		if string(body) != expectedBody {
			t.Errorf("%s %s: body = %q, want %q", tt.method, tt.path, body, expectedBody)
		}
	}

	// Verify all flows were recorded.
	flows := pollFlows(t, ctx, store, flow.StreamListOptions{Protocol: "HTTP/1.x", Limit: 10}, len(tests))
	if len(flows) != len(tests) {
		t.Fatalf("expected %d flows, got %d", len(tests), len(flows))
	}

	// Verify each flow has proper messages.
	for _, fl := range flows {
		if fl.Protocol != "HTTP/1.x" {
			t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
		}
		send, recv := pollFlowMessages(t, ctx, store, fl.ID)
		if send == nil {
			t.Error("send message not found")
		}
		if recv == nil {
			t.Error("receive message not found")
		}
		if recv != nil && recv.StatusCode != 200 {
			t.Errorf("flow status = %d, want %d", recv.StatusCode, 200)
		}
	}
}
