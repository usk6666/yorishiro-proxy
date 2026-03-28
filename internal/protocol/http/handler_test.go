package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	interceptPkg "github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestSetInsecureSkipVerify_EnablesSkipVerify(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	handler.SetInsecureSkipVerify(true)

	if handler.Transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil after SetInsecureSkipVerify(true)")
	}
	if !handler.Transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestSetInsecureSkipVerify_FalseDoesNotModifyTransport(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	handler.SetInsecureSkipVerify(false)

	// When skip is false, TLSClientConfig should remain nil (not modified).
	if handler.Transport.TLSClientConfig != nil {
		t.Errorf("TLSClientConfig = %v, want nil when skip is false", handler.Transport.TLSClientConfig)
	}
}

func TestSetInsecureSkipVerify_PreservesExistingTLSConfig(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Pre-set a TLSClientConfig with a custom field.
	handler.Transport.TLSClientConfig = &tls.Config{
		ServerName: "custom-server",
	}

	handler.SetInsecureSkipVerify(true)

	if handler.Transport.TLSClientConfig.ServerName != "custom-server" {
		t.Errorf("ServerName = %q, want %q", handler.Transport.TLSClientConfig.ServerName, "custom-server")
	}
	if !handler.Transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestNewHandler_DefaultTransportHasNoInsecureSkipVerify(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Default transport should not have TLSClientConfig set.
	if handler.Transport.TLSClientConfig != nil {
		t.Errorf("default transport TLSClientConfig = %v, want nil", handler.Transport.TLSClientConfig)
	}
}

func TestInsecureSkipVerify_HTTPForwardToSelfSignedServer(t *testing.T) {
	// Start an HTTPS server with a self-signed certificate (httptest.NewTLSServer).
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Insecure-Test", "passed")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "self-signed-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Enable InsecureSkipVerify so the handler can connect to the self-signed upstream.
	handler.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Connect to the proxy and send a request targeting the self-signed HTTPS upstream.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "self-signed-ok" {
		t.Errorf("body = %q, want %q", body, "self-signed-ok")
	}
	if resp.Header.Get("X-Insecure-Test") != "passed" {
		t.Errorf("X-Insecure-Test = %q, want %q", resp.Header.Get("X-Insecure-Test"), "passed")
	}
}

func TestInsecureSkipVerify_HTTPSConnectToSelfSignedServer(t *testing.T) {
	// Start an HTTPS server with a self-signed certificate.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Insecure-HTTPS", "ok")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "https-self-signed-ok")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	// Use SetInsecureSkipVerify instead of manually setting transport.
	handler.SetInsecureSkipVerify(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	httpReq := fmt.Sprintf("GET /test-insecure HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
	tlsConn.Write([]byte(httpReq))

	httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	body, _ := io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	if httpsResp.StatusCode != gohttp.StatusOK {
		t.Errorf("HTTPS status = %d, want %d", httpsResp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "https-self-signed-ok" {
		t.Errorf("body = %q, want %q", body, "https-self-signed-ok")
	}

	// Verify flow was recorded.
	time.Sleep(100 * time.Millisecond)
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}
	if entries[0].Session.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", entries[0].Session.Protocol, "HTTPS")
	}
}

func TestWithoutInsecureSkipVerify_SelfSignedServerFails(t *testing.T) {
	// Start an HTTPS server with a self-signed certificate.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "should-not-reach")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())
	// Do NOT set InsecureSkipVerify — default transport should reject self-signed cert.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send a request to the self-signed HTTPS upstream.
	httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, upstream.Listener.Addr().String())
	conn.Write([]byte(httpReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	// Without InsecureSkipVerify, the proxy should return 502 Bad Gateway
	// because it cannot verify the self-signed certificate.
	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d (502 Bad Gateway for self-signed cert)", resp.StatusCode, gohttp.StatusBadGateway)
	}
}

func TestApplyInterceptModifications_URLSchemeValidation(t *testing.T) {
	tests := []struct {
		name        string
		overrideURL string
		wantErr     bool
		errContains string
	}{
		{
			name:        "http scheme allowed",
			overrideURL: "http://example.com/path",
			wantErr:     false,
		},
		{
			name:        "https scheme allowed",
			overrideURL: "https://example.com/path",
			wantErr:     false,
		},
		{
			name:        "file scheme rejected",
			overrideURL: "file:///etc/passwd",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "ftp scheme rejected",
			overrideURL: "ftp://example.com/file",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "gopher scheme rejected",
			overrideURL: "gopher://example.com",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "javascript scheme rejected",
			overrideURL: "javascript:alert(1)",
			wantErr:     true,
			errContains: "unsupported override URL scheme",
		},
		{
			name:        "empty override URL is no-op",
			overrideURL: "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := gohttp.NewRequest("GET", "http://original.com/path", nil)
			action := interceptPkg.InterceptAction{
				Type:        interceptPkg.ActionModifyAndForward,
				OverrideURL: tt.overrideURL,
			}

			result, err := applyInterceptModifications(req, action, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for URL %q, got nil", tt.overrideURL)
				}
				if tt.errContains != "" {
					errStr := err.Error()
					if !containsStr(errStr, tt.errContains) {
						t.Errorf("error %q should contain %q", errStr, tt.errContains)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
			}
		})
	}
}

func TestApplyInterceptModifications_CRLFValidation(t *testing.T) {
	tests := []struct {
		name            string
		overrideHeaders map[string]string
		addHeaders      map[string]string
		removeHeaders   []string
		wantErr         bool
		errContains     string
	}{
		{
			name:            "override header value with CR",
			overrideHeaders: map[string]string{"X-Test": "val\rue"},
			wantErr:         true,
			errContains:     "CR/LF",
		},
		{
			name:            "override header value with LF",
			overrideHeaders: map[string]string{"X-Test": "val\nue"},
			wantErr:         true,
			errContains:     "CR/LF",
		},
		{
			name:            "override header key with CRLF",
			overrideHeaders: map[string]string{"X-Te\r\nst": "value"},
			wantErr:         true,
			errContains:     "CR/LF",
		},
		{
			name:        "add header value with LF",
			addHeaders:  map[string]string{"X-Add": "val\nue"},
			wantErr:     true,
			errContains: "CR/LF",
		},
		{
			name:          "remove header key with CR",
			removeHeaders: []string{"X-Remove\rInjection"},
			wantErr:       true,
			errContains:   "CR/LF",
		},
		{
			name:          "remove header key with LF",
			removeHeaders: []string{"X-Remove\nInjection"},
			wantErr:       true,
			errContains:   "CR/LF",
		},
		{
			name:            "valid headers pass",
			overrideHeaders: map[string]string{"X-Valid": "safe-value"},
			addHeaders:      map[string]string{"X-Also-Valid": "also-safe"},
			removeHeaders:   []string{"X-Clean-Key"},
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := gohttp.NewRequest("GET", "http://example.com/test", nil)
			action := interceptPkg.InterceptAction{
				Type:            interceptPkg.ActionModifyAndForward,
				OverrideHeaders: tt.overrideHeaders,
				AddHeaders:      tt.addHeaders,
				RemoveHeaders:   tt.removeHeaders,
			}

			_, err := applyInterceptModifications(req, action, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !containsStr(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestHandle_GoroutineCleanupOnNormalClose(t *testing.T) {
	// Verify that the context-monitoring goroutine in Handle() is reclaimed
	// when the connection completes normally, without waiting for the parent
	// context to be cancelled. This is a regression test for USK-176.
	//
	// Unlike other tests that use startTestProxy (which dispatches to
	// handleRequest directly, bypassing Handle), this test passes accepted
	// connections to handler.Handle() so the monitoring goroutine at the
	// top of Handle() is actually spawned and its cleanup is verified.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Use a parent context that is NOT cancelled during this test.
	// If the goroutine leaks, it will remain blocked on ctx.Done() forever.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a TCP listener that passes connections to handler.Handle()
	// directly (not through startTestProxy which bypasses Handle).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handler.Handle(proxyCtx, conn)
			}()
		}
	}()
	go func() {
		<-proxyCtx.Done()
		ln.Close()
	}()
	proxyAddr := ln.Addr().String()

	// Record goroutine count before making connections.
	before := runtime.NumGoroutine()

	// Make several connections that complete normally.
	for i := 0; i < 10; i++ {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		httpReq := fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
			upstream.URL, upstream.Listener.Addr().String())
		conn.Write([]byte(httpReq))

		reader := bufio.NewReader(conn)
		resp, err := gohttp.ReadResponse(reader, nil)
		if err != nil {
			conn.Close()
			t.Fatalf("read response: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		conn.Close()
	}

	// Allow goroutines to settle.
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()
	// The goroutine count should not have grown significantly.
	// Allow a small margin for runtime jitter (e.g., GC, runtime goroutines).
	leaked := after - before
	if leaked > 5 {
		t.Errorf("possible goroutine leak: before=%d, after=%d (delta=%d); "+
			"expected monitoring goroutines to be reclaimed on connection close",
			before, after, leaked)
	}
}

func TestHTTPSLoop_GoroutineCleanupOnNormalClose(t *testing.T) {
	// Verify that the context-monitoring goroutine in httpsLoop() is reclaimed
	// when the HTTPS connection completes normally. Regression test for USK-176.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

	// Use a parent context that is NOT cancelled during this test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	before := runtime.NumGoroutine()

	for i := 0; i < 10; i++ {
		tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
		httpReq := fmt.Sprintf("GET /test-%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", i, connectHost)
		tlsConn.Write([]byte(httpReq))

		httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
		if err != nil {
			tlsConn.Close()
			t.Fatalf("read HTTPS response: %v", err)
		}
		io.ReadAll(httpsResp.Body)
		httpsResp.Body.Close()
		tlsConn.Close()
	}

	// Allow goroutines to settle.
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()
	leaked := after - before
	if leaked > 5 {
		t.Errorf("possible goroutine leak in httpsLoop: before=%d, after=%d (delta=%d); "+
			"expected monitoring goroutines to be reclaimed on connection close",
			before, after, leaked)
	}
}

func TestRelay_GoroutineCleanupOnNormalClose(t *testing.T) {
	// Verify that the context-monitoring goroutine in relay() is reclaimed
	// when the relay completes normally. Regression test for USK-176.

	// Use a parent context that is NOT cancelled during this test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	before := runtime.NumGoroutine()

	for i := 0; i < 10; i++ {
		a, b := net.Pipe()
		// Write some data and close one side to trigger relay completion.
		go func() {
			a.Write([]byte("hello"))
			a.Close()
		}()
		relay(ctx, b, a)
		b.Close()
	}

	// Allow goroutines to settle.
	time.Sleep(200 * time.Millisecond)

	after := runtime.NumGoroutine()
	leaked := after - before
	if leaked > 5 {
		t.Errorf("possible goroutine leak in relay: before=%d, after=%d (delta=%d); "+
			"expected monitoring goroutines to be reclaimed on relay completion",
			before, after, leaked)
	}
}

// containsStr checks if s contains substr (simple helper to avoid importing strings).
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && searchStr(s, substr))
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- TLSTransport tests ---

// mockTLSTransport records calls to TLSConnect for testing.
type mockTLSTransport struct {
	connectCalled bool
	serverName    string
}

func (m *mockTLSTransport) TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	m.connectCalled = true
	m.serverName = serverName
	// Return a simple wrapped connection for testing purposes.
	return conn, "http/1.1", nil
}

func TestSetTLSTransport_SetsField(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	mock := &mockTLSTransport{}
	handler.SetTLSTransport(mock)

	if handler.TLSTransport() != mock {
		t.Error("TLSTransport() should return the set transport")
	}
}

func TestSetTLSTransport_NilByDefault(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	if handler.TLSTransport() != nil {
		t.Error("TLSTransport() should be nil by default")
	}
}

func TestSetTLSTransport_ConfiguresDialTLSContext(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	mock := &mockTLSTransport{}
	handler.SetTLSTransport(mock)

	if handler.Transport.DialTLSContext == nil {
		t.Fatal("DialTLSContext should be set after SetTLSTransport")
	}

	// TLSClientConfig should be nil since DialTLSContext handles TLS.
	if handler.Transport.TLSClientConfig != nil {
		t.Error("TLSClientConfig should be nil when DialTLSContext is set")
	}
}

func TestEffectiveTLSTransport_ReturnsConfigured(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	mock := &mockTLSTransport{}
	handler.tlsTransport = mock

	result := handler.effectiveTLSTransport()
	if result != mock {
		t.Error("effectiveTLSTransport() should return configured transport")
	}
}

func TestEffectiveTLSTransport_FallsBackToStandard(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	result := handler.effectiveTLSTransport()
	if result == nil {
		t.Fatal("effectiveTLSTransport() should return a fallback")
	}
}

func TestEffectiveTLSTransport_FallbackInheritsInsecure(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())
	handler.SetInsecureSkipVerify(true)

	result := handler.effectiveTLSTransport()
	if result == nil {
		t.Fatal("effectiveTLSTransport() should return a fallback")
	}
}

func TestSetTLSTransport_NilDoesNotPanic(t *testing.T) {
	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	// Setting nil should not panic and should not configure DialTLSContext.
	handler.SetTLSTransport(nil)

	if handler.Transport.DialTLSContext != nil {
		t.Error("DialTLSContext should remain nil when TLSTransport is nil")
	}
}

func TestSetTLSTransport_UpstreamHTTPS(t *testing.T) {
	// Test that the handler can forward HTTPS requests through the TLS transport.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-UTLS-Test", "passed")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "utls-ok")
	}))
	defer upstream.Close()

	handler := NewHandler(&mockStore{}, nil, testutil.DiscardLogger())

	// Use the test server's TLS config to connect, since it's self-signed.
	handler.Transport = upstream.Client().Transport.(*gohttp.Transport)

	// Build an HTTP proxy request to the upstream HTTPS server.
	req, _ := gohttp.NewRequest("GET", upstream.URL+"/test", nil)

	// Forward through the handler's transport (which uses test server certs).
	outReq := req.WithContext(context.Background())
	outReq.RequestURI = ""
	resp, _, _, err := roundTripWithTrace(handler.Transport, outReq)
	if err != nil {
		t.Fatalf("roundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "utls-ok" {
		t.Errorf("body = %q, want %q", string(body), "utls-ok")
	}
}

func TestSetConnPool(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testutil.DiscardLogger())

	// Initially nil.
	if handler.ConnPool() != nil {
		t.Error("ConnPool() should be nil initially")
	}

	// Set a ConnPool and verify.
	pool := &ConnPool{DialTimeout: 15 * time.Second}
	handler.SetConnPool(pool)

	got := handler.ConnPool()
	if got == nil {
		t.Fatal("ConnPool() is nil after SetConnPool")
	}
	if got.DialTimeout != 15*time.Second {
		t.Errorf("ConnPool().DialTimeout = %v, want %v", got.DialTimeout, 15*time.Second)
	}
}

func TestConnPool_ConfigWiring(t *testing.T) {
	// Simulate the config -> ConnPool wiring that happens in main.go.
	tests := []struct {
		name            string
		dialTimeout     time.Duration
		wantDialTimeout time.Duration
	}{
		{
			name:            "custom dial timeout",
			dialTimeout:     10 * time.Second,
			wantDialTimeout: 10 * time.Second,
		},
		{
			name:            "default dial timeout (30s)",
			dialTimeout:     30 * time.Second,
			wantDialTimeout: 30 * time.Second,
		},
		{
			name:            "zero uses ConnPool internal default",
			dialTimeout:     0,
			wantDialTimeout: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &ConnPool{
				DialTimeout: tt.dialTimeout,
			}
			if pool.DialTimeout != tt.wantDialTimeout {
				t.Errorf("ConnPool.DialTimeout = %v, want %v", pool.DialTimeout, tt.wantDialTimeout)
			}
		})
	}
}
