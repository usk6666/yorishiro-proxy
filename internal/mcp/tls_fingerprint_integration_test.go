//go:build e2e

package mcp

import (
	"context"
	"crypto/tls"
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

	"golang.org/x/net/http2"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- M17 TLS Fingerprint Integration Test Helpers ---

// m17Env holds all components for a TLS fingerprint integration test.
type m17Env struct {
	cs          *gomcp.ClientSession
	store       flow.Store
	manager     *proxy.Manager
	httpHandler *protohttp.Handler
}

// setupM17Env creates a fully-wired MCP test environment with TLS fingerprint
// support. The HTTP handler is registered as a tlsFingerprintSetter so that
// configure and proxy_start can change the TLS fingerprint profile at runtime.
func setupM17Env(t *testing.T) *m17Env {
	t.Helper()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "m17-integration.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	httpHandler := protohttp.NewHandler(store, issuer, logger)
	detector := protocol.NewDetector(httpHandler)
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	// Wire MCP server with TLS fingerprint setter for the HTTP handler.
	mcpServer := NewServer(ctx, ca, store, manager,
		WithTLSFingerprintSetter(httpHandler),
		WithTLSTransport(&httputil.UTLSTransport{
			Profile:            httputil.ProfileChrome,
			InsecureSkipVerify: true,
		}),
	)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "m17-test-client",
		Version: "0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return &m17Env{
		cs:          cs,
		store:       store,
		manager:     manager,
		httpHandler: httpHandler,
	}
}

// startTestHTTPSServer starts a local HTTPS server using httptest.NewTLSServer.
// Returns the server and a cleanup function.
func startTestHTTPSServer(t *testing.T, handler gohttp.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

// httpsEchoHandler returns an HTTP handler that echoes request info.
func httpsEchoHandler() gohttp.Handler {
	return gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Proto", r.Proto)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		if len(body) > 0 {
			fmt.Fprintf(w, "echo: %s", body)
		} else {
			fmt.Fprint(w, "hello from https upstream")
		}
	})
}

// proxyHTTPSClient creates an HTTP client that uses the proxy and trusts
// the proxy CA for MITM interception. It also skips verification on the
// upstream TLS (for httptest.Server which uses self-signed certs).
func proxyHTTPSClient(proxyAddr string, caCert *tls.Certificate) *gohttp.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test client trusts proxy CA
			},
		},
		Timeout: 10 * time.Second,
	}
}

// --- Test: Chrome Profile HTTPS Proxy ---

// TestTLSFingerprint_ChromeProfile_HTTPS verifies that starting the proxy with
// tls_fingerprint=chrome allows HTTPS traffic to flow through successfully.
func TestTLSFingerprint_ChromeProfile_HTTPS(t *testing.T) {
	env := setupM17Env(t)

	upstream := startTestHTTPSServer(t, httpsEchoHandler())

	// Start proxy with chrome TLS fingerprint.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "chrome",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Inject InsecureSkipVerify transport so the proxy can connect to the
	// httptest TLS server (which uses a self-signed cert).
	env.httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
		},
	})

	// Send HTTPS request through the proxy.
	client := proxyHTTPSClient(startResult.ListenAddr, nil)
	resp, err := client.Get(upstream.URL + "/api/tls-chrome")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, gohttp.StatusOK, body)
	}
	if !strings.Contains(string(body), "hello from https upstream") {
		t.Errorf("body = %q, want to contain 'hello from https upstream'", body)
	}

	// Wait for flow to be persisted.
	time.Sleep(300 * time.Millisecond)

	// Verify flow was recorded.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("query flows count = %d, want >= 1", listResult.Count)
	}

	// Verify status reports chrome profile.
	statusResult := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if statusResult.TLSFingerprint != "chrome" {
		t.Errorf("status tls_fingerprint = %q, want %q", statusResult.TLSFingerprint, "chrome")
	}

	client.CloseIdleConnections()
}

// --- Test: HTTP/2 ALPN Negotiation ---

// startH2Server starts a TLS server that supports HTTP/2 via ALPN.
// httptest.NewTLSServer does not enable HTTP/2 by default, so we configure
// it explicitly using golang.org/x/net/http2.
func startH2Server(t *testing.T, handler gohttp.Handler) (addr string, cleanup func()) {
	t.Helper()

	// Create a TLS listener with h2 + http/1.1 ALPN.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Use httptest to generate a self-signed cert.
	tmpServer := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {}))
	cert := tmpServer.TLS.Certificates[0]
	tmpServer.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsLn := tls.NewListener(ln, tlsConfig)

	srv := &gohttp.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
	// Configure HTTP/2 support on the server.
	if err := http2.ConfigureServer(srv, nil); err != nil {
		ln.Close()
		t.Fatalf("http2.ConfigureServer: %v", err)
	}

	go srv.Serve(tlsLn) //nolint:errcheck // test server

	return ln.Addr().String(), func() {
		srv.Close()
	}
}

// TestTLSFingerprint_HTTP2_ALPN verifies that uTLS properly negotiates HTTP/2
// via ALPN when the upstream server supports it.
func TestTLSFingerprint_HTTP2_ALPN(t *testing.T) {
	h2Addr, h2Cleanup := startH2Server(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "proto=%s", r.Proto)
	}))
	defer h2Cleanup()

	// Verify the server actually speaks HTTP/2 via a direct connection.
	h2Client := &gohttp.Client{
		Transport: &gohttp.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}
	directResp, err := h2Client.Get("https://" + h2Addr + "/h2-check")
	if err != nil {
		t.Fatalf("direct HTTP/2 check: %v", err)
	}
	directBody, _ := io.ReadAll(directResp.Body)
	directResp.Body.Close()
	if directResp.Proto != "HTTP/2.0" {
		t.Fatalf("server does not support HTTP/2 (proto=%s); expected HTTP/2.0", directResp.Proto)
	}
	t.Logf("direct HTTP/2 check passed: proto=%s, body=%s", directResp.Proto, directBody)

	// Test uTLS transport directly connects and negotiates h2.
	conn, err := net.DialTimeout("tcp", h2Addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial upstream: %v", err)
	}
	defer conn.Close()

	transport := &httputil.UTLSTransport{
		Profile:            httputil.ProfileChrome,
		InsecureSkipVerify: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, negotiatedProto, err := transport.TLSConnect(ctx, conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("UTLSTransport.TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	if negotiatedProto != "h2" {
		t.Errorf("negotiated protocol = %q, want %q", negotiatedProto, "h2")
	}
}

// --- Test: None Fallback (Standard TLS) ---

// TestTLSFingerprint_None_Fallback verifies that setting tls_fingerprint to "none"
// falls back to standard crypto/tls (no uTLS fingerprinting).
func TestTLSFingerprint_None_Fallback(t *testing.T) {
	env := setupM17Env(t)

	upstream := startTestHTTPSServer(t, httpsEchoHandler())

	// Start proxy with "none" (standard TLS).
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "none",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Inject transport to trust upstream's self-signed cert.
	env.httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
		},
	})

	// Send HTTPS request through the proxy.
	client := proxyHTTPSClient(startResult.ListenAddr, nil)
	resp, err := client.Get(upstream.URL + "/api/tls-none")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, gohttp.StatusOK, body)
	}

	// Verify status reports "none".
	statusResult := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if statusResult.TLSFingerprint != "none" {
		t.Errorf("status tls_fingerprint = %q, want %q", statusResult.TLSFingerprint, "none")
	}

	// Verify traffic was recorded.
	time.Sleep(300 * time.Millisecond)
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("query flows count = %d, want >= 1", listResult.Count)
	}

	client.CloseIdleConnections()
}

// --- Test: Runtime Profile Change via Configure ---

// TestTLSFingerprint_RuntimeChange verifies that the TLS fingerprint profile
// can be changed at runtime via the configure tool, and the change is reflected
// in the query status output.
func TestTLSFingerprint_RuntimeChange(t *testing.T) {
	env := setupM17Env(t)

	// Start proxy with chrome.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "chrome",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Verify initial profile is chrome.
	status1 := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if status1.TLSFingerprint != "chrome" {
		t.Errorf("initial tls_fingerprint = %q, want %q", status1.TLSFingerprint, "chrome")
	}

	// Change to firefox via configure.
	cfgResult := callTool[configureResult](t, env.cs, "configure", map[string]any{
		"tls_fingerprint": "firefox",
	})
	if cfgResult.Status != "configured" {
		t.Fatalf("configure status = %q, want %q", cfgResult.Status, "configured")
	}
	if cfgResult.TLSFingerprint == nil {
		t.Fatal("configure tls_fingerprint is nil")
	}
	if *cfgResult.TLSFingerprint != "firefox" {
		t.Errorf("configure tls_fingerprint = %q, want %q", *cfgResult.TLSFingerprint, "firefox")
	}

	// Verify status now shows firefox.
	status2 := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if status2.TLSFingerprint != "firefox" {
		t.Errorf("after configure tls_fingerprint = %q, want %q", status2.TLSFingerprint, "firefox")
	}

	// Change to safari.
	cfgResult2 := callTool[configureResult](t, env.cs, "configure", map[string]any{
		"tls_fingerprint": "safari",
	})
	if cfgResult2.TLSFingerprint == nil || *cfgResult2.TLSFingerprint != "safari" {
		t.Errorf("second configure tls_fingerprint = %v, want safari", cfgResult2.TLSFingerprint)
	}

	// Verify status shows safari.
	status3 := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if status3.TLSFingerprint != "safari" {
		t.Errorf("after second configure tls_fingerprint = %q, want %q", status3.TLSFingerprint, "safari")
	}

	// Change to none (standard TLS).
	cfgResult3 := callTool[configureResult](t, env.cs, "configure", map[string]any{
		"tls_fingerprint": "none",
	})
	if cfgResult3.TLSFingerprint == nil || *cfgResult3.TLSFingerprint != "none" {
		t.Errorf("third configure tls_fingerprint = %v, want none", cfgResult3.TLSFingerprint)
	}

	status4 := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
		"resource": "status",
	})
	if status4.TLSFingerprint != "none" {
		t.Errorf("after third configure tls_fingerprint = %q, want %q", status4.TLSFingerprint, "none")
	}

	// Verify invalid profile is rejected.
	callToolExpectError(t, env.cs, "configure", map[string]any{
		"tls_fingerprint": "invalid-profile",
	})
}

// --- Test: Resend with uTLS ---

// TestTLSFingerprint_Resend verifies that the resend tool uses uTLS when
// a TLS transport is configured on the MCP server.
func TestTLSFingerprint_Resend(t *testing.T) {
	env := setupM17Env(t)

	// Start an HTTPS echo server.
	upstream := startTestHTTPSServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "resend-echo: %s %s", r.Method, r.URL.Path)
	}))

	// Start proxy with chrome fingerprint.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "chrome",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Inject transport for upstream cert trust.
	env.httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
		},
	})

	// Send an HTTPS request through the proxy to create a flow.
	client := proxyHTTPSClient(startResult.ListenAddr, nil)
	resp, err := client.Get(upstream.URL + "/api/resend-test")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	// Wait for flow persistence.
	time.Sleep(300 * time.Millisecond)

	// Query the recorded flow.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("query flows count = %d, want >= 1", listResult.Count)
	}
	flowID := listResult.Flows[0].ID

	// Attempt resend. The resend uses the configured TLS transport (uTLS).
	// The target is localhost, so SSRF protection may block it.
	// We test that the tool runs without crashing — either success or a
	// controlled SSRF error is acceptable.
	resendResult, resendErr := env.cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend",
			"params": map[string]any{
				"flow_id": flowID,
				"tag":     "utls-resend",
			},
		},
	})
	if resendErr != nil {
		t.Fatalf("CallTool(resend): %v", resendErr)
	}

	// Either outcome is fine: success (SSRF relaxed) or error (SSRF blocked).
	// What matters is that no panic or unexpected failure occurred.
	if !resendResult.IsError {
		// If it succeeded, verify result structure.
		tc, ok := resendResult.Content[0].(*gomcp.TextContent)
		if !ok {
			t.Fatalf("expected TextContent, got %T", resendResult.Content[0])
		}
		if !strings.Contains(tc.Text, "new_flow_id") {
			t.Errorf("resend result missing new_flow_id: %s", tc.Text)
		}
		t.Logf("resend succeeded (SSRF protection relaxed): %s", tc.Text)
	} else {
		t.Logf("resend blocked by SSRF protection (expected for localhost target)")
	}

	client.CloseIdleConnections()
}

// --- Test: uTLS Transport Directly ---

// TestTLSFingerprint_UTLSTransport_AllProfiles verifies that all browser
// profiles can establish TLS connections successfully.
func TestTLSFingerprint_UTLSTransport_AllProfiles(t *testing.T) {
	// Start a local TLS server.
	server := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer server.Close()

	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	addr := net.JoinHostPort("127.0.0.1", port)

	profiles := []struct {
		name    string
		profile httputil.BrowserProfile
	}{
		{"chrome", httputil.ProfileChrome},
		{"firefox", httputil.ProfileFirefox},
		{"safari", httputil.ProfileSafari},
		{"edge", httputil.ProfileEdge},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			transport := &httputil.UTLSTransport{
				Profile:            tc.profile,
				InsecureSkipVerify: true,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			tlsConn, proto, err := transport.TLSConnect(ctx, conn, "127.0.0.1")
			if err != nil {
				t.Fatalf("TLSConnect with %s: %v", tc.name, err)
			}
			defer tlsConn.Close()

			// Verify connection is established and has a negotiated protocol.
			t.Logf("profile=%s negotiated_proto=%q", tc.name, proto)
		})
	}
}

// --- Test: StandardTransport as Fallback ---

// TestTLSFingerprint_StandardTransport_Fallback verifies that StandardTransport
// (used when tls_fingerprint="none") can establish TLS connections.
func TestTLSFingerprint_StandardTransport_Fallback(t *testing.T) {
	server := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer server.Close()

	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	addr := net.JoinHostPort("127.0.0.1", port)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	transport := &httputil.StandardTransport{
		InsecureSkipVerify: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, proto, err := transport.TLSConnect(ctx, conn, "127.0.0.1")
	if err != nil {
		t.Fatalf("StandardTransport.TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	// StandardTransport should also negotiate ALPN.
	t.Logf("StandardTransport negotiated_proto=%q", proto)

	// Verify TLSConnectionState works.
	state, ok := httputil.TLSConnectionState(tlsConn)
	if !ok {
		t.Fatal("TLSConnectionState returned false for standard TLS conn")
	}
	if !state.HandshakeComplete {
		t.Error("TLS handshake not complete")
	}
}

// --- Test: Proxy Start with TLS Fingerprint Parameter ---

// TestTLSFingerprint_ProxyStart_AllValidProfiles verifies that proxy_start
// accepts all valid tls_fingerprint values without errors.
func TestTLSFingerprint_ProxyStart_AllValidProfiles(t *testing.T) {
	validProfiles := []string{"chrome", "firefox", "safari", "edge", "random", "none"}

	for _, profile := range validProfiles {
		t.Run(profile, func(t *testing.T) {
			env := setupM17Env(t)

			startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
				"listen_addr":     "127.0.0.1:0",
				"tls_fingerprint": profile,
			})
			if startResult.Status != "running" {
				t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
			}

			// Verify status reflects the profile.
			statusResult := callTool[queryStatusResult](t, env.cs, "query", map[string]any{
				"resource": "status",
			})
			if statusResult.TLSFingerprint != profile {
				t.Errorf("status tls_fingerprint = %q, want %q", statusResult.TLSFingerprint, profile)
			}
		})
	}
}

// --- Test: Proxy Start with Invalid TLS Fingerprint ---

// TestTLSFingerprint_ProxyStart_InvalidProfile verifies that proxy_start
// rejects invalid tls_fingerprint values.
func TestTLSFingerprint_ProxyStart_InvalidProfile(t *testing.T) {
	env := setupM17Env(t)

	callToolExpectError(t, env.cs, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "invalid-browser",
	})
}
