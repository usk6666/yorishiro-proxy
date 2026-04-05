//go:build e2e

package proxy_test

import (
	"bytes"
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
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startHTTPSProxy creates and starts a proxy with TLS MITM support.
// It returns the listener, the HTTP handler (for transport configuration),
// and a cancel function for cleanup.
func startHTTPSProxy(t *testing.T, ctx context.Context, store flow.Store, ca *cert.CA) (*proxy.Listener, *protohttp.Handler, context.CancelFunc) {
	t.Helper()

	issuer := cert.NewIssuer(ca)
	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, issuer, logger)
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
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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

	// Poll for session and messages to be persisted.
	var flows []*flow.Stream
	var send, recv *flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) != 1 {
			continue
		}
		msgs, mErr := store.GetFlows(ctx, flows[0].ID, flow.FlowListOptions{})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		for _, m := range msgs {
			switch m.Direction {
			case "send":
				send = m
			case "receive":
				recv = m
			}
		}
		if send != nil && recv != nil {
			break
		}
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 HTTPS flow, got %d", len(flows))
	}

	fl := flows[0]
	if fl.Protocol != "HTTPS" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTPS")
	}
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if send.Method != "GET" {
		t.Errorf("flow method = %q, want %q", send.Method, "GET")
	}
	if send.URL == nil || send.URL.Scheme != "https" {
		scheme := ""
		if send.URL != nil {
			scheme = send.URL.Scheme
		}
		t.Errorf("flow URL scheme = %q, want %q", scheme, "https")
	}
	if send.URL == nil || send.URL.Path != "/test-path" {
		path := ""
		if send.URL != nil {
			path = send.URL.Path
		}
		t.Errorf("flow URL path = %q, want %q", path, "/test-path")
	}
	if recv.StatusCode != 200 {
		t.Errorf("flow status = %d, want %d", recv.StatusCode, 200)
	}
	if string(recv.Body) != "hello from https upstream" {
		t.Errorf("flow response body = %q, want %q", recv.Body, "hello from https upstream")
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

	// Poll for session and messages to be persisted.
	var flows []*flow.Stream
	var send, recv *flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, flow.StreamListOptions{Method: "POST", Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) != 1 {
			continue
		}
		msgs, mErr := store.GetFlows(ctx, flows[0].ID, flow.FlowListOptions{})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		for _, m := range msgs {
			switch m.Direction {
			case "send":
				send = m
			case "receive":
				recv = m
			}
		}
		if send != nil && recv != nil {
			break
		}
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 POST flow, got %d", len(flows))
	}

	fl := flows[0]
	if fl.Protocol != "HTTPS" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTPS")
	}
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if send.Method != "POST" {
		t.Errorf("flow method = %q, want %q", send.Method, "POST")
	}
	if send.URL == nil || send.URL.Scheme != "https" {
		t.Errorf("flow URL scheme = %q, want %q", send.URL.Scheme, "https")
	}
	if send.URL == nil || send.URL.Path != "/api/data" {
		t.Errorf("flow URL path = %q, want %q", send.URL.Path, "/api/data")
	}
	if string(send.Body) != reqBody {
		t.Errorf("flow request body = %q, want %q", send.Body, reqBody)
	}
	if recv.StatusCode != 201 {
		t.Errorf("flow response status = %d, want %d", recv.StatusCode, 201)
	}
	if string(recv.Body) != expectedBody {
		t.Errorf("flow response body = %q, want %q", recv.Body, expectedBody)
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

	// Send request with query parameters.
	targetURL := fmt.Sprintf("https://localhost:%s/session/check?q=test&page=1", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET through proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for flow to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Verify detailed flow recording.
	flows, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	fl := flows[0]

	// Protocol must be HTTPS.
	if fl.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTPS")
	}

	msgs, err := store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	var send, recv *flow.Flow
	for _, m := range msgs {
		switch m.Direction {
		case "send":
			send = m
		case "receive":
			recv = m
		}
	}
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}

	// URL must have https scheme.
	if send.URL == nil {
		t.Fatal("request URL is nil")
	}
	if send.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", send.URL.Scheme, "https")
	}

	// URL path must match.
	if send.URL.Path != "/session/check" {
		t.Errorf("URL path = %q, want %q", send.URL.Path, "/session/check")
	}

	// Query parameters must be preserved.
	if send.URL.RawQuery != "q=test&page=1" {
		t.Errorf("URL query = %q, want %q", send.URL.RawQuery, "q=test&page=1")
	}

	// Host must contain localhost.
	if !strings.Contains(send.URL.Host, "localhost") {
		t.Errorf("URL host = %q, does not contain %q", send.URL.Host, "localhost")
	}

	// Decrypted response body must be recorded.
	if string(recv.Body) != "session-test-body" {
		t.Errorf("response body = %q, want %q", recv.Body, "session-test-body")
	}

	// Response headers must be recorded (decrypted).
	if gohttp.Header(recv.Headers).Get("X-Custom-Response") != "custom-value" {
		t.Errorf("response header X-Custom-Response = %q, want %q",
			gohttp.Header(recv.Headers).Get("X-Custom-Response"), "custom-value")
	}

	// Duration must be positive.
	if fl.Duration <= 0 {
		t.Errorf("duration = %v, want positive", fl.Duration)
	}

	// ID must be assigned.
	if fl.ID == "" {
		t.Error("flow ID is empty")
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

	// Wait for flows to be persisted.
	time.Sleep(300 * time.Millisecond)

	// Verify all 3 flows were recorded.
	flows, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) != 3 {
		t.Fatalf("expected 3 HTTPS flows, got %d", len(flows))
	}

	// Verify each session has correct protocol and unique paths.
	paths := make(map[string]bool)
	for _, fl := range flows {
		if fl.Protocol != "HTTPS" {
			t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTPS")
		}
		sendMsgs, mErr := store.GetFlows(ctx, fl.ID, flow.FlowListOptions{Direction: "send"})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		if len(sendMsgs) == 0 {
			t.Error("no send message found")
			continue
		}
		if sendMsgs[0].URL == nil {
			t.Error("request URL is nil")
			continue
		}
		if sendMsgs[0].URL.Scheme != "https" {
			t.Errorf("URL scheme = %q, want %q", sendMsgs[0].URL.Scheme, "https")
		}
		paths[sendMsgs[0].URL.Path] = true
	}

	// Verify all 3 unique paths were recorded.
	for i := 1; i <= 3; i++ {
		expectedPath := fmt.Sprintf("/path-%d", i)
		if !paths[expectedPath] {
			t.Errorf("missing flow for path %q", expectedPath)
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

	// Wait for flows to be persisted.
	time.Sleep(200 * time.Millisecond)

	// Verify both flows were recorded with different hosts.
	flows, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) != 2 {
		t.Fatalf("expected 2 HTTPS flows, got %d", len(flows))
	}

	// Verify flows have different host:port values.
	hosts := make(map[string]bool)
	for _, fl := range flows {
		if fl.Protocol != "HTTPS" {
			t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTPS")
		}
		sendMsgs, mErr := store.GetFlows(ctx, fl.ID, flow.FlowListOptions{Direction: "send"})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		if len(sendMsgs) == 0 || sendMsgs[0].URL == nil {
			t.Error("request URL is nil")
			continue
		}
		hosts[sendMsgs[0].URL.Host] = true
		if sendMsgs[0].URL.Scheme != "https" {
			t.Errorf("URL scheme = %q, want %q", sendMsgs[0].URL.Scheme, "https")
		}
	}

	expectedHost1 := "localhost:" + port1
	expectedHost2 := "localhost:" + port2
	if !hosts[expectedHost1] {
		t.Errorf("missing flow for host %q, got hosts %v", expectedHost1, hosts)
	}
	if !hosts[expectedHost2] {
		t.Errorf("missing flow for host %q, got hosts %v", expectedHost2, hosts)
	}
}

func TestIntegration_LargeBodyBoundary_HTTPS(t *testing.T) {
	tests := []struct {
		name string
		// bodySize is the size of the request body to send.
		bodySize int
		// wantReqTruncated is whether the recorded request body should be truncated.
		wantReqTruncated bool
		// wantRespTruncated is whether the recorded response body should be truncated.
		wantRespTruncated bool
		// wantRecordedReqLen is the expected length of the recorded request body.
		wantRecordedReqLen int
		// wantRecordedRespLen is the expected length of the recorded response body.
		wantRecordedRespLen int
		// timeout is the context timeout for this test case.
		timeout time.Duration
	}{
		{
			name:                "empty body",
			bodySize:            0,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  0,
			wantRecordedRespLen: 0,
			timeout:             15 * time.Second,
		},
		{
			name:                "body 1MB (well below limit)",
			bodySize:            1 << 20,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  1 << 20,
			wantRecordedRespLen: 1 << 20,
			timeout:             30 * time.Second,
		},
		{
			name:                "body 2MB (below limit)",
			bodySize:            2 << 20,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  2 << 20,
			wantRecordedRespLen: 2 << 20,
			timeout:             30 * time.Second,
		},
		{
			name:                "body 10MB (below limit)",
			bodySize:            10 << 20,
			wantReqTruncated:    false,
			wantRespTruncated:   false,
			wantRecordedReqLen:  10 << 20,
			wantRecordedRespLen: 10 << 20,
			timeout:             60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			// Start upstream HTTPS echo server: responds with the same body it received.
			upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(gohttp.StatusOK)
				io.Copy(w, r.Body)
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
			client.Timeout = tt.timeout

			// Generate deterministic test data using a repeating pattern.
			var reqBody []byte
			if tt.bodySize > 0 {
				reqBody = bytes.Repeat([]byte("B"), tt.bodySize)
			}

			// Send POST request through the proxy via HTTPS.
			targetURL := fmt.Sprintf("https://localhost:%s/large-body-test", upstreamPort)
			resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("HTTPS POST through proxy: %v", err)
			}
			defer resp.Body.Close()

			// Verify the full response body was transferred correctly (not truncated in transit).
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}

			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
			}
			if len(respBody) != tt.bodySize {
				t.Errorf("response body length = %d, want %d (transfer should not truncate)", len(respBody), tt.bodySize)
			}
			if tt.bodySize > 0 && !bytes.Equal(respBody, reqBody) {
				t.Error("response body content differs from request body (transfer corruption)")
			}

			// Poll for session and messages to be persisted (large bodies may take longer to save).
			var httpsFlows []*flow.Stream
			var send, recv *flow.Flow
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				httpsFlows, err = store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTPS", Limit: 10})
				if err != nil {
					t.Fatalf("ListFlows: %v", err)
				}
				if len(httpsFlows) != 1 {
					continue
				}
				allMsgs, mErr := store.GetFlows(ctx, httpsFlows[0].ID, flow.FlowListOptions{})
				if mErr != nil {
					t.Fatalf("GetMessages: %v", mErr)
				}
				for _, m := range allMsgs {
					switch m.Direction {
					case "send":
						send = m
					case "receive":
						recv = m
					}
				}
				if send != nil && recv != nil {
					break
				}
			}
			if len(httpsFlows) != 1 {
				t.Fatalf("expected 1 HTTPS flow, got %d", len(httpsFlows))
			}
			fl := httpsFlows[0]
			if send == nil {
				t.Fatal("send message not found")
			}
			if recv == nil {
				t.Fatal("receive message not found")
			}

			// Verify request body recording.
			if len(send.Body) != tt.wantRecordedReqLen {
				t.Errorf("recorded request body length = %d, want %d", len(send.Body), tt.wantRecordedReqLen)
			}
			if send.BodyTruncated != tt.wantReqTruncated {
				t.Errorf("request BodyTruncated = %v, want %v", send.BodyTruncated, tt.wantReqTruncated)
			}

			// Verify response body recording.
			if len(recv.Body) != tt.wantRecordedRespLen {
				t.Errorf("recorded response body length = %d, want %d", len(recv.Body), tt.wantRecordedRespLen)
			}
			if recv.BodyTruncated != tt.wantRespTruncated {
				t.Errorf("response BodyTruncated = %v, want %v", recv.BodyTruncated, tt.wantRespTruncated)
			}

			// When truncated, verify the recorded body is the prefix of the original.
			if tt.wantReqTruncated && tt.bodySize > 0 {
				if !bytes.Equal(send.Body, reqBody[:maxBodySize]) {
					t.Error("truncated request body is not a prefix of the original body")
				}
			}
			if tt.wantRespTruncated && tt.bodySize > 0 {
				if !bytes.Equal(recv.Body, reqBody[:maxBodySize]) {
					t.Error("truncated response body is not a prefix of the original body")
				}
			}

			// Verify metadata.
			if fl.Protocol != "HTTPS" {
				t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTPS")
			}
			if send.Method != "POST" {
				t.Errorf("method = %q, want %q", send.Method, "POST")
			}
			if recv.StatusCode != 200 {
				t.Errorf("status code = %d, want %d", recv.StatusCode, 200)
			}
			if send.URL == nil || send.URL.Scheme != "https" {
				scheme := ""
				if send.URL != nil {
					scheme = send.URL.Scheme
				}
				t.Errorf("URL scheme = %q, want %q", scheme, "https")
			}
		})
	}
}

func TestIntegration_ConcurrentClients_HTTPS(t *testing.T) {
	const numClients = 15

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream HTTPS server that echoes a unique identifier back.
	upstream, upstreamTransport := newTestUpstreamHTTPS(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "echo:%s:%s", r.URL.Path, string(body))
	}))
	defer upstream.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// Create temporary SQLite database.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
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

	// Launch concurrent clients, each sending a unique HTTPS request.
	var wg sync.WaitGroup
	wg.Add(numClients)

	for i := 0; i < numClients; i++ {
		go func(id int) {
			defer wg.Done()

			// Each goroutine creates its own HTTP client (separate CONNECT tunnel).
			client := httpsProxyClient(listener.Addr(), ca.Certificate())

			path := fmt.Sprintf("/concurrent/%d", id)
			reqBody := fmt.Sprintf(`{"client":%d}`, id)
			targetURL := fmt.Sprintf("https://localhost:%s%s", upstreamPort, path)

			resp, err := client.Post(targetURL, "application/json", strings.NewReader(reqBody))
			if err != nil {
				t.Errorf("client %d: HTTPS POST through proxy: %v", id, err)
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("client %d: status = %d, want %d", id, resp.StatusCode, gohttp.StatusOK)
			}

			expectedBody := fmt.Sprintf("echo:%s:%s", path, reqBody)
			if string(body) != expectedBody {
				t.Errorf("client %d: body = %q, want %q", id, body, expectedBody)
			}
		}(i)
	}

	wg.Wait()

	// Wait for all flows to be persisted.
	time.Sleep(500 * time.Millisecond)

	// Verify all flows were recorded.
	flows, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTPS", Limit: numClients + 10})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) != numClients {
		t.Fatalf("expected %d HTTPS flows, got %d", numClients, len(flows))
	}

	// Verify each client's session is distinct and data is not mixed.
	seenPaths := make(map[string]bool)
	for _, fl := range flows {
		if fl.Protocol != "HTTPS" {
			t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTPS")
		}

		allMsgs, mErr := store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
		if mErr != nil {
			t.Fatalf("GetMessages: %v", mErr)
		}
		var send, recv *flow.Flow
		for _, m := range allMsgs {
			switch m.Direction {
			case "send":
				send = m
			case "receive":
				recv = m
			}
		}
		if send == nil {
			t.Error("send message not found")
			continue
		}
		if recv == nil {
			t.Error("receive message not found")
			continue
		}

		if send.Method != "POST" {
			t.Errorf("flow method = %q, want %q", send.Method, "POST")
		}
		if send.URL == nil {
			t.Error("request URL is nil")
			continue
		}
		if send.URL.Scheme != "https" {
			t.Errorf("flow URL scheme = %q, want %q", send.URL.Scheme, "https")
		}

		path := send.URL.Path
		seenPaths[path] = true

		// Verify request body matches the path (no cross-contamination).
		var pathID int
		if _, err := fmt.Sscanf(path, "/concurrent/%d", &pathID); err != nil {
			t.Errorf("unexpected path format: %q", path)
			continue
		}
		expectedReqBody := fmt.Sprintf(`{"client":%d}`, pathID)
		if string(send.Body) != expectedReqBody {
			t.Errorf("flow path %s: request body = %q, want %q (data mixed between flows)",
				path, send.Body, expectedReqBody)
		}

		// Verify response body matches.
		expectedRespBody := fmt.Sprintf("echo:%s:%s", path, expectedReqBody)
		if string(recv.Body) != expectedRespBody {
			t.Errorf("flow path %s: response body = %q, want %q (data mixed between flows)",
				path, recv.Body, expectedRespBody)
		}

		if recv.StatusCode != 200 {
			t.Errorf("flow path %s: status = %d, want %d", path, recv.StatusCode, 200)
		}
		if fl.ID == "" {
			t.Errorf("flow path %s: ID is empty", path)
		}
		if fl.Duration < 0 {
			t.Errorf("flow path %s: duration = %v, want non-negative", path, fl.Duration)
		}
	}

	// Verify all unique paths were recorded (no duplicates, no missing).
	if len(seenPaths) != numClients {
		t.Errorf("expected %d unique paths, got %d", numClients, len(seenPaths))
	}
	for i := 0; i < numClients; i++ {
		expectedPath := fmt.Sprintf("/concurrent/%d", i)
		if !seenPaths[expectedPath] {
			t.Errorf("missing flow for path %q", expectedPath)
		}
	}
}
