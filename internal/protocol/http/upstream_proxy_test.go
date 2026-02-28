package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

func TestSetUpstreamProxy(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	t.Run("set upstream proxy", func(t *testing.T) {
		proxyURL, _ := url.Parse("http://proxy:3128")
		handler.SetUpstreamProxy(proxyURL)

		got := handler.UpstreamProxy()
		if got == nil {
			t.Fatal("UpstreamProxy() returned nil")
		}
		if got.String() != proxyURL.String() {
			t.Errorf("UpstreamProxy() = %q, want %q", got.String(), proxyURL.String())
		}
	})

	t.Run("clear upstream proxy", func(t *testing.T) {
		handler.SetUpstreamProxy(nil)

		got := handler.UpstreamProxy()
		if got != nil {
			t.Errorf("UpstreamProxy() = %v, want nil", got)
		}
	})

	t.Run("transport proxy function is set", func(t *testing.T) {
		proxyURL, _ := url.Parse("http://proxy:3128")
		handler.SetUpstreamProxy(proxyURL)

		if handler.transport.Proxy == nil {
			t.Fatal("transport.Proxy should be set")
		}

		// Verify the proxy function returns the expected URL.
		req, _ := gohttp.NewRequest("GET", "http://example.com", nil)
		got, err := handler.transport.Proxy(req)
		if err != nil {
			t.Fatalf("transport.Proxy error: %v", err)
		}
		if got.String() != proxyURL.String() {
			t.Errorf("transport.Proxy returned %q, want %q", got.String(), proxyURL.String())
		}
	})

	t.Run("clearing proxy clears transport proxy function", func(t *testing.T) {
		handler.SetUpstreamProxy(nil)

		if handler.transport.Proxy != nil {
			t.Error("transport.Proxy should be nil after clearing")
		}
	})
}

func TestDialUpstream_Direct(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Start an echo server.
	echoAddr := startTCPEchoServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Without upstream proxy, should dial directly.
	conn, err := handler.dialUpstream(ctx, echoAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dialUpstream (direct): %v", err)
	}
	defer conn.Close()

	testMsg := "direct dial test"
	conn.Write([]byte(testMsg))
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != testMsg {
		t.Errorf("got %q, want %q", buf, testMsg)
	}
}

func TestDialUpstream_ViaHTTPProxy(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Start an echo server.
	echoAddr := startTCPEchoServer(t)

	// Start a mock HTTP CONNECT proxy.
	proxyAddr, proxyCleanup := startMockHTTPConnectProxy(t, false, "", "")
	defer proxyCleanup()

	// Configure the upstream proxy.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	handler.SetUpstreamProxy(proxyURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := handler.dialUpstream(ctx, echoAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dialUpstream (via proxy): %v", err)
	}
	defer conn.Close()

	testMsg := "proxy dial test"
	conn.Write([]byte(testMsg))
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != testMsg {
		t.Errorf("got %q, want %q", buf, testMsg)
	}
}

func TestHTTPForwardViaUpstreamProxy(t *testing.T) {
	// Start an upstream HTTP server.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Upstream-Proxy", "worked")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "upstream-proxy-ok")
	}))
	defer upstream.Close()

	// Start a mock HTTP forward proxy that relays requests.
	proxyAddr := startMockHTTPForwardProxy(t)

	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Configure the upstream proxy on the Transport.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	handler.SetUpstreamProxy(proxyURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyListenAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Connect to our proxy and send a request to the upstream.
	conn, err := net.DialTimeout("tcp", proxyListenAddr, 2*time.Second)
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
	if string(body) != "upstream-proxy-ok" {
		t.Errorf("body = %q, want %q", body, "upstream-proxy-ok")
	}
}

func TestHTTPSConnectViaUpstreamProxy(t *testing.T) {
	// Start an upstream HTTPS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Via-Proxy", "yes")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "https-via-proxy-ok")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())
	handler.SetInsecureSkipVerify(true)

	// Start a mock HTTP CONNECT proxy.
	proxyAddr, proxyCleanup := startMockHTTPConnectProxy(t, false, "", "")
	defer proxyCleanup()

	// Configure upstream proxy.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	handler.SetUpstreamProxy(proxyURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyListenAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// CONNECT through our proxy (which should CONNECT through the upstream proxy).
	tlsConn, tlsReader := doConnectAndTLS(t, proxyListenAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	httpReq := fmt.Sprintf("GET /test-via-proxy HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
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
	if string(body) != "https-via-proxy-ok" {
		t.Errorf("body = %q, want %q", body, "https-via-proxy-ok")
	}
}

func TestUpstreamProxyUnreachable(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Configure an unreachable upstream proxy.
	proxyURL, _ := url.Parse("http://127.0.0.1:1")
	handler.SetUpstreamProxy(proxyURL)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyListenAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyListenAddr, 2*time.Second)
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
	resp.Body.Close()

	// Should return 502 Bad Gateway since the upstream proxy is unreachable.
	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d (502 for unreachable proxy)", resp.StatusCode, gohttp.StatusBadGateway)
	}
}

func TestUpstreamProxyDynamicChange(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	// Start without upstream proxy.
	if handler.UpstreamProxy() != nil {
		t.Fatal("UpstreamProxy should initially be nil")
	}

	// Set upstream proxy.
	proxyURL, _ := url.Parse("http://proxy:3128")
	handler.SetUpstreamProxy(proxyURL)
	if handler.UpstreamProxy() == nil {
		t.Fatal("UpstreamProxy should be set")
	}

	// Clear upstream proxy (back to direct).
	handler.SetUpstreamProxy(nil)
	if handler.UpstreamProxy() != nil {
		t.Fatal("UpstreamProxy should be nil after clearing")
	}
}

func TestParseUpstreamProxyValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid http", input: "http://proxy:3128", wantErr: false},
		{name: "valid socks5", input: "socks5://proxy:1080", wantErr: false},
		{name: "valid http with auth", input: "http://user:pass@proxy:3128", wantErr: false},
		{name: "valid socks5 with auth", input: "socks5://user:pass@proxy:1080", wantErr: false},
		{name: "empty is valid", input: "", wantErr: false},
		{name: "https not supported", input: "https://proxy:3128", wantErr: true},
		{name: "no port", input: "http://proxy", wantErr: true},
		{name: "bad scheme", input: "ftp://proxy:21", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := proxy.ParseUpstreamProxy(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("ParseUpstreamProxy(%q) should return error", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ParseUpstreamProxy(%q) unexpected error: %v", tt.input, err)
			}
		})
	}
}

func TestHTTPSPassthroughViaUpstreamProxy(t *testing.T) {
	// Start a TCP echo server to simulate the upstream HTTPS server.
	echoAddr := startTCPEchoServer(t)

	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())

	// Configure passthrough for the echo server host.
	passthrough := proxy.NewPassthroughList()
	passthrough.Add("localhost")
	handler.SetPassthroughList(passthrough)

	// Start a mock HTTP CONNECT proxy.
	proxyAddr, proxyCleanup := startMockHTTPConnectProxy(t, false, "", "")
	defer proxyCleanup()

	// Configure upstream proxy.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	handler.SetUpstreamProxy(proxyURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyListenAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Send CONNECT to our proxy. The proxy should dial the echo server
	// through the upstream proxy (passthrough mode).
	conn, err := net.DialTimeout("tcp", proxyListenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Extract host and port from echo server address.
	_, echoPort, _ := net.SplitHostPort(echoAddr)
	connectHost := "localhost:" + echoPort

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectHost, connectHost)
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The connection should now be tunneled through to the echo server.
	testMsg := "passthrough via proxy"
	conn.Write([]byte(testMsg))
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != testMsg {
		t.Errorf("got %q, want %q", buf, testMsg)
	}
}

// --- Test helpers ---

// startTCPEchoServer starts a TCP server that echoes back data.
func startTCPEchoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startMockHTTPConnectProxy starts a mock HTTP CONNECT proxy.
func startMockHTTPConnectProxy(t *testing.T, requireAuth bool, username, password string) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock proxy: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockProxy(conn, requireAuth, username, password)
		}
	}()

	cleanup := func() {
		ln.Close()
		<-done
	}

	return ln.Addr().String(), cleanup
}

func handleMockProxy(conn net.Conn, requireAuth bool, username, password string) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := gohttp.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method != gohttp.MethodConnect {
		// For non-CONNECT requests (forward proxy), relay to target.
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}

	if requireAuth {
		authHeader := req.Header.Get("Proxy-Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		if authHeader != expected {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
	}

	target, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay bidirectionally.
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, reader)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errCh <- err
	}()
	<-errCh
}

// startMockHTTPForwardProxy starts a mock HTTP forward proxy that relays
// non-CONNECT requests to the target.
func startMockHTTPForwardProxy(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock forward proxy: %v", err)
	}

	server := &gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			// Forward proxy mode: relay request to the target.
			if r.Method == gohttp.MethodConnect {
				gohttp.Error(w, "CONNECT not implemented in mock", gohttp.StatusMethodNotAllowed)
				return
			}

			// Create outgoing request.
			outReq, _ := gohttp.NewRequest(r.Method, r.URL.String(), r.Body)
			for k, vv := range r.Header {
				for _, v := range vv {
					outReq.Header.Add(k, v)
				}
			}

			client := &gohttp.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(outReq)
			if err != nil {
				gohttp.Error(w, err.Error(), gohttp.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}),
	}

	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })

	return ln.Addr().String()
}

func TestHTTPConnectViaUpstreamProxyWithAuth(t *testing.T) {
	// Start an upstream HTTPS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "auth-proxy-ok")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())
	handler.SetInsecureSkipVerify(true)

	// Start mock proxy with authentication.
	proxyAddr, proxyCleanup := startMockHTTPConnectProxy(t, true, "user", "pass")
	defer proxyCleanup()

	// Configure upstream proxy with credentials.
	proxyURL, _ := url.Parse("http://user:pass@" + proxyAddr)
	handler.SetUpstreamProxy(proxyURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyListenAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyListenAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	httpReq := fmt.Sprintf("GET /auth-test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
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
	if string(body) != "auth-proxy-ok" {
		t.Errorf("body = %q, want %q", body, "auth-proxy-ok")
	}
}

// containsString checks if s contains substr (avoid importing strings in test).
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}
