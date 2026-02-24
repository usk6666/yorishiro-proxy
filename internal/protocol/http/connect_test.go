package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// newTestCA generates a test CA for use in tests.
func newTestCA(t *testing.T) *cert.CA {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	return ca
}

// newTestIssuer creates a test Issuer backed by a test CA.
func newTestIssuer(t *testing.T) (*cert.Issuer, *x509.CertPool) {
	t.Helper()
	ca := newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	return cert.NewIssuer(ca), pool
}

// testLogger creates a silent logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mockStore is a thread-safe minimal in-memory session store for testing.
type mockStore struct {
	mu      sync.Mutex
	entries []*session.Entry
}

func (m *mockStore) Save(_ context.Context, entry *session.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockStore) Get(_ context.Context, id string) (*session.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockStore) List(_ context.Context, _ session.ListOptions) ([]*session.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*session.Entry, len(m.entries))
	copy(result, m.entries)
	return result, nil
}

func (m *mockStore) Count(_ context.Context, _ session.ListOptions) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries), nil
}

func (m *mockStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.entries {
		if e.ID == id {
			m.entries = append(m.entries[:i], m.entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockStore) DeleteAll(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := int64(len(m.entries))
	m.entries = nil
	return n, nil
}

func (m *mockStore) Entries() []*session.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*session.Entry, len(m.entries))
	copy(result, m.entries)
	return result
}

// startTestProxy starts a TCP listener that runs the handler and returns
// the listener address. This avoids net.Pipe deadlock issues with TLS.
func startTestProxy(t *testing.T, ctx context.Context, handler *Handler) (string, context.CancelFunc) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				req, err := gohttp.ReadRequest(reader)
				if err != nil {
					return
				}
				if req.Method == gohttp.MethodConnect {
					handler.handleCONNECT(proxyCtx, conn, req)
				} else {
					handler.handleRequest(proxyCtx, conn, req)
				}
			}()
		}
	}()

	go func() {
		<-proxyCtx.Done()
		ln.Close()
	}()

	return ln.Addr().String(), proxyCancel
}

// upstreamPort extracts the port from an httptest server's listener address.
func upstreamPort(t *testing.T, server *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}

// upstreamTransport returns an http.Transport configured to trust the
// test server's certificate with InsecureSkipVerify to avoid hostname
// mismatch issues when the proxy connects to localhost but the test
// server's cert is for 127.0.0.1/example.com.
func upstreamTransport(server *httptest.Server) *gohttp.Transport {
	return &gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// doConnectAndTLS performs a CONNECT handshake and TLS connection to the proxy.
// It uses "localhost" as the hostname so that the proxy generates a cert with
// DNS SANs (not IP SANs), avoiding SNI issues with IP addresses.
func doConnectAndTLS(t *testing.T, proxyAddr, connectHost string, rootCAs *x509.CertPool) (*tls.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	// Send CONNECT request.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectHost, connectHost)
	conn.Write([]byte(connectReq))

	// Read 200 response.
	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		conn.Close()
		t.Fatalf("CONNECT status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Extract hostname for TLS SNI.
	hostname, _, err := net.SplitHostPort(connectHost)
	if err != nil {
		hostname = connectHost
	}

	// TLS handshake using bufferedConn to preserve any buffered data.
	bc := newBufferedConn(conn, reader)
	tlsConn := tls.Client(bc, &tls.Config{
		ServerName: hostname,
		RootCAs:    rootCAs,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("client TLS handshake: %v", err)
	}

	return tlsConn, bufio.NewReader(tlsConn)
}

func TestHandleCONNECT_200ConnectionEstablished(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	// Connect to the proxy.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request.
	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read response.
	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if resp.Status != "200 Connection Established" {
		t.Errorf("status = %q, want %q", resp.Status, "200 Connection Established")
	}
}

func TestHandleCONNECT_TLSHandshakeSuccess(t *testing.T) {
	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT and read response.
	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, _ := gohttp.ReadResponse(reader, nil)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}

	// Perform TLS handshake.
	bc := newBufferedConn(conn, reader)
	tlsConn := tls.Client(bc, &tls.Config{
		ServerName: "example.com",
		RootCAs:    rootCAs,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	// Verify TLS connection state.
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}

	peerCert := state.PeerCertificates[0]
	if len(peerCert.DNSNames) != 1 || peerCert.DNSNames[0] != "example.com" {
		t.Errorf("peer cert DNSNames = %v, want [example.com]", peerCert.DNSNames)
	}
}

func TestHandleCONNECT_HTTPSForwarding(t *testing.T) {
	// Start an upstream HTTPS server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "upstream-https")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from https upstream")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())
	// Use a transport that skips TLS verification for the upstream test server.
	// This avoids hostname mismatch since the httptest cert is for 127.0.0.1/example.com,
	// not localhost. What we're testing is the proxy's MITM behavior, not upstream TLS.
	handler.transport = upstreamTransport(upstream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	// Send HTTP request over the TLS tunnel.
	httpReq := fmt.Sprintf("GET /test-path HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
	tlsConn.Write([]byte(httpReq))

	// Read HTTP response.
	httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read HTTPS response: %v", err)
	}
	body, _ := io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	if httpsResp.StatusCode != gohttp.StatusOK {
		t.Errorf("HTTPS status = %d, want %d", httpsResp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from https upstream" {
		t.Errorf("body = %q, want %q", body, "hello from https upstream")
	}
	if httpsResp.Header.Get("X-Test") != "upstream-https" {
		t.Errorf("X-Test = %q, want %q", httpsResp.Header.Get("X-Test"), "upstream-https")
	}
}

func TestHandleCONNECT_SessionRecording(t *testing.T) {
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Custom", "value")
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "response-body")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())
	handler.transport = upstreamTransport(upstream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	// Send POST request with body.
	reqBody := "request-body-data"
	httpReq := fmt.Sprintf("POST /api/submit HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		connectHost, len(reqBody), reqBody)
	tlsConn.Write([]byte(httpReq))

	// Read response.
	httpsResp, _ := gohttp.ReadResponse(tlsReader, nil)
	io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	// Wait for session recording.
	time.Sleep(100 * time.Millisecond)

	// Verify session was recorded.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}

	entry := entries[0]

	if entry.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", entry.Protocol, "HTTPS")
	}
	if entry.Request.Method != "POST" {
		t.Errorf("method = %q, want %q", entry.Request.Method, "POST")
	}
	if entry.Request.URL == nil {
		t.Fatal("request URL is nil")
	}
	if entry.Request.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", entry.Request.URL.Scheme, "https")
	}
	if entry.Request.URL.Path != "/api/submit" {
		t.Errorf("URL path = %q, want %q", entry.Request.URL.Path, "/api/submit")
	}
	if string(entry.Request.Body) != reqBody {
		t.Errorf("request body = %q, want %q", entry.Request.Body, reqBody)
	}
	if entry.Response.StatusCode != gohttp.StatusCreated {
		t.Errorf("response status = %d, want %d", entry.Response.StatusCode, gohttp.StatusCreated)
	}
	if string(entry.Response.Body) != "response-body" {
		t.Errorf("response body = %q, want %q", entry.Response.Body, "response-body")
	}
	if entry.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Duration)
	}
}

func TestHandleCONNECT_KeepAlive(t *testing.T) {
	var mu sync.Mutex
	requestCount := 0
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		mu.Lock()
		requestCount++
		count := requestCount
		mu.Unlock()
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "response-%d", count)
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())
	handler.transport = upstreamTransport(upstream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	// Send multiple requests over the same TLS connection (keep-alive).
	for i := 1; i <= 3; i++ {
		httpReq := fmt.Sprintf("GET /path-%d HTTP/1.1\r\nHost: %s\r\n\r\n", i, connectHost)
		if _, err := tlsConn.Write([]byte(httpReq)); err != nil {
			t.Fatalf("write request %d: %v", i, err)
		}

		httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		body, _ := io.ReadAll(httpsResp.Body)
		httpsResp.Body.Close()

		expected := fmt.Sprintf("response-%d", i)
		if string(body) != expected {
			t.Errorf("response %d body = %q, want %q", i, body, expected)
		}
	}

	// Close and wait for cleanup.
	tlsConn.Close()
	time.Sleep(100 * time.Millisecond)

	// Verify all 3 sessions were recorded.
	entries := store.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 session entries, got %d", len(entries))
	}
	for i, entry := range entries {
		expectedPath := fmt.Sprintf("/path-%d", i+1)
		if entry.Request.URL.Path != expectedPath {
			t.Errorf("entry[%d] path = %q, want %q", i, entry.Request.URL.Path, expectedPath)
		}
		if entry.Protocol != "HTTPS" {
			t.Errorf("entry[%d] protocol = %q, want %q", i, entry.Protocol, "HTTPS")
		}
	}
}

func TestHandleCONNECT_BadHostname(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT with empty host.
	connectReq := "CONNECT  HTTP/1.1\r\nHost: \r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadRequest)
	}
}

func TestHandleCONNECT_NilIssuer(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusNotImplemented {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusNotImplemented)
	}
}

func TestHandleCONNECT_RegularHTTPStillWorks(t *testing.T) {
	// Ensure that adding CONNECT support doesn't break regular HTTP forwarding.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "http-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send a regular HTTP GET request (not CONNECT).
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
	if string(body) != "http-ok" {
		t.Errorf("body = %q, want %q", body, "http-ok")
	}

	// Wait for session recording to complete in the handler goroutine.
	time.Sleep(200 * time.Millisecond)

	// Verify session was recorded as HTTP/1.x, not HTTPS.
	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 session entry, got %d", len(entries))
	}
	if entries[0].Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", entries[0].Protocol, "HTTP/1.x")
	}
}

func TestParseConnectHost(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "host:port", input: "example.com:443", want: "example.com"},
		{name: "host:8443", input: "example.com:8443", want: "example.com"},
		{name: "IP:port", input: "127.0.0.1:443", want: "127.0.0.1"},
		{name: "host only", input: "example.com", want: "example.com"},
		{name: "empty", input: "", wantErr: true},
		{name: "IPv6 with port", input: "[::1]:443", want: "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseConnectHost(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseConnectHost(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("parseConnectHost(%q) error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("parseConnectHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHandleCONNECT_SessionURLHasHTTPSScheme(t *testing.T) {
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testLogger())
	handler.transport = upstreamTransport(upstream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	httpReq := fmt.Sprintf("GET /check-scheme?q=test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
	tlsConn.Write([]byte(httpReq))

	httpsResp, _ := gohttp.ReadResponse(tlsReader, nil)
	io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	// Wait for session recording.
	time.Sleep(100 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Request.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", entry.Request.URL.Scheme, "https")
	}
	if !strings.Contains(entry.Request.URL.Host, "localhost") {
		t.Errorf("URL host = %q, does not contain %q", entry.Request.URL.Host, "localhost")
	}
	if entry.Request.URL.Path != "/check-scheme" {
		t.Errorf("URL path = %q, want %q", entry.Request.URL.Path, "/check-scheme")
	}
	if entry.Request.URL.RawQuery != "q=test" {
		t.Errorf("URL query = %q, want %q", entry.Request.URL.RawQuery, "q=test")
	}
}

func TestHandleCONNECT_NilStore(t *testing.T) {
	// When store is nil, HTTPS requests should still be forwarded but not recorded.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	handler := NewHandler(nil, issuer, testLogger())
	handler.transport = upstreamTransport(upstream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tlsConn, tlsReader := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
	defer tlsConn.Close()

	httpReq := fmt.Sprintf("GET /path HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", connectHost)
	tlsConn.Write([]byte(httpReq))

	httpsResp, err := gohttp.ReadResponse(tlsReader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(httpsResp.Body)
	httpsResp.Body.Close()

	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

// bufferedConn wraps a net.Conn and a bufio.Reader to ensure data already
// buffered by the Reader is read before falling through to the underlying Conn.
// This is necessary when switching from HTTP-level reading (which uses bufio)
// to TLS handshaking (which needs the raw conn with any buffered data).
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(conn net.Conn, reader *bufio.Reader) *bufferedConn {
	return &bufferedConn{Conn: conn, reader: reader}
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}
