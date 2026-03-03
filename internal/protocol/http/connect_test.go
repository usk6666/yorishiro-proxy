package http

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
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

// mockStore is a thread-safe minimal in-memory session store for testing.
type mockStore struct {
	mu       sync.Mutex
	sessions []*session.Session
	messages []*session.Message
}

func (m *mockStore) SaveSession(_ context.Context, s *session.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	m.sessions = append(m.sessions, s)
	return nil
}

func (m *mockStore) UpdateSession(_ context.Context, id string, update session.SessionUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.ID == id {
			if update.State != "" {
				s.State = update.State
			}
			if update.Duration != 0 {
				s.Duration = update.Duration
			}
			if update.Tags != nil {
				s.Tags = update.Tags
			}
			if update.ServerAddr != "" {
				if s.ConnInfo == nil {
					s.ConnInfo = &session.ConnectionInfo{}
				}
				s.ConnInfo.ServerAddr = update.ServerAddr
			}
			if update.TLSServerCertSubject != "" {
				if s.ConnInfo == nil {
					s.ConnInfo = &session.ConnectionInfo{}
				}
				s.ConnInfo.TLSServerCertSubject = update.TLSServerCertSubject
			}
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockStore) GetSession(_ context.Context, id string) (*session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockStore) ListSessions(_ context.Context, _ session.ListOptions) ([]*session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*session.Session, len(m.sessions))
	copy(result, m.sessions)
	return result, nil
}

func (m *mockStore) CountSessions(_ context.Context, _ session.ListOptions) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions), nil
}

func (m *mockStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.sessions {
		if s.ID == id {
			m.sessions = append(m.sessions[:i], m.sessions[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockStore) DeleteAllSessions(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := int64(len(m.sessions))
	m.sessions = nil
	m.messages = nil
	return n, nil
}

func (m *mockStore) DeleteSessionsByProtocol(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteSessionsOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteExcessSessions(_ context.Context, _ int) (int64, error) {
	return 0, nil
}

func (m *mockStore) AppendMessage(_ context.Context, msg *session.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockStore) GetMessages(_ context.Context, sessionID string, opts session.MessageListOptions) ([]*session.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*session.Message
	for _, msg := range m.messages {
		if msg.SessionID == sessionID {
			if opts.Direction != "" && msg.Direction != opts.Direction {
				continue
			}
			result = append(result, msg)
		}
	}
	return result, nil
}

func (m *mockStore) CountMessages(_ context.Context, sessionID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, msg := range m.messages {
		if msg.SessionID == sessionID {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) SaveMacro(_ context.Context, _, _, _ string) error { return nil }
func (m *mockStore) GetMacro(_ context.Context, _ string) (*session.MacroRecord, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockStore) ListMacros(_ context.Context) ([]*session.MacroRecord, error) { return nil, nil }
func (m *mockStore) DeleteMacro(_ context.Context, _ string) error                { return nil }

// mockEntry is a convenience view of a recorded session with its send/receive messages.
type mockEntry struct {
	Session *session.Session
	Send    *session.Message
	Receive *session.Message
}

// Entries returns a list of mockEntry views for all recorded sessions.
func (m *mockStore) Entries() []mockEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	var entries []mockEntry
	for _, s := range m.sessions {
		e := mockEntry{Session: s}
		for _, msg := range m.messages {
			if msg.SessionID == s.ID {
				if msg.Direction == "send" && e.Send == nil {
					e.Send = msg
				}
				if msg.Direction == "receive" && e.Receive == nil {
					e.Receive = msg
				}
			}
		}
		entries = append(entries, e)
	}
	return entries
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
				capture := &captureReader{r: conn}
				reader := bufio.NewReader(capture)
				req, err := gohttp.ReadRequest(reader)
				if err != nil {
					return
				}
				if req.Method == gohttp.MethodConnect {
					handler.handleCONNECT(proxyCtx, conn, req)
				} else {
					handler.handleRequest(proxyCtx, conn, req, &smugglingFlags{}, capture, 0, reader)
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
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

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
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

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
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	// Use a transport that skips TLS verification for the upstream test server.
	// This avoids hostname mismatch since the httptest cert is for 127.0.0.1/example.com,
	// not localhost. What we're testing is the proxy's MITM behavior, not upstream TLS.
	handler.Transport = upstreamTransport(upstream)

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
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

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

	if entry.Session.Protocol != "HTTPS" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTPS")
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("method = %q, want %q", entry.Send.Method, "POST")
	}
	if entry.Send.URL == nil {
		t.Fatal("request URL is nil")
	}
	if entry.Send.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", entry.Send.URL.Scheme, "https")
	}
	if entry.Send.URL.Path != "/api/submit" {
		t.Errorf("URL path = %q, want %q", entry.Send.URL.Path, "/api/submit")
	}
	if string(entry.Send.Body) != reqBody {
		t.Errorf("request body = %q, want %q", entry.Send.Body, reqBody)
	}
	if entry.Receive == nil {
		t.Fatal("receive message is nil")
	}
	if entry.Receive.StatusCode != gohttp.StatusCreated {
		t.Errorf("response status = %d, want %d", entry.Receive.StatusCode, gohttp.StatusCreated)
	}
	if string(entry.Receive.Body) != "response-body" {
		t.Errorf("response body = %q, want %q", entry.Receive.Body, "response-body")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
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
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

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
		if entry.Send == nil || entry.Send.URL == nil {
			t.Errorf("entry[%d] send or URL is nil", i)
			continue
		}
		if entry.Send.URL.Path != expectedPath {
			t.Errorf("entry[%d] path = %q, want %q", i, entry.Send.URL.Path, expectedPath)
		}
		if entry.Session.Protocol != "HTTPS" {
			t.Errorf("entry[%d] protocol = %q, want %q", i, entry.Session.Protocol, "HTTPS")
		}
	}
}

func TestHandleCONNECT_BadHostname(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

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
	handler := NewHandler(store, nil, testutil.DiscardLogger())

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
	handler := NewHandler(store, nil, testutil.DiscardLogger())

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
	if entries[0].Session.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want %q", entries[0].Session.Protocol, "HTTP/1.x")
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
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

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
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.URL == nil {
		t.Fatal("send URL is nil")
	}
	if entry.Send.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", entry.Send.URL.Scheme, "https")
	}
	if !strings.Contains(entry.Send.URL.Host, "localhost") {
		t.Errorf("URL host = %q, does not contain %q", entry.Send.URL.Host, "localhost")
	}
	if entry.Send.URL.Path != "/check-scheme" {
		t.Errorf("URL path = %q, want %q", entry.Send.URL.Path, "/check-scheme")
	}
	if entry.Send.URL.RawQuery != "q=test" {
		t.Errorf("URL query = %q, want %q", entry.Send.URL.RawQuery, "q=test")
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
	handler := NewHandler(nil, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

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

func TestHandleCONNECT_MalformedRequests(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "binary garbage data",
			payload: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x81},
		},
		{
			name:    "empty line only",
			payload: []byte("\r\n\r\n"),
		},
		{
			name:    "NUL byte in CONNECT host",
			payload: []byte("CONNECT evil\x00.example.com:443 HTTP/1.1\r\nHost: evil\x00.example.com:443\r\n\r\n"),
		},
		{
			name: "ultra long hostname in CONNECT",
			payload: []byte(fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n",
				strings.Repeat("a", 9000), strings.Repeat("a", 9000))),
		},
		{
			name:    "CONNECT with missing port",
			payload: []byte("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:    "CONNECT with invalid port",
			payload: []byte("CONNECT example.com:99999 HTTP/1.1\r\nHost: example.com:99999\r\n\r\n"),
		},
		{
			name:    "CONNECT with negative port",
			payload: []byte("CONNECT example.com:-1 HTTP/1.1\r\nHost: example.com:-1\r\n\r\n"),
		},
		{
			name:    "CONNECT with empty host",
			payload: []byte("CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n"),
		},
		{
			name:    "double CONNECT request",
			payload: []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nCONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n"),
		},
		{
			name:    "CONNECT with invalid HTTP version",
			payload: []byte("CONNECT example.com:443 HTTP/9.9\r\nHost: example.com:443\r\n\r\n"),
		},
		{
			name:    "negative Content-Length on CONNECT",
			payload: []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: -1\r\n\r\n"),
		},
		{
			name:    "non-numeric Content-Length on CONNECT",
			payload: []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: abc\r\n\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := conn.Write(tt.payload); err != nil {
				// Write failure is acceptable — proxy may close the connection.
				return
			}

			// Read any response. The proxy must not panic.
			buf := make([]byte, 4096)
			_, err = conn.Read(buf)
			_ = err // Any outcome is acceptable.
		})
	}

	// Verify the proxy is still alive after all malformed requests.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy is not accepting connections after malformed requests: %v", err)
	}
	conn.Close()
}

func TestHandleCONNECT_PartialRequests(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "partial CONNECT request line",
			payload: []byte("CONNECT example.com:443 HT"),
		},
		{
			name:    "CONNECT request line without CRLF",
			payload: []byte("CONNECT example.com:443 HTTP/1.1"),
		},
		{
			name:    "CONNECT headers without blank line",
			payload: []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443"),
		},
		{
			name:    "CONNECT with single CRLF only",
			payload: []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := conn.Write(tt.payload); err != nil {
				conn.Close()
				return
			}

			// Close write side to simulate abrupt client disconnection.
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}

			// Read until EOF or error.
			buf := make([]byte, 4096)
			_, err = conn.Read(buf)
			_ = err

			conn.Close()
		})
	}

	// Verify proxy is still alive.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy is not accepting connections after partial CONNECT requests: %v", err)
	}
	conn.Close()
}

func TestHandleCONNECT_MalformedHTTPSRequests(t *testing.T) {
	// Test malformed HTTP requests sent inside an established HTTPS MITM tunnel.
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "missing Host header in TLS tunnel",
			payload: "GET /test HTTP/1.1\r\nConnection: close\r\n\r\n",
		},
		{
			name: "ultra long path in TLS tunnel",
			payload: fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
				strings.Repeat("B", 9000), connectHost),
		},
		{
			name: "NUL byte in header inside TLS tunnel",
			payload: fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s\r\nX-Evil: foo\x00bar\r\nConnection: close\r\n\r\n",
				connectHost),
		},
		{
			name: "negative Content-Length inside TLS tunnel",
			payload: fmt.Sprintf("POST /test HTTP/1.1\r\nHost: %s\r\nContent-Length: -1\r\nConnection: close\r\n\r\n",
				connectHost),
		},
		{
			name: "non-numeric Content-Length inside TLS tunnel",
			payload: fmt.Sprintf("POST /test HTTP/1.1\r\nHost: %s\r\nContent-Length: xyz\r\nConnection: close\r\n\r\n",
				connectHost),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Establish CONNECT tunnel and TLS handshake.
			tlsConn, _ := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)
			defer tlsConn.Close()

			tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

			// Send malformed request over the encrypted tunnel.
			if _, err := tlsConn.Write([]byte(tt.payload)); err != nil {
				return
			}

			// Read response — the handler should either respond with an error
			// or close the connection gracefully.
			buf := make([]byte, 4096)
			_, err := tlsConn.Read(buf)
			_ = err // Any outcome is acceptable.
		})
	}

	// Verify the proxy still accepts new CONNECT tunnels.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy is not accepting connections after malformed HTTPS requests: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn.Write([]byte(connectReq))

	reader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("proxy did not respond to valid CONNECT after malformed requests: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("CONNECT status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
}

func TestHandleCONNECT_PartialHTTPSRequests(t *testing.T) {
	// Test partial HTTP requests inside an HTTPS tunnel (client disconnects mid-request).
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	port := upstreamPort(t, upstream)
	connectHost := "localhost:" + port

	issuer, rootCAs := newTestIssuer(t)
	store := &mockStore{}
	handler := NewHandler(store, issuer, testutil.DiscardLogger())
	handler.Transport = upstreamTransport(upstream)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	proxyAddr, proxyCancel := startTestProxy(t, ctx, handler)
	defer proxyCancel()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "partial request line in TLS tunnel",
			payload: "GET /test HT",
		},
		{
			name:    "request line only in TLS tunnel",
			payload: "GET /test HTTP/1.1",
		},
		{
			name:    "headers without blank line in TLS tunnel",
			payload: fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s", connectHost),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConn, _ := doConnectAndTLS(t, proxyAddr, connectHost, rootCAs)

			tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := tlsConn.Write([]byte(tt.payload)); err != nil {
				tlsConn.Close()
				return
			}

			// Close the TLS connection to simulate abrupt client disconnection.
			tlsConn.Close()
		})
	}

	// Verify proxy is still alive.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy is not accepting connections after partial HTTPS requests: %v", err)
	}
	conn.Close()
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0000, "unknown (0x0000)"},
		{0xFFFF, "unknown (0xffff)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tlsVersionString(tt.version)
			if got != tt.want {
				t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestCaptureReader_BasicCapture(t *testing.T) {
	data := []byte("Hello, World!")
	cr := &captureReader{r: strings.NewReader(string(data))}

	buf := make([]byte, 5)
	n, err := cr.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 5 {
		t.Errorf("Read returned %d bytes, want 5", n)
	}
	if string(buf[:n]) != "Hello" {
		t.Errorf("Read returned %q, want Hello", string(buf[:n]))
	}

	// Read the rest.
	buf2 := make([]byte, 20)
	n2, _ := cr.Read(buf2)

	captured := cr.Bytes()
	if string(captured) != string(data[:n+n2]) {
		t.Errorf("Captured = %q, want %q", captured, data[:n+n2])
	}
}

func TestCaptureReader_Reset(t *testing.T) {
	cr := &captureReader{r: strings.NewReader("test data")}

	buf := make([]byte, 4)
	cr.Read(buf)

	if cr.buf.Len() == 0 {
		t.Error("expected non-empty buffer before reset")
	}

	cr.Reset()
	if cr.buf.Len() != 0 {
		t.Errorf("buffer after reset has %d bytes, want 0", cr.buf.Len())
	}
	if cr.Bytes() != nil {
		t.Errorf("Bytes() after reset = %v, want nil", cr.Bytes())
	}
}

func TestCaptureReader_MaxCaptureSize(t *testing.T) {
	// Create data larger than maxRawCaptureSize.
	bigData := make([]byte, maxRawCaptureSize+1024)
	for i := range bigData {
		bigData[i] = 'A'
	}
	cr := &captureReader{r: strings.NewReader(string(bigData))}

	// Read all data.
	buf := make([]byte, len(bigData))
	total := 0
	for {
		n, err := cr.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}

	captured := cr.Bytes()
	if len(captured) > maxRawCaptureSize {
		t.Errorf("captured %d bytes, want <= %d", len(captured), maxRawCaptureSize)
	}
}

func TestSerializeRawResponse(t *testing.T) {
	resp := &gohttp.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: 200,
		Header: gohttp.Header{
			"Content-Type": {"text/plain"},
			"X-Custom":     {"value"},
		},
	}
	body := []byte("Hello")

	raw := serializeRawResponse(resp, body)
	rawStr := string(raw)

	if !strings.HasPrefix(rawStr, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("raw response doesn't start with expected status line: %q", rawStr[:min(len(rawStr), 30)])
	}
	if !strings.Contains(rawStr, "\r\n\r\nHello") {
		t.Error("raw response doesn't contain body after header terminator")
	}
}

func TestSerializeRawResponse_NilResponse(t *testing.T) {
	raw := serializeRawResponse(nil, nil)
	if raw != nil {
		t.Errorf("serializeRawResponse(nil) = %v, want nil", raw)
	}
}
