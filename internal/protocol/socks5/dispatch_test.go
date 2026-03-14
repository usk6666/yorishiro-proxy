package socks5

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// mockTunnelHandler implements TunnelHandler for testing.
type mockTunnelHandler struct {
	handleTunnelMITMFunc func(ctx context.Context, conn net.Conn, authority string) error
	isPassthroughFunc    func(hostname string) bool
}

func (m *mockTunnelHandler) HandleTunnelMITM(ctx context.Context, conn net.Conn, authority string) error {
	if m.handleTunnelMITMFunc != nil {
		return m.handleTunnelMITMFunc(ctx, conn, authority)
	}
	return nil
}

func (m *mockTunnelHandler) IsPassthrough(hostname string) bool {
	if m.isPassthroughFunc != nil {
		return m.isPassthroughFunc(hostname)
	}
	return false
}

// mockHTTPDetector implements HTTPDetector for testing.
type mockHTTPDetector struct {
	detectFunc func(peek []byte) bool
	handleFunc func(ctx context.Context, conn net.Conn) error
}

func (m *mockHTTPDetector) Detect(peek []byte) bool {
	if m.detectFunc != nil {
		return m.detectFunc(peek)
	}
	return false
}

func (m *mockHTTPDetector) Handle(ctx context.Context, conn net.Conn) error {
	if m.handleFunc != nil {
		return m.handleFunc(ctx, conn)
	}
	return nil
}

func TestIsTLSClientHello(t *testing.T) {
	tests := []struct {
		name   string
		peek   []byte
		expect bool
	}{
		{"TLS 1.0", []byte{0x16, 0x03, 0x01}, true},
		{"TLS 1.2", []byte{0x16, 0x03, 0x03}, true},
		{"TLS 1.3", []byte{0x16, 0x03, 0x04}, true},
		{"not TLS - HTTP", []byte("GET / HTTP/1.1"), false},
		{"not TLS - random", []byte{0x00, 0x01}, false},
		{"too short - 1 byte", []byte{0x16}, false},
		{"too short - empty", []byte{}, false},
		{"wrong second byte", []byte{0x16, 0x04}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTLSClientHello(tt.peek)
			if got != tt.expect {
				t.Fatalf("isTLSClientHello(%v) = %v, want %v", tt.peek, got, tt.expect)
			}
		})
	}
}

func TestNewPostHandshakeDispatch_TLSPath(t *testing.T) {
	var capturedAuthority string
	tunnel := &mockTunnelHandler{
		handleTunnelMITMFunc: func(ctx context.Context, conn net.Conn, authority string) error {
			capturedAuthority = authority
			// Read from conn to verify the TLS ClientHello bytes are available.
			buf := make([]byte, 5)
			n, _ := conn.Read(buf)
			if n < 2 || buf[0] != 0x16 || buf[1] != 0x03 {
				return fmt.Errorf("expected TLS ClientHello bytes, got %v", buf[:n])
			}
			return nil
		},
	}

	cfg := DispatchConfig{
		TunnelHandler: tunnel,
		Logger:        slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Upstream will be closed by the dispatch since it takes the MITM path.
	upstreamClient, upstreamServer := net.Pipe()
	defer upstreamClient.Close()
	defer upstreamServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "example.com:443")
	}()

	// Send TLS ClientHello bytes.
	clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})
	clientConn.Close()

	err := <-errCh
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	if capturedAuthority != "example.com:443" {
		t.Fatalf("expected authority example.com:443, got %s", capturedAuthority)
	}
}

func TestNewPostHandshakeDispatch_TLSPassthrough(t *testing.T) {
	var mitmCalled bool
	tunnel := &mockTunnelHandler{
		handleTunnelMITMFunc: func(ctx context.Context, conn net.Conn, authority string) error {
			mitmCalled = true
			return nil
		},
		isPassthroughFunc: func(hostname string) bool {
			return hostname == "passthrough.example.com"
		},
	}

	cfg := DispatchConfig{
		TunnelHandler: tunnel,
		Logger:        slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "passthrough.example.com:443")
	}()

	// Send TLS ClientHello to trigger TLS path, which should passthrough.
	testData := []byte{0x16, 0x03, 0x01, 0x00, 0x05}
	clientConn.Write(testData)

	// In passthrough mode, data should be relayed to upstream.
	buf := make([]byte, len(testData))
	upstreamClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := upstreamClient.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("expected %v, got %v", testData, buf[:n])
	}

	// Close to end relay.
	clientConn.Close()
	upstreamClient.Close()

	<-errCh

	if mitmCalled {
		t.Fatal("MITM should not have been called for passthrough domain")
	}
}

func TestNewPostHandshakeDispatch_PlaintextHTTP(t *testing.T) {
	var capturedCtx context.Context
	httpDetector := &mockHTTPDetector{
		detectFunc: func(peek []byte) bool {
			return bytes.HasPrefix(peek, []byte("GET "))
		},
		handleFunc: func(ctx context.Context, conn net.Conn) error {
			capturedCtx = ctx
			// Read the HTTP request from conn.
			buf := make([]byte, 100)
			n, _ := conn.Read(buf)
			if !bytes.HasPrefix(buf[:n], []byte("GET ")) {
				return fmt.Errorf("expected HTTP GET, got %s", string(buf[:n]))
			}
			return nil
		},
	}

	cfg := DispatchConfig{
		HTTPDetector: httpDetector,
		Logger:       slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "example.com:80")
	}()

	// Send plaintext HTTP.
	clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	clientConn.Close()

	err := <-errCh
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}

	// Verify SOCKS5 target is in context.
	target := SOCKS5TargetFromContext(capturedCtx)
	if target != "example.com:80" {
		t.Fatalf("expected SOCKS5 target example.com:80, got %q", target)
	}

	// Upstream should have been closed.
	upstreamClient.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = upstreamClient.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected upstream to be closed")
	}
}

func TestNewPostHandshakeDispatch_RawTCPRelay(t *testing.T) {
	cfg := DispatchConfig{
		Logger: slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "db.example.com:5432")
	}()

	// Send non-TLS, non-HTTP data (e.g., PostgreSQL wire protocol).
	testData := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	clientConn.Write(testData)

	// Should be relayed to upstream.
	buf := make([]byte, len(testData))
	upstreamClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := upstreamClient.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("expected %v, got %v", testData, buf[:n])
	}

	// Test reverse direction.
	replyData := []byte("R")
	upstreamClient.Write(replyData)

	replyBuf := make([]byte, 1)
	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(replyBuf[:n], replyData) {
		t.Fatalf("expected %v, got %v", replyData, replyBuf[:n])
	}

	clientConn.Close()
	upstreamClient.Close()
	<-errCh
}

func TestNewPostHandshakeDispatch_PeekFailure(t *testing.T) {
	cfg := DispatchConfig{
		Logger: slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	// Client immediately closes before sending data.
	clientConn, serverConn := net.Pipe()
	_, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientConn.Close()

	// Should not panic; falls back to relay which will complete.
	_ = dispatch(ctx, serverConn, upstreamServer, "example.com:443")
}

func TestNewPostHandshakeDispatch_NoTunnelHandler_TLS(t *testing.T) {
	// When TLS is detected but no TunnelHandler, should fall back to relay.
	cfg := DispatchConfig{
		TunnelHandler: nil,
		Logger:        slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "example.com:443")
	}()

	// Send TLS ClientHello.
	testData := []byte{0x16, 0x03, 0x01, 0x00, 0x05}
	clientConn.Write(testData)

	// Should relay to upstream since no TunnelHandler.
	buf := make([]byte, len(testData))
	upstreamClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := upstreamClient.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("expected %v, got %v", testData, buf[:n])
	}

	clientConn.Close()
	upstreamClient.Close()
	<-errCh
}

func TestNewPostHandshakeDispatch_UpstreamClosedOnMITM(t *testing.T) {
	// Verify that the upstream connection is closed when taking the MITM path.
	upstreamClosed := make(chan struct{})
	tunnel := &mockTunnelHandler{
		handleTunnelMITMFunc: func(ctx context.Context, conn net.Conn, authority string) error {
			return nil
		},
	}

	cfg := DispatchConfig{
		TunnelHandler: tunnel,
		Logger:        slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	_, upstreamServer := net.Pipe()

	// Monitor upstream close.
	go func() {
		buf := make([]byte, 1)
		upstreamServer.Read(buf) // blocks until closed
		close(upstreamClosed)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "example.com:443")
	}()

	// Send TLS ClientHello.
	clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})
	clientConn.Close()

	<-errCh

	select {
	case <-upstreamClosed:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("upstream was not closed")
	}
}

func TestSOCKS5TargetFromContext(t *testing.T) {
	tests := []struct {
		name   string
		ctx    context.Context
		expect string
	}{
		{
			name:   "with target",
			ctx:    withSOCKS5Target(context.Background(), "example.com:443"),
			expect: "example.com:443",
		},
		{
			name:   "without target",
			ctx:    context.Background(),
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SOCKS5TargetFromContext(tt.ctx)
			if got != tt.expect {
				t.Fatalf("SOCKS5TargetFromContext() = %q, want %q", got, tt.expect)
			}
		})
	}
}

// TestHandleTunnelMITM_Integration tests the full SOCKS5 → TLS MITM → HTTPS
// request flow using real TLS with a test HTTPS server.
func TestHandleTunnelMITM_Integration(t *testing.T) {
	// Create a test HTTPS server.
	server := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "socks5-mitm")
		w.WriteHeader(200)
		w.Write([]byte("hello from socks5 mitm"))
	}))
	defer server.Close()

	// Get the server's address (host:port).
	serverAddr := strings.TrimPrefix(server.URL, "https://")

	// Create a CA and issuer for dynamic cert generation.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	// Create the HTTP handler with the issuer.
	httpHandler := protohttp.NewHandler(nil, issuer, slog.Default())
	// Set transport that trusts the test server's certificate.
	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	// Create the SOCKS5 dispatch.
	cfg := DispatchConfig{
		TunnelHandler: httpHandler,
		Logger:        slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	// Create a pipe for the client <-> dispatch communication.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// The upstream connection (not used in MITM path, will be closed).
	_, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, serverAddr)
	}()

	// Create a TLS client connection to the proxy (which will MITM the connection).
	// Use InsecureSkipVerify because the test server uses an IP address and
	// dynamically generated certs may not have matching IP SANs.
	host := strings.Split(serverAddr, ":")[0]
	tlsConn := tls.Client(clientConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// Send an HTTPS request through the MITM tunnel.
	req, _ := gohttp.NewRequest("GET", "https://"+serverAddr+"/test", nil)
	req.Host = serverAddr
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read the response using a buffered reader.
	reader := bufio.NewReader(tlsConn)
	resp, err := gohttp.ReadResponse(reader, req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hello from socks5 mitm") {
		t.Fatalf("unexpected body: %s", string(body))
	}

	tlsConn.Close()
	clientConn.Close()
	<-errCh
}

func TestNewPostHandshakeDispatch_UpstreamClosedOnHTTP(t *testing.T) {
	// Verify that the upstream connection is closed when taking the HTTP path.
	httpDetector := &mockHTTPDetector{
		detectFunc: func(peek []byte) bool {
			return bytes.HasPrefix(peek, []byte("GET "))
		},
		handleFunc: func(ctx context.Context, conn net.Conn) error {
			return nil
		},
	}

	cfg := DispatchConfig{
		HTTPDetector: httpDetector,
		Logger:       slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "example.com:80")
	}()

	clientConn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	clientConn.Close()

	<-errCh

	// Upstream should have been closed.
	upstreamClient.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := upstreamClient.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected upstream to be closed")
	}
}

func TestNewPostHandshakeDispatch_InvalidTarget_TLS(t *testing.T) {
	tunnel := &mockTunnelHandler{}

	cfg := DispatchConfig{
		TunnelHandler: tunnel,
		Logger:        slog.Default(),
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	_, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		// Invalid target (no port).
		errCh <- dispatch(ctx, serverConn, upstreamServer, "invalid-target")
	}()

	// Send TLS ClientHello.
	clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})
	clientConn.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !strings.Contains(err.Error(), "invalid target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Mock FlowWriter for dispatch tests ---

type dispatchMockStore struct {
	mu       sync.Mutex
	flows    []*flow.Flow
	updates  []dispatchFlowUpdate
	messages []*flow.Message
}

type dispatchFlowUpdate struct {
	ID     string
	Update flow.FlowUpdate
}

func (m *dispatchMockStore) SaveFlow(_ context.Context, s *flow.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		s.ID = fmt.Sprintf("flow-%d", len(m.flows)+1)
	}
	cp := *s
	m.flows = append(m.flows, &cp)
	return nil
}

func (m *dispatchMockStore) UpdateFlow(_ context.Context, id string, update flow.FlowUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updates = append(m.updates, dispatchFlowUpdate{ID: id, Update: update})
	return nil
}

func (m *dispatchMockStore) AppendMessage(_ context.Context, msg *flow.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *dispatchMockStore) getFlows() []*flow.Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*flow.Flow, len(m.flows))
	copy(out, m.flows)
	return out
}

func (m *dispatchMockStore) getUpdates() []dispatchFlowUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]dispatchFlowUpdate, len(m.updates))
	copy(out, m.updates)
	return out
}

func (m *dispatchMockStore) getMessages() []*flow.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*flow.Message, len(m.messages))
	copy(out, m.messages)
	return out
}

// --- Raw TCP flow recording tests ---

func TestNewPostHandshakeDispatch_RawTCPRelay_FlowRecording(t *testing.T) {
	store := &dispatchMockStore{}

	cfg := DispatchConfig{
		Logger:     slog.Default(),
		FlowWriter: store,
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "db.example.com:5432")
	}()

	// Send non-TLS, non-HTTP data.
	testData := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	clientConn.Write(testData)

	// Read on upstream side.
	buf := make([]byte, len(testData))
	upstreamClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := upstreamClient.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("expected %v, got %v", testData, buf[:n])
	}

	// Send reply from upstream.
	replyData := []byte("reply-data")
	upstreamClient.Write(replyData)

	replyBuf := make([]byte, len(replyData))
	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(replyBuf[:n], replyData) {
		t.Fatalf("expected %v, got %v", replyData, replyBuf[:n])
	}

	clientConn.Close()
	upstreamClient.Close()
	<-errCh

	// Verify a flow was created.
	flows := store.getFlows()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	fl := flows[0]
	if fl.Protocol != "SOCKS5+TCP" {
		t.Errorf("expected protocol SOCKS5+TCP, got %q", fl.Protocol)
	}
	if fl.FlowType != "bidirectional" {
		t.Errorf("expected flow type bidirectional, got %q", fl.FlowType)
	}
	if fl.ConnInfo == nil || fl.ConnInfo.ServerAddr != "db.example.com:5432" {
		t.Errorf("expected server addr db.example.com:5432, got %v", fl.ConnInfo)
	}

	// Verify messages were recorded.
	msgs := store.getMessages()
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(msgs))
	}

	// Verify flow was updated to complete.
	updates := store.getUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	if updates[0].Update.State != "complete" {
		t.Errorf("expected state complete, got %q", updates[0].Update.State)
	}
}

func TestNewPostHandshakeDispatch_RawTCPRelay_SOCKS5Metadata(t *testing.T) {
	store := &dispatchMockStore{}

	cfg := DispatchConfig{
		Logger:     slog.Default(),
		FlowWriter: store,
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	// Set SOCKS5 metadata in context.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = proxy.ContextWithSOCKS5AuthMethod(ctx, "username_password")
	ctx = proxy.ContextWithSOCKS5Target(ctx, "db.example.com:5432")
	ctx = proxy.ContextWithSOCKS5AuthUser(ctx, "testuser")

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "db.example.com:5432")
	}()

	// Send raw TCP data.
	clientConn.Write([]byte{0x01, 0x02, 0x03})

	buf := make([]byte, 10)
	upstreamClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	upstreamClient.Read(buf)

	clientConn.Close()
	upstreamClient.Close()
	<-errCh

	// Verify SOCKS5 metadata in flow tags.
	flows := store.getFlows()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	fl := flows[0]
	if fl.Tags == nil {
		t.Fatal("expected tags to be set")
	}
	if fl.Tags["socks5_auth_method"] != "username_password" {
		t.Errorf("expected auth method username_password, got %q", fl.Tags["socks5_auth_method"])
	}
	if fl.Tags["socks5_auth_user"] != "testuser" {
		t.Errorf("expected auth user testuser, got %q", fl.Tags["socks5_auth_user"])
	}
	if fl.Tags["socks5_target"] != "db.example.com:5432" {
		t.Errorf("expected target db.example.com:5432, got %q", fl.Tags["socks5_target"])
	}
}

func TestNewPostHandshakeDispatch_RawTCPRelay_NilFlowWriter(t *testing.T) {
	// When FlowWriter is nil, should still relay data (backward compatibility).
	cfg := DispatchConfig{
		Logger:     slog.Default(),
		FlowWriter: nil,
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "db.example.com:5432")
	}()

	// Data should still flow.
	testData := []byte{0x00, 0x01, 0x02, 0x03}
	clientConn.Write(testData)

	buf := make([]byte, len(testData))
	upstreamClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := upstreamClient.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("expected %v, got %v", testData, buf[:n])
	}

	clientConn.Close()
	upstreamClient.Close()
	<-errCh
}

func TestNewPostHandshakeDispatch_TLSPassthrough_NoFlowRecording(t *testing.T) {
	// TLS passthrough should NOT create a flow record (uses standaloneRelay).
	store := &dispatchMockStore{}

	tunnel := &mockTunnelHandler{
		isPassthroughFunc: func(hostname string) bool {
			return true
		},
	}

	cfg := DispatchConfig{
		TunnelHandler: tunnel,
		Logger:        slog.Default(),
		FlowWriter:    store,
	}
	dispatch := NewPostHandshakeDispatch(cfg)

	clientConn, serverConn := net.Pipe()
	upstreamClient, upstreamServer := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- dispatch(ctx, serverConn, upstreamServer, "passthrough.example.com:443")
	}()

	// Send TLS ClientHello.
	clientConn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})

	buf := make([]byte, 10)
	upstreamClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	upstreamClient.Read(buf)

	clientConn.Close()
	upstreamClient.Close()
	<-errCh

	// Verify no flow was created (passthrough uses standaloneRelay).
	flows := store.getFlows()
	if len(flows) != 0 {
		t.Fatalf("expected 0 flows for TLS passthrough, got %d", len(flows))
	}
}
