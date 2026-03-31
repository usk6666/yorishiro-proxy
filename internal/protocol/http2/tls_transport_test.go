package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// mockTLSTransport implements httputil.TLSTransport for testing.
// It wraps a StandardTransport and tracks whether TLSConnect was called.
type mockTLSTransport struct {
	inner   httputil.TLSTransport
	calls   atomic.Int64
	lastSNI atomic.Value // stores string
}

func (m *mockTLSTransport) TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	m.calls.Add(1)
	m.lastSNI.Store(serverName)
	return m.inner.TLSConnect(ctx, conn, serverName)
}

func TestSetTLSTransport_RoutesUpstreamTLS(t *testing.T) {
	// Start a TLS upstream server.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Transport", "utls-test")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "utls-ok")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// Use a mock TLS transport that wraps the standard one with InsecureSkipVerify.
	mock := &mockTLSTransport{
		inner: &httputil.StandardTransport{InsecureSkipVerify: true},
	}
	handler.SetTLSTransport(mock)

	// Configure the gohttp.Transport for the non-h2 fallback path.
	// httptest.NewTLSServer negotiates http/1.1 (not h2), so ConnPool routes
	// to forwardUpstreamLegacy which uses gohttp.Transport.
	handler.Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	addr, cancel := startH2CProxyListener(t, handler,
		"test-utls", "127.0.0.1:55555",
		upstream.Listener.Addr().String(),
		tlsMetadata{Version: "TLS 1.3", ALPN: "h2"})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("https://%s/api/test", upstream.Listener.Addr().String())
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "utls-ok" {
		t.Errorf("body = %q, want %q", body, "utls-ok")
	}

	// Verify the mock TLS transport was actually invoked via ConnPool.
	if mock.calls.Load() == 0 {
		t.Error("TLSTransport.TLSConnect was not called")
	}

	// Verify SNI was set correctly.
	if sni, ok := mock.lastSNI.Load().(string); !ok || sni == "" {
		t.Error("TLSTransport.TLSConnect was not called with a server name")
	}
}

func TestSetTLSTransport_NilRestoresDefault(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())

	// Set a transport first, then clear it.
	mock := &mockTLSTransport{
		inner: &httputil.StandardTransport{InsecureSkipVerify: true},
	}
	handler.SetTLSTransport(mock)
	if handler.connPool.TLSTransport == nil {
		t.Fatal("ConnPool.TLSTransport should be set after SetTLSTransport")
	}

	handler.SetTLSTransport(nil)
	if handler.connPool.TLSTransport != nil {
		t.Error("ConnPool.TLSTransport should be nil after SetTLSTransport(nil)")
	}
}

func TestSetTLSTransport_FlowRecording(t *testing.T) {
	// Verify that flows are still properly recorded when using a custom TLS transport.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "recorded-via-utls")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetTLSTransport(&httputil.StandardTransport{InsecureSkipVerify: true})
	// Configure gohttp.Transport for the non-h2 fallback path.
	handler.Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	addr, cancel := startH2CProxyListener(t, handler,
		"test-utls-rec", "127.0.0.1:55556",
		upstream.Listener.Addr().String(),
		tlsMetadata{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2"})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqBody := "test-body"
	reqURL := fmt.Sprintf("https://%s/api/record", upstream.Listener.Addr().String())
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusCreated)
	}

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entry.Session.Protocol, "HTTP/2")
	}
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("method = %q, want %q", entry.Send.Method, "POST")
	}
	if entry.Receive == nil {
		t.Fatal("receive message is nil")
	}
	if entry.Receive.StatusCode != gohttp.StatusCreated {
		t.Errorf("response status = %d, want %d", entry.Receive.StatusCode, gohttp.StatusCreated)
	}
}

// failingTLSTransport always returns an error from TLSConnect.
type failingTLSTransport struct {
	err error
}

func (f *failingTLSTransport) TLSConnect(_ context.Context, conn net.Conn, _ string) (net.Conn, string, error) {
	conn.Close()
	return nil, "", f.err
}

func TestSetTLSTransport_HandshakeFailure(t *testing.T) {
	// When TLSConnect fails, upstream requests should return 502 Bad Gateway.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetTLSTransport(&failingTLSTransport{err: fmt.Errorf("simulated handshake failure")})

	addr, cancel := startH2CProxyListener(t, handler,
		"test-utls-fail", "127.0.0.1:55557",
		upstream.Listener.Addr().String(),
		tlsMetadata{Version: "TLS 1.3", ALPN: "h2"})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("https://%s/test", upstream.Listener.Addr().String())
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d (Bad Gateway)", resp.StatusCode, gohttp.StatusBadGateway)
	}
}

func TestSetTLSTransport_GRPCContentType(t *testing.T) {
	// Verify that gRPC streams also use the custom TLS transport via ConnPool.
	// We don't need a real gRPC server; we just need to confirm the mock
	// transport is called when the stream has a gRPC content type.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Echo back a simple response for the gRPC-like request.
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "0")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte{0, 0, 0, 0, 0}) // empty gRPC frame
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	mock := &mockTLSTransport{
		inner: &httputil.StandardTransport{InsecureSkipVerify: true},
	}
	handler.SetTLSTransport(mock)
	// Configure gohttp.Transport for the non-h2 fallback path.
	handler.Transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	addr, cancel := startH2CProxyListener(t, handler,
		"test-grpc-utls", "127.0.0.1:55558",
		upstream.Listener.Addr().String(),
		tlsMetadata{Version: "TLS 1.3", ALPN: "h2"})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("https://%s/grpc.Service/Method", upstream.Listener.Addr().String())
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL,
		bytes.NewReader([]byte{0, 0, 0, 0, 0})) // empty gRPC frame
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The key assertion: the custom TLS transport was used for the gRPC stream.
	if mock.calls.Load() == 0 {
		t.Error("TLSTransport.TLSConnect was not called for gRPC stream")
	}
}

func TestSetTLSTransport_ALPNNegotiation(t *testing.T) {
	// Test that ALPN negotiation is handled correctly.
	// The StandardTransport advertises both h2 and http/1.1.
	// When connecting to an h2-capable server, h2 should be negotiated.
	upstream := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "alpn-ok")
	}))
	upstream.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetTLSTransport(&httputil.StandardTransport{InsecureSkipVerify: true})

	addr, cancel := startH2CProxyListener(t, handler,
		"test-alpn", "127.0.0.1:55559",
		upstream.Listener.Addr().String(),
		tlsMetadata{Version: "TLS 1.3", ALPN: "h2"})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("https://%s/alpn-check", upstream.Listener.Addr().String())
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "alpn-ok" {
		t.Errorf("body = %q, want %q", body, "alpn-ok")
	}
}
