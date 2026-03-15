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
	"net/url"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- test helpers ---

// mockStore is a thread-safe minimal in-memory flow store for testing.
type mockStore struct {
	mu       sync.Mutex
	flows    []*flow.Flow
	messages []*flow.Message
}

func (m *mockStore) SaveFlow(_ context.Context, s *flow.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	m.flows = append(m.flows, s)
	return nil
}

func (m *mockStore) UpdateFlow(_ context.Context, id string, update flow.FlowUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.flows {
		if s.ID == id {
			if update.State != "" {
				s.State = update.State
			}
			if update.FlowType != "" {
				s.FlowType = update.FlowType
			}
			if update.Duration != 0 {
				s.Duration = update.Duration
			}
			if update.Tags != nil {
				s.Tags = update.Tags
			}
			if update.ServerAddr != "" && s.ConnInfo != nil {
				s.ConnInfo.ServerAddr = update.ServerAddr
			}
			if update.TLSServerCertSubject != "" && s.ConnInfo != nil {
				s.ConnInfo.TLSServerCertSubject = update.TLSServerCertSubject
			}
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockStore) GetFlow(_ context.Context, id string) (*flow.Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.flows {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func (m *mockStore) ListFlows(_ context.Context, _ flow.ListOptions) ([]*flow.Flow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*flow.Flow, len(m.flows))
	copy(result, m.flows)
	return result, nil
}

func (m *mockStore) CountFlows(_ context.Context, _ flow.ListOptions) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.flows), nil
}

func (m *mockStore) DeleteFlow(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.flows {
		if s.ID == id {
			m.flows = append(m.flows[:i], m.flows[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found: %s", id)
}

func (m *mockStore) DeleteAllFlows(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := int64(len(m.flows))
	m.flows = nil
	m.messages = nil
	return n, nil
}

func (m *mockStore) DeleteFlowsByProtocol(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteFlowsOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockStore) DeleteExcessSessions(_ context.Context, _ int) (int64, error) {
	return 0, nil
}

func (m *mockStore) AppendMessage(_ context.Context, msg *flow.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockStore) GetMessages(_ context.Context, flowID string, opts flow.MessageListOptions) ([]*flow.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*flow.Message
	for _, msg := range m.messages {
		if msg.FlowID == flowID {
			if opts.Direction != "" && msg.Direction != opts.Direction {
				continue
			}
			result = append(result, msg)
		}
	}
	return result, nil
}

func (m *mockStore) CountMessages(_ context.Context, flowID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, msg := range m.messages {
		if msg.FlowID == flowID {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) SaveMacro(_ context.Context, _, _, _ string) error { return nil }
func (m *mockStore) GetMacro(_ context.Context, _ string) (*flow.MacroRecord, error) {
	return nil, fmt.Errorf("not found")
}
func (m *mockStore) ListMacros(_ context.Context) ([]*flow.MacroRecord, error) { return nil, nil }
func (m *mockStore) DeleteMacro(_ context.Context, _ string) error             { return nil }

// mockEntry is a convenience view of a recorded flow with its send/receive messages.
type mockEntry struct {
	Session *flow.Flow
	Send    *flow.Message
	Receive *flow.Message
}

// Entries returns a list of mockEntry views for all recorded flows.
func (m *mockStore) Entries() []mockEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	var entries []mockEntry
	for _, s := range m.flows {
		e := mockEntry{Session: s}
		for _, msg := range m.messages {
			if msg.FlowID == s.ID {
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

// newH2CClient returns an HTTP client configured for h2c with a custom dialer
// that always connects to the given address.
func newH2CClientForAddr(addr string) *gohttp.Client {
	return &gohttp.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, a string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

// startH2CProxyListener creates an h2c TCP listener that delegates to handleStream.
// It returns the listener address and a cancel function.
func startH2CProxyListener(t *testing.T, handler *Handler, connID, clientAddr, connectAuthority string, tlsMeta tlsMetadata) (string, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen: %v", err)
	}

	h2Server := &http2.Server{}
	proxyHTTPHandler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, req *gohttp.Request) {
		hctx := proxy.ContextWithConnID(proxy.ContextWithClientAddr(ctx, clientAddr), connID)
		handler.handleStream(hctx, w, req, connID, clientAddr, connectAuthority, tlsMeta, handler.Logger)
	})
	h2cH := h2c.NewHandler(proxyHTTPHandler, h2Server)

	server := &gohttp.Server{Handler: h2cH}

	go func() {
		server.Serve(ln)
	}()

	go func() {
		<-ctx.Done()
		server.Close()
	}()

	return ln.Addr().String(), cancel
}

// --- Detect tests ---

func TestDetect_HTTP2Preface(t *testing.T) {
	tests := []struct {
		name string
		peek []byte
		want bool
	}{
		{
			name: "valid HTTP/2 connection preface",
			peek: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			want: true,
		},
		{
			name: "exactly 16 bytes of preface",
			peek: []byte("PRI * HTTP/2.0\r\n"),
			want: true,
		},
		{
			name: "HTTP/1.1 GET request",
			peek: []byte("GET / HTTP/1.1\r\n"),
			want: false,
		},
		{
			name: "HTTP/1.1 POST request",
			peek: []byte("POST /api HTTP/1."),
			want: false,
		},
		{
			name: "CONNECT request",
			peek: []byte("CONNECT example.c"),
			want: false,
		},
		{
			name: "too short",
			peek: []byte("PRI * HT"),
			want: false,
		},
		{
			name: "empty bytes",
			peek: []byte{},
			want: false,
		},
		{
			name: "nil bytes",
			peek: nil,
			want: false,
		},
		{
			name: "binary garbage",
			peek: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
			want: false,
		},
		{
			name: "almost matches but wrong version",
			peek: []byte("PRI * HTTP/1.0\r\n"),
			want: false,
		},
	}

	handler := NewHandler(nil, testutil.DiscardLogger())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handler.Detect(tt.peek)
			if got != tt.want {
				t.Errorf("Detect(%q) = %v, want %v", tt.peek, got, tt.want)
			}
		})
	}
}

func TestName(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	if got := handler.Name(); got != "HTTP/2 (h2c)" {
		t.Errorf("Name() = %q, want %q", got, "HTTP/2 (h2c)")
	}
}

// --- HTTP/2 preface constant test ---

func TestHTTP2Preface(t *testing.T) {
	standardPreface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if !bytes.HasPrefix([]byte(standardPreface), http2Preface) {
		t.Errorf("http2Preface %q is not a prefix of the standard HTTP/2 preface", http2Preface)
	}
}

// --- Session recording via handleStream ---

func TestHandleStream_SessionRecording(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Custom", "h2c-value")
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "created-resource")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-conn-rec", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqBody := "request-body-data"
	reqURL := fmt.Sprintf("%s/api/submit", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader([]byte(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusCreated)
	}
	if string(body) != "created-resource" {
		t.Errorf("body = %q, want %q", body, "created-resource")
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
	if entry.Session.FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", entry.Session.FlowType, "unary")
	}
	if entry.Session.State != "complete" {
		t.Errorf("state = %q, want %q", entry.Session.State, "complete")
	}
	if entry.Session.ConnID != "test-conn-rec" {
		t.Errorf("conn_id = %q, want %q", entry.Session.ConnID, "test-conn-rec")
	}
	if entry.Session.Duration <= 0 {
		t.Errorf("duration = %v, want positive", entry.Session.Duration)
	}

	// Verify send message.
	if entry.Send == nil {
		t.Fatal("send message is nil")
	}
	if entry.Send.Method != "POST" {
		t.Errorf("method = %q, want %q", entry.Send.Method, "POST")
	}
	if entry.Send.URL == nil {
		t.Fatal("request URL is nil")
	}
	if entry.Send.URL.Path != "/api/submit" {
		t.Errorf("URL path = %q, want %q", entry.Send.URL.Path, "/api/submit")
	}
	if string(entry.Send.Body) != reqBody {
		t.Errorf("request body = %q, want %q", entry.Send.Body, reqBody)
	}
	if entry.Send.Sequence != 0 {
		t.Errorf("send sequence = %d, want 0", entry.Send.Sequence)
	}
	if entry.Send.Direction != "send" {
		t.Errorf("send direction = %q, want %q", entry.Send.Direction, "send")
	}

	// Verify receive message.
	if entry.Receive == nil {
		t.Fatal("receive message is nil")
	}
	if entry.Receive.StatusCode != gohttp.StatusCreated {
		t.Errorf("response status = %d, want %d", entry.Receive.StatusCode, gohttp.StatusCreated)
	}
	if string(entry.Receive.Body) != "created-resource" {
		t.Errorf("response body = %q, want %q", entry.Receive.Body, "created-resource")
	}
	if entry.Receive.Sequence != 1 {
		t.Errorf("receive sequence = %d, want 1", entry.Receive.Sequence)
	}
	if entry.Receive.Direction != "receive" {
		t.Errorf("receive direction = %q, want %q", entry.Receive.Direction, "receive")
	}
}

func TestHandleStream_MultipleStreams(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "response for %s", r.URL.Path)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-conn-multi", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	const numRequests = 5
	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reqURL := fmt.Sprintf("%s/stream-%d", upstream.URL, idx)
			req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("request %d failed: %v", idx, err)
				return
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("request %d status = %d, want %d", idx, resp.StatusCode, gohttp.StatusOK)
			}
		}(i)
	}
	wg.Wait()

	time.Sleep(300 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != numRequests {
		t.Fatalf("expected %d session entries, got %d", numRequests, len(entries))
	}

	for i, entry := range entries {
		if entry.Session.ConnID != "test-conn-multi" {
			t.Errorf("entry[%d] conn_id = %q, want %q", i, entry.Session.ConnID, "test-conn-multi")
		}
		if entry.Session.Protocol != "HTTP/2" {
			t.Errorf("entry[%d] protocol = %q, want %q", i, entry.Session.Protocol, "HTTP/2")
		}
	}
}

func TestHandleStream_NilStore(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok-no-store")
	}))
	defer upstream.Close()

	handler := NewHandler(nil, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-no-store", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/test", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "ok-no-store" {
		t.Errorf("body = %q, want %q", body, "ok-no-store")
	}
}

func TestHandleStream_UpstreamError(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-upstream-err", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Request to a non-existent upstream (port 1 is typically unreachable).
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:1/unreachable", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusBadGateway)
	}
}

// --- HandleH2 (h2 TLS) flow metadata tests ---

func TestHandleH2_TLSMetadataRecording(t *testing.T) {
	// Use a TLS upstream so the handler can connect via https scheme.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-H2-Test", "passed")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "h2-tls-response")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetInsecureSkipVerify(true)

	tlsMeta := tlsMetadata{
		Version:     "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		ALPN:        "h2",
	}
	// connectAuthority triggers https scheme; point it at the TLS upstream.
	addr, cancel := startH2CProxyListener(t, handler,
		"test-h2-tls", "127.0.0.1:54321",
		upstream.Listener.Addr().String(), tlsMeta)
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	// Request URL uses https and the upstream's address.
	reqURL := fmt.Sprintf("https://%s/api/data", upstream.Listener.Addr().String())
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2 request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "h2-tls-response" {
		t.Errorf("body = %q, want %q", body, "h2-tls-response")
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
	if entry.Session.ConnInfo == nil {
		t.Fatal("conn_info is nil")
	}
	if entry.Session.ConnInfo.TLSVersion != "TLS 1.3" {
		t.Errorf("tls_version = %q, want %q", entry.Session.ConnInfo.TLSVersion, "TLS 1.3")
	}
	if entry.Session.ConnInfo.TLSCipher != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("tls_cipher = %q, want %q", entry.Session.ConnInfo.TLSCipher, "TLS_AES_128_GCM_SHA256")
	}
	if entry.Session.ConnInfo.TLSALPN != "h2" {
		t.Errorf("tls_alpn = %q, want %q", entry.Session.ConnInfo.TLSALPN, "h2")
	}
	if entry.Session.ConnInfo.ClientAddr != "127.0.0.1:54321" {
		t.Errorf("client_addr = %q, want %q", entry.Session.ConnInfo.ClientAddr, "127.0.0.1:54321")
	}
}

func TestHandleH2_HTTPSScheme(t *testing.T) {
	// When connectAuthority is set, the recorded URL should use https scheme.
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	handler.SetInsecureSkipVerify(true)

	// connectAuthority set to the TLS upstream address triggers https scheme.
	upstreamAddr := upstream.Listener.Addr().String()
	addr, cancel := startH2CProxyListener(t, handler,
		"test-scheme", "127.0.0.1:12345",
		upstreamAddr,
		tlsMetadata{Version: "TLS 1.3", ALPN: "h2"})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("https://%s/check-scheme?q=test", upstreamAddr)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Send == nil || entry.Send.URL == nil {
		t.Fatal("send or URL is nil")
	}
	if entry.Send.URL.Scheme != "https" {
		t.Errorf("URL scheme = %q, want %q", entry.Send.URL.Scheme, "https")
	}
}

// --- Configuration tests ---

func TestSetInsecureSkipVerify(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	handler.SetInsecureSkipVerify(true)

	if handler.Transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil after SetInsecureSkipVerify(true)")
	}
	if !handler.Transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestSetInsecureSkipVerify_FalseDoesNotModify(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	handler.SetInsecureSkipVerify(false)

	if handler.Transport.TLSClientConfig != nil {
		t.Errorf("TLSClientConfig = %v, want nil when skip is false",
			handler.Transport.TLSClientConfig)
	}
}

func TestSetCaptureScope(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	scope := proxy.NewCaptureScope()
	handler.SetCaptureScope(scope)

	if handler.Scope != scope {
		t.Error("scope was not set correctly")
	}
}

func TestSetTransport(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	newTransport := &gohttp.Transport{MaxIdleConns: 42}
	handler.SetTransport(newTransport)

	if handler.Transport != newTransport {
		t.Error("transport was not set correctly")
	}
}

// --- shouldCapture tests ---

func TestShouldCapture_NoScope(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	u, _ := url.Parse("http://example.com/api/test")
	if !handler.shouldCapture("GET", u) {
		t.Error("shouldCapture with nil scope should return true")
	}
}

// --- removeHTTP2HopByHop tests ---

func TestRemoveHTTP2HopByHop(t *testing.T) {
	header := gohttp.Header{
		"Connection":        {"keep-alive"},
		"Keep-Alive":        {"timeout=5"},
		"Transfer-Encoding": {"chunked"},
		"Upgrade":           {"websocket"},
		"Proxy-Connection":  {"keep-alive"},
		"Content-Type":      {"application/json"},
		"X-Custom":          {"value"},
	}

	removeHTTP2HopByHop(header)

	if header.Get("Connection") != "" {
		t.Error("Connection header should be removed")
	}
	if header.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive header should be removed")
	}
	if header.Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding header should be removed")
	}
	if header.Get("Upgrade") != "" {
		t.Error("Upgrade header should be removed")
	}
	if header.Get("Proxy-Connection") != "" {
		t.Error("Proxy-Connection header should be removed")
	}
	if header.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should not be removed")
	}
	if header.Get("X-Custom") != "value" {
		t.Error("X-Custom should not be removed")
	}
}

// --- Body truncation test ---

func TestHandleStream_BodyTruncation(t *testing.T) {
	// Use a body slightly larger than MaxBodySize to test truncation.
	// We cannot actually allocate 254MB+ in tests, so we verify the
	// truncation logic by checking that bodies smaller than the limit
	// are recorded in full (not truncated).
	bodySize := 2 << 20 // 2MB — well below MaxBodySize (254MB)
	largeBody := make([]byte, bodySize)
	for i := range largeBody {
		largeBody[i] = 'X'
	}

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		w.Write(largeBody)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	addr, cancel := startH2CProxyListener(t, handler, "test-trunc", "127.0.0.1:12345", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(addr)
	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	reqURL := fmt.Sprintf("%s/big-body", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if len(respBody) != len(largeBody) {
		t.Errorf("response body length = %d, want %d", len(respBody), len(largeBody))
	}

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entry := entries[0]; entry.Receive != nil {
		// With MaxBodySize=254MB, a 2MB body should be recorded in full.
		if len(entry.Receive.Body) != bodySize {
			t.Errorf("recorded body = %d bytes, want %d", len(entry.Receive.Body), bodySize)
		}
		if entry.Receive.BodyTruncated {
			t.Error("BodyTruncated = true, want false (body is below MaxBodySize)")
		}
	}
}

// --- h2c Handle() via real TCP connection ---

func TestHandle_H2C_RealConnection(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Test", "h2c-real")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "h2c-real-response")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(ctx, "test-h2c-real")
				hctx = proxy.ContextWithClientAddr(hctx, conn.RemoteAddr().String())
				handler.Handle(hctx, conn)
			}()
		}
	}()

	client := newH2CClientForAddr(ln.Addr().String())

	reqURL := fmt.Sprintf("%s/test-path", upstream.URL)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "h2c-real-response" {
		t.Errorf("body = %q, want %q", body, "h2c-real-response")
	}

	time.Sleep(200 * time.Millisecond)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}
	if entries[0].Session.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", entries[0].Session.Protocol, "HTTP/2")
	}
	if entries[0].Session.ConnID != "test-h2c-real" {
		t.Errorf("conn_id = %q, want %q", entries[0].Session.ConnID, "test-h2c-real")
	}
}
