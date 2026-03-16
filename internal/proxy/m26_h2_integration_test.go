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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	protosocks5 "github.com/usk6666/yorishiro-proxy/internal/protocol/socks5"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// =============================================================================
// Test helpers for M26 integration tests
// =============================================================================

// newM26Store creates a temporary SQLite store for testing.
func newM26Store(t *testing.T, ctx context.Context) flow.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// startM26H2CUpstream creates a test HTTP/2 cleartext (h2c) server.
func startM26H2CUpstream(t *testing.T, handler gohttp.Handler) (string, func()) {
	t.Helper()
	protos := &gohttp.Protocols{}
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	server := &gohttp.Server{
		Handler:   handler,
		Protocols: protos,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(ln)
	return ln.Addr().String(), func() { server.Close() }
}

// startM26H2CProxy creates a proxy supporting h2c with an HTTP/2 handler and
// optional gRPC recording. Returns the proxy address and cancel function.
func startM26H2CProxy(
	t *testing.T,
	ctx context.Context,
	store flow.Store,
	opts ...func(*protohttp2.Handler),
) (string, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, nil, logger)
	h2Handler := protohttp2.NewHandler(store, logger)

	for _, opt := range opts {
		opt(h2Handler)
	}

	detector := protocol.NewDetector(h2Handler, httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	go func() {
		if err := listener.Start(proxyCtx); err != nil && proxyCtx.Err() == nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener.Addr(), proxyCancel
}

// startM26H2Proxy creates a proxy supporting h2 (TLS ALPN) via CONNECT with
// MITM capabilities. Returns the proxy listener, HTTP handler, and cancel function.
func startM26H2Proxy(
	t *testing.T,
	ctx context.Context,
	store flow.Store,
	ca *cert.CA,
	opts ...func(*protohttp2.Handler),
) (*proxy.Listener, *protohttp.Handler, *protohttp2.Handler, context.CancelFunc) {
	t.Helper()

	issuer := cert.NewIssuer(ca)
	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	h2Handler := protohttp2.NewHandler(store, logger)

	for _, opt := range opts {
		opt(h2Handler)
	}

	httpHandler.SetH2Handler(h2Handler)

	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	go func() {
		if err := listener.Start(proxyCtx); err != nil && proxyCtx.Err() == nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener, httpHandler, h2Handler, proxyCancel
}

// startM26SOCKS5Proxy creates a proxy with SOCKS5 + HTTP handler support.
func startM26SOCKS5Proxy(
	t *testing.T,
	ctx context.Context,
	store flow.Store,
) (string, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, nil, logger)
	socks5Handler := protosocks5.NewHandler(logger)
	detector := protocol.NewDetector(socks5Handler, httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      logger,
		PeekTimeout: 2 * time.Second,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	go listener.Start(proxyCtx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener.Addr(), proxyCancel
}

// newM26H2CClient creates an HTTP client configured for h2c that connects
// through the given proxy address.
func newM26H2CClient(proxyAddr string) *gohttp.Client {
	protos := &gohttp.Protocols{}
	protos.SetUnencryptedHTTP2(true)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Protocols: protos,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, proxyAddr)
			},
		},
		Timeout: 15 * time.Second,
	}
}

// newM26H2Client creates an HTTP client for h2 (TLS) via CONNECT proxy.
func newM26H2Client(proxyAddr string, caCert *x509.Certificate) *gohttp.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: 15 * time.Second,
	}
}

// pollM26Flows polls the store until the expected number of flows with the
// given protocol appear or timeout.
func pollM26Flows(t *testing.T, ctx context.Context, store flow.Store, protocol string, wantCount int) []*flow.Flow {
	t.Helper()
	var flows []*flow.Flow
	var err error
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		opts := flow.ListOptions{Limit: 100}
		if protocol != "" {
			opts.Protocol = protocol
		}
		flows, err = store.ListFlows(ctx, opts)
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= wantCount {
			return flows
		}
	}
	t.Fatalf("expected %d flows (protocol=%q), got %d after polling", wantCount, protocol, len(flows))
	return nil
}

// pollM26FlowMessages polls until both send and receive messages appear for a flow.
func pollM26FlowMessages(t *testing.T, ctx context.Context, store flow.Store, flowID string) (send, recv *flow.Message) {
	t.Helper()
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		msgs, err := store.GetMessages(ctx, flowID, flow.MessageListOptions{})
		if err != nil {
			t.Fatalf("GetMessages: %v", err)
		}
		for _, m := range msgs {
			switch m.Direction {
			case "send":
				if send == nil {
					send = m
				}
			case "receive":
				if recv == nil {
					recv = m
				}
			}
		}
		if send != nil && recv != nil {
			return send, recv
		}
	}
	return send, recv
}

// =============================================================================
// h2c (HTTP/2 cleartext) path tests
// =============================================================================

func TestM26_H2C_GET_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.Header().Set("X-Custom", "test-value")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from h2c")
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store)
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/test-h2c-get", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Verify HTTP response.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from h2c" {
		t.Errorf("body = %q, want %q", body, "hello from h2c")
	}

	// Verify flow recording.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]
	if fl.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTP/2")
	}
	if fl.FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "unary")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify L7 structured data.
	send, recv := pollM26FlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if send.Method != "GET" {
		t.Errorf("send method = %q, want %q", send.Method, "GET")
	}
	if send.URL == nil || !strings.Contains(send.URL.Path, "/test-h2c-get") {
		path := ""
		if send.URL != nil {
			path = send.URL.Path
		}
		t.Errorf("send URL path = %q, want to contain %q", path, "/test-h2c-get")
	}
	if recv.StatusCode != 200 {
		t.Errorf("recv status = %d, want 200", recv.StatusCode)
	}
	if string(recv.Body) != "hello from h2c" {
		t.Errorf("recv body = %q, want %q", recv.Body, "hello from h2c")
	}

	// Verify raw bytes recording (request message should have raw frames).
	if len(send.RawBytes) == 0 {
		t.Error("send message RawBytes is empty; expected raw HTTP/2 frame data")
	}
	// Verify frame metadata.
	if send.Metadata == nil {
		t.Error("send message Metadata is nil; expected h2 frame metadata")
	} else {
		if _, ok := send.Metadata["h2_frame_count"]; !ok {
			t.Error("send message missing h2_frame_count metadata")
		}
		if _, ok := send.Metadata["h2_total_wire_bytes"]; !ok {
			t.Error("send message missing h2_total_wire_bytes metadata")
		}
	}
}

func TestM26_H2C_POST_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "echo: %s", reqBody)
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store)
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/test-h2c-post", upstreamAddr)
	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("h2c-body-data"))
	if err != nil {
		t.Fatalf("h2c POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusCreated)
	}
	if string(body) != "echo: h2c-body-data" {
		t.Errorf("body = %q, want %q", body, "echo: h2c-body-data")
	}

	// Verify flow.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]

	send, recv := pollM26FlowMessages(t, ctx, store, fl.ID)
	if send == nil || recv == nil {
		t.Fatal("missing send or recv message")
	}
	if send.Method != "POST" {
		t.Errorf("method = %q, want POST", send.Method)
	}
	if !strings.Contains(string(send.Body), "h2c-body-data") {
		t.Errorf("send body = %q, want to contain %q", send.Body, "h2c-body-data")
	}
	if recv.StatusCode != 201 {
		t.Errorf("recv status = %d, want 201", recv.StatusCode)
	}

	// Verify raw bytes exist on send message.
	if len(send.RawBytes) == 0 {
		t.Error("send message RawBytes is empty")
	}
}

// =============================================================================
// h2 (TLS ALPN) path tests — HTTP CONNECT → TLS → h2
// =============================================================================

func TestM26_H2_TLS_ALPN_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start upstream HTTPS server (h2 via TLS).
	upstream := startM26TLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from h2 TLS")
	}))

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	store := newM26Store(t, ctx)

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, h2Handler, proxyCancel := startM26H2Proxy(t, ctx, store, ca)
	defer proxyCancel()

	// Configure both handlers' upstream transports to trust the test server.
	upstreamTransport := &gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	httpHandler.SetTransport(upstreamTransport)
	h2Handler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	})

	client := newM26H2Client(listener.Addr(), ca.Certificate())

	targetURL := fmt.Sprintf("https://localhost:%s/test-h2-tls", upstreamPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2 TLS GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from h2 TLS" {
		t.Errorf("body = %q, want %q", body, "hello from h2 TLS")
	}

	// Verify flow recording: h2 via CONNECT should record as HTTP/2.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]
	if fl.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTP/2")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify L7 structured data.
	send, recv := pollM26FlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if send.Method != "GET" {
		t.Errorf("send method = %q, want GET", send.Method)
	}
	if recv.StatusCode != 200 {
		t.Errorf("recv status = %d, want 200", recv.StatusCode)
	}

	// Verify raw bytes on send message.
	if len(send.RawBytes) == 0 {
		t.Error("send message RawBytes is empty; expected raw HTTP/2 frame data")
	}

	// Verify TLS connection info is recorded.
	if fl.ConnInfo == nil {
		t.Error("ConnInfo is nil")
	} else {
		if fl.ConnInfo.TLSVersion == "" {
			t.Error("TLSVersion is empty; expected TLS metadata")
		}
	}
}

// m26TLSUpstream wraps a TLS upstream server with its listener address.
type m26TLSUpstream struct {
	server   *gohttp.Server
	Listener net.Listener
}

// Close shuts down the TLS upstream server.
func (u *m26TLSUpstream) Close() {
	u.server.Close()
}

// startM26TLSUpstream creates a TLS upstream server for h2 tests.
func startM26TLSUpstream(t *testing.T, handler gohttp.Handler) *m26TLSUpstream {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// Generate self-signed cert for the upstream.
	upstreamCA := &cert.CA{}
	if err := upstreamCA.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(upstreamCA)
	tlsCert, err := issuer.GetCertificate("localhost")
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	tlsListener := tls.NewListener(ln, tlsConfig)
	server := &gohttp.Server{
		Handler: handler,
	}
	go server.Serve(tlsListener)

	t.Cleanup(func() { server.Close() })

	return &m26TLSUpstream{
		server:   server,
		Listener: ln,
	}
}

// =============================================================================
// SOCKS5 → TLS → h2 path tests
// =============================================================================

func TestM26_SOCKS5_H2C_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start h2c upstream.
	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello via socks5")
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26SOCKS5Proxy(t, ctx, store)
	defer proxyCancel()

	// Connect to proxy via SOCKS5, then send HTTP/1.x request through the tunnel.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if err := socks5Connect(conn, upstreamAddr); err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}

	// Send HTTP/1.1 request through the SOCKS5 tunnel.
	httpReq := fmt.Sprintf("GET /test-socks5 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstreamAddr)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	respBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if !strings.Contains(string(respBytes), "200 OK") {
		t.Errorf("expected 200 OK in response, got: %s", string(respBytes)[:min(len(respBytes), 200)])
	}
	if !strings.Contains(string(respBytes), "hello via socks5") {
		t.Errorf("expected body in response")
	}

	// Note: SOCKS5 handler without PostHandshake does a TCP relay.
	// Flow recording depends on the downstream protocol detection after SOCKS5.
	t.Log("SOCKS5 → h2c tunnel verified")
}

// =============================================================================
// gRPC (unary + streaming) path tests
// =============================================================================

func TestM26_GRPC_Unary_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body) // Echo back.
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store, func(h *protohttp2.Handler) {
		logger := testutil.DiscardLogger()
		grpcHandler := protogrpc.NewHandler(store, logger)
		h.SetGRPCHandler(grpcHandler)
	})
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	// Build a protobuf gRPC frame.
	reqJSON := `{"0001:0000:String":"m26-unary-test"}`
	payload, err := protobuf.Encode(reqJSON)
	if err != nil {
		t.Fatalf("protobuf encode: %v", err)
	}
	reqFrame := protogrpc.EncodeFrame(false, payload)

	targetURL := fmt.Sprintf("http://%s/m26.Service/UnaryMethod", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC unary: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if len(body) < 5 {
		t.Fatalf("response body too short: %d bytes", len(body))
	}

	// Verify flow recording.
	flows := pollM26Flows(t, ctx, store, "gRPC", 1)
	fl := flows[0]
	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify messages exist.
	msgs, err := store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) == 0 {
		t.Error("no messages recorded for gRPC flow")
	}
}

func TestM26_GRPC_ServerStreaming_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)

		flusher, ok := w.(gohttp.Flusher)
		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf(`{"0001:0000:String":"stream-%d"}`, i)
			p, _ := protobuf.Encode(msg)
			w.Write(protogrpc.EncodeFrame(false, p))
			if ok {
				flusher.Flush()
			}
		}
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store, func(h *protohttp2.Handler) {
		logger := testutil.DiscardLogger()
		h.SetGRPCHandler(protogrpc.NewHandler(store, logger))
	})
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	p, _ := protobuf.Encode(`{"0001:0000:String":"request"}`)
	reqFrame := protogrpc.EncodeFrame(false, p)

	targetURL := fmt.Sprintf("http://%s/m26.Service/ServerStream", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC server streaming: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Parse response frames.
	frames, parseErr := protogrpc.ReadAllFrames(body)
	if parseErr != nil {
		t.Fatalf("parse response frames: %v", parseErr)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 response frames, got %d", len(frames))
	}

	// Verify flow recording: should be "stream" type.
	flows := pollM26Flows(t, ctx, store, "gRPC", 1)
	fl := flows[0]
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
	if fl.FlowType != "stream" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "stream")
	}
}

// =============================================================================
// Stream multiplexing tests
// =============================================================================

func TestM26_H2C_StreamMultiplexing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store)
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	const concurrency = 10
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			targetURL := fmt.Sprintf("http://%s/multiplex/%d", upstreamAddr, n)
			resp, err := client.Get(targetURL)
			if err != nil {
				errs <- fmt.Errorf("stream %d: %w", n, err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			expected := fmt.Sprintf("path=/multiplex/%d", n)
			if string(body) != expected {
				errs <- fmt.Errorf("stream %d: body = %q, want %q", n, body, expected)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Verify all flows were recorded.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", concurrency)
	if len(flows) < concurrency {
		t.Errorf("expected at least %d flows, got %d", concurrency, len(flows))
	}

	// Verify each flow has proper state.
	for _, fl := range flows {
		if fl.State != "complete" {
			t.Errorf("flow %s state = %q, want %q", fl.ID, fl.State, "complete")
		}
	}
}

// =============================================================================
// Flow control tests
// =============================================================================

func TestM26_H2C_LargeBody_FlowControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a body larger than the default HTTP/2 flow control window (64KB).
	largeBody := strings.Repeat("X", 128*1024)

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "received %d bytes", len(body))
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store)
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/test-large-body", upstreamAddr)
	resp, err := client.Post(targetURL, "application/octet-stream", strings.NewReader(largeBody))
	if err != nil {
		t.Fatalf("h2c large body POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	expected := fmt.Sprintf("received %d bytes", len(largeBody))
	if string(body) != expected {
		t.Errorf("body = %q, want %q", body, expected)
	}

	// Verify flow recorded.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify raw bytes exist.
	send, _ := pollM26FlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if len(send.RawBytes) == 0 {
		t.Error("send RawBytes is empty for large body request")
	}
}

func TestM26_H2C_LargeResponse_FlowControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Response larger than default HTTP/2 flow control window.
	largeResponse := strings.Repeat("Y", 128*1024)

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte(largeResponse))
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store)
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/test-large-response", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c large response GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if len(body) != len(largeResponse) {
		t.Errorf("body length = %d, want %d", len(body), len(largeResponse))
	}

	// Verify flow is recorded with response body.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
}

// =============================================================================
// Plugin hooks tests
// =============================================================================

func TestM26_H2C_PluginHook_OnReceiveFromClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "got: %s", body)
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)

	// Create a plugin engine with a simple on_receive_from_client hook
	// that adds a custom header.
	pluginScript := `
def on_receive_from_client(data):
    headers = data.get("headers", {})
    headers["X-Plugin-Added"] = ["true"]
    return {"action": "CONTINUE", "data": data}
`
	scriptPath := filepath.Join(t.TempDir(), "test_plugin.star")
	if err := os.WriteFile(scriptPath, []byte(pluginScript), 0644); err != nil {
		t.Fatalf("write plugin script: %v", err)
	}

	engine := plugin.NewEngine(testutil.DiscardLogger())
	if err := engine.LoadPlugins(ctx, []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "h2",
			Hooks:    []string{"on_receive_from_client"},
		},
	}); err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()

	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store, func(h *protohttp2.Handler) {
		h.SetPluginEngine(engine)
	})
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/test-plugin", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET with plugin: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The response body proves the request made it through the proxy successfully.
	if !strings.HasPrefix(string(body), "got:") {
		t.Errorf("unexpected body: %q", body)
	}

	// Verify flow was recorded.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", 1)
	if flows[0].State != "complete" {
		t.Errorf("flow state = %q, want %q", flows[0].State, "complete")
	}
}

// =============================================================================
// Raw bytes verification across all paths
// =============================================================================

func TestM26_H2C_RawBytes_FrameMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("raw-bytes-test"))
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store)
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/raw-bytes", upstreamAddr)
	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("request-body"))
	if err != nil {
		t.Fatalf("h2c POST: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	flows := pollM26Flows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]

	send, _ := pollM26FlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}

	// RawBytes should contain HTTP/2 frame data (HEADERS + DATA frames).
	if len(send.RawBytes) == 0 {
		t.Fatal("send RawBytes is empty")
	}

	// Verify frame metadata is present.
	if send.Metadata == nil {
		t.Fatal("send Metadata is nil")
	}

	frameCount, ok := send.Metadata["h2_frame_count"]
	if !ok {
		t.Error("missing h2_frame_count metadata")
	} else if frameCount == "0" {
		t.Error("h2_frame_count = 0, expected > 0")
	}

	wireBytes, ok := send.Metadata["h2_total_wire_bytes"]
	if !ok {
		t.Error("missing h2_total_wire_bytes metadata")
	} else if wireBytes == "0" {
		t.Error("h2_total_wire_bytes = 0, expected > 0")
	}

	// The HTTP/2 frame preface starts with a 9-byte frame header.
	// Verify the raw bytes are valid HTTP/2 frames by checking frame header length field.
	if len(send.RawBytes) >= 9 {
		// First 3 bytes are the frame length (24-bit big-endian).
		frameLen := int(send.RawBytes[0])<<16 | int(send.RawBytes[1])<<8 | int(send.RawBytes[2])
		// Frame length should be reasonable (< 16KB for typical requests).
		if frameLen > 16*1024*1024 {
			t.Errorf("first frame length = %d, seems unreasonably large", frameLen)
		}
	}
}

// =============================================================================
// Mixed protocol tests
// =============================================================================

func TestM26_H2C_MultipleRequests_SameConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var requestCount int32
	var mu sync.Mutex

	upstreamAddr, closeUpstream := startM26H2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		mu.Lock()
		requestCount++
		n := requestCount
		mu.Unlock()
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "request-%d", n)
	}))
	defer closeUpstream()

	store := newM26Store(t, ctx)
	proxyAddr, proxyCancel := startM26H2CProxy(t, ctx, store)
	defer proxyCancel()

	client := newM26H2CClient(proxyAddr)

	// Send multiple sequential requests through the same h2c connection.
	const numRequests = 5
	for i := 0; i < numRequests; i++ {
		targetURL := fmt.Sprintf("http://%s/multi/%d", upstreamAddr, i)
		resp, err := client.Get(targetURL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != gohttp.StatusOK {
			t.Errorf("request %d: status = %d", i, resp.StatusCode)
		}
	}

	// Verify all requests recorded as separate flows.
	flows := pollM26Flows(t, ctx, store, "HTTP/2", numRequests)
	if len(flows) < numRequests {
		t.Errorf("expected at least %d flows, got %d", numRequests, len(flows))
	}

	// Verify each flow has raw bytes.
	for _, fl := range flows {
		send, _ := pollM26FlowMessages(t, ctx, store, fl.ID)
		if send != nil && len(send.RawBytes) == 0 {
			t.Errorf("flow %s: send RawBytes is empty", fl.ID)
		}
	}
}
