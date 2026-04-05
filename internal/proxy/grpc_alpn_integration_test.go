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
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/encoding/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// =============================================================================
// Test helpers for gRPC ALPN integration tests (USK-519)
// =============================================================================

// grpcALPNTLSUpstream holds a TLS upstream server configured for h2 ALPN.
type grpcALPNTLSUpstream struct {
	server   *gohttp.Server
	Listener net.Listener
}

func (u *grpcALPNTLSUpstream) Close() {
	u.server.Close()
}

// startGRPCALPNTLSUpstream creates a TLS upstream server that supports h2
// and acts as a gRPC backend.
func startGRPCALPNTLSUpstream(t *testing.T, handler gohttp.Handler) *grpcALPNTLSUpstream {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

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

	return &grpcALPNTLSUpstream{
		server:   server,
		Listener: ln,
	}
}

// startGRPCALPNTLSUpstreamH1Only creates a TLS upstream that only advertises
// HTTP/1.1 in ALPN (no h2 support). Used for error path testing.
func startGRPCALPNTLSUpstreamH1Only(t *testing.T, handler gohttp.Handler) *grpcALPNTLSUpstream {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

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
		NextProtos:   []string{"http/1.1"},
	}

	tlsListener := tls.NewListener(ln, tlsConfig)
	server := &gohttp.Server{
		Handler: handler,
	}
	go server.Serve(tlsListener)
	t.Cleanup(func() { server.Close() })

	return &grpcALPNTLSUpstream{
		server:   server,
		Listener: ln,
	}
}

// startGRPCALPNProxy creates a proxy with HTTP/1.x and HTTP/2 handlers
// configured for TLS MITM with gRPC support.
func startGRPCALPNProxy(
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

	grpcHandler := protogrpc.NewHandler(store, logger)
	h2Handler.SetGRPCHandler(grpcHandler)

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
			logger.Info("proxy listener error", "error", err)
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

// newGRPCALPNClient creates an HTTP client configured to use the proxy and
// trust the given CA certificate. It supports HTTP/2 via ALPN.
func newGRPCALPNClient(proxyAddr string, caCert *x509.Certificate) *gohttp.Client {
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

// buildGRPCFrame creates a gRPC wire frame (5-byte header + protobuf payload).
func buildGRPCFrame(t *testing.T, jsonStr string) []byte {
	t.Helper()
	payload, err := protobuf.Encode(jsonStr)
	if err != nil {
		t.Fatalf("protobuf encode: %v", err)
	}
	return protogrpc.EncodeFrame(false, payload)
}

// pollGRPCALPNFlows polls the store until the expected number of gRPC flows appear.
func pollGRPCALPNFlows(t *testing.T, ctx context.Context, store flow.Store, wantCount int) []*flow.Stream {
	t.Helper()
	var flows []*flow.Stream
	var err error
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, flow.StreamListOptions{Protocol: "gRPC", Limit: 100})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= wantCount {
			return flows
		}
	}
	t.Fatalf("expected %d gRPC flows, got %d after polling", wantCount, len(flows))
	return nil
}

// pollGRPCALPNFlowMessages polls until both send and receive messages appear.
func pollGRPCALPNFlowMessages(t *testing.T, ctx context.Context, store flow.Store, flowID string) (send, recv *flow.Flow) {
	t.Helper()
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		msgs, err := store.GetFlows(ctx, flowID, flow.FlowListOptions{})
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

// trackingTLSTransport wraps a TLSTransport and tracks calls.
type trackingTLSTransport struct {
	inner   httputil.TLSTransport
	calls   atomic.Int64
	lastSNI atomic.Value
}

func (m *trackingTLSTransport) TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	m.calls.Add(1)
	m.lastSNI.Store(serverName)
	return m.inner.TLSConnect(ctx, conn, serverName)
}

// =============================================================================
// gRPC ALPN integration tests (USK-519)
// =============================================================================

// TestIntegration_GRPC_TLS_ALPN_UnaryProxy verifies that a gRPC unary request
// traverses the proxy via CONNECT tunnel with h2 ALPN negotiation, completing
// without deadlock. This is the primary test for USK-519: ensuring the ConnPool
// + h2Transport pipeline replaces the legacy gohttp.Transport path.
func TestIntegration_GRPC_TLS_ALPN_UnaryProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start TLS upstream that supports h2 ALPN.
	upstream := startGRPCALPNTLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body) // Echo back the request frame.
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))

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

	listener, httpHandler, h2Handler, proxyCancel := startGRPCALPNProxy(t, ctx, store, ca)
	defer proxyCancel()

	// Configure handlers to trust the test upstream.
	httpHandler.SetInsecureSkipVerify(true)
	h2Handler.SetInsecureSkipVerify(true)

	client := newGRPCALPNClient(listener.Addr(), ca.Certificate())

	// Build a protobuf gRPC frame.
	reqJSON := `{"0001:0000:String":"hello-grpc-alpn"}`
	reqFrame := buildGRPCFrame(t, reqJSON)

	targetURL := fmt.Sprintf("https://localhost:%s/test.Service/UnaryMethod", upstreamPort)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC unary request through TLS proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify the echoed response contains our data.
	if len(body) < 5 {
		t.Fatalf("response body too short: %d bytes", len(body))
	}

	// Verify flow recording: gRPC protocol, complete state.
	flows := pollGRPCALPNFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify messages are recorded.
	// gRPC progressive recording (USK-520) records frames individually.
	// Poll for at least one message in each direction.
	var allMsgs []*flow.Flow
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		var msgErr error
		allMsgs, msgErr = store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
		if msgErr != nil {
			t.Fatalf("GetMessages: %v", msgErr)
		}
		if len(allMsgs) >= 2 {
			break
		}
	}

	if len(allMsgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(allMsgs))
	}

	// Verify we have both send and receive directions.
	hasSend, hasRecv := false, false
	for _, m := range allMsgs {
		if m.Direction == "send" {
			hasSend = true
		}
		if m.Direction == "receive" {
			hasRecv = true
		}
	}
	if !hasSend {
		t.Error("no send message recorded")
	}
	if !hasRecv {
		t.Error("no receive message recorded")
	}
}

// TestIntegration_GRPC_TLS_ALPN_UTLSFingerprint verifies that when a custom
// TLSTransport is configured (e.g. uTLS), it is used for upstream gRPC
// connections via ConnPool.
func TestIntegration_GRPC_TLS_ALPN_UTLSFingerprint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := startGRPCALPNTLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))

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

	tracker := &trackingTLSTransport{
		inner: &httputil.StandardTransport{InsecureSkipVerify: true},
	}

	listener, httpHandler, h2Handler, proxyCancel := startGRPCALPNProxy(t, ctx, store, ca,
		func(h *protohttp2.Handler) {
			h.SetTLSTransport(tracker)
		},
	)
	defer proxyCancel()

	httpHandler.SetInsecureSkipVerify(true)
	h2Handler.SetInsecureSkipVerify(true)

	client := newGRPCALPNClient(listener.Addr(), ca.Certificate())

	reqJSON := `{"0001:0000:String":"utls-fingerprint-test"}`
	reqFrame := buildGRPCFrame(t, reqJSON)

	targetURL := fmt.Sprintf("https://localhost:%s/test.Service/UTLSMethod", upstreamPort)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC request with uTLS: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify the custom TLS transport was invoked.
	if tracker.calls.Load() == 0 {
		t.Error("TLSTransport.TLSConnect was not called; expected uTLS fingerprint to be applied")
	}

	// Verify SNI was set.
	if sni, ok := tracker.lastSNI.Load().(string); !ok || sni == "" {
		t.Error("TLSTransport.TLSConnect was not called with a server name")
	}
}

// TestIntegration_GRPC_TLS_ALPN_FlowRecording verifies detailed flow recording
// for gRPC over TLS, including state transitions and message content.
func TestIntegration_GRPC_TLS_ALPN_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := startGRPCALPNTLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))

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

	listener, httpHandler, h2Handler, proxyCancel := startGRPCALPNProxy(t, ctx, store, ca)
	defer proxyCancel()

	httpHandler.SetInsecureSkipVerify(true)
	h2Handler.SetInsecureSkipVerify(true)

	client := newGRPCALPNClient(listener.Addr(), ca.Certificate())

	reqJSON := `{"0001:0000:String":"flow-recording-test"}`
	reqFrame := buildGRPCFrame(t, reqJSON)

	targetURL := fmt.Sprintf("https://localhost:%s/test.Service/RecordMethod", upstreamPort)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// Verify flow recording details.
	flows := pollGRPCALPNFlows(t, ctx, store, 1)
	fl := flows[0]

	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// gRPC progressive recording (USK-520) records:
	// - seq=0: headers-only send message (no body)
	// - seq=1+: individual frame messages with protobuf body
	// - final: trailers receive message
	// Wait for at least 3 messages (headers + request frame + response/trailers).
	var allMsgs []*flow.Flow
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		var msgErr error
		allMsgs, msgErr = store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
		if msgErr != nil {
			t.Fatalf("GetMessages: %v", msgErr)
		}
		if len(allMsgs) >= 3 {
			break
		}
	}

	if len(allMsgs) < 3 {
		t.Fatalf("expected at least 3 messages, got %d", len(allMsgs))
	}

	// Find a send message with body (frame data, not the headers-only message).
	var sendWithBody *flow.Flow
	for _, m := range allMsgs {
		if m.Direction == "send" && len(m.Body) > 0 {
			sendWithBody = m
			break
		}
	}
	if sendWithBody == nil {
		t.Fatal("no send message with body found")
	}

	// Verify the send frame body contains protobuf data that decodes correctly.
	decoded, decErr := protobuf.Decode(sendWithBody.Body)
	if decErr != nil {
		t.Errorf("protobuf decode error: %v", decErr)
	} else if !strings.Contains(decoded, "flow-recording-test") {
		t.Errorf("decoded send body = %q, does not contain expected value", decoded)
	}

	// Find a receive message with body (response frame data).
	var recvWithBody *flow.Flow
	for _, m := range allMsgs {
		if m.Direction == "receive" && len(m.Body) > 0 {
			recvWithBody = m
			break
		}
	}
	if recvWithBody == nil {
		t.Fatal("no receive message with body found")
	}

	// Verify the headers-only send message has Content-Type.
	var headerMsg *flow.Flow
	for _, m := range allMsgs {
		if m.Direction == "send" && m.Headers != nil {
			headerMsg = m
			break
		}
	}
	if headerMsg != nil {
		// HTTP/2 headers are lowercase per RFC 9113; recording preserves wire casing.
		ct := headerMsg.Headers["content-type"]
		if len(ct) == 0 || !strings.HasPrefix(ct[0], "application/grpc") {
			t.Errorf("send Content-Type = %v, want application/grpc*", ct)
		}
	}
}

// TestIntegration_GRPC_TLS_ALPN_H2Negotiation verifies that the proxy correctly
// negotiates h2 with the upstream when both sides support it. The connection
// info should reflect the h2 ALPN negotiation.
func TestIntegration_GRPC_TLS_ALPN_H2Negotiation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := startGRPCALPNTLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))

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

	listener, httpHandler, h2Handler, proxyCancel := startGRPCALPNProxy(t, ctx, store, ca)
	defer proxyCancel()

	httpHandler.SetInsecureSkipVerify(true)
	h2Handler.SetInsecureSkipVerify(true)

	client := newGRPCALPNClient(listener.Addr(), ca.Certificate())

	reqJSON := `{"0001:0000:String":"alpn-test"}`
	reqFrame := buildGRPCFrame(t, reqJSON)

	targetURL := fmt.Sprintf("https://localhost:%s/test.Service/ALPNMethod", upstreamPort)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify flow was recorded as gRPC.
	// Note: ConnInfo.TLSALPN records the client→proxy ALPN (always h2 for
	// HTTP/2 handler), not the proxy→upstream negotiation. The upstream h2
	// negotiation is verified implicitly: if ALPN negotiated h1 instead of
	// h2, sendGRPCUpstream would return 502 and the request would fail above.
	flows := pollGRPCALPNFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
}

// TestIntegration_GRPC_TLS_ALPN_ErrorPath_H1Only verifies that when the
// upstream only supports HTTP/1.1 (no h2), the gRPC request fails fast
// with a 502 (since gRPC requires h2) without deadlocking, and a flow
// is recorded.
func TestIntegration_GRPC_TLS_ALPN_ErrorPath_H1Only(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream that only supports HTTP/1.1 (no h2 in ALPN).
	upstream := startGRPCALPNTLSUpstreamH1Only(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "0")
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte{0, 0, 0, 0, 0}) // empty gRPC frame
	}))

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

	listener, httpHandler, h2Handler, proxyCancel := startGRPCALPNProxy(t, ctx, store, ca)
	defer proxyCancel()

	httpHandler.SetInsecureSkipVerify(true)
	h2Handler.SetInsecureSkipVerify(true)

	client := newGRPCALPNClient(listener.Addr(), ca.Certificate())

	reqFrame := buildGRPCFrame(t, `{"0001:0000:String":"h1-only-test"}`)

	targetURL := fmt.Sprintf("https://localhost:%s/test.Service/H1OnlyMethod", upstreamPort)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC request to h1-only upstream: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// When the upstream only supports h1, the gRPC pipeline returns 502
	// (gRPC requires h2 ALPN). The key verification is that the request
	// completes without deadlocking and a flow is recorded.
	if resp.StatusCode != gohttp.StatusBadGateway {
		t.Fatalf("expected HTTP 502 Bad Gateway for h1-only upstream gRPC request, got %d (body: %q)", resp.StatusCode, string(body))
	}

	// Poll for flow recording instead of fixed sleep.
	var allFlows []*flow.Stream
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		allFlows, err = store.ListStreams(ctx, flow.StreamListOptions{Limit: 100})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(allFlows) > 0 {
			break
		}
	}
	if len(allFlows) == 0 {
		t.Error("no flows recorded for h1-only upstream gRPC request")
	}
}
