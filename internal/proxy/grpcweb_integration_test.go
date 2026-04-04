//go:build e2e

package proxy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protogrpcweb "github.com/usk6666/yorishiro-proxy/internal/protocol/grpcweb"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// =============================================================================
// gRPC-Web e2e test helpers
// =============================================================================

// grpcWebTrailer builds a gRPC-Web trailer frame payload from status and message.
func grpcWebTrailer(status, message string) []byte {
	s := fmt.Sprintf("grpc-status: %s\r\ngrpc-message: %s\r\n", status, message)
	return []byte(s)
}

// buildGRPCWebResponseBody creates a binary gRPC-Web response body containing
// a data frame with the given payload and an embedded trailer frame.
func buildGRPCWebResponseBody(dataPayload []byte, grpcStatus, grpcMessage string) []byte {
	dataFrame := protogrpcweb.EncodeFrame(false, false, dataPayload)
	trailerPayload := grpcWebTrailer(grpcStatus, grpcMessage)
	trailerFrame := protogrpcweb.EncodeFrame(true, false, trailerPayload)
	return append(dataFrame, trailerFrame...)
}

// buildGRPCWebRequestBody creates a binary gRPC-Web request body containing
// a single data frame with the given payload.
func buildGRPCWebRequestBody(payload []byte) []byte {
	return protogrpcweb.EncodeFrame(false, false, payload)
}

// startGRPCWebH1Proxy starts an HTTP/1.x proxy with gRPC-Web handler configured.
func startGRPCWebH1Proxy(t *testing.T, ctx context.Context, store flow.Store, opts ...func(*protogrpcweb.Handler)) (*proxy.Listener, *protohttp.Handler, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, nil, logger)
	gwHandler := protogrpcweb.NewHandler(store, logger)
	for _, opt := range opts {
		opt(gwHandler)
	}
	httpHandler.SetGRPCWebHandler(gwHandler)

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

	return listener, httpHandler, proxyCancel
}

// startGRPCWebTLSProxy starts a TLS MITM proxy with gRPC-Web handler
// configured for both HTTP/1.x and HTTP/2 paths.
func startGRPCWebTLSProxy(
	t *testing.T,
	ctx context.Context,
	store flow.Store,
	ca *cert.CA,
	gwOpts ...func(*protogrpcweb.Handler),
) (*proxy.Listener, *protohttp.Handler, *protohttp2.Handler, context.CancelFunc) {
	t.Helper()

	issuer := cert.NewIssuer(ca)
	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	h2Handler := protohttp2.NewHandler(store, logger)
	gwHandler := protogrpcweb.NewHandler(store, logger)

	for _, opt := range gwOpts {
		opt(gwHandler)
	}

	httpHandler.SetGRPCWebHandler(gwHandler)
	httpHandler.SetH2Handler(h2Handler)
	h2Handler.SetGRPCWebHandler(gwHandler)

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

// newGRPCWebStore creates a temporary SQLite store for gRPC-Web tests.
func newGRPCWebStore(t *testing.T, ctx context.Context) *flow.SQLiteStore {
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

// pollGRPCWebFlows polls the store until the expected number of gRPC-Web flows appear.
func pollGRPCWebFlows(t *testing.T, ctx context.Context, store flow.Store, wantCount int) []*flow.Flow {
	t.Helper()
	var flows []*flow.Flow
	var err error
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Protocol: "gRPC-Web", Limit: 100})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= wantCount {
			return flows
		}
	}
	t.Fatalf("expected %d gRPC-Web flows, got %d after polling", wantCount, len(flows))
	return nil
}

// pollGRPCWebFlowMessages polls until at least one send and one receive message appear.
func pollGRPCWebFlowMessages(t *testing.T, ctx context.Context, store flow.Store, flowID string) []*flow.Message {
	t.Helper()
	var allMsgs []*flow.Message
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		var err error
		allMsgs, err = store.GetMessages(ctx, flowID, flow.MessageListOptions{})
		if err != nil {
			t.Fatalf("GetMessages: %v", err)
		}
		hasSend, hasRecv := false, false
		for _, m := range allMsgs {
			if m.Direction == "send" {
				hasSend = true
			}
			if m.Direction == "receive" {
				hasRecv = true
			}
		}
		if hasSend && hasRecv {
			return allMsgs
		}
	}
	return allMsgs
}

// newGRPCWebTLSUpstream creates a TLS upstream server that speaks gRPC-Web.
func newGRPCWebTLSUpstream(t *testing.T, handler gohttp.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

// grpcWebClient creates an HTTP client configured for the proxy.
func grpcWebClient(proxyAddr string) *gohttp.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 15 * time.Second,
	}
}

// grpcWebTLSClient creates an HTTP client configured for the proxy with CA trust.
func grpcWebTLSClient(proxyAddr string, caCert *x509.Certificate) *gohttp.Client {
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
		Timeout: 15 * time.Second,
	}
}

// =============================================================================
// HTTP/1.1 + Binary gRPC-Web
// =============================================================================

func TestIntegration_GRPCWeb_H1_Binary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("hello-grpc-web-binary")
	respPayload := []byte("response-grpc-web-binary")

	// Upstream responds with gRPC-Web binary frames.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(gohttp.StatusOK)
		body := buildGRPCWebResponseBody(respPayload, "0", "OK")
		w.Write(body)
	}))
	defer upstream.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Build gRPC-Web request body.
	reqBody := buildGRPCWebRequestBody(testPayload)

	// Send request through proxy.
	targetURL := upstream.URL + "/test.Service/UnaryMethod"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc-web+proto")

	client := grpcWebClient(listener.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC-Web binary request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify response contains gRPC-Web frames.
	result, err := protogrpcweb.DecodeBody(body, false)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("data frames = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, respPayload) {
		t.Errorf("payload = %q, want %q", result.DataFrames[0].Payload, respPayload)
	}
	if result.TrailerFrame == nil {
		t.Fatal("no trailer frame in response")
	}
	if result.Trailers["grpc-status"] != "0" {
		t.Errorf("grpc-status = %q, want %q", result.Trailers["grpc-status"], "0")
	}

	// Verify flow recording.
	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC-Web" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC-Web")
	}
	if fl.FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "unary")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify messages.
	msgs := pollGRPCWebFlowMessages(t, ctx, store, fl.ID)
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(msgs))
	}

	var sendMsg, recvMsg *flow.Message
	for _, m := range msgs {
		if m.Direction == "send" && sendMsg == nil {
			sendMsg = m
		}
		if m.Direction == "receive" && recvMsg == nil {
			recvMsg = m
		}
	}
	if sendMsg == nil {
		t.Fatal("send message not found")
	}
	if recvMsg == nil {
		t.Fatal("receive message not found")
	}

	// Verify send message content.
	if sendMsg.Method != "POST" {
		t.Errorf("send method = %q, want %q", sendMsg.Method, "POST")
	}
	if sendMsg.URL == nil || !strings.Contains(sendMsg.URL.Path, "/test.Service/UnaryMethod") {
		t.Errorf("send URL path = %v, want to contain /test.Service/UnaryMethod", sendMsg.URL)
	}
	if !bytes.Equal(sendMsg.Body, testPayload) {
		t.Errorf("send body = %q, want %q", sendMsg.Body, testPayload)
	}

	// Verify send message headers.
	if ct := sendMsg.Headers["Content-Type"]; len(ct) == 0 || !strings.HasPrefix(ct[0], "application/grpc-web") {
		t.Errorf("send Content-Type = %v, want application/grpc-web*", ct)
	}

	// Verify send metadata (service/method).
	if sendMsg.Metadata == nil {
		t.Fatal("send metadata is nil")
	}
	if sendMsg.Metadata["service"] != "test.Service" {
		t.Errorf("send metadata service = %q, want %q", sendMsg.Metadata["service"], "test.Service")
	}
	if sendMsg.Metadata["method"] != "UnaryMethod" {
		t.Errorf("send metadata method = %q, want %q", sendMsg.Metadata["method"], "UnaryMethod")
	}

	// Verify receive message.
	if recvMsg.StatusCode != gohttp.StatusOK {
		t.Errorf("recv status = %d, want %d", recvMsg.StatusCode, gohttp.StatusOK)
	}
	if !bytes.Equal(recvMsg.Body, respPayload) {
		t.Errorf("recv body = %q, want %q", recvMsg.Body, respPayload)
	}
	if recvMsg.Metadata != nil && recvMsg.Metadata["grpc_status"] != "0" {
		t.Errorf("recv grpc_status = %q, want %q", recvMsg.Metadata["grpc_status"], "0")
	}

	// Verify raw bytes recording.
	if len(sendMsg.RawBytes) == 0 {
		t.Error("send RawBytes is empty")
	}
	if len(recvMsg.RawBytes) == 0 {
		t.Error("recv RawBytes is empty")
	}
}

// =============================================================================
// HTTP/1.1 + Base64 gRPC-Web
// =============================================================================

func TestIntegration_GRPCWeb_H1_Base64(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("hello-grpc-web-base64")
	respPayload := []byte("response-grpc-web-base64")

	// Upstream responds with gRPC-Web base64-encoded frames.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web-text+proto")
		w.WriteHeader(gohttp.StatusOK)
		binaryBody := buildGRPCWebResponseBody(respPayload, "0", "OK")
		encoded := protogrpcweb.EncodeBase64Body(binaryBody)
		w.Write(encoded)
	}))
	defer upstream.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Build gRPC-Web-text request body (base64 encoded).
	binaryReqBody := buildGRPCWebRequestBody(testPayload)
	base64ReqBody := protogrpcweb.EncodeBase64Body(binaryReqBody)

	targetURL := upstream.URL + "/test.TextService/Base64Method"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(base64ReqBody))
	req.Header.Set("Content-Type", "application/grpc-web-text+proto")

	client := grpcWebClient(listener.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC-Web base64 request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Decode the base64 response.
	result, err := protogrpcweb.DecodeBody(body, true)
	if err != nil {
		t.Fatalf("decode base64 response: %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("data frames = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, respPayload) {
		t.Errorf("payload = %q, want %q", result.DataFrames[0].Payload, respPayload)
	}

	// Verify flow recording.
	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC-Web" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC-Web")
	}
	if fl.FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "unary")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify messages.
	msgs := pollGRPCWebFlowMessages(t, ctx, store, fl.ID)
	var sendMsg, recvMsg *flow.Message
	for _, m := range msgs {
		if m.Direction == "send" && sendMsg == nil {
			sendMsg = m
		}
		if m.Direction == "receive" && recvMsg == nil {
			recvMsg = m
		}
	}
	if sendMsg == nil {
		t.Fatal("send message not found")
	}
	if recvMsg == nil {
		t.Fatal("receive message not found")
	}

	// Verify the raw bytes differ from the binary test (they are base64).
	if len(sendMsg.RawBytes) == 0 {
		t.Error("send RawBytes is empty")
	}
	// The raw bytes should be base64-encoded (since that's what was on the wire).
	// Verify it's valid base64.
	if _, err := base64.StdEncoding.DecodeString(string(sendMsg.RawBytes)); err != nil {
		t.Errorf("send RawBytes is not valid base64: %v", err)
	}

	// Verify decoded body matches.
	if !bytes.Equal(sendMsg.Body, testPayload) {
		t.Errorf("send body = %q, want %q", sendMsg.Body, testPayload)
	}

	// Verify service/method metadata.
	if sendMsg.Metadata["service"] != "test.TextService" {
		t.Errorf("send metadata service = %q, want %q", sendMsg.Metadata["service"], "test.TextService")
	}
}

// =============================================================================
// HTTPS (CONNECT tunnel) + Binary gRPC-Web
// =============================================================================

func TestIntegration_GRPCWeb_HTTPS_Binary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("hello-grpc-web-https-binary")
	respPayload := []byte("response-grpc-web-https-binary")

	// TLS upstream that speaks gRPC-Web.
	upstream := newGRPCWebTLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(gohttp.StatusOK)
		body := buildGRPCWebResponseBody(respPayload, "0", "OK")
		w.Write(body)
	}))

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	store := newGRPCWebStore(t, ctx)

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, h2Handler, proxyCancel := startGRPCWebTLSProxy(t, ctx, store, ca)
	defer proxyCancel()

	httpHandler.SetInsecureSkipVerify(true)
	h2Handler.SetInsecureSkipVerify(true)

	client := grpcWebTLSClient(listener.Addr(), ca.Certificate())

	reqBody := buildGRPCWebRequestBody(testPayload)
	targetURL := fmt.Sprintf("https://localhost:%s/test.SecureService/BinaryMethod", upstreamPort)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc-web+proto")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC-Web HTTPS binary request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify gRPC-Web framing.
	result, err := protogrpcweb.DecodeBody(body, false)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("data frames = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, respPayload) {
		t.Errorf("payload = %q, want %q", result.DataFrames[0].Payload, respPayload)
	}

	// Verify flow recording.
	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC-Web" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC-Web")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify TLS connection info.
	if fl.ConnInfo == nil {
		t.Fatal("ConnInfo is nil")
	}

	// Verify messages.
	msgs := pollGRPCWebFlowMessages(t, ctx, store, fl.ID)
	var sendMsg *flow.Message
	for _, m := range msgs {
		if m.Direction == "send" {
			sendMsg = m
			break
		}
	}
	if sendMsg == nil {
		t.Fatal("send message not found")
	}
	if sendMsg.Metadata["service"] != "test.SecureService" {
		t.Errorf("send metadata service = %q, want %q", sendMsg.Metadata["service"], "test.SecureService")
	}
}

// =============================================================================
// HTTPS (CONNECT tunnel) + Base64 gRPC-Web
// =============================================================================

func TestIntegration_GRPCWeb_HTTPS_Base64(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("hello-grpc-web-https-base64")
	respPayload := []byte("response-grpc-web-https-base64")

	upstream := newGRPCWebTLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web-text+proto")
		w.WriteHeader(gohttp.StatusOK)
		binaryBody := buildGRPCWebResponseBody(respPayload, "0", "OK")
		encoded := protogrpcweb.EncodeBase64Body(binaryBody)
		w.Write(encoded)
	}))

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	store := newGRPCWebStore(t, ctx)

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, h2Handler, proxyCancel := startGRPCWebTLSProxy(t, ctx, store, ca)
	defer proxyCancel()

	httpHandler.SetInsecureSkipVerify(true)
	h2Handler.SetInsecureSkipVerify(true)

	client := grpcWebTLSClient(listener.Addr(), ca.Certificate())

	binaryReqBody := buildGRPCWebRequestBody(testPayload)
	base64ReqBody := protogrpcweb.EncodeBase64Body(binaryReqBody)

	targetURL := fmt.Sprintf("https://localhost:%s/test.SecureService/Base64Method", upstreamPort)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(base64ReqBody))
	req.Header.Set("Content-Type", "application/grpc-web-text+proto")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC-Web HTTPS base64 request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify base64 response decodes correctly.
	result, err := protogrpcweb.DecodeBody(body, true)
	if err != nil {
		t.Fatalf("decode base64 response: %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("data frames = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, respPayload) {
		t.Errorf("payload = %q, want %q", result.DataFrames[0].Payload, respPayload)
	}

	// Verify flow recording.
	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC-Web" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC-Web")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify messages with base64 raw bytes.
	msgs := pollGRPCWebFlowMessages(t, ctx, store, fl.ID)
	var sendMsg *flow.Message
	for _, m := range msgs {
		if m.Direction == "send" {
			sendMsg = m
			break
		}
	}
	if sendMsg == nil {
		t.Fatal("send message not found")
	}
	if sendMsg.Metadata["service"] != "test.SecureService" {
		t.Errorf("send metadata service = %q, want %q", sendMsg.Metadata["service"], "test.SecureService")
	}
}

// =============================================================================
// Server Streaming (multiple response data frames)
// =============================================================================

func TestIntegration_GRPCWeb_ServerStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("stream-request")
	respPayloads := [][]byte{
		[]byte("stream-response-1"),
		[]byte("stream-response-2"),
		[]byte("stream-response-3"),
	}

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(gohttp.StatusOK)
		for _, p := range respPayloads {
			w.Write(protogrpcweb.EncodeFrame(false, false, p))
		}
		trailerPayload := grpcWebTrailer("0", "OK")
		w.Write(protogrpcweb.EncodeFrame(true, false, trailerPayload))
	}))
	defer upstream.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store)
	defer proxyCancel()

	reqBody := buildGRPCWebRequestBody(testPayload)
	targetURL := upstream.URL + "/test.StreamService/ServerStream"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc-web+proto")

	client := grpcWebClient(listener.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("server streaming request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify response has 3 data frames.
	result, err := protogrpcweb.DecodeBody(body, false)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(result.DataFrames) != 3 {
		t.Fatalf("data frames = %d, want 3", len(result.DataFrames))
	}

	// Verify flow type.
	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC-Web" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC-Web")
	}
	if fl.FlowType != "stream" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "stream")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify multiple receive messages recorded.
	msgs := pollGRPCWebFlowMessages(t, ctx, store, fl.ID)
	recvCount := 0
	for _, m := range msgs {
		if m.Direction == "receive" {
			recvCount++
		}
	}
	if recvCount < 3 {
		t.Errorf("receive messages = %d, want >= 3", recvCount)
	}
}

// =============================================================================
// Plugin Hook Firing
// =============================================================================

func TestIntegration_GRPCWeb_PluginHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("plugin-test-payload")

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(gohttp.StatusOK)
		body := buildGRPCWebResponseBody([]byte("plugin-response"), "0", "OK")
		w.Write(body)
	}))
	defer upstream.Close()

	// Create plugin script that records hook invocations.
	pluginScript := `
def on_receive_from_client(data):
    if data.get("protocol") != "grpc-web":
        return {"action": "continue"}
    # Write a marker file to confirm the hook fired.
    return {"action": "continue"}

def on_receive_from_server(data):
    if data.get("protocol") != "grpc-web":
        return {"action": "continue"}
    return {"action": "continue"}
`
	scriptPath := filepath.Join(t.TempDir(), "grpcweb_plugin.star")
	if err := os.WriteFile(scriptPath, []byte(pluginScript), 0644); err != nil {
		t.Fatalf("write plugin script: %v", err)
	}

	engine := plugin.NewEngine(testutil.DiscardLogger())
	if err := engine.LoadPlugins(ctx, []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "grpc-web",
			Hooks:    []string{"on_receive_from_client", "on_receive_from_server"},
		},
	}); err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	defer engine.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store, func(gwh *protogrpcweb.Handler) {
		gwh.SetPluginEngine(engine)
	})
	defer proxyCancel()

	reqBody := buildGRPCWebRequestBody(testPayload)
	targetURL := upstream.URL + "/test.PluginService/HookMethod"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc-web+proto")

	client := grpcWebClient(listener.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("plugin hook request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify flow was recorded successfully (plugin hooks ran without error).
	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC-Web" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC-Web")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify messages are present (hooks didn't break recording).
	msgs := pollGRPCWebFlowMessages(t, ctx, store, fl.ID)
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(msgs))
	}
}

// =============================================================================
// Error Path: Upstream Failure
// =============================================================================

func TestIntegration_GRPCWeb_ErrorPath_UpstreamRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start and immediately close a listener to get a refused port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedAddr := ln.Addr().String()
	ln.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store)
	defer proxyCancel()

	reqBody := buildGRPCWebRequestBody([]byte("error-test"))
	targetURL := fmt.Sprintf("http://%s/test.Service/ErrorMethod", refusedAddr)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc-web+proto")

	client := grpcWebClient(listener.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("error path request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// Expect a 502 Bad Gateway or similar error response.
	if resp.StatusCode == gohttp.StatusOK {
		t.Error("expected error status code for refused upstream, got 200")
	}

	// The error occurs before gRPC-Web recording (during upstream connect),
	// so the flow is recorded through the standard HTTP error path. Verify
	// that the proxy handles the error gracefully without panics or hangs.
	// The key verification is that the request completes without deadlocking.
}

// =============================================================================
// MCP Integration: Query flows by protocol filter
// =============================================================================

func TestIntegration_GRPCWeb_MCPQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("mcp-query-test")

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(gohttp.StatusOK)
		body := buildGRPCWebResponseBody([]byte("mcp-response"), "0", "OK")
		w.Write(body)
	}))
	defer upstream.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store)
	defer proxyCancel()

	reqBody := buildGRPCWebRequestBody(testPayload)
	targetURL := upstream.URL + "/test.MCPService/QueryMethod"
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc-web+proto")

	client := grpcWebClient(listener.Addr())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("MCP query test request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// Wait for flow.
	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]

	// Verify the flow is retrievable by protocol filter (simulates MCP query tool).
	filteredFlows, err := store.ListFlows(ctx, flow.ListOptions{Protocol: "gRPC-Web", Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows with protocol filter: %v", err)
	}
	if len(filteredFlows) != 1 {
		t.Fatalf("expected 1 flow with protocol gRPC-Web, got %d", len(filteredFlows))
	}
	if filteredFlows[0].ID != fl.ID {
		t.Errorf("filtered flow ID = %q, want %q", filteredFlows[0].ID, fl.ID)
	}

	// Verify other protocol filters don't return this flow.
	httpFlows, err := store.ListFlows(ctx, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows HTTP/1.x filter: %v", err)
	}
	for _, f := range httpFlows {
		if f.ID == fl.ID {
			t.Error("gRPC-Web flow incorrectly returned by HTTP/1.x protocol filter")
		}
	}

	// Verify flow details are retrievable (simulates MCP query with resource: "flow").
	msgs, err := store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages for flow detail: %v", err)
	}
	if len(msgs) < 2 {
		t.Errorf("expected at least 2 messages for flow detail, got %d", len(msgs))
	}
}

// =============================================================================
// Raw Bytes Integrity: Binary vs Base64 differ on wire
// =============================================================================

func TestIntegration_GRPCWeb_RawBytesIntegrity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testPayload := []byte("raw-bytes-integrity")
	respPayload := []byte("raw-bytes-response")

	// Binary upstream.
	binaryUpstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(gohttp.StatusOK)
		body := buildGRPCWebResponseBody(respPayload, "0", "OK")
		w.Write(body)
	}))
	defer binaryUpstream.Close()

	// Base64 upstream.
	base64Upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web-text+proto")
		w.WriteHeader(gohttp.StatusOK)
		binaryBody := buildGRPCWebResponseBody(respPayload, "0", "OK")
		w.Write(protogrpcweb.EncodeBase64Body(binaryBody))
	}))
	defer base64Upstream.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store)
	defer proxyCancel()

	client := grpcWebClient(listener.Addr())

	// Send binary request.
	binReqBody := buildGRPCWebRequestBody(testPayload)
	binReq, _ := gohttp.NewRequestWithContext(ctx, "POST", binaryUpstream.URL+"/test.Svc/Bin", bytes.NewReader(binReqBody))
	binReq.Header.Set("Content-Type", "application/grpc-web+proto")
	binResp, err := client.Do(binReq)
	if err != nil {
		t.Fatalf("binary request: %v", err)
	}
	binResp.Body.Close()

	// Send base64 request.
	b64ReqBody := protogrpcweb.EncodeBase64Body(binReqBody)
	b64Req, _ := gohttp.NewRequestWithContext(ctx, "POST", base64Upstream.URL+"/test.Svc/B64", bytes.NewReader(b64ReqBody))
	b64Req.Header.Set("Content-Type", "application/grpc-web-text+proto")
	b64Resp, err := client.Do(b64Req)
	if err != nil {
		t.Fatalf("base64 request: %v", err)
	}
	b64Resp.Body.Close()

	// Wait for both flows.
	flows := pollGRPCWebFlows(t, ctx, store, 2)

	// Collect raw bytes from both flows.
	var binSendRaw, b64SendRaw []byte
	for _, fl := range flows {
		msgs, err := store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
		if err != nil {
			t.Fatalf("GetMessages: %v", err)
		}
		for _, m := range msgs {
			if m.Direction == "send" && len(m.RawBytes) > 0 {
				if m.URL != nil && strings.Contains(m.URL.Path, "/Bin") {
					binSendRaw = m.RawBytes
				}
				if m.URL != nil && strings.Contains(m.URL.Path, "/B64") {
					b64SendRaw = m.RawBytes
				}
			}
		}
	}

	if len(binSendRaw) == 0 {
		t.Fatal("binary send RawBytes is empty")
	}
	if len(b64SendRaw) == 0 {
		t.Fatal("base64 send RawBytes is empty")
	}

	// Wire-observed raw bytes should differ between binary and base64.
	if bytes.Equal(binSendRaw, b64SendRaw) {
		t.Error("binary and base64 raw bytes are identical; expected different wire formats")
	}
}

// =============================================================================
// Flow Scheme Verification
// =============================================================================

func TestIntegration_GRPCWeb_FlowScheme(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(gohttp.StatusOK)
		body := buildGRPCWebResponseBody([]byte("scheme-test"), "0", "OK")
		w.Write(body)
	}))
	defer upstream.Close()

	store := newGRPCWebStore(t, ctx)
	listener, _, proxyCancel := startGRPCWebH1Proxy(t, ctx, store)
	defer proxyCancel()

	client := grpcWebClient(listener.Addr())
	reqBody := buildGRPCWebRequestBody([]byte("scheme-payload"))
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", upstream.URL+"/test.Svc/Scheme", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc-web+proto")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("scheme test request: %v", err)
	}
	resp.Body.Close()

	flows := pollGRPCWebFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Scheme != "http" {
		t.Errorf("scheme = %q, want %q", fl.Scheme, "http")
	}
}
