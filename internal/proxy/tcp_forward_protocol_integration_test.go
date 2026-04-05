//go:build e2e

package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	prototcp "github.com/usk6666/yorishiro-proxy/internal/protocol/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- Helpers for TCP forward protocol integration tests ---

// tcpForwardTestEnv holds a complete test environment for TCP forward integration tests.
type tcpForwardTestEnv struct {
	store    flow.Store
	listener *proxy.TCPForwardListener
	cancel   context.CancelFunc
	ctx      context.Context
}

// startTCPForwardEnv creates a TCPForwardListener with the given config and full protocol detection.
// The detector includes HTTP/2 and HTTP/1.x handlers; TCP is the fallback handler (not in detector).
func startTCPForwardEnv(t *testing.T, ctx context.Context, fwdConfig *config.ForwardConfig, issuer *cert.Issuer) *tcpForwardTestEnv {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	httpHandler := protohttp.NewHandler(store, nil, logger)
	h2Handler := protohttp2.NewHandler(store, logger)
	tcpHandler := prototcp.NewHandler(store, nil, logger)

	// Priority: HTTP/2 > HTTP/1.x; TCP is the fallback handler.
	detector := protocol.NewDetector(h2Handler, httpHandler)

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:        "127.0.0.1:0",
		Handler:     tcpHandler,
		Detector:    detector,
		Config:      fwdConfig,
		Issuer:      issuer,
		Logger:      logger,
		PeekTimeout: 5 * time.Second,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		if err := fl.Start(proxyCtx); err != nil {
			t.Logf("tcp forward listener error: %v", err)
		}
	}()

	select {
	case <-fl.Ready():
	case <-time.After(3 * time.Second):
		proxyCancel()
		t.Fatal("tcp forward listener did not become ready")
	}

	return &tcpForwardTestEnv{
		store:    store,
		listener: fl,
		cancel:   proxyCancel,
		ctx:      proxyCtx,
	}
}

// waitForFlows polls the store until at least minCount flows are recorded or timeout.
func waitForFlows(t *testing.T, ctx context.Context, store flow.Store, opts flow.StreamListOptions, minCount int) []*flow.Stream {
	t.Helper()
	var flows []*flow.Stream
	var err error
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListStreams(ctx, opts)
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= minCount {
			return flows
		}
	}
	t.Fatalf("expected at least %d flows, got %d", minCount, len(flows))
	return nil
}

// waitForFlowState polls until a flow reaches the expected state.
func waitForFlowState(t *testing.T, ctx context.Context, store flow.Store, opts flow.StreamListOptions, state string) *flow.Stream {
	t.Helper()
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err := store.ListStreams(ctx, opts)
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		for _, f := range flows {
			if f.State == state {
				return f
			}
		}
	}
	t.Fatalf("no flow reached state %q within timeout", state)
	return nil
}

// --- Test: HTTP/1.x over TCP forward (protocol: "auto") ---

func TestTCPForward_HTTP1x_Auto(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Start upstream HTTP server.
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from http upstream")
	})}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "auto",
	}, nil)
	defer env.cancel()

	// Create HTTP/1.1 client that connects to the TCP forward listener.
	proxyAddr := env.listener.Addr()
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/test-http1", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through TCP forward: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 1. Communication success.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from http upstream" {
		t.Errorf("body = %q, want %q", body, "hello from http upstream")
	}

	// 2. Flow recording: Protocol, State.
	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")
	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want HTTP/1.x", fl.Protocol)
	}

	// 3. Message content: headers and body.
	msgs, err := env.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
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
	if send.Method != "GET" {
		t.Errorf("method = %q, want GET", send.Method)
	}
	if recv.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", recv.StatusCode)
	}
	if string(recv.Body) != "hello from http upstream" {
		t.Errorf("response body = %q, want %q", recv.Body, "hello from http upstream")
	}

	// 4. Raw bytes recorded (L4-capable principle).
	if len(send.RawBytes) == 0 {
		t.Error("send message RawBytes should not be empty")
	}
	if len(recv.RawBytes) == 0 {
		t.Error("receive message RawBytes should not be empty")
	}
}

// --- Test: HTTP/1.x over TCP forward (protocol: "http" — fixed dispatch) ---

func TestTCPForward_HTTP1x_Fixed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "fixed-http")
	})}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "http",
	}, nil)
	defer env.cancel()

	proxyAddr := env.listener.Addr()
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/fixed-http", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through TCP forward (fixed http): %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "fixed-http" {
		t.Errorf("body = %q, want %q", body, "fixed-http")
	}

	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")
	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want HTTP/1.x", fl.Protocol)
	}
}

// --- Test: h2c over TCP forward (protocol: "auto") ---

func TestTCPForward_H2C_Auto(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Start h2c upstream server.
	upstreamAddr, closeUpstream := startH2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from h2c upstream")
	}))
	defer closeUpstream()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "auto",
	}, nil)
	defer env.cancel()

	// Create h2c client.
	proxyAddr := env.listener.Addr()
	h2cProtos := &gohttp.Protocols{}
	h2cProtos.SetUnencryptedHTTP2(true)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Protocols: h2cProtos,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/test-h2c-forward", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET through TCP forward: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 1. Communication success.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "hello from h2c upstream" {
		t.Errorf("body = %q, want %q", body, "hello from h2c upstream")
	}

	// 2. Flow recording — HTTP/2 protocol detected.
	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")
	if !strings.Contains(fl.Protocol, "HTTP/2") {
		t.Errorf("protocol = %q, want to contain HTTP/2", fl.Protocol)
	}

	// 3. Message content.
	msgs, err := env.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
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
	if send.Method != "GET" {
		t.Errorf("method = %q, want GET", send.Method)
	}
	if recv.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", recv.StatusCode)
	}

	// 4. Raw bytes recorded (HTTP/2 frame-level).
	if len(send.RawBytes) == 0 {
		t.Error("send message RawBytes should not be empty")
	}
}

// --- Test: h2c over TCP forward (protocol: "http2" — fixed dispatch) ---

func TestTCPForward_H2C_Fixed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startH2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "fixed-h2c")
	}))
	defer closeUpstream()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "http2",
	}, nil)
	defer env.cancel()

	proxyAddr := env.listener.Addr()
	h2cProtos := &gohttp.Protocols{}
	h2cProtos.SetUnencryptedHTTP2(true)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Protocols: h2cProtos,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/fixed-h2c", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET through TCP forward (fixed http2): %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "fixed-h2c" {
		t.Errorf("body = %q, want %q", body, "fixed-h2c")
	}

	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")
	if !strings.Contains(fl.Protocol, "HTTP/2") {
		t.Errorf("protocol = %q, want to contain HTTP/2", fl.Protocol)
	}
}

// --- Test: h2c POST over TCP forward (message body verification) ---

func TestTCPForward_H2C_POST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startH2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "echo: %s", body)
	}))
	defer closeUpstream()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "auto",
	}, nil)
	defer env.cancel()

	proxyAddr := env.listener.Addr()
	h2cProtos := &gohttp.Protocols{}
	h2cProtos.SetUnencryptedHTTP2(true)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Protocols: h2cProtos,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/test-post-forward", upstreamAddr)
	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("h2c forward body"))
	if err != nil {
		t.Fatalf("h2c POST through TCP forward: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "echo: h2c forward body" {
		t.Errorf("body = %q, want %q", body, "echo: h2c forward body")
	}

	// Verify flow recording with message content.
	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")
	msgs, err := env.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}

	var send *flow.Flow
	for _, m := range msgs {
		if m.Direction == "send" {
			send = m
			break
		}
	}
	if send == nil {
		t.Fatal("send message not found")
	}
	if send.Method != "POST" {
		t.Errorf("method = %q, want POST", send.Method)
	}
}

// --- Test: protocol: "raw" backward compatibility ---
//
// The TCP handler resolves the upstream from its internal forwards map (keyed by
// local port), so we must configure the mapping after the listener starts and
// its port is known.

func TestTCPForward_Raw_BackwardCompat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start TCP echo upstream.
	upstreamAddr, closeUpstream := startTCPEchoServer(t)
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	tcpHandler := prototcp.NewHandler(store, nil, logger)

	fl := proxy.NewTCPForwardListener(proxy.TCPForwardListenerConfig{
		Addr:    "127.0.0.1:0",
		Handler: tcpHandler,
		Config: &config.ForwardConfig{
			Target:   upstreamAddr,
			Protocol: "raw",
		},
		Logger:      logger,
		PeekTimeout: 5 * time.Second,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	go func() {
		if err := fl.Start(proxyCtx); err != nil {
			t.Logf("listener error: %v", err)
		}
	}()

	select {
	case <-fl.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("listener not ready")
	}

	// Configure the TCP handler's forwards map with the listener port.
	_, proxyPort, _ := net.SplitHostPort(fl.Addr())
	tcpHandler.SetForwards(map[string]*config.ForwardConfig{
		proxyPort: {Target: upstreamAddr, Protocol: "raw"},
	})

	// Connect with non-HTTP binary data.
	conn, err := net.DialTimeout("tcp", fl.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	testData := []byte{
		0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10,
	}
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	// 1. Communication success.
	for i, b := range testData {
		if buf[i] != b {
			t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i, buf[i], b)
		}
	}

	// 2. Flow recording.
	conn.Close()
	flows := waitForFlows(t, ctx, store, flow.StreamListOptions{Protocol: "TCP", Limit: 10}, 1)
	flo := flows[0]
	if flo.Protocol != "TCP" {
		t.Errorf("protocol = %q, want TCP", flo.Protocol)
	}

	// 3. Raw bytes recorded.
	msgs, err := store.GetFlows(ctx, flo.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("no messages recorded for raw TCP flow")
	}
	foundRaw := false
	for _, m := range msgs {
		if len(m.RawBytes) > 0 {
			foundRaw = true
			break
		}
	}
	if !foundRaw {
		t.Error("expected at least one message with RawBytes for raw TCP flow")
	}
}

// --- Test: protocol: "auto" detects different protocols ---

func TestTCPForward_Auto_DetectsHTTP1AndH2C(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// Start h2c-capable upstream that also supports HTTP/1.x.
	upstreamAddr, closeUpstream := startH2CUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "proto=%s", r.Proto)
	}))
	defer closeUpstream()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "auto",
	}, nil)
	defer env.cancel()

	proxyAddr := env.listener.Addr()

	// 1. Send h2c request.
	h2cProtos := &gohttp.Protocols{}
	h2cProtos.SetUnencryptedHTTP2(true)
	h2cClient := &gohttp.Client{
		Transport: &gohttp.Transport{
			Protocols: h2cProtos,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/h2c-test", upstreamAddr)
	resp, err := h2cClient.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	resp.Body.Close()

	// 2. Send HTTP/1.1 request.
	http1Client := &gohttp.Client{
		Transport: &gohttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL2 := fmt.Sprintf("http://%s/http1-test", upstreamAddr)
	resp2, err := http1Client.Get(targetURL2)
	if err != nil {
		t.Fatalf("HTTP/1.1 GET: %v", err)
	}
	resp2.Body.Close()

	// Wait for both flows to be recorded.
	flows := waitForFlows(t, ctx, env.store, flow.StreamListOptions{Limit: 20}, 2)

	// Verify that both protocols were detected.
	protocolSet := make(map[string]bool)
	for _, f := range flows {
		protocolSet[f.Protocol] = true
	}

	if !protocolSet["HTTP/2"] {
		t.Error("expected HTTP/2 flow from h2c request")
	}
	if !protocolSet["HTTP/1.x"] {
		t.Error("expected HTTP/1.x flow from HTTP/1.1 request")
	}
}

// --- Test: TLS MITM over TCP forward ---

func TestTCPForward_TLSMITM_HTTP1x(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Start a plain HTTP upstream (TCP forward terminates TLS, forwards cleartext).
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "tls-mitm-response")
	})}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	// Create CA and issuer for TLS MITM.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "auto",
		TLS:      true,
	}, issuer)
	defer env.cancel()

	// Create a TLS client that trusts the test CA.
	caCert, _ := ca.SigningPair()
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	proxyAddr := env.listener.Addr()
	host, _, _ := net.SplitHostPort(upstreamAddr)
	if host == "" {
		host = "127.0.0.1"
	}

	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host,
				RootCAs:    certPool,
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("https://%s/tls-test", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTPS GET through TLS MITM TCP forward: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 1. Communication success.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "tls-mitm-response" {
		t.Errorf("body = %q, want %q", body, "tls-mitm-response")
	}

	// 2. TLS termination happened — MITM certificate issued.
	if resp.TLS == nil {
		t.Fatal("expected TLS connection state")
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificates from MITM")
	}

	// 3. Flow recording.
	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")
	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("protocol = %q, want HTTP/1.x", fl.Protocol)
	}
}

// --- Test: Error path — upstream connection failure ---

func TestTCPForward_ErrorPath_UpstreamFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Reserve an unused port, then close the listener to get a "connection refused" target.
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachableAddr := tmpLn.Addr().String()
	tmpLn.Close()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   unreachableAddr,
		Protocol: "raw",
	}, nil)
	defer env.cancel()

	// Connect and send data — the proxy should fail to reach upstream.
	conn, err := net.DialTimeout("tcp", env.listener.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send 16+ bytes to pass the peek requirement.
	testData := []byte("0123456789abcdef")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read should return EOF or error because upstream is unreachable.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 100)
	_, readErr := conn.Read(buf)
	conn.Close()

	if readErr == nil {
		t.Error("expected read error or EOF when upstream is unreachable")
	}

	// Flow should be recorded — check for either error state or at least recording.
	time.Sleep(500 * time.Millisecond)
	flows, err := env.store.ListStreams(ctx, flow.StreamListOptions{Protocol: "TCP", Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	for _, f := range flows {
		if f.State == "error" {
			return // error state recorded as expected
		}
	}
	// Some handlers may not record flows on immediate upstream failure.
	t.Errorf("no error-state flow found (got %d TCP flows); expected error state on upstream failure", len(flows))
}

// --- Test: State transition active -> complete ---

func TestTCPForward_StateTransition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "ok")
	})}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "auto",
	}, nil)
	defer env.cancel()

	proxyAddr := env.listener.Addr()
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/state-test", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	// Flow should reach "complete" state.
	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")
	if fl.State != "complete" {
		t.Errorf("state = %q, want complete", fl.State)
	}
	if fl.Duration == 0 {
		t.Error("flow duration should be non-zero")
	}
}

// --- Test: HTTP/1.x POST through TCP forward (body and raw bytes) ---

func TestTCPForward_HTTP1x_POST_BodyAndRawBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "got: %s", body)
	})}
	go upstream.Serve(upstreamListener)
	defer upstream.Close()

	upstreamAddr := upstreamListener.Addr().String()

	env := startTCPForwardEnv(t, ctx, &config.ForwardConfig{
		Target:   upstreamAddr,
		Protocol: "auto",
	}, nil)
	defer env.cancel()

	proxyAddr := env.listener.Addr()
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	targetURL := fmt.Sprintf("http://%s/post-raw", upstreamAddr)
	resp, err := client.Post(targetURL, "application/json", strings.NewReader(`{"key":"value"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `got: {"key":"value"}` {
		t.Errorf("body = %q", body)
	}

	fl := waitForFlowState(t, ctx, env.store, flow.StreamListOptions{Limit: 10}, "complete")

	msgs, err := env.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}

	for _, m := range msgs {
		if m.Direction == "send" {
			if m.Method != "POST" {
				t.Errorf("method = %q, want POST", m.Method)
			}
			// Raw bytes should contain the HTTP request line.
			if len(m.RawBytes) == 0 {
				t.Error("send RawBytes should not be empty")
			} else if !strings.Contains(string(m.RawBytes), "POST") {
				t.Error("send RawBytes should contain POST request line")
			}
		}
		if m.Direction == "receive" {
			if m.StatusCode != 200 {
				t.Errorf("status = %d, want 200", m.StatusCode)
			}
			if len(m.RawBytes) == 0 {
				t.Error("receive RawBytes should not be empty")
			}
		}
	}
}
