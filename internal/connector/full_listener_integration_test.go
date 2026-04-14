//go:build e2e

package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// ---------------------------------------------------------------------------
// Test infrastructure (duplicated from layer/http1 — different package)
// ---------------------------------------------------------------------------

// testStore implements flow.Writer for capturing recorded streams and flows.
type testStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
}

func (s *testStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *testStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}

func (s *testStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, f)
	return nil
}

func (s *testStore) getStreams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

func (s *testStore) flowsByDirection(dir string) []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*flow.Flow
	for _, f := range s.flows {
		if f.Direction == dir {
			out = append(out, f)
		}
	}
	return out
}

func (s *testStore) allFlows() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

// newTestTLSConfig creates a self-signed TLS config for a test server.
func newTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-upstream"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test-upstream"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}
}

// readHTTPRequest reads a complete HTTP/1.x request from a bufio.Reader.
func readHTTPRequest(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	headerBytes := buf.Bytes()

	contentLength := 0
	clFound := false
	for _, line := range bytes.Split(headerBytes, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("content-length:")) {
			if !clFound {
				val := strings.TrimSpace(string(line[len("content-length:"):]))
				n, err := strconv.Atoi(val)
				if err == nil {
					contentLength = n
					clFound = true
				}
			}
		}
	}

	if contentLength > 0 {
		body := make([]byte, contentLength)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
		buf.Write(body)
	}

	return buf.Bytes(), nil
}

// startUpstreamHTTPS starts a raw TLS server that reads HTTP requests and
// sends responses via the handler function. Returns the listener and a
// function that returns all captured request byte slices.
func startUpstreamHTTPS(
	t *testing.T,
	handler func(reqBytes []byte) []byte,
) (net.Listener, func() [][]byte) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newTestTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	captured := make(chan [][]byte, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		var allReqs [][]byte

		for {
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			reqBytes, err := readHTTPRequest(br)
			if err != nil {
				break
			}
			reqCopy := make([]byte, len(reqBytes))
			copy(reqCopy, reqBytes)
			allReqs = append(allReqs, reqCopy)

			resp := handler(reqBytes)
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(resp); err != nil {
				break
			}

			if bytes.Contains(bytes.ToLower(resp), []byte("connection: close")) {
				break
			}
		}

		captured <- allReqs
	}()

	return ln, func() [][]byte {
		select {
		case b := <-captured:
			return b
		case <-time.After(15 * time.Second):
			t.Fatal("timeout waiting for upstream captured bytes")
			return nil
		}
	}
}

// connectThroughProxy connects to the proxy, sends CONNECT for the given
// target, reads the 200 response, and performs a TLS handshake.
func connectThroughProxy(t *testing.T, proxyAddr, target string) *tls.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		conn.Close()
		t.Fatalf("unexpected CONNECT response: %q", got)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("TLS handshake through proxy: %v", err)
	}

	return tlsConn
}

// connectAndSendHTTP performs CONNECT, TLS handshake, sends a raw HTTP
// request, reads the response, and returns the response string.
func connectAndSendHTTP(t *testing.T, proxyAddr, target, rawRequest string) string {
	t.Helper()
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	return readHTTPResponse(t, tlsConn)
}

// readHTTPResponse reads a complete HTTP response from a connection.
func readHTTPResponse(t *testing.T, conn net.Conn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var respBuf bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			respBuf.Write(buf[:n])
		}
		if err != nil {
			break
		}
		resp := respBuf.String()
		if idx := strings.Index(resp, "\r\n\r\n"); idx >= 0 {
			headerPart := resp[:idx]
			bodyStart := idx + 4
			cl := 0
			for _, line := range strings.Split(headerPart, "\r\n") {
				if strings.HasPrefix(strings.ToLower(line), "content-length:") {
					val := strings.TrimSpace(line[len("content-length:"):])
					cl, _ = strconv.Atoi(val)
				}
			}
			if len(resp)-bodyStart >= cl {
				break
			}
		}
	}
	return respBuf.String()
}

// socks5ConnectThroughProxy sends the SOCKS5 handshake + CONNECT, then
// performs a TLS handshake. Returns the TLS connection ready for HTTP.
func socks5ConnectThroughProxy(t *testing.T, proxyAddr, target string) *tls.Conn {
	t.Helper()

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	// Version greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH(0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}

	// Read method selection: VER=5, METHOD
	methodResp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, methodResp); err != nil {
		conn.Close()
		t.Fatalf("read SOCKS5 method selection: %v", err)
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		conn.Close()
		t.Fatalf("unexpected SOCKS5 method selection: %x", methodResp)
	}

	// CONNECT command: VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAIN(3), LEN, HOST, PORT
	connectReq := make([]byte, 0, 7+len(host))
	connectReq = append(connectReq, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	connectReq = append(connectReq, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	connectReq = append(connectReq, portBytes...)

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		t.Fatalf("write SOCKS5 CONNECT: %v", err)
	}

	// Read reply: at least 10 bytes for IPv4 BND.ADDR.
	// VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4 for IPv4) + BND.PORT(2) = 10
	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		t.Fatalf("read SOCKS5 reply: %v", err)
	}
	if reply[0] != 0x05 {
		conn.Close()
		t.Fatalf("SOCKS5 reply VER = %x, want 0x05", reply[0])
	}
	if reply[1] != 0x00 {
		conn.Close()
		t.Fatalf("SOCKS5 reply REP = %x, want 0x00 (success)", reply[1])
	}

	// Reset deadline before TLS handshake.
	conn.SetReadDeadline(time.Time{})

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("TLS handshake through SOCKS5 proxy: %v", err)
	}

	return tlsConn
}

// socks5ConnectAndSendHTTP is a full roundtrip helper via SOCKS5.
func socks5ConnectAndSendHTTP(t *testing.T, proxyAddr, target, rawRequest string) string {
	t.Helper()
	tlsConn := socks5ConnectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request via SOCKS5: %v", err)
	}

	return readHTTPResponse(t, tlsConn)
}

// startFullListenerProxy starts a FullListener with CONNECT + SOCKS5 handlers.
// Returns the proxy address, testStore, and a WaitGroup that signals session
// completion (caller must wg.Add(1) before sending each request, OnStack
// calls wg.Done when the session completes).
func startFullListenerProxy(
	t *testing.T,
	ctx context.Context,
	opts fullListenerOpts,
) (proxyAddr string, store *testStore, wg *sync.WaitGroup) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store = &testStore{}
	wg = &sync.WaitGroup{}

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        opts.proxyConfig,
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}
	if buildCfg.ProxyConfig == nil {
		buildCfg.ProxyConfig = &config.ProxyConfig{}
	}
	if opts.upstreamProxy != nil {
		buildCfg.UpstreamProxy = opts.upstreamProxy
	}

	connectNeg := connector.NewCONNECTNegotiator(slog.Default())
	socks5Neg := connector.NewSOCKS5Negotiator(slog.Default())

	if opts.scope != nil {
		socks5Neg.Scope = opts.scope
	}
	if opts.rateLimiter != nil {
		socks5Neg.RateLimiter = opts.rateLimiter
	}

	onStack := func(ctx context.Context, stack *connector.ConnectionStack, snap *envelope.TLSSnapshot, target string) {
		defer wg.Done()
		defer stack.Close()

		clientCh := <-stack.ClientTopmost().Channels()

		steps := []pipeline.Step{
			pipeline.NewHostScopeStep(nil),
			pipeline.NewRecordStep(store, slog.Default()),
		}
		p := pipeline.New(steps...)

		session.RunSession(ctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return <-stack.UpstreamTopmost().Channels(), nil
		}, p)
	}

	// Override onStack if caller wants to block it (for scope/ratelimit tests).
	if opts.onStack != nil {
		onStack = opts.onStack
	}

	flCfg := connector.FullListenerConfig{
		Name: "test",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator:      connectNeg,
			BuildCfg:        buildCfg,
			Scope:           opts.scope,
			RateLimiter:     opts.rateLimiter,
			PassthroughList: opts.passthroughList,
			OnStack:         onStack,
		}),
		OnSOCKS5: connector.NewSOCKS5Handler(connector.SOCKS5HandlerConfig{
			Negotiator:      socks5Neg,
			BuildCfg:        buildCfg,
			PassthroughList: opts.passthroughList,
			OnStack:         onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener to be ready")
	}

	t.Cleanup(func() {
		// Context cancellation stops the listener.
	})

	return fl.Addr(), store, wg
}

// fullListenerOpts holds optional configuration for startFullListenerProxy.
type fullListenerOpts struct {
	proxyConfig     *config.ProxyConfig
	scope           *connector.TargetScope
	rateLimiter     *connector.RateLimiter
	passthroughList *connector.PassthroughList
	upstreamProxy   *url.URL
	onStack         connector.OnStackFunc
}

// waitSessionDone waits for the WaitGroup with a timeout.
func waitSessionDone(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}
}

// startMockHTTPConnectProxy starts a simple HTTP CONNECT proxy that accepts
// one connection, reads the CONNECT request, sends 200, and relays bytes
// bidirectionally to the target. Returns the proxy address.
func startMockHTTPConnectProxy(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		clientConn, err := ln.Accept()
		if err != nil {
			return
		}
		defer clientConn.Close()

		clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

		// Read the CONNECT request.
		br := bufio.NewReader(clientConn)
		var reqBuf bytes.Buffer
		for {
			line, err := br.ReadBytes('\n')
			if err != nil {
				return
			}
			reqBuf.Write(line)
			if bytes.Equal(line, []byte("\r\n")) {
				break
			}
		}

		// Parse the target from CONNECT request line.
		reqLine := strings.SplitN(reqBuf.String(), "\r\n", 2)[0]
		parts := strings.Fields(reqLine)
		if len(parts) < 2 || !strings.EqualFold(parts[0], "CONNECT") {
			return
		}
		target := parts[1]

		// Dial the real target.
		upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()

		// Send 200 to client.
		clientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}

		// Reset deadlines for relay.
		clientConn.SetReadDeadline(time.Time{})
		clientConn.SetWriteDeadline(time.Time{})

		// Bidirectional relay.
		var relayWg sync.WaitGroup
		relayWg.Add(2)
		go func() {
			defer relayWg.Done()
			io.Copy(upstream, br) //nolint:errcheck // relay
		}()
		go func() {
			defer relayWg.Done()
			io.Copy(clientConn, upstream) //nolint:errcheck // relay
		}()
		relayWg.Wait()
	}()

	return ln.Addr().String()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestFullListener_CONNECT_HTTPS_MITM verifies the simplest positive path:
// CONNECT -> HTTPS MITM roundtrip through FullListener.
func TestFullListener_CONNECT_HTTPS_MITM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{})

	wg.Add(1)
	rawReq := fmt.Sprintf("GET /hello HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendHTTP(t, proxyAddr, target, rawReq)

	upstreamReqs := getUpstreamReqs()
	waitSessionDone(t, wg)

	// --- Verify response ---
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	if !strings.HasSuffix(resp, "hello") {
		t.Errorf("response body not 'hello': %q", resp)
	}

	// --- Verify upstream received request ---
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	if !bytes.Contains(upstreamReqs[0], []byte("GET /hello HTTP/1.1")) {
		t.Errorf("upstream did not receive GET /hello: %q", upstreamReqs[0])
	}

	// --- Verify stream recording ---
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "http" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "http")
	}

	// --- Verify flow recording ---
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow, got 0")
	}
	recvFlows := store.flowsByDirection("receive")
	if len(recvFlows) < 1 {
		t.Fatal("expected at least 1 receive flow, got 0")
	}

	// --- Verify RawBytes ---
	if len(sendFlows[0].RawBytes) == 0 {
		t.Error("send flow RawBytes is empty")
	}
	if len(recvFlows[0].RawBytes) == 0 {
		t.Error("receive flow RawBytes is empty")
	}
}

// TestFullListener_SOCKS5_HTTPS_MITM verifies SOCKS5 -> HTTPS MITM roundtrip.
func TestFullListener_SOCKS5_HTTPS_MITM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nsocks5!")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{})

	wg.Add(1)
	rawReq := fmt.Sprintf("GET /socks5 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := socks5ConnectAndSendHTTP(t, proxyAddr, target, rawReq)

	upstreamReqs := getUpstreamReqs()
	waitSessionDone(t, wg)

	// --- Verify response ---
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	if !strings.HasSuffix(resp, "socks5!") {
		t.Errorf("response body not 'socks5!': %q", resp)
	}

	// --- Verify upstream received request ---
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	if !bytes.Contains(upstreamReqs[0], []byte("GET /socks5 HTTP/1.1")) {
		t.Errorf("upstream did not receive GET /socks5: %q", upstreamReqs[0])
	}

	// --- Verify stream recording ---
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "http" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "http")
	}

	// --- Verify flow recording ---
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow, got 0")
	}
	recvFlows := store.flowsByDirection("receive")
	if len(recvFlows) < 1 {
		t.Fatal("expected at least 1 receive flow, got 0")
	}

	// --- Verify RawBytes ---
	if len(sendFlows[0].RawBytes) == 0 {
		t.Error("send flow RawBytes is empty")
	}
	if len(recvFlows[0].RawBytes) == 0 {
		t.Error("receive flow RawBytes is empty")
	}
}

// TestCoordinator_MultipleListeners starts two listeners via Coordinator and
// verifies CONNECT through one and SOCKS5 through the other both succeed.
func TestCoordinator_MultipleListeners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn1, getReqs1 := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncoord-c!")
	})
	defer upstreamLn1.Close()
	target1 := upstreamLn1.Addr().String()

	upstreamLn2, getReqs2 := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncoord-s!")
	})
	defer upstreamLn2.Close()
	target2 := upstreamLn2.Addr().String()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store := &testStore{}
	var wg sync.WaitGroup

	connectNeg := connector.NewCONNECTNegotiator(slog.Default())
	socks5Neg := connector.NewSOCKS5Negotiator(slog.Default())

	coord := connector.NewCoordinator(connector.CoordinatorConfig{
		CONNECTNegotiator: connectNeg,
		SOCKS5Negotiator:  socks5Neg,
		BuildCfg: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             issuer,
			InsecureSkipVerify: true,
		},
		OnStack: func(ctx context.Context, stack *connector.ConnectionStack, snap *envelope.TLSSnapshot, target string) {
			defer wg.Done()
			defer stack.Close()

			clientCh := <-stack.ClientTopmost().Channels()

			steps := []pipeline.Step{
				pipeline.NewHostScopeStep(nil),
				pipeline.NewRecordStep(store, slog.Default()),
			}
			p := pipeline.New(steps...)

			session.RunSession(ctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				return <-stack.UpstreamTopmost().Channels(), nil
			}, p)
		},
	})

	if err := coord.StartNamed(ctx, "listener-a", "127.0.0.1:0"); err != nil {
		t.Fatalf("start listener-a: %v", err)
	}
	if err := coord.StartNamed(ctx, "listener-b", "127.0.0.1:0"); err != nil {
		t.Fatalf("start listener-b: %v", err)
	}
	t.Cleanup(func() { coord.StopAll(context.Background()) })

	statuses := coord.ListenerStatuses()
	if len(statuses) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(statuses))
	}

	// Find addresses by name.
	addrByName := make(map[string]string)
	for _, s := range statuses {
		addrByName[s.Name] = s.ListenAddr
	}

	// Send CONNECT through listener-a.
	wg.Add(1)
	rawReq1 := fmt.Sprintf("GET /coord-c HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target1)
	resp1 := connectAndSendHTTP(t, addrByName["listener-a"], target1, rawReq1)

	reqs1 := getReqs1()
	waitSessionDone(t, &wg)

	if !strings.Contains(resp1, "coord-c!") {
		t.Errorf("CONNECT response body not 'coord-c!': %q", resp1)
	}
	if len(reqs1) < 1 {
		t.Fatal("upstream-a received no requests")
	}

	// Send SOCKS5 through listener-b.
	wg.Add(1)
	rawReq2 := fmt.Sprintf("GET /coord-s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target2)
	resp2 := socks5ConnectAndSendHTTP(t, addrByName["listener-b"], target2, rawReq2)

	reqs2 := getReqs2()
	waitSessionDone(t, &wg)

	if !strings.Contains(resp2, "coord-s!") {
		t.Errorf("SOCKS5 response body not 'coord-s!': %q", resp2)
	}
	if len(reqs2) < 1 {
		t.Fatal("upstream-b received no requests")
	}
}

// TestFullListener_TargetScope_Blocking verifies both CONNECT and SOCKS5 are
// blocked when the target matches a scope deny rule.
func TestFullListener_TargetScope_Blocking(t *testing.T) {
	t.Run("CONNECT", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		scope := connector.NewTargetScope()
		scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}})

		// Track if OnStack was called.
		onStackCalled := make(chan struct{}, 1)

		proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{
			scope: scope,
			onStack: func(_ context.Context, stack *connector.ConnectionStack, _ *envelope.TLSSnapshot, _ string) {
				defer stack.Close()
				onStackCalled <- struct{}{}
			},
		})

		// Try to CONNECT to a blocked target (127.0.0.1:9999).
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()

		connectReq := "CONNECT 127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n"
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			t.Fatalf("write CONNECT: %v", err)
		}

		// Read the CONNECT 200 response (CONNECT negotiation succeeds, then scope blocks).
		buf := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		conn.Read(buf) //nolint:errcheck // we just need to wait

		// Give the handler time to process.
		select {
		case <-onStackCalled:
			t.Error("OnStack was called, but scope should have blocked the target")
		case <-time.After(2 * time.Second):
			// Expected: OnStack was NOT called.
		}
	})

	t.Run("SOCKS5", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		scope := connector.NewTargetScope()
		scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}})

		onStackCalled := make(chan struct{}, 1)

		proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{
			scope: scope,
			onStack: func(_ context.Context, stack *connector.ConnectionStack, _ *envelope.TLSSnapshot, _ string) {
				defer stack.Close()
				onStackCalled <- struct{}{}
			},
		})

		// SOCKS5 handshake to a blocked target.
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()

		// Version greeting.
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write SOCKS5 greeting: %v", err)
		}

		methodResp := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, methodResp); err != nil {
			t.Fatalf("read SOCKS5 method selection: %v", err)
		}

		// CONNECT to blocked host.
		host := "127.0.0.1"
		connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		connectReq = append(connectReq, []byte(host)...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, 9999)
		connectReq = append(connectReq, portBytes...)

		if _, err := conn.Write(connectReq); err != nil {
			t.Fatalf("write SOCKS5 CONNECT: %v", err)
		}

		// Read reply — REP should indicate failure (0x02 = connection not allowed).
		reply := make([]byte, 10)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		io.ReadFull(conn, reply) //nolint:errcheck // may fail if conn closes

		if reply[1] != 0x02 {
			t.Errorf("SOCKS5 reply REP = %x, want 0x02 (not allowed)", reply[1])
		}

		select {
		case <-onStackCalled:
			t.Error("OnStack was called, but scope should have blocked the target")
		case <-time.After(2 * time.Second):
			// Expected.
		}
	})
}

// TestFullListener_TLSPassthrough verifies that targets in the PassthroughList
// bypass MITM and the client TLS handshake sees the upstream certificate.
func TestFullListener_TLSPassthrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a unique upstream TLS config with a known certificate.
	upstreamKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	upstreamTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "passthrough-upstream"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"passthrough-upstream"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	upstreamCertDER, err := x509.CreateCertificate(rand.Reader, upstreamTmpl, upstreamTmpl, &upstreamKey.PublicKey, upstreamKey)
	if err != nil {
		t.Fatal(err)
	}
	upstreamCert, err := x509.ParseCertificate(upstreamCertDER)
	if err != nil {
		t.Fatal(err)
	}

	upstreamTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{upstreamCertDER},
			PrivateKey:  upstreamKey,
		}},
	}

	upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", upstreamTLSCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	// Upstream: accept a connection and echo data.
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.Copy(conn, conn) //nolint:errcheck // echo
	}()

	target := upstreamLn.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	// Create passthrough list with the upstream host.
	pl := connector.NewPassthroughList()
	pl.Add(host)

	onStackCalled := make(chan struct{}, 1)

	proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{
		passthroughList: pl,
		onStack: func(_ context.Context, stack *connector.ConnectionStack, _ *envelope.TLSSnapshot, _ string) {
			defer stack.Close()
			onStackCalled <- struct{}{}
		},
	})

	// CONNECT through proxy.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		t.Fatalf("unexpected CONNECT response: %q", got)
	}

	// TLS handshake — use the upstream cert as the trusted root.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(upstreamCert)

	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    rootPool,
		ServerName: "127.0.0.1",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with passthrough upstream: %v", err)
	}
	defer tlsConn.Close()

	// Verify the certificate subject matches the upstream.
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		t.Fatal("no peer certificates in TLS connection")
	}
	if peerCerts[0].Subject.CommonName != "passthrough-upstream" {
		t.Errorf("peer cert CN = %q, want %q", peerCerts[0].Subject.CommonName, "passthrough-upstream")
	}

	// Verify data flows through (echo test).
	testData := []byte("passthrough-test-data")
	if _, err := tlsConn.Write(testData); err != nil {
		t.Fatalf("write through passthrough: %v", err)
	}
	echoBuf := make([]byte, len(testData))
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tlsConn, echoBuf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoBuf, testData) {
		t.Errorf("echo mismatch: got %q, want %q", echoBuf, testData)
	}

	// Verify OnStack was NOT called.
	select {
	case <-onStackCalled:
		t.Error("OnStack was called, but passthrough should bypass MITM")
	case <-time.After(2 * time.Second):
		// Expected.
	}
}

// TestFullListener_RawPassthrough verifies that targets in RawPassthroughHosts
// use ByteChunk mode and flow recording shows protocol="raw".
func TestFullListener_RawPassthrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyCfg := &config.ProxyConfig{
		RawPassthroughHosts: []string{target},
	}

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{
		proxyConfig: proxyCfg,
	})

	wg.Add(1)
	rawReq := fmt.Sprintf("GET /raw HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendHTTP(t, proxyAddr, target, rawReq)

	waitSessionDone(t, wg)

	// --- Verify response ---
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}

	// --- Verify stream recording with raw protocol ---
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "raw" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "raw")
	}

	// --- Verify raw bytes in flows ---
	allFlows := store.allFlows()
	if len(allFlows) == 0 {
		t.Fatal("expected at least 1 flow, got 0")
	}
	hasRawBytes := false
	for _, f := range allFlows {
		if len(f.RawBytes) > 0 {
			hasRawBytes = true
			break
		}
	}
	if !hasRawBytes {
		t.Error("no flows have RawBytes, expected raw bytes in ByteChunk mode")
	}
}

// TestFullListener_RateLimiter_Blocking verifies that the rate limiter blocks
// connections when the budget is exhausted.
func TestFullListener_RateLimiter_Blocking(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rl := connector.NewRateLimiter()
	// Set a very low rate limit: 1 request per second globally.
	rl.SetPolicyLimits(connector.RateLimitConfig{
		MaxRequestsPerSecond: 1,
	})

	// Pre-consume the bucket so the next request is denied.
	// The limiter starts with burst=2 (rate+1), so consume twice.
	rl.Check("127.0.0.1")
	rl.Check("127.0.0.1")

	onStackCalled := make(chan struct{}, 1)

	proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{
		rateLimiter: rl,
		onStack: func(_ context.Context, stack *connector.ConnectionStack, _ *envelope.TLSSnapshot, _ string) {
			defer stack.Close()
			onStackCalled <- struct{}{}
		},
	})

	// Try CONNECT — should be rate-limited.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := "CONNECT 127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read the CONNECT 200 response.
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.Read(buf) //nolint:errcheck // may EOF if handler closes

	// Verify OnStack was NOT called.
	select {
	case <-onStackCalled:
		t.Error("OnStack was called, but rate limiter should have blocked the request")
	case <-time.After(2 * time.Second):
		// Expected.
	}
}

// TestFullListener_UpstreamProxy_CONNECT starts a mock HTTP CONNECT proxy and
// verifies that traffic flows through it when UpstreamProxy is set.
func TestFullListener_UpstreamProxy_CONNECT(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nupstream")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// Start mock upstream proxy.
	mockProxyAddr := startMockHTTPConnectProxy(t)
	proxyURL, err := url.Parse("http://" + mockProxyAddr)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{
		upstreamProxy: proxyURL,
	})

	wg.Add(1)
	rawReq := fmt.Sprintf("GET /via-proxy HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendHTTP(t, proxyAddr, target, rawReq)

	getUpstreamReqs() // Wait for upstream to finish.
	waitSessionDone(t, wg)

	// --- Verify response ---
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	if !strings.HasSuffix(resp, "upstream") {
		t.Errorf("response body not 'upstream': %q", resp)
	}

	// --- Verify stream recording ---
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
}
