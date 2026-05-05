//go:build e2e

package bytechunk_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
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
// Test infrastructure
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

// startUpstreamTLS starts a TLS server that accepts one connection, reads
// one chunk of data, sends the given response, and closes. Returns the
// listener and a function that blocks until the captured bytes are available.
func startUpstreamTLS(t *testing.T, response string) (net.Listener, func() []byte) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newTestTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	captured := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer conn.Close()

		// Read one chunk from the proxy. For small payloads on localhost,
		// a single Read() captures the entire payload.
		buf := make([]byte, 32768)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _ := conn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			captured <- data
		} else {
			captured <- nil
		}

		// Send response.
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte(response))
	}()
	return ln, func() []byte {
		select {
		case b := <-captured:
			return b
		case <-time.After(15 * time.Second):
			t.Fatal("timeout waiting for upstream captured bytes")
			return nil
		}
	}
}

// startRawPassthroughProxy starts a FullListener with raw passthrough for
// the given target and wires OnStack → RunSession with Pipeline (HostScopeStep
// + RecordStep). Returns the proxy address, testStore for flow verification,
// and a channel that closes when the first session completes.
func startRawPassthroughProxy(
	t *testing.T,
	ctx context.Context,
	target string,
) (proxyAddr string, store *testStore, sessionDone <-chan struct{}) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store = &testStore{}
	done := make(chan struct{})

	buildCfg := &connector.BuildConfig{
		ProxyConfig: &config.ProxyConfig{
			RawPassthroughHosts: []string{target},
		},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	onStack := func(ctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer close(done)
		defer stack.Close()

		clientCh := <-stack.ClientTopmost().Channels()
		upstreamCh := <-stack.UpstreamTopmost().Channels()

		p := pipeline.New(
			pipeline.NewHostScopeStep(nil), // allow all
			pipeline.NewRecordStep(store, slog.Default()),
		)

		session.RunSession(ctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return upstreamCh, nil
		}, p)
	}

	flCfg := connector.FullListenerConfig{
		Name: "test",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener ready")
	}

	return fl.Addr(), store, done
}

// connectThroughProxy connects to the proxy, sends CONNECT for the given
// target, reads the 200 response, and performs a TLS handshake. Returns the
// TLS connection ready for raw byte transmission.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRawPassthroughSmuggling verifies that a malformed HTTP request with
// dual Content-Length headers passes through the proxy byte-for-byte without
// any normalization. This is the N2 milestone success criterion: proof that
// the Envelope + Layer architecture preserves wire fidelity for raw
// passthrough mode (HTTP request smuggling diagnosis).
//
// RFC-001 §4.2 (HTTP Request Smuggling scenario)
// Implementation guide §4 (Vertical Slice — this test's success = N2's success)
func TestRawPassthroughSmuggling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Smuggling payload: dual Content-Length is the classic CL.CL vector.
	// A normalizing proxy would reject or merge these headers.
	// Raw passthrough must relay them verbatim.
	smugglingPayload := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: target.example.com\r\n" +
			"Content-Length: 10\r\n" +
			"Content-Length: 5\r\n" +
			"\r\n" +
			"SmuggInjct",
	)
	httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	// 1. Start upstream TLS server that captures received bytes.
	upstreamLn, getUpstreamBytes := startUpstreamTLS(t, httpResponse)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// 2. Start proxy with raw passthrough for this target.
	proxyAddr, store, sessionDone := startRawPassthroughProxy(t, ctx, target)

	// 3. Connect through proxy (CONNECT → 200 → TLS handshake).
	clientTLS := connectThroughProxy(t, proxyAddr, target)

	// 4. Send smuggling payload through the TLS tunnel.
	if _, err := clientTLS.Write(smugglingPayload); err != nil {
		t.Fatalf("write smuggling payload: %v", err)
	}

	// 5. Read response from upstream (relayed through proxy).
	respBuf := make([]byte, 4096)
	clientTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := clientTLS.Read(respBuf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read response: %v", err)
	}
	gotResponse := respBuf[:n]

	// 6. Close client connection to end the session.
	clientTLS.Close()

	// 7. Wait for session to complete (ensures all flows are recorded).
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Wire fidelity verification ---

	// Upstream must have received the exact bytes sent by the client.
	upstreamReceived := getUpstreamBytes()
	if !bytes.Equal(upstreamReceived, smugglingPayload) {
		t.Errorf("upstream received bytes differ from sent payload:\n  sent: %q\n  got:  %q",
			smugglingPayload, upstreamReceived)
	}

	// The dual Content-Length headers must survive (not merged or removed).
	if !bytes.Contains(upstreamReceived, []byte("Content-Length: 10\r\nContent-Length: 5\r\n")) {
		t.Error("dual Content-Length headers were normalized — smuggling detection broken")
	}

	// Response must reach the client unchanged.
	if !bytes.Equal(gotResponse, []byte(httpResponse)) {
		t.Errorf("client response differs:\n  want: %q\n  got:  %q", httpResponse, gotResponse)
	}

	// --- Flow recording verification ---

	// Stream: at least one created with protocol="raw" and state="active".
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "raw" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "raw")
	}
	if streams[0].State != "active" {
		t.Errorf("stream state = %q, want %q (RecordStep must not change state)", streams[0].State, "active")
	}

	// Send flow: RawBytes and Body must match the smuggling payload exactly.
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow, got 0")
	}
	if !bytes.Equal(sendFlows[0].RawBytes, smugglingPayload) {
		t.Errorf("send flow RawBytes differ from payload:\n  want: %q\n  got:  %q",
			smugglingPayload, sendFlows[0].RawBytes)
	}
	if !bytes.Equal(sendFlows[0].Body, smugglingPayload) {
		t.Errorf("send flow Body differ from payload:\n  want: %q\n  got:  %q",
			smugglingPayload, sendFlows[0].Body)
	}
	if sendFlows[0].Metadata == nil || sendFlows[0].Metadata["protocol"] != "raw" {
		t.Errorf("send flow metadata[protocol] = %v, want \"raw\"", sendFlows[0].Metadata)
	}

	// Receive flow: response bytes recorded.
	recvFlows := store.flowsByDirection("receive")
	if len(recvFlows) < 1 {
		t.Fatal("expected at least 1 receive flow, got 0")
	}
	if !bytes.Equal(recvFlows[0].RawBytes, []byte(httpResponse)) {
		t.Errorf("receive flow RawBytes differ from response:\n  want: %q\n  got:  %q",
			httpResponse, recvFlows[0].RawBytes)
	}
	if recvFlows[0].Metadata == nil || recvFlows[0].Metadata["protocol"] != "raw" {
		t.Errorf("receive flow metadata[protocol] = %v, want \"raw\"", recvFlows[0].Metadata)
	}
}

// TestRawPassthrough_NormalHTTP verifies that normal (well-formed) HTTP also
// passes through in raw passthrough mode without modification.
func TestRawPassthrough_NormalHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	normalPayload := []byte(
		"GET /index.html HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Accept: text/html\r\n" +
			"\r\n",
	)
	httpResponse := "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"

	upstreamLn, getUpstreamBytes := startUpstreamTLS(t, httpResponse)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, sessionDone := startRawPassthroughProxy(t, ctx, target)

	clientTLS := connectThroughProxy(t, proxyAddr, target)

	if _, err := clientTLS.Write(normalPayload); err != nil {
		t.Fatalf("write: %v", err)
	}

	respBuf := make([]byte, 4096)
	clientTLS.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := clientTLS.Read(respBuf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read response: %v", err)
	}

	clientTLS.Close()

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session")
	}

	// Wire fidelity: byte-for-byte match.
	upstreamReceived := getUpstreamBytes()
	if !bytes.Equal(upstreamReceived, normalPayload) {
		t.Errorf("upstream bytes differ:\n  sent: %q\n  got:  %q", normalPayload, upstreamReceived)
	}

	// Response delivered.
	if !bytes.Equal(respBuf[:n], []byte(httpResponse)) {
		t.Errorf("response differs:\n  want: %q\n  got:  %q", httpResponse, respBuf[:n])
	}
}

// TestRawPassthrough_TLSFailure verifies the error path when the upstream TLS
// dial fails. The MITM handshake with the client may succeed, but the
// subsequent read/write must fail because the proxy closes the connection.
func TestRawPassthrough_TLSFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a target that will cause upstream dial to fail: bind a port
	// then close the listener so nothing is listening.
	tmpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := tmpLn.Addr().String()
	tmpLn.Close()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	onStackCalled := make(chan struct{}, 1)

	buildCfg := &connector.BuildConfig{
		ProxyConfig: &config.ProxyConfig{
			RawPassthroughHosts: []string{target},
		},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}
	onStack := func(_ context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer stack.Close()
		onStackCalled <- struct{}{}
	}

	flCfg := connector.FullListenerConfig{
		Name: "test",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener ready")
	}

	conn, err := net.DialTimeout("tcp", fl.Addr(), 5*time.Second)
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

	// TLS handshake through MITM. The proxy performs the server-side TLS
	// handshake before dialing upstream, so this may succeed. If it fails,
	// the proxy closed before handshake completion — also valid.
	clientTLS := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
	})
	hsErr := clientTLS.Handshake()
	if hsErr != nil {
		// Handshake failed: proxy closed before completion. Acceptable
		// because the upstream dial failure may tear down the connection
		// before the client-side TLS handshake finishes.
	} else {
		// Handshake succeeded. The next operation should fail because the
		// proxy closes the connection after upstream dial failure.
		readBuf := make([]byte, 1)
		clientTLS.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, readErr := clientTLS.Read(readBuf)
		if readErr == nil {
			t.Error("expected read error after upstream dial failure, got nil")
		}
	}

	// OnStack must NOT have been called (stack build failed).
	select {
	case <-onStackCalled:
		t.Error("OnStack should not be called when upstream dial fails")
	default:
	}
}

// TestRawPassthrough_ScopeBlock verifies that a CONNECT target NOT in
// raw_passthrough_hosts is rejected at the stack-build level. In N2, only
// raw passthrough mode is supported; non-passthrough returns "not yet
// supported" (deferred to N3 when http1 layer is added).
func TestRawPassthrough_ScopeBlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target := "127.0.0.1:9999" // NOT in passthrough list

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	onStackCalled := make(chan struct{}, 1)

	buildCfg := &connector.BuildConfig{
		ProxyConfig: &config.ProxyConfig{
			RawPassthroughHosts: []string{"other.host:443"},
		},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}
	onStack := func(_ context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer stack.Close()
		onStackCalled <- struct{}{}
	}

	flCfg := connector.FullListenerConfig{
		Name: "test",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener ready")
	}

	conn, err := net.DialTimeout("tcp", fl.Addr(), 5*time.Second)
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

	// BuildConnectionStack returns error immediately for non-passthrough
	// targets (no TLS handshake attempted). The proxy closes the connection.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection close for non-passthrough target, got successful read")
	}

	// OnStack must NOT have been called.
	select {
	case <-onStackCalled:
		t.Error("OnStack should not be called for non-passthrough target")
	default:
	}
}
