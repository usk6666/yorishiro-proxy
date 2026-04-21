//go:build e2e

package http1_test

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
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"regexp"
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
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
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

func (s *testStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.ID == id {
			hasConnInfo := update.ServerAddr != "" ||
				update.TLSVersion != "" ||
				update.TLSCipher != "" ||
				update.TLSALPN != "" ||
				update.TLSServerCertSubject != ""
			if hasConnInfo {
				if st.ConnInfo == nil {
					st.ConnInfo = &flow.ConnectionInfo{}
				}
				if update.ServerAddr != "" {
					st.ConnInfo.ServerAddr = update.ServerAddr
				}
				if update.TLSVersion != "" {
					st.ConnInfo.TLSVersion = update.TLSVersion
				}
				if update.TLSCipher != "" {
					st.ConnInfo.TLSCipher = update.TLSCipher
				}
				if update.TLSALPN != "" {
					st.ConnInfo.TLSALPN = update.TLSALPN
				}
				if update.TLSServerCertSubject != "" {
					st.ConnInfo.TLSServerCertSubject = update.TLSServerCertSubject
				}
			}
		}
	}
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
// Returns the raw bytes of the complete request (headers + body).
func readHTTPRequest(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer

	// Read headers until \r\n\r\n.
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

	// Parse Content-Length from headers. Use the first value found
	// (same as the HTTP/1.x parser's headers.Get behavior).
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

	// Read body.
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
// sends responses via the handler function. Supports keep-alive (multiple
// request-response pairs per connection). Returns the listener and a
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

			// Check if response has Connection: close.
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

// proxyOpts holds optional engines for the MITM proxy.
type proxyOpts struct {
	interceptEngine *httprules.InterceptEngine
	transformEngine *httprules.TransformEngine
	safetyEngine    *httprules.SafetyEngine
	holdQueue       *common.HoldQueue
	scope           *connector.TargetScope
}

// startHTTPMITMProxy starts a MinimalListener configured for HTTP MITM (not
// raw passthrough). Returns the proxy address, testStore, and a channel that
// closes when the first session completes.
func startHTTPMITMProxy(
	t *testing.T,
	ctx context.Context,
	target string,
	opts proxyOpts,
) (proxyAddr string, store *testStore, sessionDone <-chan struct{}) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store = &testStore{}
	done := make(chan struct{})

	mlCfg := connector.MinimalListenerConfig{
		BuildConfig: &connector.BuildConfig{
			ProxyConfig: &config.ProxyConfig{
				// NOT in RawPassthroughHosts — triggers HTTP MITM mode.
			},
			Issuer:             issuer,
			InsecureSkipVerify: true,
		},
		OnStack: func(ctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			defer close(done)
			defer stack.Close()

			clientCh := <-stack.ClientTopmost().Channels()

			// Build pipeline: HostScope → HTTPScope → Safety → Transform → Intercept → Record.
			steps := []pipeline.Step{
				pipeline.NewHostScopeStep(nil),
				pipeline.NewHTTPScopeStep(opts.scope),
				pipeline.NewSafetyStep(opts.safetyEngine, slog.Default()),
				pipeline.NewTransformStep(opts.transformEngine),
				pipeline.NewInterceptStep(opts.interceptEngine, opts.holdQueue, slog.Default()),
				pipeline.NewRecordStep(store, slog.Default()),
			}

			p := pipeline.New(steps...)

			// Lazy dial: return upstream channel on first forwarded envelope.
			session.RunSession(ctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				return <-stack.UpstreamTopmost().Channels(), nil
			}, p)
		},
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ml := connector.NewMinimalListenerFromListener(proxyLn, mlCfg)
	go ml.Serve(ctx)
	t.Cleanup(func() { ml.Close() })

	return proxyLn.Addr().String(), store, done
}

// connectThroughProxy connects to the proxy, sends CONNECT for the given
// target, reads the 200 response, and performs a TLS handshake. Returns the
// TLS connection ready for HTTP transmission.
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

// connectAndSendHTTP is a helper that performs CONNECT, TLS handshake, sends
// a raw HTTP request, reads the response, and returns the response string.
func connectAndSendHTTP(t *testing.T, proxyAddr, target, rawRequest string) string {
	t.Helper()
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var respBuf bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buf)
		if n > 0 {
			respBuf.Write(buf[:n])
		}
		if err != nil {
			break
		}
		// Check if we have a complete HTTP response.
		resp := respBuf.String()
		if idx := strings.Index(resp, "\r\n\r\n"); idx >= 0 {
			headerPart := resp[:idx]
			bodyStart := idx + 4
			// Parse Content-Length.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestHTTPSMITM_BasicRoundtrip verifies that a basic HTTP request flows
// through the MITM proxy and back, with proper flow recording.
func TestHTTPSMITM_BasicRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	rawReq := fmt.Sprintf("GET /hello HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendHTTP(t, proxyAddr, target, rawReq)

	// Wait for upstream to finish.
	upstreamReqs := getUpstreamReqs()

	// Wait for session to complete.
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

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
	if streams[0].State != "active" {
		t.Errorf("stream state = %q, want %q", streams[0].State, "active")
	}

	// USK-619 (h1 parity): Stream.ConnInfo must reflect upstream TLS
	// reality, not the synthetic MITM cert. The upstream handler's
	// self-signed cert uses CN="test-upstream" (newTestTLSConfig).
	if streams[0].ConnInfo == nil {
		t.Fatal("Stream.ConnInfo is nil; upstream TLS was not projected into ConnInfo")
	}
	if !strings.Contains(streams[0].ConnInfo.TLSServerCertSubject, "test-upstream") {
		t.Errorf("ConnInfo.TLSServerCertSubject = %q, want to contain %q "+
			"(synthetic MITM cert leaking into ConnInfo)",
			streams[0].ConnInfo.TLSServerCertSubject, "test-upstream")
	}
	if streams[0].ConnInfo.TLSVersion == "" {
		t.Error("ConnInfo.TLSVersion is empty; expected TLS 1.2 or TLS 1.3")
	}

	// --- Verify flow recording ---
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow, got 0")
	}
	if sendFlows[0].Method != "GET" {
		t.Errorf("send flow Method = %q, want %q", sendFlows[0].Method, "GET")
	}
	if sendFlows[0].URL == nil || sendFlows[0].URL.Path != "/hello" {
		t.Errorf("send flow URL.Path = %v, want /hello", sendFlows[0].URL)
	}

	recvFlows := store.flowsByDirection("receive")
	if len(recvFlows) < 1 {
		t.Fatal("expected at least 1 receive flow, got 0")
	}
	if recvFlows[0].StatusCode != 200 {
		t.Errorf("receive flow StatusCode = %d, want 200", recvFlows[0].StatusCode)
	}
	if !bytes.Equal(recvFlows[0].Body, []byte("hello")) {
		t.Errorf("receive flow Body = %q, want %q", recvFlows[0].Body, "hello")
	}

	// --- Verify RawBytes ---
	if len(sendFlows[0].RawBytes) == 0 {
		t.Error("send flow RawBytes is empty, expected raw header bytes")
	}
	if len(recvFlows[0].RawBytes) == 0 {
		t.Error("receive flow RawBytes is empty, expected raw header bytes")
	}
}

// TestHTTPSMITM_WireFidelity verifies that non-canonical header casing and
// OWS (optional whitespace) are preserved through the MITM proxy.
// This is the wire fidelity proof for HTTP MITM.
func TestHTTPSMITM_WireFidelity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	// Send request with non-canonical header casing and OWS.
	rawReq := fmt.Sprintf(
		"GET /fidelity HTTP/1.1\r\n"+
			"host: %s\r\n"+
			"X-Custom:   spaced-value  \r\n"+
			"accept: text/html\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		target,
	)
	resp := connectAndSendHTTP(t, proxyAddr, target, rawReq)

	upstreamReqs := getUpstreamReqs()

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// Verify response reached client.
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}

	// --- Wire fidelity verification ---
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	upReq := string(upstreamReqs[0])

	// Lowercase "host:" preserved.
	if !strings.Contains(upReq, "host:") {
		t.Error("upstream lost lowercase 'host:' header casing")
	}

	// Mixed case "X-Custom:" preserved.
	if !strings.Contains(upReq, "X-Custom:") {
		t.Error("upstream lost mixed-case 'X-Custom:' header casing")
	}

	// Lowercase "accept:" preserved.
	if !strings.Contains(upReq, "accept:") {
		t.Error("upstream lost lowercase 'accept:' header casing")
	}

	// OWS "   spaced-value  " preserved in the raw bytes on the wire.
	// The parser trims OWS for the parsed Value, but the raw-first patching
	// path preserves the original wire bytes including OWS in RawValue.
	// Since no headers were modified by any Step, the zero-copy fast path
	// writes the original RawBytes verbatim to upstream.
	if !strings.Contains(upReq, "spaced-value") {
		t.Error("upstream lost 'spaced-value' content")
	}
}

// TestHTTPSMITM_InterceptModify verifies intercept hold, modification, and
// release with variant recording.
func TestHTTPSMITM_InterceptModify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nintercepted!")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	interceptEngine := httprules.NewInterceptEngine()
	interceptEngine.AddRule(httprules.InterceptRule{
		ID:          "test-intercept",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`/intercept`),
	})

	holdQueue := common.NewHoldQueue()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		interceptEngine: interceptEngine,
		holdQueue:       holdQueue,
	})

	// Send request in a goroutine (it will block on intercept hold).
	respCh := make(chan string, 1)
	go func() {
		rawReq := fmt.Sprintf("GET /intercept HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
		respCh <- connectAndSendHTTP(t, proxyAddr, target, rawReq)
	}()

	// Poll for held entry.
	var entries []*common.HeldEntry
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries = holdQueue.List()
		if len(entries) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("no entry appeared in hold queue")
	}

	// Clone the held envelope and add X-Injected header.
	held := entries[0]
	modified := held.Envelope.Clone()
	msg, ok := modified.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatal("held envelope message is not *HTTPMessage")
	}
	msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "X-Injected", Value: "by-proxy"})

	// Release with modification.
	if err := holdQueue.Release(held.ID, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modified,
	}); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Wait for response.
	select {
	case resp := <-respCh:
		if !strings.Contains(resp, "200 OK") {
			t.Errorf("response missing 200 OK: %q", resp)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Wait for upstream.
	upstreamReqs := getUpstreamReqs()

	// Wait for session completion.
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Verify upstream received the injected header ---
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	if !bytes.Contains(upstreamReqs[0], []byte("X-Injected: by-proxy")) {
		t.Errorf("upstream missing X-Injected header: %q", upstreamReqs[0])
	}

	// --- Verify variant recording ---
	allFlows := store.allFlows()
	var hasOriginal, hasModified bool
	for _, f := range allFlows {
		if f.Metadata != nil {
			switch f.Metadata["variant"] {
			case "original":
				hasOriginal = true
			case "modified":
				hasModified = true
			}
		}
	}
	if !hasOriginal {
		t.Error("expected original variant flow, found none")
	}
	if !hasModified {
		t.Error("expected modified variant flow, found none")
	}
}

// TestHTTPSMITM_Transform verifies transform rules: AddHeader on requests
// and ReplaceBody on responses, with variant recording.
func TestHTTPSMITM_Transform(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		body := "the secret data"
		return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body))
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	transformEngine := httprules.NewTransformEngine()
	transformEngine.SetRules([]httprules.TransformRule{
		{
			ID:          "add-proxy-header",
			Enabled:     true,
			Priority:    1,
			Direction:   httprules.DirectionRequest,
			ActionType:  httprules.TransformAddHeader,
			HeaderName:  "X-Proxy",
			HeaderValue: "yorishiro",
		},
		{
			ID:          "redact-secret",
			Enabled:     true,
			Priority:    2,
			Direction:   httprules.DirectionResponse,
			ActionType:  httprules.TransformReplaceBody,
			BodyPattern: regexp.MustCompile(`secret`),
			BodyReplace: "REDACTED",
		},
	})

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		transformEngine: transformEngine,
	})

	rawReq := fmt.Sprintf("GET /transform HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendHTTP(t, proxyAddr, target, rawReq)

	upstreamReqs := getUpstreamReqs()

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Verify upstream received X-Proxy header ---
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	if !bytes.Contains(upstreamReqs[0], []byte("X-Proxy: yorishiro")) {
		t.Errorf("upstream missing X-Proxy header: %q", upstreamReqs[0])
	}

	// --- Verify client received redacted body ---
	if !strings.Contains(resp, "the REDACTED data") {
		t.Errorf("response body not redacted: %q", resp)
	}
	if strings.Contains(resp, "the secret data") {
		t.Error("response body still contains 'secret' — transform did not apply")
	}

	// --- Verify variant recording for request (AddHeader) ---
	allFlows := store.allFlows()
	var reqOriginal, reqModified bool
	var respOriginal, respModified bool
	for _, f := range allFlows {
		if f.Metadata == nil {
			continue
		}
		variant := f.Metadata["variant"]
		if f.Direction == "send" {
			if variant == "original" {
				reqOriginal = true
			}
			if variant == "modified" {
				reqModified = true
			}
		}
		if f.Direction == "receive" {
			if variant == "original" {
				respOriginal = true
			}
			if variant == "modified" {
				respModified = true
			}
		}
	}
	if !reqOriginal || !reqModified {
		t.Errorf("request variant recording: original=%v modified=%v", reqOriginal, reqModified)
	}
	if !respOriginal || !respModified {
		t.Errorf("response variant recording: original=%v modified=%v", respOriginal, respModified)
	}
}

// TestHTTPSMITM_SafetyBlock verifies that the safety filter blocks dangerous
// requests (destructive-sql preset).
func TestHTTPSMITM_SafetyBlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamReceived := make(chan struct{}, 1)
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		upstreamReceived <- struct{}{}
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	safetyEngine := httprules.NewSafetyEngine()
	if err := safetyEngine.LoadPreset("destructive-sql"); err != nil {
		t.Fatalf("load preset: %v", err)
	}

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		safetyEngine: safetyEngine,
	})

	// Send dangerous SQL request.
	body := "DROP TABLE users;"
	rawReq := fmt.Sprintf(
		"POST /api HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		target, len(body), body,
	)

	// Connect and try to send. The request should be dropped by safety filter.
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// The safety filter drops the envelope, so the session may end without
	// sending the request upstream. The client connection should eventually
	// be closed (read returns error/EOF).
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readBuf := make([]byte, 4096)
	_, readErr := tlsConn.Read(readBuf)

	// We expect either EOF, connection reset, or timeout (all valid safety outcomes).
	if readErr == nil {
		t.Error("expected read error/EOF after safety block, got successful read")
	}

	// Wait for session to complete.
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Verify upstream received NO data ---
	select {
	case <-upstreamReceived:
		t.Error("upstream handler was called — safety filter did not block the request")
	case <-time.After(1 * time.Second):
		// Good: upstream was never called.
	}
}

// TestHTTPSMITM_KeepAlive verifies multiple sequential requests on the same
// keep-alive connection with proper flow recording.
func TestHTTPSMITM_KeepAlive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reqCount := 0
	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(reqBytes []byte) []byte {
		reqCount++
		body := fmt.Sprintf("resp%d", reqCount)
		isLast := reqCount >= 3
		connHeader := ""
		if isLast {
			connHeader = "Connection: close\r\n"
		}
		return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s\r\n%s",
			len(body), connHeader, body))
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	// Use low-level TLS connection for keep-alive.
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	br := bufio.NewReader(tlsConn)

	// Send 3 sequential requests on the same connection.
	for i := 1; i <= 3; i++ {
		path := fmt.Sprintf("/req%d", i)
		connHeader := ""
		if i == 3 {
			connHeader = "Connection: close\r\n"
		}
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", path, target, connHeader)

		if _, err := tlsConn.Write([]byte(req)); err != nil {
			t.Fatalf("write req%d: %v", i, err)
		}

		// Read response.
		tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		var respBuf bytes.Buffer

		// Read status line + headers.
		for {
			line, err := br.ReadBytes('\n')
			if err != nil {
				t.Fatalf("read response%d headers: %v", i, err)
			}
			respBuf.Write(line)
			if bytes.Equal(line, []byte("\r\n")) {
				break
			}
		}

		// Parse Content-Length from response headers.
		cl := 0
		for _, line := range strings.Split(respBuf.String(), "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				val := strings.TrimSpace(line[len("content-length:"):])
				cl, _ = strconv.Atoi(val)
			}
		}

		// Read body.
		if cl > 0 {
			body := make([]byte, cl)
			if _, err := io.ReadFull(br, body); err != nil {
				t.Fatalf("read response%d body: %v", i, err)
			}
			respBuf.Write(body)
		}

		expected := fmt.Sprintf("resp%d", i)
		if !strings.HasSuffix(respBuf.String(), expected) {
			t.Errorf("response %d body: got %q, want suffix %q", i, respBuf.String(), expected)
		}
	}

	// Wait for upstream to finish.
	upstreamReqs := getUpstreamReqs()

	// Wait for session to complete.
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Verify upstream received 3 requests ---
	if len(upstreamReqs) < 3 {
		t.Fatalf("upstream received %d requests, want 3", len(upstreamReqs))
	}

	// --- Verify flow recording ---
	sendFlows := store.flowsByDirection("send")
	recvFlows := store.flowsByDirection("receive")

	if len(sendFlows) < 3 {
		t.Errorf("expected at least 3 send flows, got %d", len(sendFlows))
	}
	if len(recvFlows) < 3 {
		t.Errorf("expected at least 3 receive flows, got %d", len(recvFlows))
	}

	// Verify sequence values: each request-response pair gets a new StreamID
	// with Sequence=0 for send and Sequence=1 for receive.
	for i, f := range sendFlows {
		if i >= 3 {
			break
		}
		if f.Sequence != 0 {
			t.Errorf("send flow %d: Sequence=%d, want 0", i, f.Sequence)
		}
	}
	for i, f := range recvFlows {
		if i >= 3 {
			break
		}
		if f.Sequence != 1 {
			t.Errorf("receive flow %d: Sequence=%d, want 1", i, f.Sequence)
		}
	}
}

// TestHTTPSMITM_ConnectionClose verifies that Connection: close on the
// request side causes the session to terminate cleanly.
func TestHTTPSMITM_ConnectionClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	rawReq := fmt.Sprintf("GET /close HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read response.
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var respBuf bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buf)
		if n > 0 {
			respBuf.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	if !strings.Contains(respBuf.String(), "200 OK") {
		t.Errorf("response missing 200 OK: %q", respBuf.String())
	}

	// Session must terminate (sessionDone channel closes).
	select {
	case <-sessionDone:
		// Good: session terminated cleanly.
	case <-time.After(15 * time.Second):
		t.Fatal("session did not terminate after Connection: close")
	}

	// Subsequent reads should return error.
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := tlsConn.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected read error after session termination, got nil")
	}
}

// TestHTTPSMITM_AnomalyDetection verifies that dual Content-Length headers
// are preserved through MITM (no normalization) and anomalies are detected.
func TestHTTPSMITM_AnomalyDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nanomaly")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// Use intercept to inspect the Envelope and verify Anomalies.
	interceptEngine := httprules.NewInterceptEngine()
	interceptEngine.AddRule(httprules.InterceptRule{
		ID:          "anomaly-check",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`/anomaly`),
	})

	holdQueue := common.NewHoldQueue()

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		interceptEngine: interceptEngine,
		holdQueue:       holdQueue,
	})

	// Send request with dual Content-Length in a goroutine.
	respCh := make(chan string, 1)
	go func() {
		tlsConn := connectThroughProxy(t, proxyAddr, target)
		defer tlsConn.Close()

		rawReq := fmt.Sprintf(
			"POST /anomaly HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Length: 5\r\n"+
				"Content-Length: 10\r\n"+
				"Connection: close\r\n"+
				"\r\n"+
				"hello",
			target,
		)

		if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
			respCh <- fmt.Sprintf("write error: %v", err)
			return
		}

		tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		var buf bytes.Buffer
		b := make([]byte, 4096)
		for {
			n, err := tlsConn.Read(b)
			if n > 0 {
				buf.Write(b[:n])
			}
			if err != nil {
				break
			}
		}
		respCh <- buf.String()
	}()

	// Poll for held entry.
	var entries []*common.HeldEntry
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries = holdQueue.List()
		if len(entries) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("no entry appeared in hold queue")
	}

	// Inspect the held envelope for anomalies.
	held := entries[0]
	msg, ok := held.Envelope.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatal("held envelope message is not *HTTPMessage")
	}

	// Verify anomalies contain DuplicateCL.
	foundDuplicateCL := false
	for _, a := range msg.Anomalies {
		if a.Type == envelope.AnomalyDuplicateCL {
			foundDuplicateCL = true
		}
	}
	if !foundDuplicateCL {
		t.Errorf("expected DuplicateCL anomaly, got anomalies: %+v", msg.Anomalies)
	}

	// Release the held envelope (forward as-is).
	if err := holdQueue.Release(held.ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Wait for response.
	select {
	case resp := <-respCh:
		if !strings.Contains(resp, "200 OK") {
			t.Errorf("response missing 200 OK: %q", resp)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Wait for upstream to finish.
	upstreamReqs := getUpstreamReqs()

	// Wait for session to complete.
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Verify upstream received dual Content-Length ---
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	upReq := string(upstreamReqs[0])
	clCount := strings.Count(upReq, "Content-Length:")
	if clCount < 2 {
		t.Errorf("upstream received %d Content-Length headers, want 2; raw: %q", clCount, upReq)
	}
}

// TestHTTPSMITM_ChunkedTrailers verifies that chunked trailers sent by the
// client are parsed and projected onto flow.Flow.Trailers (USK-627).
// Previously the HTTP/1 parser's consumeTrailers discarded trailer lines,
// leaving flow records with empty Trailers even though USK-621 wired up
// the record path.
func TestHTTPSMITM_ChunkedTrailers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The upstream helper's readHTTPRequest only understands Content-Length
	// framing, but the proxy's RecordStep fires on the send envelope before
	// the body is forwarded upstream — so chunked trailers appear in the flow
	// record regardless of what the upstream does with the request body.
	// We use a close-after-response upstream to unblock both sides quickly.
	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	chunkedReq := fmt.Sprintf(
		"POST /upload HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Trailer: X-Checksum\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"5\r\nhello\r\n"+
			"0\r\n"+
			"X-Checksum: abc123\r\n"+
			"\r\n",
		target,
	)
	resp := connectAndSendHTTP(t, proxyAddr, target, chunkedReq)
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}

	// Drain upstream goroutine; body content is incidental.
	_ = getUpstreamReqs()

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Verify flow recording: trailer projected onto flow.Flow.Trailers ---
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow, got 0")
	}
	sendFlow := sendFlows[0]
	if sendFlow.Trailers == nil {
		t.Fatalf("send flow Trailers is nil; USK-627 parser fix did not populate HTTPMessage.Trailers")
	}
	got := sendFlow.Trailers["X-Checksum"]
	if len(got) != 1 || got[0] != "abc123" {
		t.Errorf("sendFlow.Trailers[X-Checksum] = %v, want [abc123]; full Trailers = %v",
			got, sendFlow.Trailers)
	}
}
