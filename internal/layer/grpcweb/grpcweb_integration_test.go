//go:build e2e

package grpcweb_test

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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	nethttp "net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// testStore implements flow.Writer for capturing recorded streams and flows.
// Mirrors the testStore used by sibling layer integration tests.
type testStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
}

func (s *testStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *st
	s.streams = append(s.streams, &cp)
	return nil
}

func (s *testStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.ID != id {
			continue
		}
		if update.State != "" {
			st.State = update.State
		}
		if update.FailureReason != "" {
			st.FailureReason = update.FailureReason
		}
	}
	return nil
}

func (s *testStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *f
	s.flows = append(s.flows, &cp)
	return nil
}

func (s *testStore) getStreams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

func (s *testStore) allFlows() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

// newTestTLSConfig produces a self-signed TLS server config for testing.
// nextProtos selects ALPN (e.g. []string{"h2"} for HTTP/2 servers, nil for h1).
func newTestTLSConfig(t *testing.T, nextProtos []string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "grpcweb-upstream"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"grpcweb-upstream", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
			Leaf:        parsed,
		}},
		NextProtos: nextProtos,
	}
}

// readHTTPRequest reads a complete HTTP/1.x request (headers + body framed
// by Content-Length). Mirrors the helper in sibling http1 integration tests.
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
	hdr := buf.Bytes()
	cl := 0
	for _, line := range bytes.Split(hdr, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("content-length:")) {
			val := strings.TrimSpace(string(line[len("content-length:"):]))
			n, err := strconv.Atoi(val)
			if err == nil {
				cl = n
			}
		}
	}
	if cl > 0 {
		body := make([]byte, cl)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
		buf.Write(body)
	}
	return buf.Bytes(), nil
}

// buildGRPCWebResponseBody returns the wire body for a single-message
// gRPC-Web response (one data frame + one trailer frame). When base64Wire
// is true the binary body is base64-encoded per the -text wire format.
func buildGRPCWebResponseBody(payload []byte, status uint32, message string, base64Wire bool) []byte {
	dataFrame := grpcweb.EncodeFrame(false, false, payload)
	trailerText := fmt.Sprintf("grpc-status: %d\r\ngrpc-message: %s\r\n", status, message)
	trailerFrame := grpcweb.EncodeFrame(true, false, []byte(trailerText))
	body := append(append([]byte{}, dataFrame...), trailerFrame...)
	if base64Wire {
		body = grpcweb.EncodeBase64Body(body)
	}
	return body
}

// buildGRPCWebResponseHTTP returns a complete HTTP/1.1 response with a
// gRPC-Web body. Caller selects binary vs base64 wire via base64Wire.
func buildGRPCWebResponseHTTP(payload []byte, status uint32, message string, base64Wire bool) []byte {
	body := buildGRPCWebResponseBody(payload, status, message, base64Wire)
	ct := "application/grpc-web+proto"
	if base64Wire {
		ct = "application/grpc-web-text+proto"
	}
	return []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		ct, len(body)) + string(body))
}

// startGRPCWebHTTP1Upstream starts a TLS upstream that reads a single HTTP
// request and replies with a hand-crafted gRPC-Web response. The response
// content is determined at call time by the responseBuilder. The upstream
// always reads the request to completion before responding so the proxy's
// upstream Send buffer is fully flushed (which requires the test's
// sendEndInjector to push a synthetic GRPCEndMessage on Send-side EOF).
func startGRPCWebHTTP1Upstream(
	t *testing.T,
	responseBuilder func(reqBytes []byte) []byte,
) (net.Listener, func() [][]byte) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newTestTLSConfig(t, nil))
	if err != nil {
		t.Fatal(err)
	}

	captured := make(chan [][]byte, 1)

	go func() {
		var allReqs [][]byte
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				captured <- allReqs
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(conn)
				reqBytes, rerr := readHTTPRequest(br)
				if rerr != nil {
					return
				}
				cp := make([]byte, len(reqBytes))
				copy(cp, reqBytes)
				allReqs = append(allReqs, cp)
				resp := responseBuilder(reqBytes)
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, _ = conn.Write(resp)
			}()
		}
	}()

	return ln, func() [][]byte {
		select {
		case b := <-captured:
			return b
		case <-time.After(15 * time.Second):
			return nil
		}
	}
}

// startGRPCWebHTTP2Upstream starts a TLS+ALPN h2 upstream that replies to
// a single gRPC-Web request with a hand-crafted gRPC-Web response body.
// Built on x/net/http2 so we depend only on the already-approved x/net.
func startGRPCWebHTTP2Upstream(
	t *testing.T,
	responseBuilder func(req *nethttp.Request) ([]byte, string),
) (string, func()) {
	t.Helper()
	tlsCfg := newTestTLSConfig(t, []string{"h2"})

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h2s := &http2.Server{}
	handler := nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Read and discard the request body so framing closes cleanly.
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()

		body, ct := responseBuilder(r)
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})

	var wg sync.WaitGroup
	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			tlsConn := tls.Server(c, tlsCfg)
			wg.Add(1)
			go func(tc *tls.Conn) {
				defer wg.Done()
				defer tc.Close()
				if err := tc.Handshake(); err != nil {
					return
				}
				h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
			}(tlsConn)
		}
	}()

	shutdown := func() {
		_ = tcpLn.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return tcpLn.Addr().String(), shutdown
}

// connectThroughProxy CONNECTs to the proxy for target, then performs a TLS
// handshake. nextProtos selects ALPN ("" → no ALPN; "h2" for HTTP/2).
func connectThroughProxy(t *testing.T, proxyAddr, target string, nextProtos []string) *tls.Conn {
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
	if got := string(buf[:n]); !strings.Contains(got, "200") {
		conn.Close()
		t.Fatalf("unexpected CONNECT response: %q", got)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		NextProtos:         nextProtos,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("TLS handshake through proxy: %v", err)
	}
	return tlsConn
}

// ---------------------------------------------------------------------------
// sendEndInjector: bridges grpcweb.RoleServer.Next EOF into a synthetic
// GRPCEndMessage(Direction=Send) that the upstream-side grpcweb.RoleClient
// uses as its D6 flush sentinel. Without this injector the Send-side
// assembly buffer would never flush and the upstream would never receive
// the request — so the proactive-response upstream pattern alone is
// insufficient for h2 (the handler runs only after HEADERS arrive).
// ---------------------------------------------------------------------------

type sendEndInjector struct {
	inner    layer.Channel
	streamID string
	mu       sync.Mutex
	emitted  bool
	lastSeq  int
}

func newSendEndInjector(inner layer.Channel) *sendEndInjector {
	return &sendEndInjector{inner: inner, streamID: inner.StreamID()}
}

func (s *sendEndInjector) StreamID() string        { return s.inner.StreamID() }
func (s *sendEndInjector) Closed() <-chan struct{} { return s.inner.Closed() }
func (s *sendEndInjector) Err() error              { return s.inner.Err() }
func (s *sendEndInjector) Close() error            { return s.inner.Close() }
func (s *sendEndInjector) Send(ctx context.Context, env *envelope.Envelope) error {
	return s.inner.Send(ctx, env)
}

func (s *sendEndInjector) Next(ctx context.Context) (*envelope.Envelope, error) {
	env, err := s.inner.Next(ctx)
	if err != nil {
		// Only mark `emitted` and synthesize a sentinel on EOF — non-EOF
		// errors must propagate without consuming the one-shot guard so
		// that a subsequent EOF (if any) still injects the GRPCEndMessage.
		if !errors.Is(err, io.EOF) {
			return nil, err
		}
		s.mu.Lock()
		alreadyEmitted := s.emitted
		s.emitted = true
		seq := s.lastSeq + 1
		s.mu.Unlock()
		if alreadyEmitted {
			return nil, err
		}
		return &envelope.Envelope{
			StreamID:  s.streamID,
			FlowID:    uuid.New().String(),
			Sequence:  seq,
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolGRPCWeb,
			Message:   &envelope.GRPCEndMessage{Status: 0},
		}, nil
	}
	s.mu.Lock()
	s.lastSeq = env.Sequence
	// If the inner Channel itself emits a real Send-direction End (e.g. the
	// USK-660 unexpected-request-trailer path), mark emitted so we don't
	// double up with a synthetic End on subsequent inner-EOF — sendEndLocked
	// rejects a second End once sendStart has been consumed.
	if env.Direction == envelope.Send {
		if _, isEnd := env.Message.(*envelope.GRPCEndMessage); isEnd {
			s.emitted = true
		}
	}
	s.mu.Unlock()
	return env, nil
}

// ---------------------------------------------------------------------------
// Pipeline assembly (shared between h1 and h2 paths)
// ---------------------------------------------------------------------------

type pipelineOpts struct {
	transformEngine *grpcrules.TransformEngine
	interceptEngine *grpcrules.InterceptEngine
	safetyEngine    *grpcrules.SafetyEngine
}

func buildPipeline(store flow.Writer, opts pipelineOpts) *pipeline.Pipeline {
	logger := slog.Default()
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(nil, nil, opts.safetyEngine, logger),
		pipeline.NewTransformStep(nil, nil, opts.transformEngine),
		pipeline.NewInterceptStep(nil, nil, opts.interceptEngine, nil, nil, logger),
		pipeline.NewRecordStep(store, logger,
			pipeline.WithWireEncoder(envelope.ProtocolGRPCWeb, grpcweb.EncodeWireBytes),
		),
	}
	return pipeline.New(steps...)
}

// ---------------------------------------------------------------------------
// HTTP/1.1 MITM proxy harness
// ---------------------------------------------------------------------------

// sessionResult captures the outcome of one session.RunSession invocation
// inside the test harness. lastErr is the error reported to OnComplete
// (nil on normal EOF). It is delivered before sessionDone is closed.
type sessionResult struct {
	mu      sync.Mutex
	lastErr error
}

func (r *sessionResult) record(err error) {
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
}

func (r *sessionResult) get() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// startGRPCWebHTTP1Proxy starts a FullListener configured for HTTP MITM.
// Inside OnStack, both client and upstream HTTP/1 channels are wrapped with
// grpcweb (Server / Client roles). The client side is additionally wrapped
// with sendEndInjector so the upstream's grpcweb.RoleClient buffer flushes
// once the client EOFs.
func startGRPCWebHTTP1Proxy(
	t *testing.T,
	ctx context.Context,
	opts pipelineOpts,
) (proxyAddr string, store *testStore, result *sessionResult, sessionDone <-chan struct{}) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store = &testStore{}
	result = &sessionResult{}
	done := make(chan struct{})

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	onStack := func(streamCtx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer close(done)
		defer stack.Close()

		rawClientCh := <-stack.ClientTopmost().Channels()
		clientCh := newSendEndInjector(grpcweb.Wrap(rawClientCh, grpcweb.RoleServer))

		p := buildPipeline(store, opts)

		session.RunSession(streamCtx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			rawUp := <-stack.UpstreamTopmost().Channels()
			return grpcweb.Wrap(rawUp, grpcweb.RoleClient), nil
		}, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, streamID string, err error) {
				result.record(err)
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if streamID != "" {
					_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
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
	go fl.Start(ctx) //nolint:errcheck // test
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener ready")
	}

	return fl.Addr(), store, result, done
}

// ---------------------------------------------------------------------------
// HTTP/2 MITM proxy harness (client-side wrapping via connector.DispatchH2Stream;
// upstream side stays manual because OpenStream returns a fresh Channel that
// cannot be peeked).
// ---------------------------------------------------------------------------

// startGRPCWebHTTP2Proxy starts a FullListener with CONNECT routing and
// dispatches each inbound h2 stream via connector.DispatchH2Stream, which
// (post-USK-658) routes application/grpc-web* to httpaggregator + grpcweb.
// The upstream side is constructed manually inside the dial function: a
// fresh OpenStream Channel emits no events until the proxy sends HEADERS,
// so the peek-and-classify pattern of DispatchH2Stream cannot be applied
// there (Friction 4-A).
func startGRPCWebHTTP2Proxy(
	t *testing.T,
	ctx context.Context,
	opts pipelineOpts,
) (proxyAddr string, store *testStore, sessionDone <-chan struct{}) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)
	store = &testStore{}
	done := make(chan struct{}, 16)

	bcfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	onHTTP2Stack := func(cbCtx context.Context, stack *connector.ConnectionStack, upstreamH2 *intHTTP2.Layer, _, _ *envelope.TLSSnapshot, _ string) {
		clientL, ok := stack.ClientTopmost().(*intHTTP2.Layer)
		if !ok {
			t.Errorf("ClientTopmost is not *http2.Layer")
			return
		}
		clientLOpts := httpaggregator.OptionsFromLayer(clientL)
		upstreamLOpts := httpaggregator.OptionsFromLayer(upstreamH2)

		var wg sync.WaitGroup
		for {
			select {
			case <-cbCtx.Done():
				wg.Wait()
				return
			case streamCh, open := <-clientL.Channels():
				if !open {
					wg.Wait()
					return
				}
				wg.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					defer func() {
						select {
						case done <- struct{}{}:
						default:
						}
					}()

					// connector.DispatchH2Stream peeks the first H2HeadersEvent,
					// classifies the content-type, and (post-USK-658) routes
					// application/grpc-web* to httpaggregator + grpcweb. The
					// returned Channel is wrapped with sendEndInjector to bridge
					// client-side EOF into a synthetic GRPCEndMessage(Send) that
					// the upstream-side grpcweb.RoleClient uses as its flush
					// sentinel.
					dispatched, derr := connector.DispatchH2Stream(
						cbCtx, ch, httpaggregator.RoleServer, clientLOpts, slog.Default())
					if derr != nil {
						_ = ch.Close()
						return
					}
					clientCh := newSendEndInjector(dispatched)

					p := buildPipeline(store, opts)
					session.RunSession(cbCtx, clientCh, func(dctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
						upStream, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						aggUp := httpaggregator.Wrap(upStream, httpaggregator.RoleClient, nil, upstreamLOpts)
						return grpcweb.Wrap(aggUp, grpcweb.RoleClient), nil
					}, p, session.SessionOptions{
						OnComplete: func(cctx context.Context, streamID string, err error) {
							state := "complete"
							if err != nil && !errors.Is(err, io.EOF) {
								state = "error"
							}
							if streamID != "" {
								_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{
									State:         state,
									FailureReason: session.ClassifyError(err),
								})
							}
						},
					})
				}(streamCh)
			}
		}
	}

	flCfg := connector.FullListenerConfig{
		Name: "grpcweb-h2-mitm",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:   bcfg,
			OnStack: func(_ context.Context, s *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
				_ = s.Close()
			},
			OnHTTP2Stack: onHTTP2Stack,
			Logger:       slog.Default(),
		}),
	}
	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck // test

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("h2 full listener not ready")
	}
	return fl.Addr(), store, done
}

// ---------------------------------------------------------------------------
// gRPC-Web client helpers
// ---------------------------------------------------------------------------

// sendGRPCWebHTTP1Request connects through the proxy via CONNECT, performs
// TLS handshake (no ALPN), writes a complete HTTP/1.1 gRPC-Web POST with the
// supplied body, and reads back the full HTTP response.
func sendGRPCWebHTTP1Request(t *testing.T, proxyAddr, target string, payload []byte, base64Wire bool) []byte {
	t.Helper()
	frame := grpcweb.EncodeFrame(false, false, payload)
	body := frame
	ct := "application/grpc-web+proto"
	if base64Wire {
		body = grpcweb.EncodeBase64Body(frame)
		ct = "application/grpc-web-text+proto"
	}
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, ct, len(body))
	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if _, err := tlsConn.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}
	_ = tlsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.Bytes()
}

// sendGRPCWebHTTP2Request opens an h2 conn through the proxy via CONNECT
// and posts a single gRPC-Web request. Returns the response body bytes.
func sendGRPCWebHTTP2Request(t *testing.T, proxyAddr, target string, payload []byte, base64Wire bool) (status int, ct string, body []byte) {
	t.Helper()
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
			if _, err := c.Write([]byte(req)); err != nil {
				c.Close()
				return nil, err
			}
			br := bufio.NewReader(c)
			if _, err := br.ReadString('\n'); err != nil {
				c.Close()
				return nil, err
			}
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					c.Close()
					return nil, err
				}
				if l == "\r\n" || l == "\n" {
					break
				}
			}
			tlsConn := tls.Client(c, cfg)
			if err := tlsConn.Handshake(); err != nil {
				c.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	frame := grpcweb.EncodeFrame(false, false, payload)
	reqBody := frame
	requestCT := "application/grpc-web+proto"
	if base64Wire {
		reqBody = grpcweb.EncodeBase64Body(frame)
		requestCT = "application/grpc-web-text+proto"
	}
	cli := &nethttp.Client{Transport: tr, Timeout: 30 * time.Second}
	urlStr := "https://" + target + "/pkg.Echo/Say"
	req, err := nethttp.NewRequest("POST", urlStr, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", requestCT)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("h2 client Do: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), rb
}

// ---------------------------------------------------------------------------
// Shared assertion helpers
// ---------------------------------------------------------------------------

// waitFor pollerFn until it returns true or timeout fires.
func waitFor(t *testing.T, deadline time.Duration, fn func() bool) bool {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if fn() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// assertGRPCWebStream asserts the basic gRPC-Web stream invariants: exactly
// one Stream with Protocol="grpc-web" and per-direction grpc_event metadata.
func assertGRPCWebStream(t *testing.T, store *testStore) {
	t.Helper()
	if !waitFor(t, 5*time.Second, func() bool {
		streams := store.getStreams()
		return len(streams) >= 1
	}) {
		t.Fatalf("no streams recorded within timeout (got %d)", len(store.getStreams()))
	}

	streams := store.getStreams()
	if streams[0].Protocol != string(envelope.ProtocolGRPCWeb) {
		t.Errorf("Stream.Protocol = %q, want %q", streams[0].Protocol, string(envelope.ProtocolGRPCWeb))
	}
}

// flowsForStream returns flows for the first recorded stream id.
func flowsForFirstStream(store *testStore) []*flow.Flow {
	streams := store.getStreams()
	if len(streams) == 0 {
		return nil
	}
	id := streams[0].ID
	all := store.allFlows()
	out := make([]*flow.Flow, 0, len(all))
	for _, f := range all {
		if f.StreamID == id {
			out = append(out, f)
		}
	}
	return out
}

// firstFlowWithEvent returns the first flow whose Metadata["grpc_event"]
// matches the given value, or nil if none is found.
func firstFlowWithEvent(flows []*flow.Flow, dir, event string) *flow.Flow {
	for _, f := range flows {
		if f.Direction != dir {
			continue
		}
		if f.Metadata != nil && f.Metadata["grpc_event"] == event {
			return f
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Round-trip tests (tests 1-4)
// ---------------------------------------------------------------------------

func runRoundTripHTTP1(t *testing.T, base64Wire bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("hello-grpc-web")
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP(respPayload, 0, "OK", base64Wire)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	resp := sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping"), base64Wire)
	if !bytes.Contains(resp, []byte("200 OK")) {
		t.Errorf("client did not see 200 OK; resp=%q", resp)
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	assertGRPCWebStream(t, store)

	flows := flowsForFirstStream(store)
	if startF := firstFlowWithEvent(flows, "send", "start"); startF == nil {
		t.Errorf("missing send-start flow; flows=%d", len(flows))
	}
	if dataF := firstFlowWithEvent(flows, "send", "data"); dataF == nil {
		t.Errorf("missing send-data flow; flows=%d", len(flows))
	}
	if startF := firstFlowWithEvent(flows, "receive", "start"); startF == nil {
		t.Errorf("missing receive-start flow; flows=%d", len(flows))
	}
	if dataF := firstFlowWithEvent(flows, "receive", "data"); dataF == nil {
		t.Errorf("missing receive-data flow; flows=%d", len(flows))
	}
	if endF := firstFlowWithEvent(flows, "receive", "end"); endF == nil {
		t.Errorf("missing receive-end flow; flows=%d", len(flows))
	}
}

// TestGRPCWeb_BinaryOverHTTP1_RoundTrip — application/grpc-web over HTTP/1.1
func TestGRPCWeb_BinaryOverHTTP1_RoundTrip(t *testing.T) {
	runRoundTripHTTP1(t, false)
}

// TestGRPCWeb_Base64OverHTTP1_RoundTrip — application/grpc-web-text over HTTP/1.1
func TestGRPCWeb_Base64OverHTTP1_RoundTrip(t *testing.T) {
	runRoundTripHTTP1(t, true)
}

func runRoundTripHTTP2(t *testing.T, base64Wire bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("hello-grpc-web-h2")
	upAddr, upShutdown := startGRPCWebHTTP2Upstream(t, func(_ *nethttp.Request) ([]byte, string) {
		body := buildGRPCWebResponseBody(respPayload, 0, "OK", base64Wire)
		ct := "application/grpc-web+proto"
		if base64Wire {
			ct = "application/grpc-web-text+proto"
		}
		return body, ct
	})
	defer upShutdown()

	proxyAddr, store, _ := startGRPCWebHTTP2Proxy(t, ctx, pipelineOpts{})

	status, _, _ := sendGRPCWebHTTP2Request(t, proxyAddr, upAddr, []byte("ping"), base64Wire)
	if status != 200 {
		t.Errorf("client status = %d, want 200", status)
	}

	if !waitFor(t, 5*time.Second, func() bool {
		return len(store.getStreams()) >= 1
	}) {
		t.Fatalf("no streams recorded within timeout")
	}

	assertGRPCWebStream(t, store)

	flows := flowsForFirstStream(store)
	if startF := firstFlowWithEvent(flows, "receive", "start"); startF == nil {
		t.Errorf("missing receive-start flow; flows=%d", len(flows))
	}
	if dataF := firstFlowWithEvent(flows, "receive", "data"); dataF == nil {
		t.Errorf("missing receive-data flow; flows=%d", len(flows))
	}
	if endF := firstFlowWithEvent(flows, "receive", "end"); endF == nil {
		t.Errorf("missing receive-end flow; flows=%d", len(flows))
	}
}

// TestGRPCWeb_BinaryOverHTTP2_RoundTrip — application/grpc-web over HTTP/2.
func TestGRPCWeb_BinaryOverHTTP2_RoundTrip(t *testing.T) {
	runRoundTripHTTP2(t, false)
}

// TestGRPCWeb_Base64OverHTTP2_RoundTrip — application/grpc-web-text over HTTP/2.
func TestGRPCWeb_Base64OverHTTP2_RoundTrip(t *testing.T) {
	runRoundTripHTTP2(t, true)
}

// ---------------------------------------------------------------------------
// Test 5: RawBytes preserved per frame
// ---------------------------------------------------------------------------

// TestGRPCWeb_RawBytesPreservedPerFrame — flow.RawBytes must equal the
// per-frame wire bytes. For binary wire, that is the LPM-prefixed frame
// bytes (5-byte header + payload); for base64 wire, the frame is
// base64-encoded individually before recording.
func TestGRPCWeb_RawBytesPreservedPerFrame(t *testing.T) {
	for _, tc := range []struct {
		name       string
		base64Wire bool
	}{
		{"binary", false},
		{"base64", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			respPayload := []byte("rawbytes-payload")
			expectedDataFrame := grpcweb.EncodeFrame(false, false, respPayload)
			if tc.base64Wire {
				expectedDataFrame = []byte(base64.StdEncoding.EncodeToString(expectedDataFrame))
			}

			upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
				return buildGRPCWebResponseHTTP(respPayload, 0, "OK", tc.base64Wire)
			})
			defer upstreamLn.Close()
			target := upstreamLn.Addr().String()

			proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})
			_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping"), tc.base64Wire)

			select {
			case <-sessionDone:
			case <-time.After(15 * time.Second):
				t.Fatal("timeout waiting for session to complete")
			}

			flows := flowsForFirstStream(store)
			dataF := firstFlowWithEvent(flows, "receive", "data")
			if dataF == nil {
				t.Fatal("missing receive-data flow")
			}
			if !bytes.Equal(dataF.RawBytes, expectedDataFrame) {
				t.Errorf("receive-data RawBytes mismatch (base64Wire=%v)\n got=%q\nwant=%q",
					tc.base64Wire, dataF.RawBytes, expectedDataFrame)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 6: Variant recording on transform
// ---------------------------------------------------------------------------

// TestGRPCWeb_VariantRecordingOnTransform — applying a TransformReplacePayload
// rule on the Send-side GRPCDataMessage.Payload must produce two flow rows
// (original + modified) with the modified row tagged variant=modified. With
// the grpc-web WireEncoder registered (USK-661), the modified row's RawBytes
// must hold a freshly-encoded LPM frame with the replacement payload — not
// the cleared env.Raw, and not the original wire bytes.
func TestGRPCWeb_VariantRecordingOnTransform(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("server-ack")
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP(respPayload, 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	xfm := grpcrules.NewTransformEngine()
	rule, err := grpcrules.CompileTransformRule(
		"replace-payload", 1, grpcrules.DirectionSend,
		"", "",
		grpcrules.TransformReplacePayload,
		"", "",
		`secret`, "REDACTED",
		0, "",
	)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	xfm.AddRule(*rule)

	proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{transformEngine: xfm})
	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("the-secret-payload"), false)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	flows := flowsForFirstStream(store)
	var origCount, modCount int
	var modFlow *flow.Flow
	for _, f := range flows {
		if f.Direction != "send" || f.Metadata == nil {
			continue
		}
		if f.Metadata["grpc_event"] != "data" {
			continue
		}
		switch f.Metadata["variant"] {
		case "original":
			origCount++
		case "modified":
			modCount++
			modFlow = f
		}
	}
	if origCount < 1 {
		t.Errorf("expected >=1 send-data variant=original flow; got %d (flows=%d)", origCount, len(flows))
	}
	if modCount < 1 {
		t.Errorf("expected >=1 send-data variant=modified flow; got %d (flows=%d)", modCount, len(flows))
	}
	if modFlow != nil {
		// transform.go clears env.Raw on commit; the registered WireEncoder
		// then re-renders the modified GRPCDataMessage into a binary LPM
		// frame so the recorded modified variant carries the post-mutation
		// wire bytes.
		wantWire := grpcweb.EncodeFrame(false, false, []byte("the-REDACTED-payload"))
		if !bytes.Equal(modFlow.RawBytes, wantWire) {
			t.Errorf("modified flow RawBytes mismatch:\n got %d bytes: %x\nwant %d bytes: %x",
				len(modFlow.RawBytes), modFlow.RawBytes, len(wantWire), wantWire)
		}
		if !bytes.Contains(modFlow.Body, []byte("REDACTED")) {
			t.Errorf("modified flow Body does not contain replacement: %q", modFlow.Body)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 7: Malformed wire-format input produces recorded Anomaly (USK-659)
// ---------------------------------------------------------------------------

// runMalformedAnomalyTest drives a single malformed-body request through the
// proxy and asserts the recorded Anomaly path. The three Anomaly variants
// (base64, LPM, trailer) share identical assertion shape — only the body
// bytes, content-type, and expected metadata key differ.
func runMalformedAnomalyTest(t *testing.T, body []byte, contentType, anomalyMetadataKey string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		// Upstream may receive a connection (the proxy dials lazily on
		// the first upstream.Send carrying the Anomaly Start) but never a
		// real request body — sendStartLocked just buffers metadata, no
		// flush sentinel ever follows because the channel latched EOF.
		return buildGRPCWebResponseHTTP([]byte("never"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, contentType, len(body))
	if _, err := tlsConn.Write(append([]byte(req), body...)); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}
	// Drain any response bytes — the proxy closes the connection cleanly
	// after the session finalizes (no error response is sent because the
	// session terminated via EOF, not StreamError).
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	tmp := make([]byte, 1024)
	for {
		_, err := tlsConn.Read(tmp)
		if err != nil {
			break
		}
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// The session sees clean termination because emitAnomalyStart latches
	// io.EOF — no *layer.StreamError reaches OnComplete.
	if gotErr := result.get(); gotErr != nil && !errors.Is(gotErr, io.EOF) {
		t.Errorf("session error = %v, want nil or io.EOF", gotErr)
	}

	// Exactly one Stream is recorded with Protocol="grpc-web". The OnComplete
	// callback transitions State to "complete" because the err is nil/EOF.
	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	st := streams[0]
	if st.Protocol != string(envelope.ProtocolGRPCWeb) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, string(envelope.ProtocolGRPCWeb))
	}
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want %q", st.State, "complete")
	}
	if st.FailureReason != "" {
		t.Errorf("Stream.FailureReason = %q, want empty", st.FailureReason)
	}

	// Among the recorded flows there must be exactly one Send "start" flow
	// carrying the Anomaly metadata. The harness's sendEndInjector also
	// synthesizes a GRPCEndMessage on inner-EOF so a "end" Send flow is
	// expected too — but the load-bearing assertion is the anomaly Start.
	flows := store.allFlows()
	var startFlow *flow.Flow
	for _, f := range flows {
		if f.Direction == "send" && f.Metadata["grpc_event"] == "start" {
			if startFlow != nil {
				t.Fatalf("multiple Send start flows recorded; want 1")
			}
			startFlow = f
		}
	}
	if startFlow == nil {
		t.Fatalf("no Send start flow recorded; flows=%d", len(flows))
	}

	// Metadata carries the per-anomaly diagnostic key with the parser's
	// error text in Detail.
	detail, ok := startFlow.Metadata[anomalyMetadataKey]
	if !ok {
		t.Errorf("Metadata[%s] missing; metadata keys: %v", anomalyMetadataKey, metadataKeys(startFlow.Metadata))
	} else if detail == "" {
		t.Errorf("Metadata[%s] is empty; want parser error text", anomalyMetadataKey)
	}

	// Wire-fidelity acceptance: RawBytes byte-equals the malformed wire
	// bytes the client sent. This is the load-bearing signal for the
	// MITM-diagnostic principle that drove USK-659.
	if !bytes.Equal(startFlow.RawBytes, body) {
		t.Errorf("RawBytes mismatch:\n got %d bytes: %q\nwant %d bytes: %q",
			len(startFlow.RawBytes), truncate(startFlow.RawBytes), len(body), truncate(body))
	}
}

// metadataKeys returns the keys of m in unspecified order. Used for test
// failure messages to surface which keys WERE present when the expected
// key was missing.
func metadataKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// truncate returns up to the first 64 bytes of b for failure messages.
func truncate(b []byte) []byte {
	const maxLen = 64
	if len(b) <= maxLen {
		return b
	}
	return b[:maxLen]
}

// TestGRPCWeb_MalformedBase64ProducesAnomaly — a request with content-type
// application/grpc-web-text+proto but a body that is not valid base64 must
// emit a recorded Anomaly envelope (Metadata["grpc_anomaly_malformed_base64"])
// rather than a terminal *layer.StreamError. The malformed wire bytes are
// preserved verbatim on Flow.RawBytes for analyst inspection.
func TestGRPCWeb_MalformedBase64ProducesAnomaly(t *testing.T) {
	body := []byte("!!!definitely-not-base64!!!")
	runMalformedAnomalyTest(t, body, "application/grpc-web-text+proto", "grpc_anomaly_malformed_base64")
}

// TestGRPCWeb_MalformedLPMProducesAnomaly — a request whose binary body has
// a 5-byte LPM header declaring a length larger than the available payload
// bytes must emit Anomaly("MalformedGRPCWebLPM").
func TestGRPCWeb_MalformedLPMProducesAnomaly(t *testing.T) {
	// Frame header claiming 1000 bytes of payload but only 4 bytes follow —
	// readAllFrames returns ErrMalformedLPM (incomplete payload).
	body := []byte{
		0x00,                   // flags: not compressed, not trailer
		0x00, 0x00, 0x03, 0xe8, // length: 1000 (big-endian)
		'a', 'b', 'c', 'd', // only 4 payload bytes
	}
	runMalformedAnomalyTest(t, body, "application/grpc-web+proto", "grpc_anomaly_malformed_lpm")
}

// TestGRPCWeb_MalformedTrailerProducesAnomaly — a request with one valid
// data frame followed by a trailer frame whose text payload lacks the
// "name: value" colon separator must emit Anomaly("MalformedGRPCWebTrailer").
func TestGRPCWeb_MalformedTrailerProducesAnomaly(t *testing.T) {
	dataFrame := grpcweb.EncodeFrame(false, false, []byte("hello"))
	// Trailer frame payload: a line with no colon. ParseTrailers returns an
	// error; readAllFrames wraps it with ErrMalformedTrailer.
	trailerFrame := grpcweb.EncodeFrame(true, false, []byte("nocolon\r\n"))
	body := append(append([]byte{}, dataFrame...), trailerFrame...)
	runMalformedAnomalyTest(t, body, "application/grpc-web+proto", "grpc_anomaly_malformed_trailer")
}

// TestGRPCWeb_OversizeMessageProducesStreamError — the per-LPM size cap
// (CWE-400 mitigation) is intentionally NOT classified as an Anomaly; an
// oversize declared length is a security-cap termination, not a wire-format
// observability signal. The session aborts with *layer.StreamError as
// before, and ClassifyError yields "internal_error".
func TestGRPCWeb_OversizeMessageProducesStreamError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("never"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	// Frame header declaring 0xFFFFFFFF (4 GiB) length — exceeds the
	// default MaxGRPCMessageSize cap, triggers the security-cap path.
	body := []byte{
		0x00,
		0xff, 0xff, 0xff, 0xff,
	}
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, len(body))
	if _, err := tlsConn.Write(append([]byte(req), body...)); err != nil {
		t.Fatalf("write oversize request: %v", err)
	}
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	tmp := make([]byte, 1024)
	for {
		_, err := tlsConn.Read(tmp)
		if err != nil {
			break
		}
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	gotErr := result.get()
	if gotErr == nil {
		t.Fatal("expected non-nil session error from oversize LPM body")
	}
	var se *layer.StreamError
	if !errors.As(gotErr, &se) {
		t.Fatalf("session error is not *layer.StreamError; got %T: %v", gotErr, gotErr)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %s, want %s", se.Code, layer.ErrorInternalError)
	}
	if !strings.Contains(se.Reason, "too large") {
		t.Errorf("StreamError.Reason = %q, want substring %q", se.Reason, "too large")
	}
	if got := session.ClassifyError(gotErr); got != "internal_error" {
		t.Errorf("ClassifyError = %q, want %q", got, "internal_error")
	}
}

// ---------------------------------------------------------------------------
// Test 8: Stream.Protocol = "grpc-web"
// ---------------------------------------------------------------------------

// TestGRPCWeb_StreamProtocolIsGRPCWeb — a successful round-trip must
// produce a Stream with Protocol == string(envelope.ProtocolGRPCWeb).
// This is the lightest possible assertion that the grpcweb Wrap is
// engaged in the proxy datapath.
func TestGRPCWeb_StreamProtocolIsGRPCWeb(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("ack"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})
	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("hi"), false)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	streams := store.getStreams()
	if len(streams) == 0 {
		t.Fatal("no streams recorded")
	}
	if got := streams[0].Protocol; got != string(envelope.ProtocolGRPCWeb) {
		t.Errorf("Stream.Protocol = %q, want %q", got, string(envelope.ProtocolGRPCWeb))
	}
	if want := "grpc-web"; streams[0].Protocol != want {
		t.Errorf("Stream.Protocol = %q, want literal %q", streams[0].Protocol, want)
	}
}

// ---------------------------------------------------------------------------
// Test 9: Per-frame Metadata["grpc_event"] ∈ {start, data, end}
// ---------------------------------------------------------------------------

// TestGRPCWeb_GRPCEventMetadataOnFlows — projectGRPC* in RecordStep must
// stamp Metadata["grpc_event"] on every recorded flow. For one round-trip
// over a single-message RPC we expect at minimum:
//   - Send: start, data
//   - Receive: start, data, end
func TestGRPCWeb_GRPCEventMetadataOnFlows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("ack"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})
	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("hi"), false)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	flows := flowsForFirstStream(store)
	allowed := map[string]bool{"start": true, "data": true, "end": true}
	seenSend := map[string]bool{}
	seenRecv := map[string]bool{}
	for _, f := range flows {
		if f.Metadata == nil {
			t.Errorf("flow %s has nil Metadata; expected grpc_event stamp", f.ID)
			continue
		}
		ev, ok := f.Metadata["grpc_event"]
		if !ok {
			t.Errorf("flow %s missing Metadata[grpc_event]; metadata=%v", f.ID, f.Metadata)
			continue
		}
		if !allowed[ev] {
			t.Errorf("flow %s grpc_event = %q, expected one of {start, data, end}", f.ID, ev)
		}
		if f.Direction == "send" {
			seenSend[ev] = true
		}
		if f.Direction == "receive" {
			seenRecv[ev] = true
		}
	}
	for _, ev := range []string{"start", "data"} {
		if !seenSend[ev] {
			t.Errorf("missing send-side grpc_event=%q (got=%v)", ev, seenSend)
		}
	}
	for _, ev := range []string{"start", "data", "end"} {
		if !seenRecv[ev] {
			t.Errorf("missing receive-side grpc_event=%q (got=%v)", ev, seenRecv)
		}
	}

	// Confirm every receive-side flow's grpc_service / grpc_method are
	// populated when present. They are denormalized from the Start envelope.
	for _, f := range flows {
		if f.Direction != "receive" || f.Metadata == nil {
			continue
		}
		if f.Metadata["grpc_event"] == "start" {
			// The response side has no :path so service/method may legitimately
			// be empty here; the stamp itself is still expected to exist.
			if _, ok := f.Metadata["grpc_service"]; !ok {
				t.Errorf("receive-start flow missing grpc_service stamp: %v", f.Metadata)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// USK-660: missing-trailer / unexpected-request-trailer anomaly tests
// ---------------------------------------------------------------------------

// TestGRPCWeb_MissingTrailerProducesAnomaly — a Receive-direction body that
// parses cleanly (one or more data frames) but lacks a terminating trailer
// LPM must surface as a recorded GRPCEndMessage envelope on the Receive side
// stamped with AnomalyMissingGRPCWebTrailer. Without this signal the analyst
// would only see a silently-truncated event tail and could not distinguish
// "well-formed RPC with grpc-status=0" from "upstream/proxy/server bug or
// truncation attack".
func TestGRPCWeb_MissingTrailerProducesAnomaly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("hello-no-trailer")
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		// Build a response body that contains ONE data frame and NO
		// terminating trailer LPM. Hand-crafted (intentionally NOT using
		// buildGRPCWebResponseBody, which always appends a trailer).
		dataFrame := grpcweb.EncodeFrame(false, false, respPayload)
		return []byte(fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
			len(dataFrame)) + string(dataFrame))
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping"), false)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// The session terminates cleanly — the missing trailer is recorded as an
	// anomaly, not a *layer.StreamError.
	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	if streams[0].State != "complete" {
		t.Errorf("Stream.State = %q, want %q", streams[0].State, "complete")
	}

	// Locate the synthetic Receive End flow stamped with the anomaly. The
	// missing-trailer condition is detected at refill time and emits a
	// synthetic GRPCEndMessage with Status=0, Raw=nil, and the anomaly key.
	flows := flowsForFirstStream(store)
	var endFlow *flow.Flow
	for _, f := range flows {
		if f.Direction != "receive" || f.Metadata == nil {
			continue
		}
		if f.Metadata["grpc_event"] != "end" {
			continue
		}
		if _, ok := f.Metadata["grpc_anomaly_missing_trailer"]; !ok {
			continue
		}
		endFlow = f
		break
	}
	if endFlow == nil {
		t.Fatalf("no Receive end flow with grpc_anomaly_missing_trailer found; flows=%d", len(flows))
	}

	// Detail is the parser's diagnostic text — non-empty by contract.
	if endFlow.Metadata["grpc_anomaly_missing_trailer"] == "" {
		t.Errorf("Metadata[grpc_anomaly_missing_trailer] is empty; want diagnostic text")
	}
	// Synthetic End: Raw is empty so the analyst can distinguish synthesized
	// from wire-observed Ends.
	if len(endFlow.RawBytes) != 0 {
		t.Errorf("synthetic End RawBytes = %d bytes (%q), want empty", len(endFlow.RawBytes), truncate(endFlow.RawBytes))
	}
	// grpc_status defaults to 0 (placeholder per design).
	if got := endFlow.Metadata["grpc_status"]; got != "0" {
		t.Errorf("synthetic End grpc_status = %q, want %q", got, "0")
	}

	// Receive-side data envelope is still emitted (the body parsed cleanly
	// before we noticed the absent trailer). Without this the synthesized
	// End would be the only Receive-direction flow and the test would fail
	// to distinguish "upstream sent nothing" from "upstream sent data only".
	if dataF := firstFlowWithEvent(flows, "receive", "data"); dataF == nil {
		t.Errorf("missing receive-data flow; flows=%d", len(flows))
	} else if !bytes.Equal(dataF.Body, respPayload) {
		t.Errorf("receive-data Body = %q, want %q", dataF.Body, respPayload)
	}
}

// TestGRPCWeb_UnexpectedRequestTrailerProducesAnomaly — a Send-direction
// (request) body that carries an embedded trailer LPM frame must produce a
// recorded GRPCEndMessage envelope on the Send side stamped with
// AnomalyUnexpectedGRPCWebRequestTrailer. The Anomaly captures both the
// fact of the protocol violation AND the trailer's wire bytes via
// flow.RawBytes for analyst inspection.
func TestGRPCWeb_UnexpectedRequestTrailerProducesAnomaly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		// Upstream replies with a normal grpc-web response so the proxy's
		// Receive-side path is well-formed (no second anomaly to confuse
		// the assertion). The request the upstream actually sees has the
		// trailer stripped (defensive at sendEndLocked when dir==Send).
		return buildGRPCWebResponseHTTP([]byte("ack"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	// Compose a request body: one data frame + one trailer LPM. Under RFC
	// gRPC-Web semantics the trailer belongs only on the response side.
	dataFrame := grpcweb.EncodeFrame(false, false, []byte("ping"))
	trailerFrame := grpcweb.EncodeFrame(true, false, []byte("grpc-status: 0\r\n"))
	body := append(append([]byte{}, dataFrame...), trailerFrame...)

	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, len(body))
	if _, err := tlsConn.Write(append([]byte(req), body...)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	tmp := make([]byte, 1024)
	for {
		_, err := tlsConn.Read(tmp)
		if err != nil {
			break
		}
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	if streams[0].State != "complete" {
		t.Errorf("Stream.State = %q, want %q", streams[0].State, "complete")
	}

	// Locate the Send End flow stamped with the unexpected-trailer anomaly.
	// The harness's sendEndInjector also synthesizes a Send End on inner-EOF,
	// so multiple Send End flows may be recorded — we filter by anomaly key.
	flows := flowsForFirstStream(store)
	var endFlow *flow.Flow
	for _, f := range flows {
		if f.Direction != "send" || f.Metadata == nil {
			continue
		}
		if f.Metadata["grpc_event"] != "end" {
			continue
		}
		if _, ok := f.Metadata["grpc_anomaly_unexpected_request_trailer"]; !ok {
			continue
		}
		endFlow = f
		break
	}
	if endFlow == nil {
		t.Fatalf("no Send end flow with grpc_anomaly_unexpected_request_trailer found; flows=%d", len(flows))
	}

	if endFlow.Metadata["grpc_anomaly_unexpected_request_trailer"] == "" {
		t.Errorf("Metadata[grpc_anomaly_unexpected_request_trailer] is empty; want diagnostic text")
	}
	// Wire fidelity: the trailer's wire bytes are preserved verbatim on
	// flow.RawBytes (perFrameRaw produced trailerRawBytes regardless of
	// direction).
	if !bytes.Equal(endFlow.RawBytes, trailerFrame) {
		t.Errorf("RawBytes mismatch:\n got %d bytes: %q\nwant %d bytes: %q",
			len(endFlow.RawBytes), truncate(endFlow.RawBytes), len(trailerFrame), truncate(trailerFrame))
	}
}

// ---------------------------------------------------------------------------
// USK-661: base64 wire fidelity (no double-encode in Send fast path)
// ---------------------------------------------------------------------------

// TestGRPCWeb_Base64WireNoDoubleEncode — a round-trip on grpc-web-text wire
// must forward the request body to the upstream as base64-once (binary LPM
// frame after a single base64 decode), not base64-twice. The previous bug
// appended Envelope.Raw verbatim in sendDataLocked; refillFromHTTPMessage
// emits Raw in base64 form for -text content-types (USK-641), and the
// terminal sendEndLocked wrap then encoded the buffer a second time.
//
// This test runs without rawClearOnSend (the harness work-around removed by
// USK-661), so any regression of the double-encode bug fails here directly.
func TestGRPCWeb_Base64WireNoDoubleEncode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("ack-base64")
	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP(respPayload, 0, "OK", true)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	clientPayload := []byte("ping-base64")
	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, clientPayload, true)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	upstreamLn.Close()

	reqs := captured()
	if len(reqs) == 0 {
		t.Fatal("upstream captured no requests")
	}
	upstreamReq := reqs[0]

	hdrEnd := bytes.Index(upstreamReq, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		t.Fatalf("could not locate header terminator in upstream request: %q", truncate(upstreamReq))
	}
	upstreamHeaders := upstreamReq[:hdrEnd]
	upstreamBody := upstreamReq[hdrEnd+4:]

	if !bytes.Contains(bytes.ToLower(upstreamHeaders),
		[]byte("application/grpc-web-text")) {
		t.Errorf("upstream content-type lost the -text wire format: headers=%q",
			truncate(upstreamHeaders))
	}

	decodedOnce, err := base64.StdEncoding.DecodeString(string(upstreamBody))
	if err != nil {
		t.Fatalf("upstream body is not valid base64: %v\nbody=%q",
			err, truncate(upstreamBody))
	}
	wantFrame := grpcweb.EncodeFrame(false, false, clientPayload)
	if !bytes.Equal(decodedOnce, wantFrame) {
		t.Errorf("after one base64 decode, upstream body is not the expected LPM frame "+
			"(double-encode regression?):\n got %d bytes: %x\nwant %d bytes: %x",
			len(decodedOnce), decodedOnce, len(wantFrame), wantFrame)
	}
}
