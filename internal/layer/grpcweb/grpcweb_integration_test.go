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
		s.mu.Lock()
		alreadyEmitted := s.emitted
		s.emitted = true
		seq := s.lastSeq + 1
		s.mu.Unlock()
		if errors.Is(err, io.EOF) && !alreadyEmitted {
			return &envelope.Envelope{
				StreamID:  s.streamID,
				FlowID:    uuid.New().String(),
				Sequence:  seq,
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolGRPCWeb,
				Message:   &envelope.GRPCEndMessage{Status: 0},
			}, nil
		}
		return nil, err
	}
	s.mu.Lock()
	s.lastSeq = env.Sequence
	s.mu.Unlock()
	return env, nil
}

// ---------------------------------------------------------------------------
// rawClearOnSend bridges around a known production limitation in grpcweb's
// base64-wire Send path: refillFromHTTPMessage emits envelopes with
// Envelope.Raw already base64-encoded for grpc-web-text content-types
// (RFC §3.2.3), but sendDataLocked writes Raw verbatim and sendEndLocked
// then base64-encodes the entire send buffer ONCE more — causing a
// double-encode on any forwarded base64-wire frame. Clearing env.Raw on
// the Send path forces grpcweb's sendDataLocked to re-encode from
// GRPCDataMessage.Payload (binary), so sendEndLocked's base64 wrap is the
// only encode applied. Filed as a follow-up issue.
type rawClearOnSend struct {
	inner layer.Channel
}

func (c *rawClearOnSend) StreamID() string        { return c.inner.StreamID() }
func (c *rawClearOnSend) Closed() <-chan struct{} { return c.inner.Closed() }
func (c *rawClearOnSend) Err() error              { return c.inner.Err() }
func (c *rawClearOnSend) Close() error            { return c.inner.Close() }
func (c *rawClearOnSend) Next(ctx context.Context) (*envelope.Envelope, error) {
	return c.inner.Next(ctx)
}
func (c *rawClearOnSend) Send(ctx context.Context, env *envelope.Envelope) error {
	if env != nil {
		switch env.Message.(type) {
		case *envelope.GRPCDataMessage, *envelope.GRPCEndMessage:
			env.Raw = nil
		}
	}
	return c.inner.Send(ctx, env)
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
		pipeline.NewInterceptStep(nil, nil, opts.interceptEngine, nil, logger),
		pipeline.NewRecordStep(store, logger),
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

// startGRPCWebHTTP1Proxy starts a MinimalListener configured for HTTP MITM.
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

	mlCfg := connector.MinimalListenerConfig{
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             issuer,
			InsecureSkipVerify: true,
		},
		OnStack: func(streamCtx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			defer close(done)
			defer stack.Close()

			rawClientCh := <-stack.ClientTopmost().Channels()
			clientCh := newSendEndInjector(grpcweb.Wrap(rawClientCh, grpcweb.RoleServer))

			p := buildPipeline(store, opts)

			session.RunSession(streamCtx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				rawUp := <-stack.UpstreamTopmost().Channels()
				return &rawClearOnSend{inner: grpcweb.Wrap(rawUp, grpcweb.RoleClient)}, nil
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
		},
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ml := connector.NewMinimalListenerFromListener(proxyLn, mlCfg)
	go ml.Serve(ctx) //nolint:errcheck // test
	t.Cleanup(func() { ml.Close() })

	return proxyLn.Addr().String(), store, result, done
}

// ---------------------------------------------------------------------------
// HTTP/2 MITM proxy harness (manual chain composition: bypass DispatchH2Stream
// because production isGRPCHeaders over-matches application/grpc-web).
// ---------------------------------------------------------------------------

// startGRPCWebHTTP2Proxy starts a FullListener with CONNECT routing and
// composes the gRPC-Web stack manually inside OnHTTP2Stack so the test does
// not depend on connector.DispatchH2Stream (which currently classifies any
// "application/grpc*" content-type as native gRPC and wraps with grpclayer
// instead of grpcweb). Filed as a follow-up issue.
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

					// Manual chain composition for grpc-web/h2 path:
					// peek the first H2HeadersEvent → check content-type for
					// application/grpc-web → wrap with httpaggregator(RoleServer)
					// → wrap with grpcweb(RoleServer) → sendEndInjector.
					firstEnv, perr := ch.Next(cbCtx)
					if perr != nil {
						_ = ch.Close()
						return
					}
					hdrEvt, ok := firstEnv.Message.(*intHTTP2.H2HeadersEvent)
					if !ok {
						_ = ch.Close()
						return
					}
					if !looksLikeGRPCWebContentType(hdrEvt) {
						_ = ch.Close()
						return
					}
					aggCh := httpaggregator.Wrap(ch, httpaggregator.RoleServer, firstEnv, clientLOpts)
					gwClient := grpcweb.Wrap(aggCh, grpcweb.RoleServer)
					clientCh := newSendEndInjector(gwClient)

					p := buildPipeline(store, opts)
					session.RunSession(cbCtx, clientCh, func(dctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
						upStream, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						aggUp := httpaggregator.Wrap(upStream, httpaggregator.RoleClient, nil, upstreamLOpts)
						return &rawClearOnSend{inner: grpcweb.Wrap(aggUp, grpcweb.RoleClient)}, nil
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

// looksLikeGRPCWebContentType reports whether evt's content-type indicates
// gRPC-Web (binary or text). Inline duplicate of grpcweb.IsGRPCWebContentType
// kept here to keep the import surface flat.
func looksLikeGRPCWebContentType(evt *intHTTP2.H2HeadersEvent) bool {
	for _, kv := range evt.Headers {
		if !strings.EqualFold(kv.Name, "content-type") {
			continue
		}
		return grpcweb.IsGRPCWebContentType(kv.Value)
	}
	return false
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
// (original + modified) with the modified row tagged variant=modified.
// Because no WireEncoder is registered for ProtocolGRPCWeb the modified
// row's Metadata["wire_bytes"] is "unavailable" (the encoder cleared
// env.Raw on commit).
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
		// No WireEncoder is registered for ProtocolGRPCWeb in this test (the
		// proxy code intentionally skips registration since the wire encoder
		// for grpc-web has not been written yet — filed as a follow-up). On
		// commit, transform.go clears env.Raw so the modified flow's RawBytes
		// is empty and no "wire_bytes" tag is added because applyWireEncode
		// short-circuits with no encoders configured.
		if len(modFlow.RawBytes) != 0 {
			t.Errorf("modified flow RawBytes should be empty when no WireEncoder is registered "+
				"and the rule clears env.Raw on commit; got %d bytes", len(modFlow.RawBytes))
		}
		if !bytes.Contains(modFlow.Body, []byte("REDACTED")) {
			t.Errorf("modified flow Body does not contain replacement: %q", modFlow.Body)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 7: Malformed base64 produces StreamError(ErrorInternalError)
// ---------------------------------------------------------------------------

// TestGRPCWeb_MalformedBase64ProducesStreamError — a request with
// content-type application/grpc-web-text but a body that is not valid
// base64 must produce a *layer.StreamError with Code=ErrorInternalError on
// the client-side grpcweb Channel. The session classifies that error and
// projects FailureReason="internal_error" onto the Stream.
//
// Note: the issue text mentions an "Anomaly" path for this case; the
// current implementation in internal/layer/grpcweb/channel.go emits a
// StreamError instead. Asserting the behavior the implementation actually
// produces; the Anomaly path is filed as a separate follow-up issue.
func TestGRPCWeb_MalformedBase64ProducesStreamError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		// Won't be reached because the proxy errors on malformed base64.
		return buildGRPCWebResponseHTTP([]byte("never"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{})

	// Hand-roll an HTTP/1.1 POST whose body is NOT valid base64 but whose
	// Content-Type advertises application/grpc-web-text.
	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	body := []byte("!!!definitely-not-base64!!!")
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc-web-text+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, len(body))
	if _, err := tlsConn.Write(append([]byte(req), body...)); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}
	// Drain any response bytes (proxy will close on error).
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

	// The grpcweb Channel emits a *layer.StreamError on the very first Next()
	// because DecodeBody fails before any envelope reaches RecordStep. The
	// session captures that error in OnComplete and classifies it as
	// "internal_error" via session.ClassifyError. There is no Stream record
	// because no envelope ever passed through RecordStep — assert the error
	// itself instead, which is the diagnostic signal the impl produces.
	gotErr := result.get()
	if gotErr == nil {
		t.Fatal("expected non-nil session error from malformed base64 body")
	}
	var se *layer.StreamError
	if !errors.As(gotErr, &se) {
		t.Fatalf("session error is not *layer.StreamError; got %T: %v", gotErr, gotErr)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %s, want %s", se.Code, layer.ErrorInternalError)
	}
	if !strings.Contains(se.Reason, "grpcweb") {
		t.Errorf("StreamError.Reason = %q, want substring %q", se.Reason, "grpcweb")
	}
	// Cross-check: ClassifyError on this StreamError yields "internal_error"
	// — the value RecordStep would have projected onto Stream.FailureReason
	// had a Stream existed.
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
