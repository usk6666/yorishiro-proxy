//go:build e2e

package http2_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	nethttp "net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	h2frame "github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	h2hpack "github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pushrecorder"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// testStore implements flow.Writer for capturing streams/flows/updates.
type testStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
	updates []streamUpdateRecord
}

type streamUpdateRecord struct {
	streamID string
	update   flow.StreamUpdate
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
	s.updates = append(s.updates, streamUpdateRecord{streamID: id, update: update})
	// Also apply to recorded stream for convenience.
	for _, st := range s.streams {
		if st.ID == id {
			if update.State != "" {
				st.State = update.State
			}
			if update.FailureReason != "" {
				st.FailureReason = update.FailureReason
			}
			if update.Tags != nil {
				if st.Tags == nil {
					st.Tags = make(map[string]string, len(update.Tags))
				}
				for k, v := range update.Tags {
					st.Tags[k] = v
				}
			}
			// Project ConnInfo fields if any TLS/addr update is present.
			hasConnInfoUpdate := update.ServerAddr != "" ||
				update.TLSVersion != "" ||
				update.TLSCipher != "" ||
				update.TLSALPN != "" ||
				update.TLSServerCertSubject != ""
			if hasConnInfoUpdate {
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
	cp := *f
	// Shallow copy of slices - sufficient since tests don't mutate.
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

func (s *testStore) flowsForStream(streamID string) []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*flow.Flow
	for _, f := range s.flows {
		if f.StreamID == streamID {
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

func (s *testStore) getUpdates(streamID string) []flow.StreamUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []flow.StreamUpdate
	for _, u := range s.updates {
		if u.streamID == streamID {
			out = append(out, u.update)
		}
	}
	return out
}

// newUpstreamTLSConfig builds a self-signed TLS server config with a cert CN
// that marks the upstream (used to verify TLS snapshot correctness).
func newUpstreamTLSConfig(t *testing.T, cn string) (*tls.Config, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{cn, "localhost"},
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
		NextProtos: []string{"h2"},
	}, parsed
}

// ---------------------------------------------------------------------------
// Upstream servers
// ---------------------------------------------------------------------------

// startH2CUpstream starts an h2c (cleartext HTTP/2) upstream server using
// x/net/http2 with h2c.NewHandler.
func startH2CUpstream(t *testing.T, handler nethttp.Handler) (addr string, shutdown func()) {
	t.Helper()
	h2s := &http2.Server{}
	srv := &nethttp.Server{
		Handler: h2c.NewHandler(handler, h2s),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln) //nolint:errcheck // test
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
}

// startH2TLSUpstream starts a TLS upstream offering ALPN "h2".
// acceptCount returns the number of accepted TLS connections.
func startH2TLSUpstream(t *testing.T, cn string, handler nethttp.Handler) (addr string, cert *x509.Certificate, acceptCount func() int64, shutdown func()) {
	t.Helper()
	tlsCfg, leafCert := newUpstreamTLSConfig(t, cn)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int64
	h2s := &http2.Server{}

	done := make(chan struct{})
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			tlsConn := tls.Server(c, tlsCfg)
			wg.Add(1)
			go func(tc *tls.Conn) {
				defer wg.Done()
				defer tc.Close()
				if err := tc.Handshake(); err != nil {
					return
				}
				h2s.ServeConn(tc, &http2.ServeConnOpts{
					Handler: handler,
				})
			}(tlsConn)
		}
	}()

	return tcpLn.Addr().String(), leafCert, func() int64 { return accepts.Load() }, func() {
		close(done)
		_ = tcpLn.Close()
		// Wait briefly for goroutines to exit.
		doneCh := make(chan struct{})
		go func() { wg.Wait(); close(doneCh) }()
		select {
		case <-doneCh:
		case <-time.After(2 * time.Second):
		}
	}
}

// ---------------------------------------------------------------------------
// Proxy startup helpers
// ---------------------------------------------------------------------------

type pipelineOpts struct {
	interceptEngine *httprules.InterceptEngine
	transformEngine *httprules.TransformEngine
	safetyEngine    *httprules.SafetyEngine
	holdQueue       *common.HoldQueue
	// recordMaxBodySize caps flow.Flow.Body when RecordStep materializes a
	// BodyBuffer. Zero means "use config.MaxBodySize".
	recordMaxBodySize int64
}

func buildPipeline(store flow.Writer, opts pipelineOpts) *pipeline.Pipeline {
	// USK-622: register the HTTP/2 wire-encoder so that modified-variant
	// RawBytes reflects the re-encoded frame bytes instead of the ingress
	// env.Raw that was captured before mutation.
	// USK-635: MaxBodySize override is opt-in for the exceed-cap test path.
	recordOpts := []pipeline.Option{
		pipeline.WithWireEncoder(envelope.ProtocolHTTP, httpaggregator.EncodeWireBytes),
	}
	if opts.recordMaxBodySize > 0 {
		recordOpts = append(recordOpts, pipeline.WithMaxBodySize(opts.recordMaxBodySize))
	}

	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(opts.safetyEngine, nil, nil, slog.Default()),
		pipeline.NewTransformStep(opts.transformEngine, nil, nil),
		pipeline.NewInterceptStep(opts.interceptEngine, nil, nil, opts.holdQueue, slog.Default()),
		pipeline.NewRecordStep(store, slog.Default(), recordOpts...),
	}
	return pipeline.New(steps...)
}

// startH2CProxy starts a FullListener with the h2c handler on OnHTTP2 so the
// Coordinator routes cleartext HTTP/2 directly to HTTP/2 Layer.
func startH2CProxy(t *testing.T, ctx context.Context, upstreamAddr string, opts pipelineOpts) (proxyAddr string, store *testStore) {
	t.Helper()
	store = &testStore{}

	onStream := func(streamCtx context.Context, clientCh layer.Channel) {
		// USK-637: wrap the event-granular client channel with the
		// aggregator so Pipeline sees HTTPMessage envelopes.
		aggClient, derr := connector.DispatchH2Stream(streamCtx, clientCh, httpaggregator.RoleServer, httpaggregator.WrapOptions{}, slog.Default())
		if derr != nil {
			_ = clientCh.Close()
			return
		}
		dial := func(dialCtx context.Context, env *envelope.Envelope) (layer.Channel, error) {
			// Dial upstream h2c via a raw TCP connection + ClientRole layer.
			upConn, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			upLayer, err := intHTTP2.New(upConn, "test-upstream", intHTTP2.ClientRole,
				intHTTP2.WithScheme("http"),
			)
			if err != nil {
				upConn.Close()
				return nil, err
			}
			ch, err := upLayer.OpenStream(dialCtx)
			if err != nil {
				upLayer.Close()
				return nil, err
			}
			go func() {
				<-dialCtx.Done()
				upLayer.Close()
			}()
			// Wrap upstream client-role event channel with aggregator.
			return httpaggregator.Wrap(ch, httpaggregator.RoleClient, nil, httpaggregator.OptionsFromLayer(upLayer)), nil
		}
		pipe := buildPipeline(store, opts)
		session.RunSession(streamCtx, aggClient, dial, pipe, session.SessionOptions{
			OnComplete: func(cctx context.Context, streamID string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				store.UpdateStream(cctx, streamID, flow.StreamUpdate{
					State:         state,
					FailureReason: session.ClassifyError(err),
				})
			},
		})
	}

	flCfg := connector.FullListenerConfig{
		Name: "h2c-test",
		Addr: "127.0.0.1:0",
		OnHTTP2: connector.NewH2CHandler(connector.H2CHandlerConfig{
			OnStream: onStream,
			Logger:   slog.Default(),
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("full listener not ready")
	}
	return fl.Addr(), store
}

// startH2MITMProxy starts a FullListener with CONNECT handler routing through
// ALPN-selected h2 stacks using BuildConnectionStack + OnHTTP2Stack.
func startH2MITMProxy(t *testing.T, ctx context.Context, buildCfg *connector.BuildConfig, opts pipelineOpts) (proxyAddr string, store *testStore) {
	t.Helper()
	store = &testStore{}

	// USK-623: install an OnHTTP2UpstreamDialed hook that spawns the
	// upstream push recorder for every freshly-dialed upstream h2 Layer.
	// The recorder goroutine's lifetime matches the Layer's (runs until
	// Layer.Channels() closes on shutdown). On pool hit the hook does
	// NOT fire, so the original recorder keeps draining — no double
	// attach.
	if buildCfg != nil {
		buildCfg.OnHTTP2UpstreamDialed = func(l *intHTTP2.Layer) {
			go pushrecorder.RunUpstream(ctx, l, store, slog.Default())
		}
	}

	onHTTP2Stack := func(cbCtx context.Context, stack *connector.ConnectionStack, upstreamH2 *intHTTP2.Layer, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
		_ = clientSnap
		_ = upstreamSnap
		// The client-side layer is the stack's ClientTopmost (a *http2.Layer
		// in ServerRole). Fan out one goroutine per client stream and wire
		// a session to the upstream Layer via OpenStream.
		clientL, ok := stack.ClientTopmost().(*intHTTP2.Layer)
		if !ok {
			t.Errorf("stack.ClientTopmost is not *http2.Layer")
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
			case clientCh, ok := <-clientL.Channels():
				if !ok {
					wg.Wait()
					return
				}
				wg.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					// USK-637: peek the first H2HeadersEvent for gRPC
					// detection, then wrap with HTTPAggregator.
					aggCh, derr := connector.DispatchH2Stream(cbCtx, ch, httpaggregator.RoleServer, clientLOpts, slog.Default())
					if derr != nil {
						_ = ch.Close()
						return
					}
					dial := func(dctx context.Context, env *envelope.Envelope) (layer.Channel, error) {
						upCh, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						// Wrap upstream client-role event channel with
						// aggregator (no peek — we open the stream).
						return httpaggregator.Wrap(upCh, httpaggregator.RoleClient, nil, upstreamLOpts), nil
					}
					pipe := buildPipeline(store, opts)
					session.RunSession(cbCtx, aggCh, dial, pipe, session.SessionOptions{
						OnComplete: func(cctx context.Context, streamID string, err error) {
							state := "complete"
							if err != nil && !errors.Is(err, io.EOF) {
								state = "error"
							}
							if streamID != "" {
								store.UpdateStream(cctx, streamID, flow.StreamUpdate{
									State:         state,
									FailureReason: session.ClassifyError(err),
								})
							}
						},
					})
				}(clientCh)
			}
		}
	}

	// Build a default non-h2 onStack for other routes; it won't be used.
	onStack := func(_ context.Context, s *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		_ = s.Close()
	}

	flCfg := connector.FullListenerConfig{
		Name: "h2-mitm",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator:   connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:     buildCfg,
			OnStack:      onStack,
			OnHTTP2Stack: onHTTP2Stack,
			Logger:       slog.Default(),
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("full listener not ready")
	}
	return fl.Addr(), store
}

// makeBuildCfg creates a BuildConfig for ALPN h2 MITM tests.
func makeBuildCfg(t *testing.T, h2Pool *pool.Pool) *connector.BuildConfig {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)
	return &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
		HTTP2Pool:          h2Pool,
	}
}

// makeBuildCfgWithBody is makeBuildCfg plus body-spill configuration (USK-635).
// Zero values for spillDir/threshold/maxBody fall back to the layer defaults.
func makeBuildCfgWithBody(t *testing.T, h2Pool *pool.Pool, spillDir string, threshold, maxBody int64) *connector.BuildConfig {
	t.Helper()
	cfg := makeBuildCfg(t, h2Pool)
	cfg.BodySpillDir = spillDir
	cfg.BodySpillThreshold = threshold
	cfg.MaxBodySize = maxBody
	return cfg
}

// ---------------------------------------------------------------------------
// HTTP/2 client helpers
// ---------------------------------------------------------------------------

// newH2CClient builds an http.Client speaking h2c via direct TCP.
func newH2CClient() *nethttp.Client {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	return &nethttp.Client{Transport: tr, Timeout: 15 * time.Second}
}

// connectTunnelDialer opens a CONNECT tunnel to proxyAddr for target.
// Returns the raw conn after reading the 200 line. Caller is responsible for
// TLS-wrapping if needed.
func connectTunnelDialer(proxyAddr, target string) (net.Conn, error) {
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
	line, err := br.ReadString('\n')
	if err != nil {
		c.Close()
		return nil, err
	}
	if !bytes.Contains([]byte(line), []byte("200")) {
		c.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", line)
	}
	// Skip remaining headers.
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
	// Return a conn that drains any buffered bytes first. Should be none at
	// this point (upstream hasn't sent anything).
	if br.Buffered() > 0 {
		return nil, fmt.Errorf("unexpected buffered bytes after CONNECT")
	}
	return c, nil
}

// newMITMH2Client builds an http.Client going GET→CONNECT→TLS h2 through the
// proxy at proxyAddr, for the given upstream target host:port.
func newMITMH2Client(proxyAddr, target string) *nethttp.Client {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			raw, err := connectTunnelDialer(proxyAddr, target)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, cfg)
			if err := tlsConn.Handshake(); err != nil {
				raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	return &nethttp.Client{Transport: tr, Timeout: 90 * time.Second}
}

// waitForStreams blocks until the store contains at least n streams or
// the timeout expires.
func waitForStreams(t *testing.T, store *testStore, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(store.getStreams()) >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d streams (got %d)", n, len(store.getStreams()))
}

// waitForStreamState waits for a store update transitioning the given stream
// to the expected state.
func waitForStreamState(t *testing.T, store *testStore, streamID, wantState string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, u := range store.getUpdates(streamID) {
			if u.State == wantState {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for stream %s to reach state %q", streamID, wantState)
}

// ensureLinkedExchange asserts that at least one Stream exists whose flow list
// contains both a send and a receive flow (the MITM-diagnostic invariant:
// one exchange = one Stream record).
func ensureLinkedExchange(t *testing.T, store *testStore, timeout time.Duration) (*flow.Stream, []*flow.Flow) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, st := range store.getStreams() {
			flows := store.flowsForStream(st.ID)
			var hasSend, hasRecv bool
			for _, f := range flows {
				if f.Direction == "send" {
					hasSend = true
				}
				if f.Direction == "receive" {
					hasRecv = true
				}
			}
			if hasSend && hasRecv {
				return st, flows
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	allFlows := store.allFlows()
	hasGlobalSend := false
	hasGlobalRecv := false
	for _, f := range allFlows {
		if f.Direction == "send" {
			hasGlobalSend = true
		}
		if f.Direction == "receive" {
			hasGlobalRecv = true
		}
	}
	t.Fatalf("no stream with both send+receive flows (hasSend=%v hasRecv=%v)", hasGlobalSend, hasGlobalRecv)
	return nil, nil
}

// ---------------------------------------------------------------------------
// Scenario 1: H2C basic roundtrip
// ---------------------------------------------------------------------------

func TestH2C_BasicRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upShutdown := startH2CUpstream(t, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path != "/hello" {
			nethttp.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("world"))
	}))
	defer upShutdown()

	proxyAddr, store := startH2CProxy(t, ctx, upstreamAddr, pipelineOpts{})

	cli := newH2CClient()
	req, err := nethttp.NewRequestWithContext(ctx, "GET", "http://"+proxyAddr+"/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "world" {
		t.Errorf("body = %q, want %q", body, "world")
	}

	st, flows := ensureLinkedExchange(t, store, 5*time.Second)
	if st.Protocol != "http" {
		t.Errorf("Protocol = %q, want http", st.Protocol)
	}
	if st.Scheme != "http" {
		t.Errorf("Scheme = %q, want http", st.Scheme)
	}
	if len(flows) != 2 {
		t.Errorf("expected exactly 2 flows, got %d", len(flows))
	}
	var sendF, recvF *flow.Flow
	for _, f := range flows {
		if f.Direction == "send" {
			sendF = f
		} else if f.Direction == "receive" {
			recvF = f
		}
	}
	if sendF == nil || recvF == nil {
		t.Fatalf("missing send/receive flow: send=%v, recv=%v", sendF, recvF)
	}
	if sendF.Method != "GET" {
		t.Errorf("send Method = %q, want GET", sendF.Method)
	}
	if sendF.URL == nil || sendF.URL.Path != "/hello" {
		t.Errorf("send URL.Path = %v, want /hello", sendF.URL)
	}
	if recvF.StatusCode != 200 {
		t.Errorf("recv StatusCode = %d, want 200", recvF.StatusCode)
	}
	if string(recvF.Body) != "world" {
		t.Errorf("recv Body = %q, want world", recvF.Body)
	}
	if len(sendF.RawBytes) == 0 {
		t.Error("send RawBytes empty - wire bytes not captured")
	}
	if len(recvF.RawBytes) == 0 {
		t.Error("recv RawBytes empty - wire bytes not captured")
	}
}

// ---------------------------------------------------------------------------
// Scenario 2: ALPN h2 MITM, upstream TLS snapshot correctness
// ---------------------------------------------------------------------------

func TestALPN_H2_MITM_UpstreamTLSSnapshotIsUpstream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "upstream-tls-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, err := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	waitForStreams(t, store, 1, 5*time.Second)
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("no streams recorded")
	}
	st := streams[0]
	if st.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", st.Scheme)
	}

	// USK-619 diagnostic invariant: Stream.ConnInfo must reflect UPSTREAM
	// TLS reality, not the synthetic client-side MITM cert. The upstream
	// handler starts with CN="upstream-tls-marker" — that string must appear
	// in the recorded cert subject.
	if st.ConnInfo == nil {
		t.Fatal("Stream.ConnInfo is nil; upstream TLS was not projected into ConnInfo")
	}
	if !strings.Contains(st.ConnInfo.TLSServerCertSubject, "upstream-tls-marker") {
		t.Errorf("ConnInfo.TLSServerCertSubject = %q, want to contain %q "+
			"(synthetic MITM cert is leaking into ConnInfo)",
			st.ConnInfo.TLSServerCertSubject, "upstream-tls-marker")
	}
	if st.ConnInfo.TLSALPN != "h2" {
		t.Errorf("ConnInfo.TLSALPN = %q, want h2", st.ConnInfo.TLSALPN)
	}
	if st.ConnInfo.TLSVersion == "" {
		t.Error("ConnInfo.TLSVersion is empty; expected TLS 1.2 or TLS 1.3")
	}
	if st.ConnInfo.TLSCipher == "" {
		t.Error("ConnInfo.TLSCipher is empty; expected a cipher suite name")
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: Multiple concurrent streams, recording isolation
// ---------------------------------------------------------------------------

func TestMultipleConcurrentStreams_RecordingIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "concurrency-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.Header.Get("X-Stream-Id")
		_, _ = w.Write([]byte("stream-" + id))
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	const n = 3
	cli := newMITMH2Client(proxyAddr, upAddr)

	var wg sync.WaitGroup
	type result struct {
		id   string
		body string
		err  error
	}
	resCh := make(chan result, n)
	// Trigger an initial request first to establish a single shared tunnel so
	// subsequent concurrent requests multiplex over it.
	warmReq, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/warm", nil)
	warmReq.Header.Set("X-Stream-Id", "warm")
	if wResp, wErr := cli.Do(warmReq); wErr == nil {
		_, _ = io.ReadAll(wResp.Body)
		wResp.Body.Close()
	}
	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			req, err := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/concurrent/"+id, nil)
			if err != nil {
				resCh <- result{id: id, err: err}
				return
			}
			req.Header.Set("X-Stream-Id", id)
			resp, err := cli.Do(req)
			if err != nil {
				resCh <- result{id: id, err: err}
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			resCh <- result{id: id, body: string(b)}
		}(id)
	}
	wg.Wait()
	close(resCh)

	got := map[string]string{}
	var firstErr error
	for r := range resCh {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		got[r.id] = r.body
	}
	if firstErr != nil {
		t.Fatalf("at least one request failed: %v", firstErr)
	}
	if len(got) != n {
		t.Fatalf("got %d unique responses, want %d (firstErr=%v)", len(got), n, firstErr)
	}
	for id, body := range got {
		if body != "stream-"+id {
			t.Errorf("id=%s body=%q, want stream-%s", id, body, id)
		}
	}

	// Wait for recordings to settle.
	waitForStreams(t, store, n, 5*time.Second)
	time.Sleep(200 * time.Millisecond)

	// MITM invariant: n concurrent streams → n Streams with send+recv each
	// (no cross-contamination). The warm-up stream issued above establishes
	// the shared tunnel and is recorded as its own Stream; count only the
	// n concurrent streams by filtering on X-Stream-Id != "warm".
	streams := store.getStreams()
	linked := 0
	for _, st := range streams {
		flows := store.flowsForStream(st.ID)
		var sendF, recvF *flow.Flow
		for _, f := range flows {
			if f.Direction == "send" {
				sendF = f
			} else if f.Direction == "receive" {
				recvF = f
			}
		}
		if sendF == nil || recvF == nil {
			continue
		}
		// Extract X-Stream-Id from the send flow to distinguish the warm-up
		// stream from the n concurrent streams.
		sent := ""
		for k, v := range sendF.Headers {
			if (k == "X-Stream-Id" || k == "x-stream-id") && len(v) > 0 {
				sent = v[0]
				break
			}
		}
		if sent == "warm" {
			continue
		}
		linked++
		// Cross-contamination check:
		if sent != "" && string(recvF.Body) != "stream-"+sent {
			t.Errorf("stream %s: send id=%s but recv body=%q, want %q (cross-contamination)",
				st.ID, sent, recvF.Body, "stream-"+sent)
		}
	}
	if linked == 0 {
		allFlows := store.allFlows()
		hasSend, hasRecv := false, false
		for _, f := range allFlows {
			if f.Direction == "send" {
				hasSend = true
			}
			if f.Direction == "receive" {
				hasRecv = true
			}
		}
		t.Fatalf("no linked streams: hasSend=%v hasRecv=%v", hasSend, hasRecv)
	}
	if linked != n {
		t.Errorf("linked send+recv pairs = %d, want %d (excluding warm-up)", linked, n)
	}
}

// ---------------------------------------------------------------------------
// Scenario 4: Stream-per-pipeline, held stream does not block others
// ---------------------------------------------------------------------------

func TestStreamPerPipeline_HeldStreamDoesNotBlockOthers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "hold-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/slow" {
			_, _ = w.Write([]byte("slow-response"))
			return
		}
		_, _ = w.Write([]byte("fast-response"))
	}))
	defer upShutdown()

	interceptEngine := httprules.NewInterceptEngine()
	interceptEngine.AddRule(httprules.InterceptRule{
		ID:          "hold-slow",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/slow`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		interceptEngine: interceptEngine,
		holdQueue:       holdQueue,
	})

	cli := newMITMH2Client(proxyAddr, upAddr)

	// Start slow request (will be held).
	slowDone := make(chan struct{})
	go func() {
		defer close(slowDone)
		req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/slow", nil)
		resp, err := cli.Do(req)
		if err != nil {
			t.Errorf("slow request: %v", err)
			return
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}()

	// Wait until the slow request is held.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if holdQueue.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if holdQueue.Len() == 0 {
		t.Fatal("slow request was not held")
	}

	// While held, fast request must complete.
	fastReq, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/fast", nil)
	fastResp, err := cli.Do(fastReq)
	if err != nil {
		t.Fatalf("fast request: %v", err)
	}
	fastBody, _ := io.ReadAll(fastResp.Body)
	fastResp.Body.Close()
	if string(fastBody) != "fast-response" {
		t.Errorf("fast response body = %q, want fast-response", fastBody)
	}

	// Verify slow still not complete.
	select {
	case <-slowDone:
		t.Error("slow request completed before release")
	default:
	}

	// Release the hold.
	entries := holdQueue.List()
	if len(entries) == 0 {
		t.Fatal("no held entries")
	}
	if err := holdQueue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	select {
	case <-slowDone:
	case <-time.After(10 * time.Second):
		t.Fatal("slow request did not complete after release")
	}

	waitForStreams(t, store, 2, 5*time.Second)
	if len(store.getStreams()) < 2 {
		t.Errorf("expected >=2 streams recorded, got %d", len(store.getStreams()))
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: RST_STREAM from client → error state
// ---------------------------------------------------------------------------

func TestRSTStream_RecordsAsErrorWithCanceledReason(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	block := make(chan struct{})
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "rst-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Block until released OR client cancel propagates.
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer upShutdown()
	defer close(block)

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)

	reqCtx, reqCancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		req, _ := nethttp.NewRequestWithContext(reqCtx, "GET", "https://"+upAddr+"/rst-test", nil)
		resp, err := cli.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		errCh <- nil
	}()

	// Wait for stream to appear.
	waitForStreams(t, store, 1, 5*time.Second)

	// Cancel - x/net/http2.Transport emits RST_STREAM(CANCEL).
	reqCancel()

	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not return after cancel")
	}

	// Give time for OnComplete to fire.
	time.Sleep(1 * time.Second)
	streams := store.getStreams()
	if len(streams) == 0 {
		t.Fatal("no streams recorded")
	}
	for _, st := range streams {
		for _, u := range store.getUpdates(st.ID) {
			t.Logf("stream=%s update.state=%q", st.ID, u.State)
		}
	}
	// The MITM invariant: a canceled stream must be recorded with
	// State="error" so an analyst can distinguish normal completion from
	// abnormal termination. The session OnComplete hook is wired in the
	// test to call UpdateStream; verify it fired.
	var hasErrorState, sawAny bool
	for _, st := range streams {
		for _, u := range store.getUpdates(st.ID) {
			sawAny = true
			if u.State == "error" {
				hasErrorState = true
			}
		}
	}
	if !sawAny {
		t.Fatalf("no StreamUpdate recorded for any stream — session OnComplete did not fire (streams=%d)", len(streams))
	}
	if !hasErrorState {
		t.Fatalf(`expected at least one StreamUpdate with State=="error" — MITM analyst cannot distinguish normal EOF from RST_STREAM(CANCEL)`)
	}

	// USK-620: classification via StreamUpdate.FailureReason (first-class
	// column). The session OnComplete closure wires the layer.StreamError
	// code (from the upstream Channel's cascaded close) via
	// session.ClassifyError so MITM analysts can filter canceled streams
	// from other failure modes.
	var hasCanceledReason bool
	for _, st := range streams {
		for _, u := range store.getUpdates(st.ID) {
			if u.State == "error" && u.FailureReason == "canceled" {
				hasCanceledReason = true
			}
		}
	}
	if !hasCanceledReason {
		t.Errorf(`expected FailureReason=="canceled" on the error update (streams=%d)`, len(streams))
	}
}

// ---------------------------------------------------------------------------
// Scenario 6: GOAWAY from upstream → affected stream recorded as refused
// ---------------------------------------------------------------------------

func TestGOAWAY_AffectedStreamsRecordedAsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Upstream is our own intHTTP2.Layer in ServerRole. It accepts one
	// h2c preface, then immediately Close()s the Layer which emits a
	// GOAWAY(NO_ERROR) frame to the MITM-side ClientRole Layer. On the
	// MITM's subsequent OpenStream call, the Layer returns a
	// *layer.StreamError{Code: ErrorRefused, Reason: "GOAWAY received"|"layer shutdown"},
	// which session.RunSession propagates to OnComplete. The test asserts
	// the recording surfaces FailureReason="refused" so an analyst can
	// distinguish a GOAWAY-induced refusal from a plain error.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		conn, err := upLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		upL, err := intHTTP2.New(conn, "upstream-goaway", intHTTP2.ServerRole)
		if err != nil {
			return
		}
		// GOAWAY is enqueued by Close. The writer has a 100ms drain window
		// to deliver the frame before the underlying conn is torn down.
		_ = upL.Close()
	}()

	store := &testStore{}
	onStream := func(streamCtx context.Context, clientCh layer.Channel) {
		dial := func(dialCtx context.Context, env *envelope.Envelope) (layer.Channel, error) {
			upConn, dErr := net.DialTimeout("tcp", upLn.Addr().String(), 5*time.Second)
			if dErr != nil {
				return nil, dErr
			}
			upLayer, dErr := intHTTP2.New(upConn, "mitm-upstream", intHTTP2.ClientRole,
				intHTTP2.WithScheme("http"),
			)
			if dErr != nil {
				upConn.Close()
				return nil, dErr
			}
			// The reader goroutine processes GOAWAY asynchronously after
			// preface. Poll OpenStream until it either returns Refused
			// (GOAWAY observed) or succeeds (race lost). A short ceiling
			// keeps the test bounded on CI.
			deadline := time.Now().Add(500 * time.Millisecond)
			var ch layer.Channel
			var openErr error
			for time.Now().Before(deadline) {
				ch, openErr = upLayer.OpenStream(dialCtx)
				if openErr != nil {
					break
				}
				// Stream allocated but GOAWAY may still be in-flight.
				// Drop the Channel and retry briefly; the server will
				// eventually refuse once GOAWAY is processed.
				_ = ch.Close()
				ch = nil
				time.Sleep(20 * time.Millisecond)
			}
			if openErr != nil {
				upLayer.Close()
				return nil, openErr
			}
			if ch != nil {
				go func() {
					<-dialCtx.Done()
					upLayer.Close()
				}()
				return ch, nil
			}
			upLayer.Close()
			return nil, fmt.Errorf("OpenStream did not refuse within deadline")
		}
		pipe := buildPipeline(store, pipelineOpts{})
		session.RunSession(streamCtx, clientCh, dial, pipe, session.SessionOptions{
			OnComplete: func(cctx context.Context, streamID string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if streamID != "" {
					store.UpdateStream(cctx, streamID, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
	}

	flCfg := connector.FullListenerConfig{
		Name: "h2c-goaway",
		Addr: "127.0.0.1:0",
		OnHTTP2: connector.NewH2CHandler(connector.H2CHandlerConfig{
			OnStream: onStream,
			Logger:   slog.Default(),
		}),
	}
	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("proxy not ready")
	}

	// Client issues one h2c request. MITM's dial will hit the refused path.
	cli := newH2CClient()
	req, _ := nethttp.NewRequestWithContext(ctx, "GET", "http://"+fl.Addr()+"/", nil)
	resp, _ := cli.Do(req)
	if resp != nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}

	// Give OnComplete time to fire and persist the update. Bounded by ctx.
	select {
	case <-upstreamDone:
	case <-ctx.Done():
	}
	time.Sleep(300 * time.Millisecond)

	streams := store.getStreams()
	if len(streams) == 0 {
		t.Fatal("no streams recorded — Stream must be created before dial failure")
	}

	var hasRefused bool
	var observed []string
	for _, st := range streams {
		for _, u := range store.getUpdates(st.ID) {
			observed = append(observed, fmt.Sprintf("state=%q reason=%q", u.State, u.FailureReason))
			if u.State == "error" && u.FailureReason == "refused" {
				hasRefused = true
			}
		}
	}
	if !hasRefused {
		t.Errorf(`expected FailureReason=="refused" on at least one error update; got updates=%v`, observed)
	}
}

// ---------------------------------------------------------------------------
// Scenario 7: Large response body round-trips via spill-backed BodyBuffer
// ---------------------------------------------------------------------------

// TestLargeResponseBody_SpillRoundtrip_11MiB verifies that an 11 MiB body
// round-trips through the MITM proxy end-to-end under the USK-632 model:
// the assembler aggregates all DATA frames into a BodyBuffer (memory →
// file-backed past the configured spill threshold) and emits the envelope
// only after END_STREAM. After USK-633, RecordStep materializes the
// BodyBuffer into flow.Flow.Body via projectHTTPBody (capped at
// config.MaxBodySize = 254 MiB), so recvF.Body carries the full 11 MiB —
// the wire-observed bytes also remain on RawBytes (L7/L4 duality).
func TestLargeResponseBody_SpillRoundtrip_11MiB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const size = 11 << 20
	// Deterministic pattern: 256-byte repeating counter.
	pattern := make([]byte, 256)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	expected := bytes.Repeat(pattern, size/256)
	if len(expected) != size {
		expected = append(expected, make([]byte, size-len(expected))...)
	}
	expectedHash := sha256.Sum256(expected)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "large-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(expected)
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/big", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		// An analyst driving a large download MUST get the full body through
		// the proxy. A FLOW_CONTROL_ERROR is a proxy bug, not a client bug.
		t.Fatalf("copy: %v", err)
	}
	if n != size {
		t.Errorf("got %d bytes, want %d", n, size)
	}
	gotHash := h.Sum(nil)
	if !bytes.Equal(gotHash, expectedHash[:]) {
		t.Errorf("body hash mismatch: got=%x want=%x", gotHash, expectedHash)
	}

	st, flows := ensureLinkedExchange(t, store, 5*time.Second)
	var recvF *flow.Flow
	for _, f := range flows {
		if f.Direction == "receive" {
			recvF = f
			break
		}
	}
	if recvF == nil {
		t.Fatal("no receive flow under linked stream")
	}
	// RecordStep materializes the BodyBuffer into flow.Flow.Body after USK-633
	// (projectHTTPBody with MaxBodySize=254 MiB). 11 MiB fits under the cap
	// and must be recorded faithfully for analyst review.
	if len(recvF.Body) != size {
		t.Errorf("receive flow Body length = %d, want %d", len(recvF.Body), size)
	} else {
		gotBodyHash := sha256.Sum256(recvF.Body)
		if !bytes.Equal(gotBodyHash[:], expectedHash[:]) {
			t.Errorf("receive flow Body hash mismatch: got=%x want=%x", gotBodyHash, expectedHash)
		}
	}
	if len(recvF.Headers) == 0 {
		t.Error("receive flow headers missing")
	}
	if len(recvF.RawBytes) == 0 {
		t.Error("receive flow RawBytes empty")
	}

	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
}

// ---------------------------------------------------------------------------
// Scenario 8: Connection pool reuse + stream isolation
// ---------------------------------------------------------------------------

func TestConnectionPoolReuse_StreamIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, accepts, upShutdown := startH2TLSUpstream(t, "pool-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("echo-" + r.URL.Path))
	}))
	defer upShutdown()

	p := pool.New(pool.PoolOptions{})
	defer p.Close()

	bcfg := makeBuildCfg(t, p)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	// Two CONNECT tunnels, each doing one request. Pool should reuse the
	// upstream h2 layer.
	doRequest := func(path string) string {
		cli := newMITMH2Client(proxyAddr, upAddr)
		req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+path, nil)
		resp, err := cli.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(b)
	}

	if got := doRequest("/a"); got != "echo-/a" {
		t.Errorf("first req body = %q", got)
	}
	// Give the pool time to record Put.
	time.Sleep(50 * time.Millisecond)

	if got := doRequest("/b"); got != "echo-/b" {
		t.Errorf("second req body = %q", got)
	}

	waitForStreams(t, store, 2, 5*time.Second)
	time.Sleep(200 * time.Millisecond)

	// USK-624: pool fast-path consults the h2 pool before upstream TLS dial,
	// so the second CONNECT reuses the first connection and upstream accept
	// count stays at 1. This is the externally-observable correctness signal
	// of pool reuse (tcpdump would see a single upstream handshake).
	if acc := accepts(); acc != 1 {
		t.Fatalf("upstream accept count = %d, want 1 (pool reuse must suppress second dial)", acc)
	}

	streams := store.getStreams()
	linked := 0
	seenIDs := map[string]bool{}
	for _, st := range streams {
		if seenIDs[st.ID] {
			t.Errorf("duplicate stream ID: %s", st.ID)
		}
		seenIDs[st.ID] = true
		flows := store.flowsForStream(st.ID)
		var sendF, recvF *flow.Flow
		for _, f := range flows {
			if f.Direction == "send" {
				sendF = f
			} else if f.Direction == "receive" {
				recvF = f
			}
		}
		if sendF != nil && recvF != nil {
			linked++
			// Cross-contamination check.
			if sendF.URL != nil {
				expected := "echo-" + sendF.URL.Path
				if string(recvF.Body) != expected {
					t.Errorf("cross-contamination: send path=%s but recv=%q", sendF.URL.Path, recvF.Body)
				}
			}
		}
	}
	if linked == 0 {
		t.Fatalf("no linked streams")
	}
}

// ---------------------------------------------------------------------------
// Scenario 9: Protocol/Scheme + State lifecycle
// ---------------------------------------------------------------------------

func TestStreamFlowRecording_ProtocolAndStateLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "lifecycle-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/lifecycle", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	st, flows := ensureLinkedExchange(t, store, 5*time.Second)
	if st.Protocol != "http" {
		t.Errorf("Protocol = %q", st.Protocol)
	}
	if st.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", st.Scheme)
	}
	if st.Timestamp.IsZero() {
		t.Error("Timestamp not populated")
	}

	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)

	if len(flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(flows))
	}
	var sendF, recvF *flow.Flow
	for _, f := range flows {
		if f.Direction == "send" {
			sendF = f
		} else if f.Direction == "receive" {
			recvF = f
		}
	}
	if sendF == nil || recvF == nil {
		t.Fatal("missing send/receive flow")
	}
	if sendF.Sequence != 0 {
		t.Errorf("send Sequence = %d, want 0", sendF.Sequence)
	}
	// HTTP/2 Sequence is per-channel (RFC §3.1). The upstream ClientRole
	// channel that produced this response envelope starts its own counter at
	// 0, independent of the client-facing channel. After USK-615, the two
	// halves share a StreamID but keep independent Sequence — both sides
	// legitimately report Sequence=0 and are distinguishable by Direction.
	if recvF.Sequence != 0 {
		t.Errorf("recv Sequence = %d, want 0 (per-channel counter)", recvF.Sequence)
	}
	if sendF.StreamID != st.ID || recvF.StreamID != st.ID {
		t.Error("flow StreamID mismatch with stream")
	}
}

// ---------------------------------------------------------------------------
// Scenario 10: Raw bytes contain wire frames
// ---------------------------------------------------------------------------

func TestRawBytesRecording_ContainsWireFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "raw-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("raw-response"))
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req1, _ := nethttp.NewRequestWithContext(ctx, "POST", "https://"+upAddr+"/marker-1", bytes.NewReader([]byte("BBBBBB")))
	req1.Header.Set("X-Marker", "AAAAAA")
	resp1, err := cli.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp1.Body)
	resp1.Body.Close()

	req2, _ := nethttp.NewRequestWithContext(ctx, "POST", "https://"+upAddr+"/marker-2", bytes.NewReader([]byte("CCCCCC")))
	req2.Header.Set("X-Marker", "ZZZZZZ")
	resp2, err := cli.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp2.Body)
	resp2.Body.Close()

	waitForStreams(t, store, 2, 5*time.Second)
	streams := store.getStreams()
	if len(streams) < 2 {
		t.Fatalf("expected 2 streams, got %d", len(streams))
	}

	var raw1, raw2 []byte
	for _, st := range streams {
		for _, f := range store.flowsForStream(st.ID) {
			if f.Direction != "send" {
				continue
			}
			if f.URL != nil && f.URL.Path == "/marker-1" {
				raw1 = f.RawBytes
			}
			if f.URL != nil && f.URL.Path == "/marker-2" {
				raw2 = f.RawBytes
			}
		}
	}
	if len(raw1) == 0 {
		t.Error("raw1 (marker-1 send) empty")
	}
	if len(raw2) == 0 {
		t.Error("raw2 (marker-2 send) empty")
	}
	if len(raw1) > 0 && len(raw2) > 0 && bytes.Equal(raw1, raw2) {
		t.Error("raw1 and raw2 identical - per-stream RawBytes are not isolated")
	}
	// DATA frame body "BBBBBB" / "CCCCCC" should appear verbatim in the wire
	// bytes since DATA frames are not HPACK-compressed.
	if len(raw1) > 0 && !bytes.Contains(raw1, []byte("BBBBBB")) {
		t.Error("raw1 missing literal body bytes (BBBBBB) - DATA frame not captured")
	}
	if len(raw2) > 0 && !bytes.Contains(raw2, []byte("CCCCCC")) {
		t.Error("raw2 missing literal body bytes (CCCCCC) - DATA frame not captured")
	}
}

// ---------------------------------------------------------------------------
// Scenario 11: Trailers preserved in HTTPMessage
// ---------------------------------------------------------------------------

func TestTrailers_PreservedInHTTPMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "trailer-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Trailer", "X-Trailer-1")
		if f, ok := w.(nethttp.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte("trailerbody"))
		w.Header().Set("X-Trailer-1", "trailer-value")
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/trailer", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if got := resp.Trailer.Get("X-Trailer-1"); got != "trailer-value" {
		t.Errorf("client-side Trailer X-Trailer-1 = %q, want trailer-value", got)
	}

	_, flows := ensureLinkedExchange(t, store, 5*time.Second)
	var recvF *flow.Flow
	for _, f := range flows {
		if f.Direction == "receive" {
			recvF = f
		}
	}
	if recvF == nil {
		t.Fatal("no receive flow under linked stream")
	}

	// USK-621: recvF.Trailers is the canonical projection path.
	// envelopeToFlow in pipeline/record_step.go projects HTTPMessage.Trailers
	// onto flow.Flow.Trailers with the same shape as Headers. HTTP/2 wire
	// reality is lowercase header names (RFC 9113 §8.2.1), so the projected
	// key is "x-trailer-1". This MITM preserves wire casing per the
	// "no normalization" principle.
	if recvF.Trailers == nil {
		t.Fatal("receive flow Trailers is nil; USK-621 should have projected HTTPMessage.Trailers")
	}
	got := recvF.Trailers["x-trailer-1"]
	if len(got) != 1 || got[0] != "trailer-value" {
		t.Errorf("recvF.Trailers[x-trailer-1] = %v, want [trailer-value]; full Trailers = %v",
			got, recvF.Trailers)
	}
	// Wire-level trailer frame must also be present in the raw snapshot
	// (L7/L4 duality).
	if len(recvF.RawBytes) == 0 {
		t.Error("receive flow RawBytes empty")
	}
}

// ---------------------------------------------------------------------------
// Scenario 12: Variant recording on intercept modify
// ---------------------------------------------------------------------------

func TestVariantRecording_InterceptModifyHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "variant-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Injected")))
	}))
	defer upShutdown()

	interceptEngine := httprules.NewInterceptEngine()
	interceptEngine.AddRule(httprules.InterceptRule{
		ID:          "modify-rule",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/modify`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		interceptEngine: interceptEngine,
		holdQueue:       holdQueue,
	})

	cli := newMITMH2Client(proxyAddr, upAddr)
	done := make(chan []byte, 1)
	go func() {
		req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/modify", nil)
		resp, err := cli.Do(req)
		if err != nil {
			done <- nil
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- b
	}()

	// Wait for held entry.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if holdQueue.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries := holdQueue.List()
	if len(entries) == 0 {
		t.Fatal("no held entry")
	}
	held := entries[0]

	// Modify: add X-Injected header.
	modified := held.Envelope.Clone()
	msg := modified.Message.(*envelope.HTTPMessage)
	msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "x-injected", Value: "by-proxy"})
	if err := holdQueue.Release(held.ID, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modified,
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case body := <-done:
		if string(body) != "by-proxy" {
			t.Errorf("upstream saw body=%q, want 'by-proxy' (expecting injected header to reach upstream)", body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request did not finish")
	}

	// Verify variant recording: original + modified send flows for the same stream.
	waitForStreams(t, store, 1, 5*time.Second)
	streams := store.getStreams()
	st := streams[0]
	flows := store.flowsForStream(st.ID)

	var origSend, modSend *flow.Flow
	for _, f := range flows {
		if f.Direction != "send" {
			continue
		}
		if f.Metadata != nil {
			switch f.Metadata["variant"] {
			case "original":
				origSend = f
			case "modified":
				modSend = f
			}
		}
	}
	if origSend == nil {
		t.Error("no 'original' variant send flow recorded")
	}
	if modSend == nil {
		t.Error("no 'modified' variant send flow recorded")
	}
	if origSend != nil && modSend != nil {
		// Modified should have X-Injected header; original must NOT.
		hasInjected := func(f *flow.Flow) bool {
			for k, v := range f.Headers {
				if (k == "x-injected" || k == "X-Injected") && len(v) > 0 {
					return true
				}
			}
			return false
		}
		if hasInjected(origSend) {
			t.Error("original variant should NOT contain X-Injected")
		}
		if !hasInjected(modSend) {
			t.Error("modified variant should contain X-Injected")
		}

		// USK-622: the modified variant's RawBytes must reflect the
		// re-encoded wire representation (HPACK-encoded header block +
		// END_STREAM), NOT the ingress env.Raw captured before the
		// injection. The two byte strings must therefore differ, and the
		// modified bytes must decode back via hpack to a header list
		// containing x-injected: by-proxy.
		if bytes.Equal(origSend.RawBytes, modSend.RawBytes) && len(origSend.RawBytes) > 0 {
			t.Error("modified variant RawBytes equals original — WireEncoder did not run")
		}
		if len(modSend.RawBytes) == 0 {
			t.Fatal("modified variant RawBytes is empty")
		}

		// Decode the modified wire bytes back through hpack and assert the
		// injected header is present. HPACK indices differ from the live
		// wire bytes (documented caveat in EncodeWireBytes godoc) but the
		// decoded (name, value) sequence must round-trip the injection.
		rdr := h2frame.NewReader(bytes.NewReader(modSend.RawBytes))
		var fragment []byte
		for {
			f, rerr := rdr.ReadFrame()
			if rerr != nil {
				break
			}
			if f.Header.Type != h2frame.TypeHeaders &&
				f.Header.Type != h2frame.TypeContinuation {
				continue
			}
			fragment = append(fragment, f.Payload...)
			if f.Header.Flags&h2frame.FlagEndHeaders != 0 {
				break
			}
		}
		if len(fragment) == 0 {
			t.Fatalf("no HEADERS/CONTINUATION frame in modified variant RawBytes: % x", modSend.RawBytes)
		}
		dec := h2hpack.NewDecoder(4096)
		hdrs, derr := dec.Decode(fragment)
		if derr != nil {
			t.Fatalf("hpack.Decode: %v", derr)
		}
		var foundInjected bool
		for _, hf := range hdrs {
			if hf.Name == "x-injected" && hf.Value == "by-proxy" {
				foundInjected = true
				break
			}
		}
		if !foundInjected {
			t.Errorf("hpack decode of modified RawBytes missing x-injected: by-proxy; got %v", hdrs)
		}
	}
}

// ---------------------------------------------------------------------------
// Scenario 13: Server push recorded separately
// ---------------------------------------------------------------------------

func TestServerPush_PushStreamRecordedSeparately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "push-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/index.html" {
			if pusher, ok := w.(nethttp.Pusher); ok {
				_ = pusher.Push("/pushed.css", nil)
			}
			_, _ = w.Write([]byte("<html></html>"))
			return
		}
		if r.URL.Path == "/pushed.css" {
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte("body{}"))
			return
		}
		nethttp.NotFound(w, r)
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/index.html", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Let push stream propagate.
	time.Sleep(200 * time.Millisecond)

	streams := store.getStreams()
	var pushFound bool
	for _, st := range streams {
		for _, f := range store.flowsForStream(st.ID) {
			if f.URL != nil && f.URL.Path == "/pushed.css" {
				pushFound = true
			}
		}
	}
	if !pushFound {
		t.Fatalf("push stream recording missing: no flow with URL.Path=/pushed.css across %d streams", len(streams))
	}

	// USK-623 acceptance: the push stream must be recorded as an INDEPENDENT
	// Stream tagged with the push's origin identifier. The tag value is the
	// origin channel's streamID on the UPSTREAM Layer — it does NOT match
	// the store's client-side Stream.ID (session.upstreamToClient rewrites
	// every upstream envelope's StreamID to the captured client stream id
	// before RecordStep fires, so origin Stream rows are keyed by the
	// client-side id). Analysts correlate push↔origin via the origin
	// Stream's flow carrying H2PushPromise + URL.Path rather than by ID
	// equality.
	var pushStreamFound bool
	for _, st := range streams {
		if st.Tags != nil && st.Tags[pushrecorder.OriginStreamTag] != "" {
			pushStreamFound = true
			break
		}
	}
	if !pushStreamFound {
		t.Errorf("no Stream with Tags[%q] recorded for the pushed resource", pushrecorder.OriginStreamTag)
	}
}
