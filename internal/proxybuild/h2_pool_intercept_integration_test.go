//go:build e2e && !e2e_smoke

// USK-816: regression coverage for the h2 + HTTP2Pool + intercept combination.
// The repro reported that intercept release / modify_and_forward on an h2 path
// with the production HTTP2Pool wired never relayed the upstream response
// back to the client. The pre-existing h2 intercept test in
// internal/layer/http2 (TestVariantRecording_InterceptModifyHeader) explicitly
// uses HTTP2Pool=nil, so the pool-on path was unexercised.
//
// This file constructs the proxy via BuildLiveStack (the same production
// assembly as cmd/yorishiro-proxy/init) so OnHTTP2Stack runs against the
// real connector handler chain — not the test-local copy in
// http2_integration_test.go. A non-nil pool.Pool is wired through
// BuildConfig.HTTP2Pool, exactly matching mcpserver/init.go:467.
package proxybuild_test

import (
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
	gohttp "net/http"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startH2TLSUpstreamForPoolTest spins up a TLS upstream that serves HTTP/2 via
// golang.org/x/net/http2.Server. Returns the listener addr, an accept counter
// (used to verify pool reuse), and a shutdown closure. Modeled on the
// internal/layer/http2 helper but local to this package so the proxybuild
// import surface stays clean.
func startH2TLSUpstreamForPoolTest(t *testing.T, cn string, handler gohttp.Handler) (addr string, acceptCount func() int64, shutdown func()) {
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
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{"h2"},
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int64
	h2s := &http2.Server{}

	var wg sync.WaitGroup
	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			accepts.Add(1)
			tlsConn := tls.Server(c, tlsCfg)
			wg.Add(1)
			go func(tc *tls.Conn) {
				defer wg.Done()
				defer tc.Close()
				if herr := tc.Handshake(); herr != nil {
					return
				}
				h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
			}(tlsConn)
		}
	}()

	return tcpLn.Addr().String(), func() int64 { return accepts.Load() }, func() {
		_ = tcpLn.Close()
		doneCh := make(chan struct{})
		go func() { wg.Wait(); close(doneCh) }()
		select {
		case <-doneCh:
		case <-time.After(2 * time.Second):
		}
	}
}

// connectTunnelDialerForPoolTest opens a CONNECT tunnel to proxyAddr for the
// given target. Mirrors the http2_integration_test helper.
func connectTunnelDialerForPoolTest(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, werr := c.Write([]byte(req)); werr != nil {
		c.Close()
		return nil, werr
	}
	br := bytes.NewBuffer(nil)
	buf := make([]byte, 1)
	for {
		n, rerr := c.Read(buf)
		if rerr != nil {
			c.Close()
			return nil, rerr
		}
		if n == 0 {
			continue
		}
		br.Write(buf[:n])
		text := br.String()
		if (len(text) >= 4 && text[len(text)-4:] == "\r\n\r\n") || (len(text) >= 2 && text[len(text)-2:] == "\n\n") {
			break
		}
		if br.Len() > 4096 {
			c.Close()
			return nil, fmt.Errorf("CONNECT response too large")
		}
	}
	if !bytes.Contains(br.Bytes(), []byte(" 200")) {
		c.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", br.String())
	}
	return c, nil
}

// newH2ClientThroughProxyForPoolTest wires an http.Client that funnels every
// request through proxyAddr using CONNECT + TLS h2.
func newH2ClientThroughProxyForPoolTest(proxyAddr, target string) *gohttp.Client {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			raw, err := connectTunnelDialerForPoolTest(proxyAddr, target)
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
	return &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
}

// startProxyForH2PoolInterceptTest builds a live Stack via BuildLiveStack and
// starts its listener. The stack is wired with a non-nil HTTP2Pool to mirror
// production wiring (mcpserver/init.go:467).
func startProxyForH2PoolInterceptTest(
	t *testing.T,
	ctx context.Context,
	store flow.Writer,
	intercept *httprules.InterceptEngine,
	holdQueue *common.HoldQueue,
	pool *h2pool.Pool,
) (proxyAddr string) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	logger := testutil.DiscardLogger()
	if testing.Verbose() && os.Getenv("USK816_DEBUG") != "" {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	deps := proxybuild.Deps{
		Logger:       logger,
		ListenerName: "usk-816-test",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
			HTTP2Pool:          pool,
		},
		HTTPInterceptEngine: intercept,
		HoldQueue:           holdQueue,
	}

	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()

	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	addr := stack.Listener.Addr()
	if addr == "" {
		t.Fatal("listener has no addr")
	}
	return addr
}

// flowStoreForH2Pool is a flow.Writer that records every Stream/Flow under a
// mutex so test goroutines can inspect them safely.
type flowStoreForH2Pool struct {
	mu      sync.Mutex
	streams []*flow.Stream
	updates map[string][]flow.StreamUpdate
	flows   []*flow.Flow
}

func (s *flowStoreForH2Pool) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *st
	s.streams = append(s.streams, &cp)
	return nil
}

func (s *flowStoreForH2Pool) UpdateStream(_ context.Context, id string, upd flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updates == nil {
		s.updates = make(map[string][]flow.StreamUpdate)
	}
	s.updates[id] = append(s.updates[id], upd)
	for _, st := range s.streams {
		if st.ID == id {
			if upd.State != "" {
				st.State = upd.State
			}
			if upd.FailureReason != "" {
				st.FailureReason = upd.FailureReason
			}
		}
	}
	return nil
}

func (s *flowStoreForH2Pool) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *f
	s.flows = append(s.flows, &cp)
	return nil
}

func (s *flowStoreForH2Pool) Streams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

func (s *flowStoreForH2Pool) Flows() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

// releaseFirstHeldEntry waits up to timeout for the queue to receive a held
// entry and then releases it with the given action. Returns the released
// entry's stored envelope so the caller can mutate it for modify_and_forward.
func releaseFirstHeldEntry(t *testing.T, q *common.HoldQueue, timeout time.Duration, build func(held *common.HeldEntry) *common.HoldAction) *common.HeldEntry {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if q.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries := q.List()
	if len(entries) == 0 {
		t.Fatal("no held entry observed within timeout")
	}
	held := entries[0]
	if err := q.Release(held.ID, build(held)); err != nil {
		t.Fatalf("HoldQueue.Release: %v", err)
	}
	return held
}

// TestUSK816_H2Pool_InterceptRelease_ResponseRelays is the headline regression
// test. It exercises the production assembly (BuildLiveStack + non-nil
// HTTP2Pool) with an HTTP intercept rule that holds the request envelope.
// The operator releases (no modification); the upstream's response body must
// reach the client and be recorded as state="complete" with status=200.
func TestUSK816_H2Pool_InterceptRelease_ResponseRelays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "usk816-marker", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("upstream-body-for-" + r.URL.Path))
	}))
	defer upShutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk816-release",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/headers$`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	pool := h2pool.New(h2pool.PoolOptions{})
	defer pool.Close()

	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForH2PoolInterceptTest(t, ctx, store, intercept, holdQueue, pool)

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/headers", nil)
		resp, err := cli.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(_ *common.HeldEntry) *common.HoldAction {
		return &common.HoldAction{Type: common.ActionRelease}
	})

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client error: %v", r.err)
		}
		if r.status != 200 {
			t.Errorf("client status = %d, want 200 (USK-816: upstream response did not relay)", r.status)
		}
		if r.body != "upstream-body-for-/headers" {
			t.Errorf("client body = %q, want %q (response body did not propagate after intercept release)",
				r.body, "upstream-body-for-/headers")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client never received upstream response after intercept release (USK-816 reproduced)")
	}

	// Wait for recording to settle.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= 1 && len(store.Flows()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected >=1 stream recorded, got %d", len(streams))
	}
	st := streams[0]
	if st.State != "complete" {
		t.Errorf("stream State = %q, want %q (USK-816 repro: stream closed without proper completion)", st.State, "complete")
	}

	flows := store.Flows()
	var sendF, recvF *flow.Flow
	for _, f := range flows {
		// USK-897: filter on semantic envelopes — the aggregator-path
		// h2 DATA frame record callback (wire_level=h2-frame) now lands
		// here too, and those envelopes carry no StatusCode/Body.
		if f.WireLevel != "" && f.WireLevel != flow.WireLevelSemantic {
			continue
		}
		switch f.Direction {
		case "send":
			if sendF == nil {
				sendF = f
			}
		case "receive":
			if recvF == nil {
				recvF = f
			}
		}
	}
	if sendF == nil {
		t.Fatal("no send-direction flow recorded")
	}
	if recvF == nil {
		t.Fatal("no receive-direction flow recorded (USK-816: response side missing entirely)")
	}
	if recvF.StatusCode != 200 {
		t.Errorf("recv StatusCode = %d, want 200 (USK-816: response_status_code=0 reproduces the bug)",
			recvF.StatusCode)
	}
	if len(recvF.Body) == 0 {
		t.Error("recv Body empty (USK-816: response_body=\"\" reproduces the bug)")
	}
}

// TestUSK816_H2Pool_InterceptModifyAndForward_ResponseRelays mirrors the
// release test but uses ActionModifyAndForward with a header injection. The
// upstream must observe the injected header AND the response must reach the
// client.
func TestUSK816_H2Pool_InterceptModifyAndForward_ResponseRelays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var observedInjected atomic.Value
	observedInjected.Store("")

	upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "usk816-modify", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		observedInjected.Store(r.Header.Get("X-Yorishiro"))
		_, _ = w.Write([]byte("modified-upstream-body"))
	}))
	defer upShutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk816-modify",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/headers$`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	pool := h2pool.New(h2pool.PoolOptions{})
	defer pool.Close()

	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForH2PoolInterceptTest(t, ctx, store, intercept, holdQueue, pool)

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/headers", nil)
		resp, err := cli.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(held *common.HeldEntry) *common.HoldAction {
		modified := held.Envelope.Clone()
		msg := modified.Message.(*envelope.HTTPMessage)
		msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "x-yorishiro", Value: "p5-01-injected"})
		return &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified}
	})

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client error: %v", r.err)
		}
		if r.status != 200 {
			t.Errorf("client status = %d, want 200 (USK-816: upstream response did not relay)", r.status)
		}
		if r.body != "modified-upstream-body" {
			t.Errorf("client body = %q, want %q", r.body, "modified-upstream-body")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client never received upstream response after modify_and_forward (USK-816 reproduced)")
	}

	if got := observedInjected.Load().(string); got != "p5-01-injected" {
		t.Errorf("upstream observed X-Yorishiro = %q, want %q (modify_and_forward did not deliver injected header)", got, "p5-01-injected")
	}
}

// TestUSK816_H2Pool_InterceptRelease_TwoSequentialCONNECTs forces the pool
// reuse code path: after the first CONNECT completes, the upstream Layer is
// returned to the pool. The second CONNECT must consult the pool fast-path
// AND must still relay the response after intercept release.
func TestUSK816_H2Pool_InterceptRelease_TwoSequentialCONNECTs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	upAddr, accepts, upShutdown := startH2TLSUpstreamForPoolTest(t, "usk816-pool", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = w.Write([]byte("seq-" + r.URL.Path))
	}))
	defer upShutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk816-seq",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/.*$`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	pool := h2pool.New(h2pool.PoolOptions{})
	defer pool.Close()

	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForH2PoolInterceptTest(t, ctx, store, intercept, holdQueue, pool)

	doRequestAndRelease := func(label string, path string) string {
		type result struct {
			body string
			err  error
		}
		resCh := make(chan result, 1)
		go func() {
			cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
			req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+path, nil)
			resp, err := cli.Do(req)
			if err != nil {
				resCh <- result{err: err}
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			resCh <- result{body: string(b)}
			cli.CloseIdleConnections()
		}()

		releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(_ *common.HeldEntry) *common.HoldAction {
			return &common.HoldAction{Type: common.ActionRelease}
		})

		select {
		case r := <-resCh:
			if r.err != nil {
				t.Fatalf("[%s] client error: %v", label, r.err)
			}
			return r.body
		case <-time.After(15 * time.Second):
			t.Fatalf("[%s] response never arrived (USK-816 reproduced on pool-reuse path)", label)
			return ""
		}
	}

	if got := doRequestAndRelease("first", "/a"); got != "seq-/a" {
		t.Errorf("first request body = %q, want %q", got, "seq-/a")
	}
	// Give the pool time to receive Pool.Put after handler exit.
	time.Sleep(200 * time.Millisecond)

	if got := doRequestAndRelease("second", "/b"); got != "seq-/b" {
		t.Errorf("second request body = %q, want %q", got, "seq-/b")
	}

	// Pool reuse signal: only one upstream TCP accept across two CONNECTs.
	// This is the externally-observable correctness signal of the
	// HTTP2Pool fast-path. If accepts == 2 the pool was bypassed and the
	// test no longer covers the regression scenario.
	time.Sleep(200 * time.Millisecond)
	if a := accepts(); a != 1 {
		t.Errorf("upstream accept count = %d, want 1 (HTTP2Pool fast-path was bypassed; test no longer covers USK-816 path)", a)
	}
}

// TestUSK816_H2Pool_InterceptDrop verifies the drop semantics are unchanged.
// Drop must not relay anything to upstream, and the client sees a closed
// stream. This is the negative control for the release / modify_and_forward
// repro path: it confirms the test harness exercises the production path,
// while the response-relay tests above confirm the regression class.
func TestUSK816_H2Pool_InterceptDrop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var upstreamHits atomic.Int64
	upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "usk816-drop", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("should-not-reach"))
	}))
	defer upShutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk816-drop",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/headers$`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	pool := h2pool.New(h2pool.PoolOptions{})
	defer pool.Close()

	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForH2PoolInterceptTest(t, ctx, store, intercept, holdQueue, pool)

	type result struct {
		err  error
		body string
	}
	resCh := make(chan result, 1)
	go func() {
		cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/headers", nil)
		resp, err := cli.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{body: string(b)}
	}()

	releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(_ *common.HeldEntry) *common.HoldAction {
		return &common.HoldAction{Type: common.ActionDrop}
	})

	select {
	case r := <-resCh:
		// Drop semantics: client either gets an error from the broken
		// stream OR an empty body. The test only requires that upstream
		// did NOT see the request.
		_ = r
	case <-time.After(15 * time.Second):
		// Drop closes the request stream; the client should observe an
		// error or empty body within seconds. Hitting the full timeout
		// is itself a failure.
		t.Fatal("drop semantics: client.Do never returned (test harness desync)")
	}

	if hits := upstreamHits.Load(); hits != 0 {
		t.Errorf("upstream observed %d request hits after intercept drop, want 0", hits)
	}
}

// startHTTP1TLSUpstreamForPoolTest spins up a TLS upstream that serves
// HTTP/1.1 only (NextProtos = ["http/1.1"]) so the MITM negotiates h1
// instead of h2. This exercises the non-h2 OnStack route — the h2 pool
// fast-path is bypassed entirely.
func startHTTP1TLSUpstreamForPoolTest(t *testing.T, cn string, handler gohttp.Handler) (addr string, shutdown func()) {
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
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{"http/1.1"},
	}

	srv := &gohttp.Server{Handler: handler, TLSConfig: tlsCfg}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(tcpLn, tlsCfg)
	go func() { _ = srv.Serve(tlsLn) }()
	return tcpLn.Addr().String(), func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = tlsLn.Close()
	}
}

// startH2AndH1TLSUpstreamForPoolTest spins up a TLS upstream that advertises
// BOTH "h2" and "http/1.1" via ALPN so the proxy's upstream redial chooses
// based on the client's chosen ALPN — the exact mismatch path the curl repro
// exercises (h1 client + h2-capable origin). Uses gohttp.Server's native
// http2 + http1 multiplex so both protocols are served from one listener.
func startH2AndH1TLSUpstreamForPoolTest(t *testing.T, cn string, h1Handler gohttp.Handler) (addr string, shutdown func()) {
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
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{"h2", "http/1.1"},
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &gohttp.Server{Handler: h1Handler, TLSConfig: tlsCfg}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(tcpLn, tlsCfg)
	go func() { _ = srv.Serve(tlsLn) }()
	return tcpLn.Addr().String(), func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = tlsLn.Close()
	}
}

// TestUSK816_H1Client_H2CapableUpstream_InterceptRelease_ResponseRelays
// reproduces the exact wire profile of the bug report: h1 client (curl) +
// h2-capable upstream (httpbingo.org). The proxy MITM presents h1 to the
// client, then must redial upstream as h1 (canonicalRedialALPNOffer) so
// the inner stack is h1-end-to-end. Despite that, the upstream-facing
// dial may consult the h2 pool, the ALPN cache may have been warmed for
// h2, etc. Asserts the response body reaches the client after intercept
// release.
func TestUSK816_H1Client_H2CapableUpstream_InterceptRelease_ResponseRelays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upShutdown := startH2AndH1TLSUpstreamForPoolTest(t, "usk816-mixed", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = w.Write([]byte("mixed-body-" + r.URL.Path))
	}))
	defer upShutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk816-mixed",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/headers$`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	pool := h2pool.New(h2pool.PoolOptions{})
	defer pool.Close()

	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForH2PoolInterceptTest(t, ctx, store, intercept, holdQueue, pool)

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		tr := &gohttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DialTLS: func(network, addr string) (net.Conn, error) {
				raw, err := connectTunnelDialerForPoolTest(proxyAddr, upAddr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(raw, &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
					NextProtos:         []string{"http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					raw.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			DisableKeepAlives: true,
		}
		cli := &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/headers", nil)
		resp, err := cli.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(_ *common.HeldEntry) *common.HoldAction {
		return &common.HoldAction{Type: common.ActionRelease}
	})

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client error: %v", r.err)
		}
		if r.status != 200 {
			t.Errorf("client status = %d, want 200 (USK-816 wire-shape repro: h1 client + h2-capable upstream)", r.status)
		}
		if r.body != "mixed-body-/headers" {
			t.Errorf("client body = %q, want %q (response did not relay after intercept release)", r.body, "mixed-body-/headers")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("USK-816 wire-shape repro: h1 client + h2-capable upstream — response never arrived after intercept release")
	}
}

// TestUSK821_HTTP1_InterceptResponseDirection_HoldsResponse is the headline
// regression test for USK-821: a direction:"response" rule with a
// path_pattern must fire on the response side. Before the fix, matchesRule
// evaluated PathPattern unconditionally, so the empty Path on response
// envelopes (per HTTPMessage field-validity contract) silently rejected
// every direction:"response" rule that included path_pattern.
//
// The test asserts:
//   - request side does NOT hold (Direction == response excludes Send)
//   - response side DOES hold with the rule id
//   - after release, the response body is delivered to the client unchanged
func TestUSK821_HTTP1_InterceptResponseDirection_HoldsResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upShutdown := startHTTP1TLSUpstreamForPoolTest(t, "usk821-resp", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = w.Write([]byte("usk821-body-" + r.URL.Path))
	}))
	defer upShutdown()

	intercept := httprules.NewInterceptEngine()
	// USK-821 repro shape: direction:"response" + path_pattern + host_pattern.
	// Pre-fix this rule never fired (PathPattern.MatchString("") on response
	// short-circuits to false). Post-fix the response side matches by host
	// (path skipped on Receive), and the request side is excluded by
	// direction filter alone. HostPattern matches the connector-stamped
	// EnvelopeContext.TargetHost (the upstream loopback address — the CN
	// is not the dial target).
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk821-response-hold",
		Enabled:     true,
		Direction:   httprules.DirectionResponse,
		HostPattern: regexp.MustCompile(`^127\.0\.0\.1$`),
		PathPattern: regexp.MustCompile(`^/get$`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	pool := h2pool.New(h2pool.PoolOptions{})
	defer pool.Close()

	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForH2PoolInterceptTest(t, ctx, store, intercept, holdQueue, pool)

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		tr := &gohttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DialTLS: func(network, addr string) (net.Conn, error) {
				raw, err := connectTunnelDialerForPoolTest(proxyAddr, upAddr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(raw, &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
					NextProtos:         []string{"http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					raw.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			DisableKeepAlives: true,
		}
		cli := &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/get", nil)
		resp, err := cli.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	// Wait for a held entry. With direction:"response" + path on a request
	// path that DOES match (/get), a pre-fix proxy would never enter the
	// held state at all (request side is filtered by direction; response
	// side's matchesRule short-circuits on empty Path) — so the held queue
	// would stay empty for the full timeout.
	held := releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(_ *common.HeldEntry) *common.HoldAction {
		return &common.HoldAction{Type: common.ActionRelease}
	})

	// Confirm the held envelope is the response side.
	if held.Envelope == nil {
		t.Fatal("held entry has no envelope")
	}
	if held.Envelope.Direction != envelope.Receive {
		t.Errorf("held envelope direction = %v, want %v (USK-821: rule should hold on the response side)", held.Envelope.Direction, envelope.Receive)
	}
	if len(held.MatchedRules) != 1 || held.MatchedRules[0] != "usk821-response-hold" {
		t.Errorf("held entry matched_rules = %v, want [usk821-response-hold]", held.MatchedRules)
	}

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client error: %v", r.err)
		}
		if r.status != 200 {
			t.Errorf("client status = %d, want 200 (post-release response should still relay)", r.status)
		}
		if r.body != "usk821-body-/get" {
			t.Errorf("client body = %q, want %q (post-release response body should match upstream verbatim)", r.body, "usk821-body-/get")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("USK-821: client never received upstream response after response-side release")
	}
}

// TestUSK816_HTTP1_InterceptRelease_ResponseRelays is the negative control
// that exercises the same intercept path against an HTTP/1.x-only upstream
// so the h2 pool fast-path is bypassed. If this also passes (it does), the
// regression class is not localized in the proxybuild data path at all —
// the bug must originate in the MCP / control-plane wiring (proxy_start
// argument plumbing, capture_scope translation, etc.) which this harness
// deliberately does not exercise.
func TestUSK816_HTTP1_InterceptRelease_ResponseRelays(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upShutdown := startHTTP1TLSUpstreamForPoolTest(t, "usk816-h1", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = w.Write([]byte("h1-body-" + r.URL.Path))
	}))
	defer upShutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk816-h1",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/headers$`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(10 * time.Second)

	pool := h2pool.New(h2pool.PoolOptions{})
	defer pool.Close()

	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForH2PoolInterceptTest(t, ctx, store, intercept, holdQueue, pool)

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		// HTTP/1.1 client through CONNECT.
		tr := &gohttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DialTLS: func(network, addr string) (net.Conn, error) {
				raw, err := connectTunnelDialerForPoolTest(proxyAddr, upAddr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(raw, &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
					NextProtos:         []string{"http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					raw.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			DisableKeepAlives: true,
		}
		cli := &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/headers", nil)
		resp, err := cli.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(_ *common.HeldEntry) *common.HoldAction {
		return &common.HoldAction{Type: common.ActionRelease}
	})

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client error: %v", r.err)
		}
		if r.status != 200 {
			t.Errorf("client status = %d, want 200", r.status)
		}
		if r.body != "h1-body-/headers" {
			t.Errorf("client body = %q, want %q", r.body, "h1-body-/headers")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("HTTP/1.x client never received upstream response after intercept release")
	}
}
