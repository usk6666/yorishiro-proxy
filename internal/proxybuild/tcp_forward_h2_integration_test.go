//go:build e2e && !e2e_smoke

// Package proxybuild_test exhaustive tier — USK-914 h2c (HTTP/2 over
// cleartext) forward proxy. Validates the new ForwardConfig.Protocol="http2"
// arm wires DispatchH2StreamFull per stream with per-stream wire-record
// callbacks; the stand-alone gRPC suite lives in
// tcp_forward_grpc_integration_test.go.
package proxybuild_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// h2cEchoUpstream starts an h2c upstream server using the standard
// golang.org/x/net/http2 + h2c shim. Returns (addr, shutdown).
func h2cEchoUpstream(t *testing.T, handler gohttp.Handler) (addr string, shutdown func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	h2s := &http2.Server{}
	srv := &gohttp.Server{
		Handler: h2c.NewHandler(handler, h2s),
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() {
		_ = srv.Close()
		_ = ln.Close()
	}
}

// h2cForwardClient builds an http.Client speaking h2c directly to addr
// (bypasses TLS via AllowHTTP+plain dial). The returned *gohttp.Client
// carries a single shared http2.Transport whose connection captures into
// dialedConns — the test's force-close-on-teardown pattern needs the
// caller-side conn handle to avoid the xhttp2.Transport.CloseIdleConnections
// race (race-flake memory item #6).
func h2cForwardClient(addr string, dialedConns *[]net.Conn, mu *sync.Mutex) *gohttp.Client {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(network, _ string, _ *tls.Config) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			if dialedConns != nil {
				mu.Lock()
				*dialedConns = append(*dialedConns, c)
				mu.Unlock()
			}
			return c, nil
		},
	}
	return &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
}

// newH2ForwardTestManager constructs a *proxybuild.Manager for the h2
// forward path tests. Mirrors newForwardTestManager (see
// tcp_forward_integration_test.go) but accepts a custom BuildConfig so
// h2-specific settings (body spill, max body size, max concurrent streams)
// can be overridden when needed.
func newH2ForwardTestManager(t *testing.T, store *flowStoreCapture) *proxybuild.Manager {
	t.Helper()
	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    store,
			BuildConfig:  buildCfg,
		})
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// startH2ForwardListener spins up the proxy with one TCP forward entry
// targeting upstreamAddr with Protocol="http2" or "grpc". Returns the
// bound forward address and the FlowStore.
func startH2ForwardListener(t *testing.T, ctx context.Context, upstreamAddr, protocol string) (
	mgr *proxybuild.Manager, fwdAddr string, store *flowStoreCapture,
) {
	t.Helper()
	store = &flowStoreCapture{}
	mgr = newH2ForwardTestManager(t, store)

	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: upstreamAddr, Protocol: protocol},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards(%s): %v", protocol, err)
	}
	addrs := mgr.TCPForwardAddrs()
	fwdAddr = addrs["0"]
	if fwdAddr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0: %v", addrs)
	}
	return mgr, fwdAddr, store
}

// closeDialedConns force-closes every captured client-side TCP conn.
// Required by the xhttp2.Transport.CloseIdleConnections race workaround
// documented in feedback_h2_concurrency_flake_patterns.md item #6.
func closeDialedConns(dialedConns []net.Conn) {
	for _, c := range dialedConns {
		_ = c.Close()
	}
}

// TestProxybuild_TCPForward_H2C_BasicRoundtrip is the minimum viable
// h2c forward proof: a single GET / round-trips end-to-end via the
// forward listener with Protocol="http2".
func TestProxybuild_TCPForward_H2C_BasicRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Echo-Path", r.URL.Path)
		_, _ = fmt.Fprintf(w, "h2c-echo:%s", r.URL.Path)
	}))
	defer upStop()

	mgr, fwdAddr, store := startH2ForwardListener(t, ctx, upAddr, "http2")
	defer mgr.StopAll(context.Background())

	var dialedConns []net.Conn
	var mu sync.Mutex
	cli := h2cForwardClient(fwdAddr, &dialedConns, &mu)

	req, err := gohttp.NewRequestWithContext(ctx, "GET", "http://"+fwdAddr+"/hello", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got, want := resp.StatusCode, gohttp.StatusOK; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
	if got, want := string(body), "h2c-echo:/hello"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "/hello" {
		t.Errorf("X-Echo-Path = %q, want /hello", got)
	}

	// Wait for recording to settle, then assert at least one Stream
	// recorded under Protocol=http and observable Flows.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= 1 && len(store.Flows()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cli.CloseIdleConnections()
	mu.Lock()
	dial := append([]net.Conn{}, dialedConns...)
	mu.Unlock()
	closeDialedConns(dial)

	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected at least 1 stream recorded, got %d", len(streams))
	}
	// h2 forward path produces Protocol=http (semantic) streams; gRPC-Web
	// auto-routing would produce grpc-web, but this handler returns plain
	// bytes.
	sawHTTP := false
	for _, st := range streams {
		if st.Protocol == "http" {
			sawHTTP = true
			break
		}
	}
	if !sawHTTP {
		t.Errorf("expected at least one stream with Protocol=http, got %+v", streams)
	}
}

// TestProxybuild_TCPForward_H2C_ConcurrentStreams_RecordingIsolation
// exercises ≥10 parallel streams through the h2 forward listener and
// asserts each stream's recorded flows reflect its own X-Stream-Id (no
// cross-contamination). USK-739 / USK-740 race-flake lessons applied:
// warm-up first, sync.WaitGroup drain, force-close dialed conns before
// assertions.
func TestProxybuild_TCPForward_H2C_ConcurrentStreams_RecordingIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		id := r.Header.Get("X-Stream-Id")
		_, _ = fmt.Fprintf(w, "stream-%s", id)
	}))
	defer upStop()

	mgr, fwdAddr, store := startH2ForwardListener(t, ctx, upAddr, "http2")
	defer mgr.StopAll(context.Background())

	var dialedConns []net.Conn
	var mu sync.Mutex
	cli := h2cForwardClient(fwdAddr, &dialedConns, &mu)

	// Warm-up establishes the single shared TCP conn so the n parallel
	// requests multiplex over the same h2 connection.
	warm, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://"+fwdAddr+"/warm", nil)
	warm.Header.Set("X-Stream-Id", "warm")
	if wResp, wErr := cli.Do(warm); wErr == nil {
		_, _ = io.ReadAll(wResp.Body)
		_ = wResp.Body.Close()
	} else {
		t.Fatalf("warm-up request: %v", wErr)
	}

	const n = 10
	var wg sync.WaitGroup
	var failed atomic.Int64
	results := make([]string, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := strconv.Itoa(i)
			req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://"+fwdAddr+"/concurrent/"+id, nil)
			req.Header.Set("X-Stream-Id", id)
			resp, rerr := cli.Do(req)
			if rerr != nil {
				failed.Add(1)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			results[i] = string(b)
		}()
	}
	wg.Wait()

	if failed.Load() > 0 {
		t.Fatalf("%d requests failed", failed.Load())
	}
	for i, body := range results {
		want := "stream-" + strconv.Itoa(i)
		if body != want {
			t.Errorf("stream %d body=%q want %q (response cross-contamination)", i, body, want)
		}
	}

	// Wait for recordings to settle.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= n+1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Force-close client conns before reading store (race memory item #6).
	cli.CloseIdleConnections()
	mu.Lock()
	dial := append([]net.Conn{}, dialedConns...)
	mu.Unlock()
	closeDialedConns(dial)

	// Recording isolation invariant: each concurrent stream (excluding the
	// warm-up) must show send+receive flows with matching X-Stream-Id.
	streams := store.Streams()
	linked := 0
	for _, st := range streams {
		flows := store.Flows()
		var sendF, recvF *flowFlowAlias
		for _, f := range flows {
			if f.StreamID != st.ID {
				continue
			}
			ff := &flowFlowAlias{Direction: f.Direction, Headers: f.Headers, RawBytes: f.RawBytes, Body: f.Body}
			if f.Direction == "send" && sendF == nil {
				sendF = ff
			} else if f.Direction == "receive" && recvF == nil {
				recvF = ff
			}
		}
		if sendF == nil || recvF == nil {
			continue
		}
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
		// Cross-contamination check.
		if sent != "" {
			body := string(recvF.Body)
			if body == "" {
				body = string(recvF.RawBytes)
			}
			wantSub := "stream-" + sent
			if !bytes.Contains([]byte(body), []byte(wantSub)) {
				t.Errorf("stream id=%s recv body=%q does not contain %q (cross-contamination)", sent, body, wantSub)
			}
		}
	}
	if linked < n {
		t.Errorf("expected ≥%d linked concurrent-stream send+recv pairs, got %d (streams=%d)", n, linked, len(streams))
	}
}

// flowFlowAlias is a thin projection of flow.Flow used to keep the
// recording-isolation loop above readable. The only fields the assertion
// needs are Direction, Headers, RawBytes, Body — projecting them avoids
// passing the full flow.Flow shape around.
type flowFlowAlias struct {
	Direction string
	Headers   map[string][]string
	RawBytes  []byte
	Body      []byte
}
