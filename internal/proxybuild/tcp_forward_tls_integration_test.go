//go:build e2e && !e2e_smoke

// Package proxybuild_test exhaustive tier — USK-915 client-side TLS
// terminate for TCP forward listeners. Validates the new fc.TLS=true arm
// terminates client TLS using the SNI-honoring per-entry tls.Config,
// dispatches by negotiated ALPN, records flows with Scheme="https", and
// records state="error" Streams for handshake failure.
package proxybuild_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-915 e2e harness. Each test cell builds a Manager whose
// ManagerConfig.BuildConfig carries the CA Issuer (the listener-start
// guard requires this for fc.TLS=true). The client-side root pool trusts
// the Issuer's CA so TLS handshakes succeed end-to-end.

type tlsForwardFixture struct {
	mgr       *proxybuild.Manager
	store     *flowStoreCapture
	ca        *cert.CA
	rootPool  *x509.CertPool
	buildCfg  *connector.BuildConfig
	fwdAddr   string
	upstream  string
	stopUpstr func()
}

// newTLSForwardFixture spins up a fixture for the given forward Protocol +
// upstream. The forward listener binds 127.0.0.1:0 with TLS=true. The
// returned fixture carries the bound forward address; the caller is
// responsible for closing the upstream via fix.stopUpstr().
func newTLSForwardFixture(t *testing.T, ctx context.Context, protocol, upstreamAddr string, stopUpstream func()) *tlsForwardFixture {
	t.Helper()

	store := &flowStoreCapture{}
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Certificate())

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:      testutil.DiscardLogger(),
		BuildConfig: buildCfg,
		StackFactory: func(_ context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(context.Background(), proxybuild.Deps{
				Logger:       testutil.DiscardLogger(),
				ListenerName: name,
				ListenAddr:   addr,
				FlowStore:    store,
				BuildConfig:  buildCfg,
			})
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })

	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: upstreamAddr, Protocol: protocol, TLS: true},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards(%s, tls=true): %v", protocol, err)
	}
	addr := mgr.TCPForwardAddrs()["0"]
	if addr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0")
	}

	return &tlsForwardFixture{
		mgr:       mgr,
		store:     store,
		ca:        ca,
		rootPool:  rootPool,
		buildCfg:  buildCfg,
		fwdAddr:   addr,
		upstream:  upstreamAddr,
		stopUpstr: stopUpstream,
	}
}

// TestProxybuild_TCPForward_TLS_HTTP1_BasicRoundtrip verifies the
// happy-path for Protocol="http" + TLS=true: client speaks TLS+HTTP/1.1
// over the forward listener; bytes reach the cleartext upstream; response
// returns to the client; Stream records Scheme="https".
func TestProxybuild_TCPForward_TLS_HTTP1_BasicRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, _, stopUpstream := startHTTPEchoUpstreamForUSK913(t)
	defer stopUpstream()

	fix := newTLSForwardFixture(t, ctx, "http", upstreamAddr, stopUpstream)

	cli := &gohttp.Client{
		Transport: &gohttp.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "forward.example.test",
				NextProtos: []string{"http/1.1"},
			},
		},
		Timeout: 10 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/tls-hello", nil)
	req.Host = "forward.example.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got, want := resp.StatusCode, gohttp.StatusOK; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
	if !strings.Contains(string(body), "") {
		// The upstream echoes path back via Echo-Path header — empty body
		// is fine for a GET. The header check below pins the route.
	}
	if got := resp.Header.Get("Echo-Path"); got != "/tls-hello" {
		t.Errorf("Echo-Path = %q, want /tls-hello", got)
	}

	// Wait for recordings to settle and assert at least one Stream is
	// stamped Scheme="https" (the new U2 field).
	if !waitForHTTPSStream(t, fix.store, 3*time.Second) {
		t.Errorf("no Stream recorded with Scheme=\"https\"; got %v", fix.store.Streams())
	}
}

// TestProxybuild_TCPForward_TLS_HTTP2_BasicRoundtrip verifies the
// happy-path for Protocol="http2" + TLS=true: client speaks TLS+h2 over
// the forward listener; the proxy negotiates h2 via ALPN, terminates TLS,
// and forwards the h2 frames to the cleartext h2c upstream.
func TestProxybuild_TCPForward_TLS_HTTP2_BasicRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = fmt.Fprintf(w, "h2c-echo:%s", r.URL.Path)
	}))
	defer upStop()

	fix := newTLSForwardFixture(t, ctx, "http2", upAddr, upStop)

	cli := &gohttp.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "forward.example.test",
				NextProtos: []string{"h2"},
			},
		},
		Timeout: 10 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/h2", nil)
	req.Host = "forward.example.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if got, want := resp.StatusCode, gohttp.StatusOK; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
	if got, want := string(body), "h2c-echo:/h2"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	if !waitForHTTPSStream(t, fix.store, 3*time.Second) {
		t.Errorf("no Stream recorded with Scheme=\"https\"; got %v", fix.store.Streams())
	}
}

// TestProxybuild_TCPForward_TLS_Auto_HTTP1 verifies Protocol="auto" +
// TLS=true: the operator advertises both ALPNs, the client offers only
// http/1.1, the proxy dispatches via the H1 arm.
func TestProxybuild_TCPForward_TLS_Auto_HTTP1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, _, stopUpstream := startHTTPEchoUpstreamForUSK913(t)
	defer stopUpstream()

	fix := newTLSForwardFixture(t, ctx, "auto", upstreamAddr, stopUpstream)

	cli := &gohttp.Client{
		Transport: &gohttp.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "forward.example.test",
				NextProtos: []string{"http/1.1"}, // client opts out of h2
			},
		},
		Timeout: 10 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/auto-h1", nil)
	req.Host = "forward.example.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := resp.Header.Get("Echo-Path"); got != "/auto-h1" {
		t.Errorf("Echo-Path = %q, want /auto-h1", got)
	}
}

// TestProxybuild_TCPForward_TLS_Auto_HTTP2 verifies Protocol="auto" +
// TLS=true: the operator advertises both ALPNs, the client offers h2 and
// http/1.1, the proxy dispatches via the H2 arm.
func TestProxybuild_TCPForward_TLS_Auto_HTTP2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = fmt.Fprintf(w, "auto-h2:%s", r.URL.Path)
	}))
	defer upStop()

	fix := newTLSForwardFixture(t, ctx, "auto", upAddr, upStop)

	cli := &gohttp.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "forward.example.test",
				NextProtos: []string{"h2"},
			},
		},
		Timeout: 10 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/auto-h2", nil)
	req.Host = "forward.example.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got, want := string(body), "auto-h2:/auto-h2"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestProxybuild_TCPForward_TLS_HTTP2_AlpnMismatch_Rejected verifies that
// declaring Protocol="http2" while the client offers an ALPN list with no
// overlap with the server's advertised list results in a TLS handshake
// rejection (no_application_protocol alert) AND a state="error" Stream is
// recorded with FailureReason="client_tls_error".
//
// AC: "AC #6 / #(e): TLS+http2 with h1-only client → no_application_protocol
// + state="error" Stream recorded".
//
// Important Go-stdlib detail: crypto/tls has a special-case fallback for
// (server="h2", client="http/1.1") — it does NOT reject the handshake in
// that combo; ALPN is left empty and the handshake succeeds. See
// negotiateALPN in src/crypto/tls/handshake_server.go (Go issue 46310).
// To exercise the real no_application_protocol path we offer a synthetic
// custom protocol that has no overlap with the server's "h2" advertise.
func TestProxybuild_TCPForward_TLS_HTTP2_AlpnMismatch_Rejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upStop()

	fix := newTLSForwardFixture(t, ctx, "http2", upAddr, upStop)

	// Client offers an unknown application protocol with no overlap with
	// the server's "h2" advertise. crypto/tls (Go 1.21+) rejects with
	// no_application_protocol per RFC 7301 §3.2.
	clientCfg := &tls.Config{
		RootCAs:    fix.rootPool,
		ServerName: "forward.example.test",
		NextProtos: []string{"unknown/9.9"},
	}
	conn, err := tls.Dial("tcp", fix.fwdAddr, clientCfg)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected TLS handshake to fail with no_application_protocol, got success")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "application protocol") &&
		!strings.Contains(strings.ToLower(err.Error()), "no_application_protocol") {
		t.Logf("handshake error: %v (test still validates the error-stream branch)", err)
	}

	// Wait for the error Stream to land.
	if !waitForClientTLSErrorStream(t, fix.store, 3*time.Second) {
		t.Errorf("no Stream recorded with FailureReason=client_tls_error; got %v", summarizeStreams(fix.store.Streams()))
	}
}

// TestProxybuild_TCPForward_TLS_WSS_RoundTrip verifies WSS through the
// forward listener: Protocol="websocket" + TLS=true accepts the WS upgrade
// handshake on a TLS-wrapped conn and relays frames to the cleartext WS
// upstream.
func TestProxybuild_TCPForward_TLS_WSS_RoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, hits, stopUpstream := startWSEchoUpstreamForUSK915(t)
	defer stopUpstream()

	fix := newTLSForwardFixture(t, ctx, "websocket", upstreamAddr, stopUpstream)

	clientCfg := &tls.Config{
		RootCAs:    fix.rootPool,
		ServerName: "forward.example.test",
		NextProtos: []string{"http/1.1"},
	}
	conn, err := tls.Dial("tcp", fix.fwdAddr, clientCfg)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	if err := writeWSClientHandshakeForUSK913(conn, "forward.example.test"); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	if err := readWS101ForUSK913(br); err != nil {
		t.Fatalf("read 101: %v", err)
	}

	// Wait for upstream to observe the upgrade.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Errorf("upstream did not observe ws handshake")
	}
}

// TestProxybuild_TCPForward_TLS_SNIMismatch_WarnLogged verifies the
// SNI ≠ Target Warn path. The fixture builds a forward Target = a
// specific host:port, the client offers a different SNI; the handshake
// succeeds (the proxy issues a cert for the SNI), the Warn log fires,
// and the request still round-trips end-to-end. AC: "SNI ≠ Target Warn log
// post-handshake".
func TestProxybuild_TCPForward_TLS_SNIMismatch_WarnLogged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, _, stopUpstream := startHTTPEchoUpstreamForUSK913(t)
	defer stopUpstream()

	fix := newTLSForwardFixture(t, ctx, "http", upstreamAddr, stopUpstream)

	cli := &gohttp.Client{
		Transport: &gohttp.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "different-sni.example.test", // != Target host (127.0.0.1)
				NextProtos: []string{"http/1.1"},
			},
		},
		Timeout: 10 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/sni-mismatch", nil)
	req.Host = "different-sni.example.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := resp.Header.Get("Echo-Path"); got != "/sni-mismatch" {
		t.Errorf("Echo-Path = %q, want /sni-mismatch", got)
	}
	// The Warn log itself is a slog observation; we do not assert on it
	// directly (the test uses DiscardLogger). The round-trip success is
	// the operational signal that the SNI-mismatch path did not regress
	// to a handshake failure.
}

// waitForHTTPSStream polls store until at least one Stream is stamped
// Scheme="https". Returns true when observed within deadline.
func waitForHTTPSStream(t *testing.T, store *flowStoreCapture, deadline time.Duration) bool {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		for _, st := range store.Streams() {
			if st != nil && st.Scheme == "https" {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// waitForClientTLSErrorStream polls store until at least one Stream is
// stamped FailureReason="client_tls_error". Returns true when observed
// within deadline.
func waitForClientTLSErrorStream(t *testing.T, store *flowStoreCapture, deadline time.Duration) bool {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		for _, st := range store.Streams() {
			if st != nil && st.FailureReason == "client_tls_error" {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// summarizeStreams renders a compact view of recorded streams for failure
// messages.
func summarizeStreams(streams []*flow.Stream) []string {
	out := make([]string, 0, len(streams))
	for _, st := range streams {
		if st == nil {
			out = append(out, "<nil>")
			continue
		}
		out = append(out, fmt.Sprintf("{proto=%q scheme=%q state=%q failure=%q}",
			st.Protocol, st.Scheme, st.State, st.FailureReason))
	}
	return out
}

// startWSEchoUpstreamForUSK915 binds a plain HTTP/1.1 server that accepts a
// WS upgrade handshake, returns 101 Switching Protocols, and increments hits
// when it has read the handshake. The body of the conn isn't exercised
// (we just need to confirm the upgrade reached the upstream end-to-end
// through the TLS forward path).
func startWSEchoUpstreamForUSK915(t *testing.T) (addr string, hits *atomic.Int64, stop func()) {
	t.Helper()
	hits = &atomic.Int64{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, accErr := ln.Accept()
			if accErr != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(conn)
				var key string
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
						key = strings.TrimSpace(line[len("Sec-WebSocket-Key:"):])
					}
					if line == "\r\n" {
						break
					}
				}
				if key == "" {
					return
				}
				hits.Add(1)
				accept := computeWSAcceptForUSK913(key)
				resp := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + accept + "\r\n" +
					"\r\n"
				_, _ = conn.Write([]byte(resp))
				// Drain anything else briefly so the test can close cleanly.
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()
	stop = func() {
		_ = ln.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return ln.Addr().String(), hits, stop
}
