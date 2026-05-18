//go:build e2e && !e2e_smoke

// Package proxybuild_test exhaustive tier — USK-916 upstream-side TLS
// dial for TCP forward listeners. Validates the new fc.UpstreamTLS=true
// arm dials upstream over TLS, completes the four (TLS × UpstreamTLS)
// combinations across H1 and H2, advertises ALPN per the propagation
// policy, fires the (tls, on_handshake, side="client") plugin hook, and
// records state="error" Streams for upstream cert verification failure.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// upstreamTLSFixture captures the inputs needed to drive the forward
// listener under test and assert on recordings.
type upstreamTLSFixture struct {
	mgr      *proxybuild.Manager
	store    *flowStoreCapture
	buildCfg *connector.BuildConfig
	fwdAddr  string
	upstream string
	rootPool *x509.CertPool // populated when fc.TLS=true (client trusts the MITM CA)
}

// upstreamTLSFixtureOpts is the variant matrix for newUpstreamTLSFixture.
type upstreamTLSFixtureOpts struct {
	protocol     string
	clientTLS    bool // fc.TLS=true
	upstreamTLS  bool // fc.UpstreamTLS=true (always true in USK-916 tests)
	insecureSkip bool // BuildConfig.InsecureSkipVerify
	// perEntryInsecureSkipVerify (USK-918) sets
	// ForwardConfig.UpstreamInsecureSkipVerify when non-nil; tri-state
	// override of the global insecureSkip above.
	perEntryInsecureSkipVerify *bool
	pluginEngine               *pluginv2.Engine
}

// newUpstreamTLSFixture spins up a Manager with a forward listener whose
// (TLS, UpstreamTLS, Protocol) is determined by opts. Skips the per-conn
// TCP listener — only the manager-driven forward listener is exercised.
func newUpstreamTLSFixture(t *testing.T, ctx context.Context, upstreamAddr string, opts upstreamTLSFixtureOpts) *upstreamTLSFixture {
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
		InsecureSkipVerify: opts.insecureSkip,
	}

	deps := proxybuild.Deps{
		Logger:         testutil.DiscardLogger(),
		FlowStore:      store,
		BuildConfig:    buildCfg,
		PluginV2Engine: opts.pluginEngine,
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:      testutil.DiscardLogger(),
		BuildConfig: buildCfg,
		StackFactory: func(_ context.Context, name, addr string) (*proxybuild.Stack, error) {
			d := deps
			d.ListenerName = name
			d.ListenAddr = addr
			return proxybuild.BuildLiveStack(context.Background(), d)
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
			"0": {
				Target:                     upstreamAddr,
				Protocol:                   opts.protocol,
				TLS:                        opts.clientTLS,
				UpstreamTLS:                opts.upstreamTLS,
				UpstreamInsecureSkipVerify: opts.perEntryInsecureSkipVerify,
			},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards(%s, tls=%v, upstream_tls=%v): %v",
			opts.protocol, opts.clientTLS, opts.upstreamTLS, err)
	}
	addr := mgr.TCPForwardAddrs()["0"]
	if addr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0")
	}

	return &upstreamTLSFixture{
		mgr:      mgr,
		store:    store,
		buildCfg: buildCfg,
		fwdAddr:  addr,
		upstream: upstreamAddr,
		rootPool: rootPool,
	}
}

// startTLSHTTPEchoUpstream binds an httptest.NewTLSServer that echoes the
// request path back via "Echo-Path" header. The returned cert is the
// server's self-signed leaf, suitable for client root trust when
// InsecureSkipVerify=false. Used by the HTTP→HTTPS bridge and HTTPS→HTTPS
// cells.
func startTLSHTTPEchoUpstream(t *testing.T) (addr string, certPool *x509.CertPool, stop func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Echo-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		_, _ = fmt.Fprintf(w, "tls-echo:%s", r.URL.Path)
	}))
	srv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	// Trim the "https://" prefix to expose host:port for our fc.Target.
	u := strings.TrimPrefix(srv.URL, "https://")
	return u, pool, srv.Close
}

// startTLSH2EchoUpstream spins up an h2-over-TLS upstream that echoes
// "h2-echo:<path>" in the body. Returns (addr, certPool, stop).
func startTLSH2EchoUpstream(t *testing.T) (addr string, certPool *x509.CertPool, stop func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Proto", r.Proto)
		w.WriteHeader(gohttp.StatusOK)
		_, _ = fmt.Fprintf(w, "h2-echo:%s", r.URL.Path)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{NextProtos: []string{"h2"}}
	srv.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u := strings.TrimPrefix(srv.URL, "https://")
	return u, pool, srv.Close
}

// waitForCompleteStream polls store until at least one Stream is in
// state=complete (or the deadline expires). Useful for asserting recording
// reached the terminal state before the test exits.
func waitForCompleteStream(_ *testing.T, store *flowStoreCapture, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		for _, st := range store.Streams() {
			if st == nil {
				continue
			}
			if upds := store.StreamUpdates(st.ID); len(upds) > 0 {
				for _, u := range upds {
					if u.State == "complete" {
						return true
					}
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// waitForUpstreamTLSErrorStream polls store until at least one Stream is
// stamped FailureReason="upstream_tls_error". Returns true when observed
// within deadline.
func waitForUpstreamTLSErrorStream(_ *testing.T, store *flowStoreCapture, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		for _, st := range store.Streams() {
			if st != nil && st.FailureReason == "upstream_tls_error" {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// ---------------------------------------------------------------------------
// 1) Happy-path round-trips: 4 (TLS × UpstreamTLS) combinations × {H1, H2}.
// ---------------------------------------------------------------------------

// TestProxybuild_TCPForward_UpstreamTLS_HTTP_PlainClient drives the
// "HTTP→HTTPS bridge" cell for H1: plaintext client, fc.TLS=false,
// fc.UpstreamTLS=true. The proxy dials upstream over TLS while still
// accepting cleartext from the client. Recorded Stream Scheme stays "http"
// (client-facing wire) per Decision #11.
func TestProxybuild_TCPForward_UpstreamTLS_HTTP_PlainClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, stopUp := startTLSHTTPEchoUpstream(t)
	defer stopUp()

	fix := newUpstreamTLSFixture(t, ctx, upAddr, upstreamTLSFixtureOpts{
		protocol:     "http",
		clientTLS:    false,
		upstreamTLS:  true,
		insecureSkip: true, // self-signed upstream cert; per-host trust deferred
	})

	req := "GET /upstream-tls-h1 HTTP/1.1\r\nHost: upstream.example.test\r\nConnection: close\r\n\r\n"
	conn, err := net.Dial("tcp", fix.fwdAddr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	buf, _ := io.ReadAll(conn)
	if !strings.Contains(string(buf), "Echo-Path: /upstream-tls-h1") {
		t.Errorf("response missing Echo-Path: got=%q", string(buf))
	}
	if !strings.Contains(string(buf), "tls-echo:/upstream-tls-h1") {
		t.Errorf("response missing body: got=%q", string(buf))
	}
	// Decision #11: HTTP→HTTPS bridge records Scheme="http" (client wire).
	if !waitForCompleteStream(t, fix.store, 3*time.Second) {
		t.Errorf("no Stream reached state=complete; got %v", summarizeStreams(fix.store.Streams()))
	}
	if !assertStreamScheme(t, fix.store, "http") {
		t.Errorf("no Stream recorded with Scheme=\"http\" (HTTP→HTTPS bridge): got %v", summarizeStreams(fix.store.Streams()))
	}
}

// TestProxybuild_TCPForward_UpstreamTLS_HTTP_TLSClient drives the
// "HTTPS→HTTPS" cell for H1: client TLS, fc.TLS=true, fc.UpstreamTLS=true.
// Recorded Stream Scheme="https".
func TestProxybuild_TCPForward_UpstreamTLS_HTTP_TLSClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, stopUp := startTLSHTTPEchoUpstream(t)
	defer stopUp()

	fix := newUpstreamTLSFixture(t, ctx, upAddr, upstreamTLSFixtureOpts{
		protocol:     "http",
		clientTLS:    true,
		upstreamTLS:  true,
		insecureSkip: true,
	})

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
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/upstream-tls-h1-tls", nil)
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
	if want := "tls-echo:/upstream-tls-h1-tls"; string(body) != want {
		t.Errorf("body = %q, want %q", string(body), want)
	}
	if !waitForHTTPSStream(t, fix.store, 3*time.Second) {
		t.Errorf("no Stream recorded with Scheme=\"https\" (HTTPS→HTTPS): got %v", summarizeStreams(fix.store.Streams()))
	}
}

// TestProxybuild_TCPForward_UpstreamTLS_H2_PlainClient drives the
// "h2c→h2 over TLS" cell: plaintext client speaks h2c, the proxy dials
// upstream over TLS+h2. Operator declared Protocol="http2".
func TestProxybuild_TCPForward_UpstreamTLS_H2_PlainClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, stopUp := startTLSH2EchoUpstream(t)
	defer stopUp()

	fix := newUpstreamTLSFixture(t, ctx, upAddr, upstreamTLSFixtureOpts{
		protocol:     "http2",
		clientTLS:    false,
		upstreamTLS:  true,
		insecureSkip: true,
	})

	cli := h2cForwardClient(fix.fwdAddr, nil, nil)
	defer cli.CloseIdleConnections()
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://"+fix.fwdAddr+"/h2c-to-h2-tls", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got, want := string(body), "h2-echo:/h2c-to-h2-tls"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestProxybuild_TCPForward_UpstreamTLS_H2_TLSClient drives the
// "h2 over TLS→h2 over TLS" cell. Both client and upstream TLS+h2.
func TestProxybuild_TCPForward_UpstreamTLS_H2_TLSClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, stopUp := startTLSH2EchoUpstream(t)
	defer stopUp()

	fix := newUpstreamTLSFixture(t, ctx, upAddr, upstreamTLSFixtureOpts{
		protocol:     "http2",
		clientTLS:    true,
		upstreamTLS:  true,
		insecureSkip: true,
	})

	cli := &gohttp.Client{
		Transport: &xhttp2.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "forward.example.test",
				NextProtos: []string{"h2"},
			},
		},
		Timeout: 10 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/h2tls-to-h2tls", nil)
	req.Host = "forward.example.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got, want := string(body), "h2-echo:/h2tls-to-h2tls"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if !waitForHTTPSStream(t, fix.store, 3*time.Second) {
		t.Errorf("no Stream recorded with Scheme=\"https\" (HTTPS→HTTPS H2): got %v", summarizeStreams(fix.store.Streams()))
	}
}

// ---------------------------------------------------------------------------
// 2) ALPN propagation policy: 4 cells per Decision #4 / #5.
// ---------------------------------------------------------------------------

// TestProxybuild_UpstreamTLS_ALPN_ExplicitHTTP2 asserts that operator-declared
// Protocol="http2" + UpstreamTLS=true offers ALPN=[h2] upstream — the
// upstream server observes "h2" as the negotiated protocol.
func TestProxybuild_UpstreamTLS_ALPN_ExplicitHTTP2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiated, addr, stop := startALPNObservingTLSUpstream(t, []string{"h2", "http/1.1"})
	defer stop()

	fix := newUpstreamTLSFixture(t, ctx, addr, upstreamTLSFixtureOpts{
		protocol:     "http2",
		clientTLS:    false,
		upstreamTLS:  true,
		insecureSkip: true,
	})

	cli := h2cForwardClient(fix.fwdAddr, nil, nil)
	defer cli.CloseIdleConnections()
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://"+fix.fwdAddr+"/alpn-h2", nil)
	resp, err := cli.Do(req)
	if err != nil {
		// Even if the test handler 502s, the TLS handshake completed —
		// negotiated.Load() is what we care about.
		t.Logf("client.Do error (acceptable; the handshake is what we assert): %v", err)
	} else {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	// Wait briefly for the upstream goroutine to observe the handshake.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v := negotiated.Load(); v != nil && v.(string) != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	got := alpnFromAtomic(negotiated)
	if got != "h2" {
		t.Errorf("upstream negotiated ALPN = %q, want %q (Protocol=http2 → [h2])", got, "h2")
	}
}

// TestProxybuild_UpstreamTLS_ALPN_AutoClientH2 asserts the
// auto-propagate-client-ALPN policy: Protocol="auto" + TLS=true +
// UpstreamTLS=true with a client offering h2 → upstream sees ALPN="h2"
// (single-element propagation).
func TestProxybuild_UpstreamTLS_ALPN_AutoClientH2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiated, addr, stop := startALPNObservingTLSUpstream(t, []string{"h2", "http/1.1"})
	defer stop()

	fix := newUpstreamTLSFixture(t, ctx, addr, upstreamTLSFixtureOpts{
		protocol:     "auto",
		clientTLS:    true,
		upstreamTLS:  true,
		insecureSkip: true,
	})

	cli := &gohttp.Client{
		Transport: &xhttp2.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "forward.example.test",
				NextProtos: []string{"h2"},
			},
		},
		Timeout: 5 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/auto-client-h2", nil)
	req.Host = "forward.example.test"
	if resp, err := cli.Do(req); err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v := negotiated.Load(); v != nil && v.(string) != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := alpnFromAtomic(negotiated); got != "h2" {
		t.Errorf("upstream negotiated ALPN = %q, want %q (auto+client-h2 propagates)", got, "h2")
	}
}

// TestProxybuild_UpstreamTLS_ALPN_AutoClientH1 asserts auto-propagate for
// client offering http/1.1 → upstream sees ALPN="http/1.1".
func TestProxybuild_UpstreamTLS_ALPN_AutoClientH1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiated, addr, stop := startALPNObservingTLSUpstream(t, []string{"h2", "http/1.1"})
	defer stop()

	fix := newUpstreamTLSFixture(t, ctx, addr, upstreamTLSFixtureOpts{
		protocol:     "auto",
		clientTLS:    true,
		upstreamTLS:  true,
		insecureSkip: true,
	})

	cli := &gohttp.Client{
		Transport: &gohttp.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    fix.rootPool,
				ServerName: "forward.example.test",
				NextProtos: []string{"http/1.1"},
			},
		},
		Timeout: 5 * time.Second,
	}
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+fix.fwdAddr+"/auto-client-h1", nil)
	req.Host = "forward.example.test"
	if resp, err := cli.Do(req); err == nil {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v := negotiated.Load(); v != nil && v.(string) != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := alpnFromAtomic(negotiated); got != "http/1.1" {
		t.Errorf("upstream negotiated ALPN = %q, want %q (auto+client-h1 propagates)", got, "http/1.1")
	}
}

// TestProxybuild_UpstreamTLS_ALPN_AutoPlainClient asserts Decision #5:
// Protocol="auto" + plaintext client + UpstreamTLS=true offers only
// ["http/1.1"] upstream (NOT h2; single-protocol-per-stack invariant).
// The upstream server advertises [h2, http/1.1]; the proxy MUST only
// offer http/1.1 so the negotiation lands on http/1.1.
func TestProxybuild_UpstreamTLS_ALPN_AutoPlainClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiated, addr, stop := startALPNObservingTLSUpstream(t, []string{"h2", "http/1.1"})
	defer stop()

	fix := newUpstreamTLSFixture(t, ctx, addr, upstreamTLSFixtureOpts{
		protocol:     "auto",
		clientTLS:    false,
		upstreamTLS:  true,
		insecureSkip: true,
	})

	// Plaintext client speaks HTTP/1.x; the proxy peeks and routes to H1
	// arm. Upstream dial offers only http/1.1.
	req := "GET /auto-plain HTTP/1.1\r\nHost: upstream.example.test\r\nConnection: close\r\n\r\n"
	conn, err := net.Dial("tcp", fix.fwdAddr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	_, _ = io.ReadAll(conn)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v := negotiated.Load(); v != nil && v.(string) != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := alpnFromAtomic(negotiated); got != "http/1.1" {
		t.Errorf("upstream negotiated ALPN = %q, want %q (auto+plaintext-client offers only http/1.1)", got, "http/1.1")
	}
}

// ---------------------------------------------------------------------------
// 3) Error path: upstream cert verification failure → state="error".
// ---------------------------------------------------------------------------

// TestProxybuild_UpstreamTLS_CertVerifyFailure_RecordsError drives a real
// upstream TLS handshake with a self-signed cert against a proxy that has
// InsecureSkipVerify=false. The dial fails; the recorder produces a
// state="error" Stream with FailureReason="upstream_tls_error".
func TestProxybuild_UpstreamTLS_CertVerifyFailure_RecordsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, stopUp := startTLSHTTPEchoUpstream(t)
	defer stopUp()

	// InsecureSkipVerify=false + self-signed upstream cert (no per-host
	// trust) → cert verification must fail.
	fix := newUpstreamTLSFixture(t, ctx, upAddr, upstreamTLSFixtureOpts{
		protocol:     "http",
		clientTLS:    false,
		upstreamTLS:  true,
		insecureSkip: false,
	})

	req := "GET /cert-fail HTTP/1.1\r\nHost: upstream.example.test\r\nConnection: close\r\n\r\n"
	conn, err := net.Dial("tcp", fix.fwdAddr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	_, _ = conn.Write([]byte(req))
	// The proxy drops the connection after the upstream TLS dial fails.
	_, _ = io.ReadAll(conn)
	_ = conn.Close()

	if !waitForUpstreamTLSErrorStream(t, fix.store, 3*time.Second) {
		t.Errorf("no Stream recorded with FailureReason=upstream_tls_error; got %v",
			summarizeStreams(fix.store.Streams()))
	}
}

// ---------------------------------------------------------------------------
// 3a) Per-entry upstream_insecure_skip_verify override (USK-918).
// ---------------------------------------------------------------------------

// TestTCPForward_UpstreamTLS_PerEntryInsecureSkipVerify drives the tri-state
// override matrix introduced by USK-918. Each cell exercises a different
// (global × per-entry) combination against a self-signed httptest upstream
// and asserts whether the dial succeeds (recorded as a complete Stream) or
// fails (recorded as a FailureReason="upstream_tls_error" Stream).
//
// The single dial site (dialForwardUpstream) covers both H1 and H2 forward
// arms; the H1 protocol is exercised here as the cheapest probe. The pure
// resolution logic is independently covered by
// TestResolveUpstreamInsecureSkipVerify.
func TestTCPForward_UpstreamTLS_PerEntryInsecureSkipVerify(t *testing.T) {
	skip := true
	enforce := false
	cases := []struct {
		name            string
		globalSkip      bool
		perEntry        *bool
		wantHandshakeOK bool
	}{
		{
			// USK-918 motivating case: global enforce, per-entry skip → succeed.
			name:            "global_false_per_entry_true_succeeds",
			globalSkip:      false,
			perEntry:        &skip,
			wantHandshakeOK: true,
		},
		{
			// Per-entry enforce wins over global skip → fail.
			name:            "global_true_per_entry_false_fails",
			globalSkip:      true,
			perEntry:        &enforce,
			wantHandshakeOK: false,
		},
		{
			// nil per-entry inherits global skip → succeed.
			name:            "global_true_per_entry_nil_inherits_succeeds",
			globalSkip:      true,
			perEntry:        nil,
			wantHandshakeOK: true,
		},
		{
			// nil per-entry inherits global enforce → fail.
			name:            "global_false_per_entry_nil_inherits_fails",
			globalSkip:      false,
			perEntry:        nil,
			wantHandshakeOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			upAddr, _, stopUp := startTLSHTTPEchoUpstream(t)
			defer stopUp()

			fix := newUpstreamTLSFixture(t, ctx, upAddr, upstreamTLSFixtureOpts{
				protocol:                   "http",
				clientTLS:                  false,
				upstreamTLS:                true,
				insecureSkip:               tc.globalSkip,
				perEntryInsecureSkipVerify: tc.perEntry,
			})

			req := "GET /usk918-matrix HTTP/1.1\r\nHost: upstream.example.test\r\nConnection: close\r\n\r\n"
			conn, err := net.Dial("tcp", fix.fwdAddr)
			if err != nil {
				t.Fatalf("net.Dial: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte(req)); err != nil {
				t.Fatalf("conn.Write: %v", err)
			}
			buf, _ := io.ReadAll(conn)

			if tc.wantHandshakeOK {
				// Handshake-succeeds path: assert echo body reached the
				// client (proof the upstream-TLS dial completed and the
				// proxy forwarded the response back).
				if !strings.Contains(string(buf), "tls-echo:/usk918-matrix") {
					t.Errorf("response missing echo body; got=%q (handshake-succeeds case should succeed)", string(buf))
				}
				if !waitForCompleteStream(t, fix.store, 3*time.Second) {
					t.Errorf("no Stream reached state=complete on handshake-succeeds case; got %v",
						summarizeStreams(fix.store.Streams()))
				}
			} else {
				// Handshake-fails path: assert the recorder produced a
				// state="error" Stream with FailureReason="upstream_tls_error".
				if !waitForUpstreamTLSErrorStream(t, fix.store, 3*time.Second) {
					t.Errorf("no Stream recorded with FailureReason=upstream_tls_error on handshake-fails case; got %v",
						summarizeStreams(fix.store.Streams()))
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4) Plugin hook firing: (tls, on_handshake, side="client") for upstream TLS.
// ---------------------------------------------------------------------------

// TestProxybuild_UpstreamTLS_PluginHookFires loads a Starlark plugin that
// emits a print() sentinel each time (tls, on_handshake) fires and asserts
// the sentinel appears in the plugin-print log stream after a forward
// round-trip with fc.UpstreamTLS=true. The dispatch path's thread.Print
// hook forwards plugin print() to the engine logger
// (internal/pluginv2/lifecycle.go::dispatchLifecycleHook); a CaptureLogger
// makes the output observable from the test.
//
// Hook firing happens for BOTH sides — side="server" if fc.TLS=true (we
// only do client-side TLS for this test, so server-side does not fire),
// and side="client" for the upstream TLS dial that USK-916 newly wires.
// We assert ≥1 sentinel.
func TestProxybuild_UpstreamTLS_PluginHookFires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pluginPath := writeUSK913PluginScript(t, `
def on_hs(env, ctx):
    print("USK916_TLS_HOOK_FIRED")
    return None
register_hook("tls", "on_handshake", on_hs)
`)
	cap, logger := testutil.NewCaptureLogger()
	engine := pluginv2.NewEngine(logger)
	if err := engine.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: pluginPath, OnError: string(pluginv2.OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	upAddr, _, stopUp := startTLSHTTPEchoUpstream(t)
	defer stopUp()

	fix := newUpstreamTLSFixture(t, ctx, upAddr, upstreamTLSFixtureOpts{
		protocol:     "http",
		clientTLS:    false,
		upstreamTLS:  true,
		insecureSkip: true,
		pluginEngine: engine,
	})

	req := "GET /plugin-hook HTTP/1.1\r\nHost: upstream.example.test\r\nConnection: close\r\n\r\n"
	conn, err := net.Dial("tcp", fix.fwdAddr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	_, _ = conn.Write([]byte(req))
	_, _ = io.ReadAll(conn)
	_ = conn.Close()

	// Wait for the recording side to finalize so the hook has had time to
	// run.
	_ = waitForCompleteStream(t, fix.store, 3*time.Second)

	// Poll up to 3 s for the sentinel to surface (the hook fires from the
	// dial goroutine; the capture logger writes synchronously but the
	// dispatch may happen after the response has been written).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cap.Contains("USK916_TLS_HOOK_FIRED") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("plugin (tls, on_handshake) sentinel not observed in capture log; output=%q",
		cap.Output())
}

// ---------------------------------------------------------------------------
// Helpers (local to this file).
// ---------------------------------------------------------------------------

// startALPNObservingTLSUpstream binds a TCP listener that performs a TLS
// handshake offering the supplied ALPN advertise list, records the
// negotiated ALPN in the returned atomic.Value, and then drops the
// connection. This is the minimal harness needed to assert the proxy's
// upstream-ALPN offer list — we do not need to handle any L7 protocol
// (the negotiated ALPN string is observable directly from the TLS state).
func startALPNObservingTLSUpstream(t *testing.T, alpnAdvertise []string) (*atomic.Value, string, func()) {
	t.Helper()

	// Build a self-signed cert (the proxy uses
	// BuildConfig.InsecureSkipVerify=true in these tests so trust is not
	// asserted by the dial side).
	srvCert := buildSelfSignedTLSCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		NextProtos:   alpnAdvertise,
		MinVersion:   tls.VersionTLS12,
	}
	negotiated := &atomic.Value{}
	stopCh := make(chan struct{})

	go func() {
		for {
			c, accErr := ln.Accept()
			if accErr != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
				tlsConn := tls.Server(raw, tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				st := tlsConn.ConnectionState()
				negotiated.Store(st.NegotiatedProtocol)
				// Drain any inner bytes briefly so the proxy's HTTP/1.x or
				// h2 frame writer does not block on a full receive window.
				_ = tlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
				_, _ = io.Copy(io.Discard, tlsConn)
				_ = tlsConn.Close()
			}(c)
		}
	}()
	stop := func() {
		close(stopCh)
		_ = ln.Close()
	}
	return negotiated, ln.Addr().String(), stop
}

// buildSelfSignedTLSCert returns a fresh self-signed TLS leaf cert,
// produced via httptest.NewUnstartedServer + StartTLS. The cert is
// captured before the throwaway server is torn down by t.Cleanup; it has
// no NextProtos so each caller can set its own. Used by
// startALPNObservingTLSUpstream so the test does not need to hand-roll
// x509.CreateCertificate.
func buildSelfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	srv := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(_ gohttp.ResponseWriter, _ *gohttp.Request) {}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.TLS.Certificates[0]
}

// alpnFromAtomic safely reads the negotiated ALPN value from an
// atomic.Value, returning the empty string on uninitialised value.
func alpnFromAtomic(a *atomic.Value) string {
	v := a.Load()
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// assertStreamScheme returns true when at least one recorded Stream has
// the given Scheme.
func assertStreamScheme(_ *testing.T, store *flowStoreCapture, scheme string) bool {
	for _, st := range store.Streams() {
		if st != nil && st.Scheme == scheme {
			return true
		}
	}
	return false
}
