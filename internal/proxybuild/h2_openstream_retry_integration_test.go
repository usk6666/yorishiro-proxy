//go:build e2e

// USK-993 smoke-tier integration coverage for the auto-redial-and-retry
// behaviour at OpenStream-Refused. The unit tests in h2_redial_test.go
// pin the helper-level invariants deterministically (Refused → retry →
// success, budget exactly 1, classifier widened to all 3 Refused
// reasons). This file confirms the helper is wired into the production
// dial closure via BuildLiveStack and that the end-to-end recording
// surface is `state=complete` for the POST method when the upstream
// Layer is forced stale during the intercept hold.
//
// Why smoke tier (`//go:build e2e`, NOT `e2e && !e2e_smoke`): the retry
// is part of the merge-gate browser-parity guarantee. A regression that
// reverts to `state=error` on POST during the residual race would land
// silently if this only ran nightly. See CLAUDE.md "e2e test tiers"
// note and design review §12.
package proxybuild_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	gohttp "net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// shuttableH2Upstream is an h2 TLS upstream that can be commanded to send
// GOAWAY to all active connections. The handler accepts POST requests and
// echoes the body; the listener wraps each accepted TLS conn so the test
// can drive a coordinated shutdown.
type shuttableH2Upstream struct {
	addr        string
	tlsLn       net.Listener
	h2s         *http2.Server
	wg          sync.WaitGroup
	mu          sync.Mutex
	activeConns []*tls.Conn
	closed      atomic.Bool
}

func startShuttableH2Upstream(t *testing.T, cn string, handler gohttp.Handler) *shuttableH2Upstream {
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
	srv := &shuttableH2Upstream{
		addr:  tcpLn.Addr().String(),
		tlsLn: tcpLn,
		h2s:   &http2.Server{},
	}

	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			tlsConn := tls.Server(c, tlsCfg)
			srv.mu.Lock()
			srv.activeConns = append(srv.activeConns, tlsConn)
			srv.mu.Unlock()
			srv.wg.Add(1)
			go func(tc *tls.Conn) {
				defer srv.wg.Done()
				defer tc.Close()
				if herr := tc.Handshake(); herr != nil {
					return
				}
				srv.h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
			}(tlsConn)
		}
	}()

	return srv
}

// closeAll forcibly closes every active TLS connection. The MITM's
// upstream-side h2 Layer reader observes EOF and flips IsShutdown true
// — staging the staleness that drives the retry path.
func (s *shuttableH2Upstream) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.activeConns {
		_ = c.Close()
	}
}

func (s *shuttableH2Upstream) shutdown() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	_ = s.tlsLn.Close()
	doneCh := make(chan struct{})
	go func() { s.wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
	}
}

// TestUSK993_H2_POST_StateCompleteAfterUpstreamShutdown_DuringHold pins
// the integration-level browser-parity invariant: a POST request that is
// held by an intercept rule MUST land as `state=complete` even when the
// upstream connection is closed (forces IsShutdown→true on the upstream
// Layer) during the hold. Without USK-993 the residual race between
// selectUpstreamForDial and OpenStream surfaces as `state=error` /
// `failure_reason=refused` — even though zero wire bytes hit the wire.
// With USK-993 the dial closure retries once and the request completes
// transparently.
//
// This is the merge-gate smoke variant: it does not deterministically
// stage the microsecond race (the unit tests in h2_redial_test.go do
// that), but it confirms the helper is wired into the production dial
// closure and that POST goes through under the worst-case scheduling
// pattern.
func TestUSK993_H2_POST_StateCompleteAfterUpstreamShutdown_DuringHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var hits atomic.Int64
	up := startShuttableH2Upstream(t, "usk993-post", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("echo:" + string(body)))
	}))
	defer up.shutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk993-hold-post",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/usk993$`),
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
		cli := newH2ClientThroughProxyForPoolTest(proxyAddr, up.addr)
		req, _ := gohttp.NewRequestWithContext(ctx, "POST", "https://"+up.addr+"/usk993",
			strings.NewReader("payload-993"))
		resp, err := cli.Do(req)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	// Wait for the intercept to capture the request, then forcibly close
	// the upstream h2 conn. The Layer reader observes EOF → IsShutdown
	// flips true. On release, the dial closure must observe the stale
	// Layer (via selectUpstreamForDial → isStaleH2) and fresh-dial OR
	// hit the OpenStream-Refused retry path (USK-993). Either way, the
	// request must reach the upstream because the upstream listener is
	// still accepting.
	releaseFirstHeldEntry(t, holdQueue, 5*time.Second, func(_ *common.HeldEntry) *common.HoldAction {
		// Close upstream conns just before release so the dial closure
		// runs with a stale Layer.
		up.closeAll()
		// Yield briefly so the reader goroutine observes EOF and flips
		// IsShutdown before the dial closure samples it.
		time.Sleep(50 * time.Millisecond)
		return &common.HoldAction{Type: common.ActionRelease}
	})

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client error: %v", r.err)
		}
		if r.status != 200 {
			t.Errorf("POST status = %d, want 200 (USK-993: residual race must not surface as state=error)", r.status)
		}
		if r.body != "echo:payload-993" {
			t.Errorf("POST body = %q, want %q", r.body, "echo:payload-993")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("POST never returned (USK-993: retry path may be unwired)")
	}

	if hits.Load() == 0 {
		t.Error("upstream observed 0 POST hits — POST never reached upstream")
	}

	// Wait for recording to settle.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= 1 {
			if got := store.Streams()[0].State; got == "complete" || got == "error" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected >=1 stream recorded, got %d", len(streams))
	}
	if got, want := streams[0].State, "complete"; got != want {
		t.Errorf("stream State = %q, want %q (USK-993: POST must record state=complete despite upstream shutdown during hold; failure_reason=%q)",
			got, want, streams[0].FailureReason)
	}
}

// TestUSK993_H2_GET_StateCompleteAfterUpstreamShutdown_DuringHold mirrors
// the POST variant for an idempotent method. The retry behaviour is the
// same regardless of method (OpenStream-Refused is pre-HEADERS — no bytes
// have hit the wire — so retry is byte-for-byte equivalent to a fresh
// request). This test exists to confirm method-axis parity rather than
// independent coverage.
func TestUSK993_H2_GET_StateCompleteAfterUpstreamShutdown_DuringHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var hits atomic.Int64
	up := startShuttableH2Upstream(t, "usk993-get", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok:" + r.URL.Path))
	}))
	defer up.shutdown()

	intercept := httprules.NewInterceptEngine()
	intercept.AddRule(httprules.InterceptRule{
		ID:          "usk993-hold-get",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/usk993get$`),
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
		cli := newH2ClientThroughProxyForPoolTest(proxyAddr, up.addr)
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+up.addr+"/usk993get", nil)
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
		up.closeAll()
		time.Sleep(50 * time.Millisecond)
		return &common.HoldAction{Type: common.ActionRelease}
	})

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client error: %v", r.err)
		}
		if r.status != 200 {
			t.Errorf("GET status = %d, want 200", r.status)
		}
		if r.body != "ok:/usk993get" {
			t.Errorf("GET body = %q, want %q", r.body, "ok:/usk993get")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("GET never returned")
	}

	if hits.Load() == 0 {
		t.Error("upstream observed 0 hits")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= 1 {
			if got := store.Streams()[0].State; got == "complete" || got == "error" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected >=1 stream recorded, got %d", len(streams))
	}
	if got, want := streams[0].State, "complete"; got != want {
		t.Errorf("GET stream State = %q, want %q (failure_reason=%q)",
			got, want, streams[0].FailureReason)
	}
}
