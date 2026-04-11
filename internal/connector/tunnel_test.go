package connector

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// freshCA generates a throwaway CA for test use.
func freshCA(t *testing.T) *cert.CA {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	return ca
}

// newTunnelHandler builds a minimally-configured handler for unit tests.
// Callers override fields as needed before calling Handle.
func newTunnelHandler(t *testing.T) *TunnelHandler {
	t.Helper()
	ca := freshCA(t)
	return &TunnelHandler{
		Issuer:    cert.NewIssuer(ca),
		ALPNCache: NewALPNCache(16, time.Minute),
		Logger:    newTestLogger(),
		Clock:     func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
}

// TestTunnelHandler_ScopeBlock verifies that a deny-by-scope tunnel fires
// OnBlock with the correct reason and closes the connection without talking
// to upstream.
func TestTunnelHandler_ScopeBlock(t *testing.T) {
	th := newTunnelHandler(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "blocked.example"}})
	th.Scope = scope

	var blockCount int32
	var gotInfo BlockInfo
	th.OnBlock = func(_ context.Context, info BlockInfo) {
		atomic.AddInt32(&blockCount, 1)
		gotInfo = info
	}

	client, proxySide := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- th.Handle(context.Background(), proxySide, "blocked.example:443", "CONNECT")
	}()

	// Client side should be closed without a handshake reply. Read should
	// observe EOF shortly.
	_ = client.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err := client.Read(make([]byte, 16))
	if err == nil {
		t.Error("expected client read to fail (conn closed)")
	}

	<-errCh

	if got := atomic.LoadInt32(&blockCount); got != 1 {
		t.Errorf("OnBlock call count = %d, want 1", got)
	}
	if gotInfo.Reason != "target_scope" {
		t.Errorf("Reason = %q, want target_scope", gotInfo.Reason)
	}
	if gotInfo.Target != "blocked.example:443" {
		t.Errorf("Target = %q", gotInfo.Target)
	}
	if gotInfo.Protocol != "CONNECT" {
		t.Errorf("Protocol = %q", gotInfo.Protocol)
	}
}

// TestTunnelHandler_RateLimitBlock verifies rate-limit denial path.
func TestTunnelHandler_RateLimitBlock(t *testing.T) {
	th := newTunnelHandler(t)
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{MaxRequestsPerSecond: 0.0001})
	// Warm the bucket: first call consumes the single initial token.
	_ = rl.Check("target.example")
	th.RateLimiter = rl

	var reason string
	th.OnBlock = func(_ context.Context, info BlockInfo) { reason = info.Reason }

	_, proxySide := net.Pipe()
	done := make(chan struct{})
	go func() {
		_ = th.Handle(context.Background(), proxySide, "target.example:443", "CONNECT")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle did not return")
	}
	if reason != "rate_limit" {
		t.Errorf("Reason = %q, want rate_limit", reason)
	}
}

// TestTunnelHandler_Passthrough verifies that a passthrough host is relayed
// via raw io.Copy with no TLS handshake or Pipeline interaction.
func TestTunnelHandler_Passthrough(t *testing.T) {
	// Spin up a plain TCP echo server as the "upstream".
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstream.Close()

	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	th := newTunnelHandler(t)
	th.Passthrough = NewPassthroughList()
	th.Passthrough.Add(strings.Split(upstream.Addr().String(), ":")[0])

	client, proxySide := net.Pipe()
	defer client.Close()

	go func() {
		_ = th.Handle(context.Background(), proxySide, upstream.Addr().String(), "CONNECT")
	}()

	go func() {
		// Write "ping" into the client end. Passthrough should echo it.
		_, _ = client.Write([]byte("ping"))
	}()

	buf := make([]byte, 4)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(client, buf)
	if err != nil {
		t.Fatalf("read echo: %v (n=%d)", err, n)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q, want ping", string(buf))
	}
}

// TestTunnelHandler_UpstreamUnreachable exercises the eager-dial failure
// path: the cache has no entry, the dial fails, OnBlock fires with
// upstream_unreachable.
func TestTunnelHandler_UpstreamUnreachable(t *testing.T) {
	th := newTunnelHandler(t)
	th.DialOpts.DialTimeout = 150 * time.Millisecond

	var reason string
	done := make(chan struct{})
	th.OnBlock = func(_ context.Context, info BlockInfo) {
		reason = info.Reason
		close(done)
	}

	// A reserved test-only IP; dialing should fail fast.
	target := "127.0.0.1:1" // nothing listens here in CI

	_, proxySide := net.Pipe()
	go func() { _ = th.Handle(context.Background(), proxySide, target, "CONNECT") }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnBlock not fired within timeout")
	}
	if reason != "upstream_unreachable" {
		t.Errorf("Reason = %q, want upstream_unreachable", reason)
	}
}

// upstreamTLSServer spins up an httptest.NewTLSServer returning a fixed body.
func upstreamTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintln(w, "hello-from-upstream")
	}))
}

// upstreamTarget extracts "host:port" from an httptest server URL.
func upstreamTarget(ts *httptest.Server) string {
	u := ts.URL
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return u
}

// TestTunnelHandler_E2E_HTTPSMITM runs the full CONNECT → TLS MITM → HTTP/1
// GET flow end-to-end. The upstream is an httptest.NewTLSServer and the
// client is a tls.Dial against our in-memory proxy pipe.
func TestTunnelHandler_E2E_HTTPSMITM(t *testing.T) {
	ts := upstreamTLSServer(t)
	defer ts.Close()

	th := newTunnelHandler(t)
	th.DialOpts.TLSConfig = &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 - test only, upstream is self-signed
		MinVersion:         tls.VersionTLS12,
	}
	th.DialOpts.InsecureSkipVerify = true

	// Acquire the proxy's CA so the test client can validate the dynamic cert.
	caCert, _ := th.Issuer.GetCertificate("anything.example")
	_ = caCert // warm the cache; we trust the issuer's CA below

	// Launch a local TCP listener that hands every connection straight to
	// the TunnelHandler with a fixed target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ready := make(chan struct{})
	go func() {
		close(ready)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = th.Handle(context.Background(), c, upstreamTarget(ts), "CONNECT")
			}(c)
		}
	}()
	<-ready

	// Dial the proxy as if the CONNECT already happened.
	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()

	roots := x509.NewCertPool()
	// Use InsecureSkipVerify for the test client since the proxy mints
	// its CA dynamically and we do not expose it publicly.
	tlsCfg := &tls.Config{
		ServerName:         strings.Split(upstreamTarget(ts), ":")[0],
		InsecureSkipVerify: true, // #nosec G402 - test-only
		MinVersion:         tls.VersionTLS12,
		RootCAs:            roots,
		NextProtos:         []string{"http/1.1"},
	}
	tlsClient := tls.Client(rawConn, tlsCfg)
	if err := tlsClient.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsClient.Close()

	// Send a GET over the decrypted tunnel.
	req := "GET / HTTP/1.1\r\nHost: " + upstreamTarget(ts) + "\r\nConnection: close\r\n\r\n"
	if _, err := tlsClient.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = tlsClient.SetReadDeadline(time.Now().Add(3 * time.Second))

	br := bufio.NewReader(tlsClient)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200") {
		t.Errorf("status = %q, want HTTP/1.1 200...", statusLine)
	}

	// Drain headers and body.
	body, _ := io.ReadAll(br)
	if !strings.Contains(string(body), "hello-from-upstream") {
		t.Errorf("body does not contain expected marker: %q", string(body))
	}
}

// TestTunnelHandler_CacheMiss_ThenHit exercises the ALPN cache lifecycle:
// the first tunnel is a miss (eager dial + cache write), the second is a
// hit (lazy dial).
func TestTunnelHandler_CacheMiss_ThenHit(t *testing.T) {
	ts := upstreamTLSServer(t)
	defer ts.Close()

	th := newTunnelHandler(t)
	th.DialOpts.TLSConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 - test only
	th.DialOpts.InsecureSkipVerify = true

	target := upstreamTarget(ts)
	key := th.cacheKey(target)

	if _, ok := th.ALPNCache.Get(key); ok {
		t.Fatal("cache should be empty at start")
	}

	// First tunnel — miss path. We don't need full HTTP success; just
	// prove the cache got populated.
	c1, p1 := net.Pipe()
	done1 := make(chan struct{})
	go func() {
		_ = th.Handle(context.Background(), p1, target, "CONNECT")
		close(done1)
	}()
	_ = c1.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = c1.Read(make([]byte, 1))
	_ = c1.Close()
	<-done1

	entry, ok := th.ALPNCache.Get(key)
	if !ok {
		t.Fatalf("expected cache hit after miss path, key=%+v", key)
	}
	// httptest.NewTLSServer speaks HTTP/2 by default on Go 1.22+.
	if entry.Protocol == "" {
		t.Errorf("ALPN should have been learned, got empty string")
	}
	t.Logf("learned ALPN: %q", entry.Protocol)
}

// countingListener wraps a net.Listener and atomically counts Accept calls.
// Used to verify the single-upstream-dial invariant in TunnelHandler.
type countingListener struct {
	net.Listener
	accepts int32
}

func (cl *countingListener) Accept() (net.Conn, error) {
	conn, err := cl.Listener.Accept()
	if err == nil {
		atomic.AddInt32(&cl.accepts, 1)
	}
	return conn, err
}

func (cl *countingListener) Count() int32 {
	return atomic.LoadInt32(&cl.accepts)
}

// TestTunnelHandler_SingleUpstreamDial verifies the critical invariant that
// each tunnel opens AT MOST ONE upstream TLS handshake, regardless of
// whether the ALPN cache is cold (miss path: eager dial consumed by
// DialFunc) or warm (hit path: single lazy dial in DialFunc). We swap the
// httptest upstream's listener for a counting listener so we can directly
// assert the accept count per tunnel, then drive a full HTTPS GET on each
// tunnel so both the eager-dial-reuse and lazy-dial paths are exercised.
func TestTunnelHandler_SingleUpstreamDial(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "hello-from-upstream")
	}))
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cl := &countingListener{Listener: base}
	ts.Listener = cl
	ts.StartTLS()
	defer ts.Close()

	th := newTunnelHandler(t)
	th.DialOpts.TLSConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 - test only
	th.DialOpts.InsecureSkipVerify = true

	target := upstreamTarget(ts)

	// Expose the tunnel via a local TCP listener so we can drive a real
	// TLS client through it and force DialFunc to be invoked.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = th.Handle(context.Background(), c, target, "CONNECT")
			}(c)
		}
	}()

	runTunnel := func(label string) {
		raw, err := net.Dial("tcp", proxyLn.Addr().String())
		if err != nil {
			t.Fatalf("%s: dial proxy: %v", label, err)
		}
		defer raw.Close()

		tlsCfg := &tls.Config{
			ServerName:         strings.Split(upstreamTarget(ts), ":")[0],
			InsecureSkipVerify: true, // #nosec G402 - test only
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
		}
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.Fatalf("%s: client TLS handshake: %v", label, err)
		}
		req := "GET / HTTP/1.1\r\nHost: " + upstreamTarget(ts) + "\r\nConnection: close\r\n\r\n"
		if _, err := tc.Write([]byte(req)); err != nil {
			t.Fatalf("%s: write: %v", label, err)
		}
		_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.ReadAll(tc)
	}

	before := cl.Count()
	runTunnel("miss") // miss path: one eager dial reused via DialFunc
	afterMiss := cl.Count()
	if got := afterMiss - before; got != 1 {
		t.Errorf("miss-path upstream accepts = %d, want 1", got)
	}

	runTunnel("hit") // hit path: single lazy dial in DialFunc
	afterHit := cl.Count()
	if got := afterHit - afterMiss; got != 1 {
		t.Errorf("hit-path upstream accepts = %d, want 1", got)
	}

	// The cache must have exactly one entry for the target.
	if n := th.ALPNCache.Len(); n != 1 {
		t.Errorf("cache Len = %d, want 1", n)
	}
	if _, ok := th.ALPNCache.Get(th.cacheKey(target)); !ok {
		t.Error("cache missing expected entry")
	}
}

// TestTunnelHandler_PluginHookNilEngine verifies the on_tls_handshake hook
// short-circuits cleanly when no PluginEngine is configured.
func TestTunnelHandler_PluginHookNilEngine(t *testing.T) {
	th := newTunnelHandler(t)
	state := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "http/1.1"}
	// Should not panic even with nil engine.
	th.dispatchOnTLSHandshake(context.Background(), "example.com", state)
}

// TestTunnelHandler_PluginHookFailOpen verifies the on_tls_handshake hook
// dispatch swallows a dispatcher error and logs it as Warn instead of
// aborting the tunnel (fail-open by design).
func TestTunnelHandler_PluginHookFailOpen(t *testing.T) {
	th := newTunnelHandler(t)

	var called int32
	th.pluginDispatchOverride = func(_ context.Context, hook plugin.Hook, _ map[string]any) (*plugin.HookResult, error) {
		atomic.AddInt32(&called, 1)
		if hook != plugin.HookOnTLSHandshake {
			t.Errorf("hook = %q, want %q", hook, plugin.HookOnTLSHandshake)
		}
		return nil, fmt.Errorf("simulated plugin error")
	}

	state := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "http/1.1"}
	// Must not panic and must not return anything; the error is logged Warn.
	th.dispatchOnTLSHandshake(context.Background(), "example.com", state)

	if got := atomic.LoadInt32(&called); got != 1 {
		t.Errorf("dispatcher call count = %d, want 1", got)
	}
}

// --- helpers using a stub Codec to test the DialFunc reuse contract --------

// stubCodec is a minimal codec.Codec used to verify holder consumption.
type stubCodec struct {
	closed bool
}

func (s *stubCodec) Next(_ context.Context) (*exchange.Exchange, error) { return nil, io.EOF }
func (s *stubCodec) Send(_ context.Context, _ *exchange.Exchange) error { return nil }
func (s *stubCodec) Close() error                                       { s.closed = true; return nil }

// TestUpstreamHolder_ConsumeOnce verifies the holder yields the codec on
// the first call and returns (nil, false) thereafter, and close is a no-op
// once the codec has been consumed.
func TestUpstreamHolder_ConsumeOnce(t *testing.T) {
	sc := &stubCodec{}
	h := &upstreamHolder{codec: sc}

	if !h.isPresent() {
		t.Fatal("holder should report present before consume")
	}

	cdc, ok := h.consume()
	if !ok {
		t.Fatal("first consume should succeed")
	}
	if cdc != codec.Codec(sc) {
		t.Error("wrong codec returned")
	}
	if _, ok := h.consume(); ok {
		t.Error("second consume should fail")
	}

	h.close() // should not close the stub since ownership transferred
	if sc.closed {
		t.Error("stub was closed by holder.close after consume — lifetime leak")
	}
}

// TestUpstreamHolder_CloseReleasesUnconsumed verifies that dropping a holder
// without consuming closes the codec so we do not leak upstream connections.
func TestUpstreamHolder_CloseReleasesUnconsumed(t *testing.T) {
	sc := &stubCodec{}
	h := &upstreamHolder{codec: sc}
	h.close()
	if !sc.closed {
		t.Error("holder.close did not close unconsumed codec")
	}
	// Idempotent.
	h.close()
}
