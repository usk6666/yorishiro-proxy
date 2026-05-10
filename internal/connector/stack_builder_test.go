package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

func TestBuildConnectionStack_RawPassthrough(t *testing.T) {
	// --- Setup: upstream TLS server that echoes data ---
	serverCfg, err := newSelfSignedTLSConfig("target.example.com")
	if err != nil {
		t.Fatal(err)
	}

	upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	// --- Setup: CA + Issuer for MITM ---
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	// --- Setup: Config with raw_passthrough for the upstream target ---
	target := upstreamLn.Addr().String()
	proxyCfg := &config.ProxyConfig{
		RawPassthroughHosts: []string{target},
	}

	buildCfg := &BuildConfig{
		ProxyConfig:        proxyCfg,
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	// Use a TCP listener instead of net.Pipe to avoid TLS handshake
	// deadlocks (net.Pipe has zero buffering).
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	// Run BuildConnectionStack in a goroutine. It accepts on the server
	// side of the connection and performs TLS MITM + upstream dial.
	type buildResult struct {
		stack *ConnectionStack
		err   error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, err := clientLn.Accept()
		if err != nil {
			resultCh <- buildResult{nil, err}
			return
		}
		stack, _, _, err := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack, err}
	}()

	// Client-side: connect and perform TLS handshake with the proxy (MITM).
	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	// Extract the host from target to match the MITM cert.
	host, _, _ := net.SplitHostPort(target)

	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Certificate())

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName:         host,
		RootCAs:            certPool,
		InsecureSkipVerify: true, //nolint:gosec // test: MITM cert for IP
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	// Wait for BuildConnectionStack to complete.
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("BuildConnectionStack: %v", result.err)
	}

	stack := result.stack
	if stack == nil {
		t.Fatal("expected non-nil stack")
	}
	defer stack.Close()

	if stack.ConnID == "" {
		t.Error("expected non-empty ConnID")
	}

	if stack.ClientTopmost() == nil {
		t.Error("expected non-nil client topmost layer")
	}
	if stack.UpstreamTopmost() == nil {
		t.Error("expected non-nil upstream topmost layer")
	}
}

func TestBuildConnectionStack_HTTPMITMStack(t *testing.T) {
	// --- Setup: upstream TLS server that speaks HTTP/1.x ---
	serverCfg, err := newSelfSignedTLSConfig("target.example.com")
	if err != nil {
		t.Fatal(err)
	}

	upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Minimal HTTP/1.x server: read until \r\n\r\n, respond 200 OK.
		buf := make([]byte, 4096)
		for n := 0; n < len(buf); {
			nn, err := conn.Read(buf[n:])
			if err != nil {
				return
			}
			n += nn
			if bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
				break
			}
		}
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
		conn.Write([]byte(resp))
	}()

	// --- Setup: CA + Issuer for MITM ---
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	// --- Setup: Config WITHOUT raw_passthrough (default = HTTP MITM) ---
	target := upstreamLn.Addr().String()
	proxyCfg := &config.ProxyConfig{} // empty = no raw_passthrough hosts

	buildCfg := &BuildConfig{
		ProxyConfig:        proxyCfg,
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	// Use a TCP listener to avoid TLS handshake deadlocks (net.Pipe is zero-buffered).
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	type buildResult struct {
		stack        *ConnectionStack
		clientSnap   *envelope.TLSSnapshot
		upstreamSnap *envelope.TLSSnapshot
		err          error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, err := clientLn.Accept()
		if err != nil {
			resultCh <- buildResult{err: err}
			return
		}
		stack, clientSnap, upstreamSnap, err := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack, clientSnap, upstreamSnap, err}
	}()

	// Client-side: connect and perform TLS handshake with the proxy (MITM).
	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	host, _, _ := net.SplitHostPort(target)

	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Certificate())

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName:         host,
		RootCAs:            certPool,
		InsecureSkipVerify: true, //nolint:gosec // test: MITM cert for IP
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	// Wait for BuildConnectionStack to complete.
	result := <-resultCh
	if result.err != nil {
		t.Fatalf("BuildConnectionStack: %v", result.err)
	}

	stack := result.stack
	if stack == nil {
		t.Fatal("expected non-nil stack")
	}
	defer stack.Close()

	if stack.ConnID == "" {
		t.Error("expected non-empty ConnID")
	}

	if stack.ClientTopmost() == nil {
		t.Error("expected non-nil client topmost layer")
	}
	if stack.UpstreamTopmost() == nil {
		t.Error("expected non-nil upstream topmost layer")
	}

	// Verify the client-side layer produces a Channel.
	clientCh := stack.ClientTopmost().Channels()
	ch, ok := <-clientCh
	if !ok || ch == nil {
		t.Error("expected client layer to produce a Channel")
	}

	// Verify the upstream-side layer produces a Channel.
	upstreamCh := stack.UpstreamTopmost().Channels()
	uch, ok := <-upstreamCh
	if !ok || uch == nil {
		t.Error("expected upstream layer to produce a Channel")
	}

	// Verify both TLS snapshots are populated. The client snapshot captures
	// the synthetic MITM handshake we performed with the test client; the
	// upstream snapshot captures the real upstream TLS reality.
	if result.clientSnap == nil {
		t.Fatal("expected non-nil client TLSSnapshot")
	}
	if result.clientSnap.Version == 0 {
		t.Error("expected non-zero TLS version in client snapshot")
	}
	if result.upstreamSnap == nil {
		t.Fatal("expected non-nil upstream TLSSnapshot")
	}
	if result.upstreamSnap.Version == 0 {
		t.Error("expected non-zero TLS version in upstream snapshot")
	}
	if result.upstreamSnap.PeerCertificate == nil {
		t.Error("expected upstream snapshot to carry PeerCertificate (upstream cert)")
	}
}

func TestBuildConnectionStack_NilConfig(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	_, _, _, err := BuildConnectionStack(context.Background(), proxyConn, "example.com:443", nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

// TestBuildConnectionStack_H2MITMStack verifies that the stack builder
// correctly wires an HTTP/2 Layer pair when upstream negotiates ALPN=h2:
//   - Client-side topmost is an *http2.Layer (ServerRole), exposed via
//     stack.ClientTopmost().
//   - Upstream-side h2 Layer is available via stack.UpstreamH2Layer() and is
//     NOT pushed into the upstream stack (so stack.UpstreamTopmost() is nil
//     for the h2 route).
//   - stack.PoolKey() yields the key used for pool lookup.
//   - stack.Close() does not affect UpstreamH2Layer (pool owns its lifecycle).
func TestBuildConnectionStack_H2MITMStack(t *testing.T) {
	// --- Setup: upstream TLS server that advertises ALPN=h2 and runs a
	// ServerRole *http2.Layer long enough for the preface exchange. The
	// layer stays alive until the test closes the TLS listener.
	serverCfg, err := newSelfSignedTLSConfig("target.example.com")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg.NextProtos = []string{"h2"}

	upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	// Track the server-side layer so the test can close it cleanly.
	type serverResult struct {
		layer *http2.Layer
		err   error
	}
	srvCh := make(chan serverResult, 1)

	go func() {
		conn, acceptErr := upstreamLn.Accept()
		if acceptErr != nil {
			srvCh <- serverResult{err: acceptErr}
			return
		}
		// The TLS handshake completes inside tls.Listen's wrapper when the
		// first Read/Write happens. Force it by constructing http2.New,
		// which immediately performs runServerPreface over the conn.
		srv, sErr := http2.New(conn, "test-server", http2.ServerRole,
			http2.WithScheme("https"),
		)
		srvCh <- serverResult{layer: srv, err: sErr}
	}()

	// --- Setup: CA + Issuer for MITM ---
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	// --- Setup: BuildConfig with pool ---
	target := upstreamLn.Addr().String()
	proxyCfg := &config.ProxyConfig{}
	h2Pool := pool.New(pool.PoolOptions{})
	defer h2Pool.Close()

	buildCfg := &BuildConfig{
		ProxyConfig:        proxyCfg,
		Issuer:             issuer,
		InsecureSkipVerify: true,
		HTTP2Pool:          h2Pool,
	}

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	type buildResult struct {
		stack        *ConnectionStack
		clientSnap   *envelope.TLSSnapshot
		upstreamSnap *envelope.TLSSnapshot
		err          error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, acceptErr := clientLn.Accept()
		if acceptErr != nil {
			resultCh <- buildResult{err: acceptErr}
			return
		}
		stack, clientSnap, upstreamSnap, buildErr := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack, clientSnap, upstreamSnap, buildErr}
	}()

	// --- Client-side: connect to the proxy and perform a TLS handshake
	// offering only h2. This forces the proxy's server-side MITM handshake
	// to negotiate h2 as well (server NextProtos is learned from upstream).
	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	host, _, _ := net.SplitHostPort(target)
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Certificate())

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName:         host,
		RootCAs:            certPool,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true, //nolint:gosec // test: MITM cert for IP
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer clientTLS.Close()

	// We also need to drive the client-side http2 preface so the proxy's
	// http2.New(ServerRole) can complete runServerPreface. Create a
	// ClientRole Layer here in the test to do exactly that.
	clientH2, err := http2.New(clientTLS, "test-client", http2.ClientRole,
		http2.WithScheme("https"),
	)
	if err != nil {
		t.Fatalf("test-client http2.New: %v", err)
	}
	defer clientH2.Close()

	// --- Wait for BuildConnectionStack to finish.
	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("BuildConnectionStack: %v", result.err)
		}
		stack := result.stack
		if stack == nil {
			t.Fatal("expected non-nil stack")
		}

		// Client side should be a *http2.Layer.
		clientTop := stack.ClientTopmost()
		if clientTop == nil {
			t.Fatal("expected non-nil client topmost layer")
		}
		if _, ok := clientTop.(*http2.Layer); !ok {
			t.Errorf("ClientTopmost = %T, want *http2.Layer", clientTop)
		}

		// Upstream-side h2 Layer lives on UpstreamH2Layer, not UpstreamTopmost.
		if up := stack.UpstreamTopmost(); up != nil {
			t.Errorf("UpstreamTopmost = %T, want nil for h2 route", up)
		}
		if stack.UpstreamH2Layer() == nil {
			t.Error("UpstreamH2Layer is nil; expected pooled layer")
		}

		// PoolKey should match what the stack builder computed. The builder
		// folds the resolvedTLS overlay into the key (USK-737), so resolve
		// the same overlay here for an apples-to-apples comparison.
		wantHostTLS, hostTLSErr := resolvePerHostTLS(target, buildCfg)
		if hostTLSErr != nil {
			t.Fatalf("resolvePerHostTLS: %v", hostTLSErr)
		}
		wantKey := poolKeyForH2(target, buildCfg, wantHostTLS)
		if gotKey := stack.PoolKey(); gotKey != wantKey {
			t.Errorf("PoolKey = %+v, want %+v", gotKey, wantKey)
		}

		// Both TLS snapshots are populated; upstream ALPN is h2 (the
		// diagnostic signal for USK-619 — upstream reality, not synthetic
		// client MITM reality).
		if result.clientSnap == nil {
			t.Fatal("expected non-nil client TLSSnapshot")
		}
		if result.upstreamSnap == nil {
			t.Fatal("expected non-nil upstream TLSSnapshot")
		}
		if result.upstreamSnap.ALPN != "h2" {
			t.Errorf("upstream TLSSnapshot.ALPN = %q, want %q", result.upstreamSnap.ALPN, "h2")
		}

		// Return the upstream Layer to the pool (the handler would normally
		// do this on exit). Then close the stack — must leave upstreamH2
		// untouched.
		h2Pool.Put(stack.PoolKey(), stack.UpstreamH2Layer())
		if err := stack.Close(); err != nil {
			t.Errorf("stack.Close: %v", err)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("BuildConnectionStack timed out")
	}

	// Drain the server-side layer construction result so the goroutine is
	// not leaked.
	select {
	case sres := <-srvCh:
		if sres.err != nil {
			t.Logf("server preface error (expected on teardown): %v", sres.err)
		}
		if sres.layer != nil {
			_ = sres.layer.Close()
		}
	case <-time.After(2 * time.Second):
		// ok — server goroutine may still be alive; the Close above tears
		// down its underlying conn via listener close.
	}
}

// startCachedH2Layer constructs a live ClientRole *http2.Layer over a
// net.Pipe and runs a ServerRole peer on the other end. The returned
// Layer is suitable for pre-populating an h2 pool entry; teardown closes
// both sides cleanly. The Layer is stamped with the supplied
// EnvelopeContext template so that EnvelopeContextTemplate() returns
// deterministic values for assertions.
func startCachedH2Layer(t *testing.T, template envelope.EnvelopeContext) (cached *http2.Layer, teardown func()) {
	t.Helper()
	srvConn, cliConn := net.Pipe()

	type srvRes struct {
		l   *http2.Layer
		err error
	}
	srvDone := make(chan srvRes, 1)
	go func() {
		l, err := http2.New(srvConn, "cached-server", http2.ServerRole, http2.WithScheme("https"))
		srvDone <- srvRes{l: l, err: err}
	}()

	type cliRes struct {
		l   *http2.Layer
		err error
	}
	cliDone := make(chan cliRes, 1)
	go func() {
		l, err := http2.New(cliConn, "cached-client", http2.ClientRole,
			http2.WithScheme("https"),
			http2.WithEnvelopeContext(template),
		)
		cliDone <- cliRes{l: l, err: err}
	}()

	var srv, cli *http2.Layer
	deadline := time.After(3 * time.Second)
	for srv == nil || cli == nil {
		select {
		case r := <-srvDone:
			if r.err != nil {
				t.Fatalf("cached-server http2.New: %v", r.err)
			}
			srv = r.l
		case r := <-cliDone:
			if r.err != nil {
				t.Fatalf("cached-client http2.New: %v", r.err)
			}
			cli = r.l
		case <-deadline:
			t.Fatal("startCachedH2Layer: handshake timeout")
		}
	}

	return cli, func() {
		_ = cli.Close()
		_ = srv.Close()
		_ = cliConn.Close()
		_ = srvConn.Close()
	}
}

// TestBuildConnectionStack_H2PoolFastPath_ClientMITMFailReleasesReservation
// verifies that when the h2 pool fast path is triggered but the subsequent
// client-side TLS MITM handshake fails (e.g., the client closes mid-
// handshake), the pool reservation taken by Pool.Get is returned via
// Pool.Put — not leaked or evicted. A leaked inUseCount would silently
// cap the pool after a few failed handshakes; an Evict would destroy a
// reusable Layer for an unrelated client-side problem.
//
// The test uses MaxStreamsPerConn=1 so a successful Pool.Get followed by
// a leaked reservation makes the second Get return miss (capacity full).
// If the reservation is correctly released, the second Get succeeds.
func TestBuildConnectionStack_H2PoolFastPath_ClientMITMFailReleasesReservation(t *testing.T) {
	target := "127.0.0.1:1" // unreachable; only the FAST path can succeed without dialing

	// CA + Issuer for MITM (issuer needs to mint a cert for the host portion).
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	// Pool with capacity=1 so we can detect a leaked reservation.
	h2Pool := pool.New(pool.PoolOptions{MaxStreamsPerConn: 1})
	defer h2Pool.Close()

	buildCfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
		HTTP2Pool:          h2Pool,
	}

	// Pre-populate the pool with a live cached Layer.
	cached, teardown := startCachedH2Layer(t, envelope.EnvelopeContext{
		ConnID:     "cached-conn",
		TargetHost: target,
		TLS:        &envelope.TLSSnapshot{ALPN: "h2", SNI: "cached-marker"},
	})
	defer teardown()
	hostTLSForKey, err := resolvePerHostTLS(target, buildCfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS: %v", err)
	}
	poolKey := poolKeyForH2(target, buildCfg, hostTLSForKey)
	h2Pool.Put(poolKey, cached)

	// Sanity: pool returns the cached Layer on first Get (and increments
	// inUseCount). Put it back so the BuildConnectionStack call below can
	// take it.
	if got, err := h2Pool.Get(poolKey); err != nil || got != cached {
		t.Fatalf("sanity Get: got=%v err=%v", got, err)
	}
	h2Pool.Put(poolKey, cached)

	// Run BuildConnectionStack with a clientConn whose far side closes
	// immediately — performClientMITM's tlslayer.Server will fail reading
	// the ClientHello, returning an error.
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	type buildResult struct {
		stack *ConnectionStack
		err   error
	}
	resultCh := make(chan buildResult, 1)
	go func() {
		serverConn, acceptErr := clientLn.Accept()
		if acceptErr != nil {
			resultCh <- buildResult{err: acceptErr}
			return
		}
		stack, _, _, buildErr := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack: stack, err: buildErr}
	}()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Close immediately — the proxy's TLS handshake will see EOF and fail.
	_ = clientConn.Close()

	select {
	case r := <-resultCh:
		if r.err == nil {
			if r.stack != nil {
				_ = r.stack.Close()
			}
			t.Fatal("BuildConnectionStack: expected error from client MITM, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BuildConnectionStack timed out")
	}

	// Verify the pool reservation was released: Pool.Get must return the
	// cached Layer again. With MaxStreamsPerConn=1, a leaked reservation
	// would make Get return nil (entry at capacity).
	got, err := h2Pool.Get(poolKey)
	if err != nil {
		t.Fatalf("Get after MITM fail: err=%v", err)
	}
	if got == nil {
		t.Fatal("Get after MITM fail: returned nil; reservation appears to have leaked (Pool.Put not called on failure path)")
	}
	if got != cached {
		t.Errorf("Get after MITM fail: returned %v, want cached %v", got, cached)
	}
}

// TestPoolKeyForH2_StableAndDistinct verifies that poolKeyForH2 produces the
// same key for identical configs, and distinct keys when any of the
// canonicalised fields differ. This guards against silent cache misses
// (two logically-identical connections not sharing a pool entry) and
// against collisions (two distinct configs sharing a pool entry).
func TestPoolKeyForH2_StableAndDistinct(t *testing.T) {
	baseCfg := &BuildConfig{
		InsecureSkipVerify: false,
		TLSFingerprint:     "chrome",
	}
	target := "example.com:443"

	k1 := poolKeyForH2(target, baseCfg, nil)
	k2 := poolKeyForH2(target, baseCfg, nil)
	if k1 != k2 {
		t.Errorf("stable: k1=%+v k2=%+v", k1, k2)
	}
	if k1.HostPort != target {
		t.Errorf("HostPort = %q, want %q", k1.HostPort, target)
	}
	if k1.TLSConfigHash == "" {
		t.Error("empty TLSConfigHash")
	}

	// Different InsecureSkipVerify -> different hash.
	// BuildConfig embeds atomic.Pointer (non-copyable), so build alternates
	// as fresh struct literals rather than copying baseCfg.
	altCfg := &BuildConfig{
		InsecureSkipVerify: true,
		TLSFingerprint:     "chrome",
	}
	kAlt := poolKeyForH2(target, altCfg, nil)
	if kAlt.TLSConfigHash == k1.TLSConfigHash {
		t.Error("InsecureSkipVerify change did not affect hash")
	}

	// Different TLSFingerprint -> different hash.
	altCfg2 := &BuildConfig{
		InsecureSkipVerify: false,
		TLSFingerprint:     "firefox",
	}
	kAlt2 := poolKeyForH2(target, altCfg2, nil)
	if kAlt2.TLSConfigHash == k1.TLSConfigHash {
		t.Error("TLSFingerprint change did not affect hash")
	}

	// Different target -> different HostPort (hash may collide if canonical
	// bytes happen to match, but HostPort differs which is part of the key).
	kOther := poolKeyForH2("other.example.com:443", baseCfg, nil)
	if kOther == k1 {
		t.Error("different target produced identical PoolKey")
	}
}

// TestPoolKeyForH2_NilCfg ensures the helper survives a nil BuildConfig
// (used by some tunnel paths that only carry an UpstreamProxy).
func TestPoolKeyForH2_NilCfg(t *testing.T) {
	k := poolKeyForH2("example.com:443", nil, nil)
	if k.HostPort != "example.com:443" {
		t.Errorf("HostPort = %q, want %q", k.HostPort, "example.com:443")
	}
	if k.TLSConfigHash == "" {
		t.Error("empty TLSConfigHash for nil cfg")
	}
}

// TestPoolKeyForH2_RegistryClientCertReplacement verifies USK-737: when a
// runtime HostTLSRegistry update replaces the client certificate for a
// host, poolKeyForH2 (called with the post-update resolvedTLS) must mint a
// distinct key from the pre-update one. Without this, an H2 pool entry
// established under cert A would silently be reused for requests that
// should now be sent under cert B.
func TestPoolKeyForH2_RegistryClientCertReplacement(t *testing.T) {
	target := "api.example.com:443"

	dirA := t.TempDir()
	certA, keyA := generateTestCertFiles(t, dirA)
	dirB := t.TempDir()
	certB, keyB := generateTestCertFiles(t, dirB)

	reg := transport.NewHostTLSRegistry()
	cfg := &BuildConfig{HostTLSRegistry: reg}

	// Step 1: install cert A. Resolve and mint the pool key under A.
	reg.SetGlobal(&transport.HostTLSConfig{
		ClientCertPath: certA,
		ClientKeyPath:  keyA,
	})
	hostTLSA, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS A: %v", err)
	}
	keyUnderA := poolKeyForH2(target, cfg, hostTLSA)

	// Step 2: replace with cert B. Resolve and mint the pool key under B.
	reg.SetGlobal(&transport.HostTLSConfig{
		ClientCertPath: certB,
		ClientKeyPath:  keyB,
	})
	hostTLSB, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS B: %v", err)
	}
	keyUnderB := poolKeyForH2(target, cfg, hostTLSB)

	if keyUnderA == keyUnderB {
		t.Fatalf("pool key did not change after registry cert replacement: %+v", keyUnderA)
	}

	// Step 3: install no cert at all (clearing the registry). Key must
	// differ from both A and B.
	reg.SetGlobal(nil)
	hostTLSNone, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS none: %v", err)
	}
	keyNoCert := poolKeyForH2(target, cfg, hostTLSNone)
	if keyNoCert == keyUnderA || keyNoCert == keyUnderB {
		t.Fatalf("clearing registry did not change pool key: noCert=%+v A=%+v B=%+v", keyNoCert, keyUnderA, keyUnderB)
	}
}

// TestPoolKeyForH2_RegistryInsecureSkipVerifyToggle verifies that flipping
// the runtime registry's TLS-verify flag invalidates the pool key, so a
// connection established under verify=true is not reused after the
// operator switches to verify=false (or vice versa).
func TestPoolKeyForH2_RegistryInsecureSkipVerifyToggle(t *testing.T) {
	target := "api.example.com:443"

	verifyTrue := true
	verifyFalse := false

	reg := transport.NewHostTLSRegistry()
	cfg := &BuildConfig{HostTLSRegistry: reg}

	reg.SetGlobal(&transport.HostTLSConfig{TLSVerify: &verifyTrue})
	hostTLSVerify, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS verify=true: %v", err)
	}
	keyVerify := poolKeyForH2(target, cfg, hostTLSVerify)

	reg.SetGlobal(&transport.HostTLSConfig{TLSVerify: &verifyFalse})
	hostTLSInsecure, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS verify=false: %v", err)
	}
	keyInsecure := poolKeyForH2(target, cfg, hostTLSInsecure)

	if keyVerify == keyInsecure {
		t.Fatalf("pool key did not change after TLSVerify toggle: %+v", keyVerify)
	}
}

// TestPoolKeyForH2_RegistryCABundleReplacement verifies that replacing the
// runtime registry's CA bundle for a host invalidates the pool key.
// Pre-fix, the pool key did not include the CA bundle at all, so
// connections established under bundle A would silently be reused after
// the operator swapped to bundle B.
func TestPoolKeyForH2_RegistryCABundleReplacement(t *testing.T) {
	target := "api.example.com:443"

	// Reuse generateTestCertFiles to produce real PEM cert files that
	// AppendCertsFromPEM accepts (the resolver's CA loader rejects bundles
	// with no parseable certificates). Each call produces a distinct file
	// because ecdsa.GenerateKey returns a fresh key per invocation.
	dirA := t.TempDir()
	caA, _ := generateTestCertFiles(t, dirA)
	dirB := t.TempDir()
	caB, _ := generateTestCertFiles(t, dirB)

	reg := transport.NewHostTLSRegistry()
	cfg := &BuildConfig{HostTLSRegistry: reg}

	// Bundle A.
	reg.SetGlobal(&transport.HostTLSConfig{CABundlePath: caA})
	hostTLSA, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS A: %v", err)
	}
	if hostTLSA.caBundleHash == "" {
		t.Fatal("caBundleHash empty after CA bundle install (USK-737)")
	}
	keyUnderA := poolKeyForH2(target, cfg, hostTLSA)

	// Bundle B.
	reg.SetGlobal(&transport.HostTLSConfig{CABundlePath: caB})
	hostTLSB, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS B: %v", err)
	}
	if hostTLSB.caBundleHash == hostTLSA.caBundleHash {
		t.Fatal("caBundleHash did not change after CA bundle replacement")
	}
	keyUnderB := poolKeyForH2(target, cfg, hostTLSB)

	if keyUnderA == keyUnderB {
		t.Fatalf("pool key did not change after CA bundle replacement: %+v", keyUnderA)
	}
}

// TestBuildConfig_ProtocolLimitsFieldsDefaultZero verifies that the
// per-protocol limit fields newly added in USK-649 default to zero on a
// freshly-allocated BuildConfig (Go's zero-value contract). The Resolve*
// helpers and Layer Options interpret zero as "use default", so leaving
// these unset is equivalent to using the package-level constants.
func TestBuildConfig_ProtocolLimitsFieldsDefaultZero(t *testing.T) {
	cfg := &BuildConfig{}
	if cfg.WSMaxFrameSize != 0 {
		t.Errorf("WSMaxFrameSize = %d, want 0", cfg.WSMaxFrameSize)
	}
	if cfg.WSDeflateEnabled {
		t.Errorf("WSDeflateEnabled = true, want false (zero value)")
	}
	if cfg.GRPCMaxMessageSize != 0 {
		t.Errorf("GRPCMaxMessageSize = %d, want 0", cfg.GRPCMaxMessageSize)
	}
	if cfg.SSEMaxEventSize != 0 {
		t.Errorf("SSEMaxEventSize = %d, want 0", cfg.SSEMaxEventSize)
	}
}

// TestBuildConfig_ProtocolLimitsFieldsRoundTrip verifies that explicit
// per-protocol limit values assigned to a BuildConfig survive — i.e., the
// fields are simple value carriers wired via the Resolve* helpers at
// construction time.
func TestBuildConfig_ProtocolLimitsFieldsRoundTrip(t *testing.T) {
	cfg := &BuildConfig{
		WSMaxFrameSize:     8192,
		WSDeflateEnabled:   true,
		GRPCMaxMessageSize: 1 << 20,
		SSEMaxEventSize:    16384,
	}
	if cfg.WSMaxFrameSize != 8192 {
		t.Errorf("WSMaxFrameSize = %d, want 8192", cfg.WSMaxFrameSize)
	}
	if !cfg.WSDeflateEnabled {
		t.Error("WSDeflateEnabled = false, want true")
	}
	if cfg.GRPCMaxMessageSize != 1<<20 {
		t.Errorf("GRPCMaxMessageSize = %d, want %d", cfg.GRPCMaxMessageSize, 1<<20)
	}
	if cfg.SSEMaxEventSize != 16384 {
		t.Errorf("SSEMaxEventSize = %d, want 16384", cfg.SSEMaxEventSize)
	}
}

// TestClientH2MaxConcurrentStreamsOption_NilCfg returns nil so callers can
// safely append-with-guard. nil BuildConfig is the unconfigured fallback.
func TestClientH2MaxConcurrentStreamsOption_NilCfg(t *testing.T) {
	if got := clientH2MaxConcurrentStreamsOption(nil); got != nil {
		t.Errorf("nil cfg: got non-nil option, want nil (use H2 layer default)")
	}
}

// TestClientH2MaxConcurrentStreamsOption_ZeroValue returns nil when the
// field is unset (zero) so the H2 layer keeps its compile-time default.
// This is the documented "preserve current behaviour" sentinel for
// USK-713.
func TestClientH2MaxConcurrentStreamsOption_ZeroValue(t *testing.T) {
	cfg := &BuildConfig{}
	if got := clientH2MaxConcurrentStreamsOption(cfg); got != nil {
		t.Errorf("zero cfg: got non-nil option, want nil (use H2 layer default)")
	}
}

// TestClientH2MaxConcurrentStreamsOption_NonZeroProducesOption returns a
// non-nil option when the field is set. The option's effect is exercised
// at the H2 layer level (TestLayer_WithMaxConcurrentStreams_*).
func TestClientH2MaxConcurrentStreamsOption_NonZeroProducesOption(t *testing.T) {
	cfg := &BuildConfig{MaxConcurrentStreams: 42}
	if got := clientH2MaxConcurrentStreamsOption(cfg); got == nil {
		t.Errorf("non-zero cfg: got nil option, want non-nil")
	}
}

// TestBuildConfig_TLSFingerprint_DynamicOverride verifies the USK-809
// runtime-mutation surface: SetTLSFingerprint installs an override that
// EffectiveTLSFingerprint returns in preference to the static
// TLSFingerprint field, and an empty profile clears the override so
// the static field re-emerges. The dial-time read sites
// (DialUpstreamRaw call sites in stack_builder.go) consult
// EffectiveTLSFingerprint, so this test gates that runtime
// proxy_start / configure changes reach the live wire path rather
// than being frozen at boot like the pre-fix behaviour.
func TestBuildConfig_TLSFingerprint_DynamicOverride(t *testing.T) {
	cfg := &BuildConfig{TLSFingerprint: "chrome"}

	// Boot-time value is observable via EffectiveTLSFingerprint when no
	// runtime override is in place.
	if got := cfg.EffectiveTLSFingerprint(); got != "chrome" {
		t.Errorf("initial EffectiveTLSFingerprint = %q, want chrome (boot fallback)", got)
	}

	// Runtime override takes precedence.
	cfg.SetTLSFingerprint("firefox")
	if got := cfg.EffectiveTLSFingerprint(); got != "firefox" {
		t.Errorf("after SetTLSFingerprint(firefox), EffectiveTLSFingerprint = %q, want firefox", got)
	}
	// Static field unchanged — override is layered on top, not destructive.
	if cfg.TLSFingerprint != "chrome" {
		t.Errorf("static TLSFingerprint mutated to %q, want chrome (override must not destroy boot value)", cfg.TLSFingerprint)
	}

	// Override another profile to confirm replacement (not append) semantics.
	cfg.SetTLSFingerprint("safari")
	if got := cfg.EffectiveTLSFingerprint(); got != "safari" {
		t.Errorf("after SetTLSFingerprint(safari), EffectiveTLSFingerprint = %q, want safari", got)
	}

	// Empty clears the override; the static field surfaces again.
	cfg.SetTLSFingerprint("")
	if got := cfg.EffectiveTLSFingerprint(); got != "chrome" {
		t.Errorf("after SetTLSFingerprint(\"\"), EffectiveTLSFingerprint = %q, want chrome (cleared override)", got)
	}
}

// TestBuildConfig_TLSFingerprint_NilSafe ensures the accessor + setter
// short-circuit on a nil receiver — defensive guard mirroring the
// SetUpstreamProxy precedent. A nil BuildConfig occurs in test
// constructions and on early-failure paths; the runtime mutation must
// not panic.
func TestBuildConfig_TLSFingerprint_NilSafe(t *testing.T) {
	var cfg *BuildConfig
	if got := cfg.EffectiveTLSFingerprint(); got != "" {
		t.Errorf("nil-receiver EffectiveTLSFingerprint = %q, want empty string", got)
	}
	// Must not panic.
	cfg.SetTLSFingerprint("chrome")
}

// TestBuildConfig_MaxConcurrentStreamsRoundTrip verifies the new field
// is a simple value carrier on BuildConfig (USK-713).
func TestBuildConfig_MaxConcurrentStreamsRoundTrip(t *testing.T) {
	cfg := &BuildConfig{}
	if cfg.MaxConcurrentStreams != 0 {
		t.Errorf("default MaxConcurrentStreams = %d, want 0 (sentinel for layer default)", cfg.MaxConcurrentStreams)
	}
	cfg.MaxConcurrentStreams = 250
	if cfg.MaxConcurrentStreams != 250 {
		t.Errorf("MaxConcurrentStreams = %d, want 250", cfg.MaxConcurrentStreams)
	}
}

// TestGRPCOptionsFromBuildConfig verifies the helper that translates
// BuildConfig.GRPCMaxMessageSize into the [grpclayer.Option] slice
// consumed by DispatchH2Stream.
func TestGRPCOptionsFromBuildConfig(t *testing.T) {
	if got := GRPCOptionsFromBuildConfig(nil); len(got) != 0 {
		t.Errorf("nil cfg: len(opts) = %d, want 0", len(got))
	}
	if got := GRPCOptionsFromBuildConfig(&BuildConfig{}); len(got) != 0 {
		t.Errorf("zero cfg: len(opts) = %d, want 0", len(got))
	}
	if got := GRPCOptionsFromBuildConfig(&BuildConfig{GRPCMaxMessageSize: 1024}); len(got) != 1 {
		t.Errorf("with cap: len(opts) = %d, want 1", len(got))
	}
}

// TestResolvePerHostTLS_RegistryRuntimeUpdate verifies USK-733: a runtime
// SetGlobal on the HostTLSRegistry surfaces in the next resolvePerHostTLS
// call, even though the BuildConfig was assembled before the registry was
// populated. This is the gating behaviour for proxy_start(client_cert=...)
// reaching the live MITM dial path without a server restart.
func TestResolvePerHostTLS_RegistryRuntimeUpdate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateTestCertFiles(t, dir)

	reg := transport.NewHostTLSRegistry()
	cfg := &BuildConfig{
		HostTLSRegistry: reg,
	}

	// Before SetGlobal: registry is empty, fallbacks (nil ClientCert,
	// false InsecureSkipVerify) win.
	resolved, err := resolvePerHostTLS("api.example.com:443", cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS pre-SetGlobal: %v", err)
	}
	if resolved.clientCert != nil {
		t.Errorf("pre-SetGlobal: clientCert = %v, want nil", resolved.clientCert)
	}

	// Runtime SetGlobal — this is what proxy_start(client_cert=...) does.
	reg.SetGlobal(&transport.HostTLSConfig{
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	})

	// After SetGlobal: the same BuildConfig now resolves with the cert.
	resolved, err = resolvePerHostTLS("api.example.com:443", cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS post-SetGlobal: %v", err)
	}
	if resolved.clientCert == nil {
		t.Fatal("post-SetGlobal: clientCert is nil; registry update did not reach the dial path (USK-733)")
	}
	if len(resolved.clientCert.Certificate) == 0 {
		t.Errorf("post-SetGlobal: clientCert.Certificate is empty")
	}
}

// TestResolvePerHostTLS_RegistryPerHostOverride verifies a per-host
// registry entry takes precedence over the registry global slot.
func TestResolvePerHostTLS_RegistryPerHostOverride(t *testing.T) {
	dir := t.TempDir()
	globalCert, globalKey := generateTestCertFiles(t, dir)

	hostDir := t.TempDir()
	hostCert, hostKey := generateTestCertFiles(t, hostDir)

	reg := transport.NewHostTLSRegistry()
	reg.SetGlobal(&transport.HostTLSConfig{
		ClientCertPath: globalCert,
		ClientKeyPath:  globalKey,
	})
	reg.Set("special.example.com", &transport.HostTLSConfig{
		ClientCertPath: hostCert,
		ClientKeyPath:  hostKey,
	})

	cfg := &BuildConfig{HostTLSRegistry: reg}

	// Per-host hit: special.example.com resolves to hostCert.
	specialResolved, err := resolvePerHostTLS("special.example.com:443", cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS special: %v", err)
	}
	if specialResolved.clientCert == nil {
		t.Fatal("special host: clientCert is nil")
	}

	// Global fallback: api.example.com resolves to globalCert.
	apiResolved, err := resolvePerHostTLS("api.example.com:443", cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS api: %v", err)
	}
	if apiResolved.clientCert == nil {
		t.Fatal("api host: global fallback returned nil clientCert")
	}

	// The two certs must be distinct (different DER bytes).
	if specialResolved.clientCert == apiResolved.clientCert {
		t.Error("special and api resolved to the same *tls.Certificate; per-host override did not take precedence")
	}
}

// TestResolvePerHostTLS_RegistryOverridesResolverFallback verifies the
// runtime registry entry takes precedence over a stale HostTLSResolver
// match for the same host. This locks the documented resolution order
// (resolver → registry; registry wins).
func TestResolvePerHostTLS_RegistryOverridesResolverFallback(t *testing.T) {
	dir := t.TempDir()
	resolverCert, resolverKey := generateTestCertFiles(t, dir)

	regDir := t.TempDir()
	regCert, regKey := generateTestCertFiles(t, regDir)

	resolver := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {
			ClientCertPath: resolverCert,
			ClientKeyPath:  resolverKey,
		},
	})

	reg := transport.NewHostTLSRegistry()
	reg.Set("example.com", &transport.HostTLSConfig{
		ClientCertPath: regCert,
		ClientKeyPath:  regKey,
	})

	cfg := &BuildConfig{
		HostTLSResolver: resolver,
		HostTLSRegistry: reg,
	}

	resolved, err := resolvePerHostTLS("example.com:443", cfg)
	if err != nil {
		t.Fatalf("resolvePerHostTLS: %v", err)
	}
	if resolved.clientCert == nil {
		t.Fatal("clientCert is nil")
	}
	// The cert reached should be the registry's, not the resolver's.
	// We compare DER bytes of the leaf to disambiguate.
	wantCert, err := tls.LoadX509KeyPair(regCert, regKey)
	if err != nil {
		t.Fatalf("load registry cert for compare: %v", err)
	}
	if !bytes.Equal(resolved.clientCert.Certificate[0], wantCert.Certificate[0]) {
		t.Error("registry cert did not win; resolver cert leaked through")
	}
}
