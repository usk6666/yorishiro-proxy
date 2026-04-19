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
		stack, _, err := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
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
		stack *ConnectionStack
		snap  *envelope.TLSSnapshot
		err   error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, err := clientLn.Accept()
		if err != nil {
			resultCh <- buildResult{nil, nil, err}
			return
		}
		stack, snap, err := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack, snap, err}
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

	// Verify TLSSnapshot is populated.
	if result.snap == nil {
		t.Fatal("expected non-nil TLSSnapshot")
	}
	if result.snap.Version == 0 {
		t.Error("expected non-zero TLS version in snapshot")
	}
}

func TestBuildConnectionStack_NilConfig(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	_, _, err := BuildConnectionStack(context.Background(), proxyConn, "example.com:443", nil)
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
		stack *ConnectionStack
		snap  *envelope.TLSSnapshot
		err   error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, acceptErr := clientLn.Accept()
		if acceptErr != nil {
			resultCh <- buildResult{err: acceptErr}
			return
		}
		stack, snap, buildErr := BuildConnectionStack(context.Background(), serverConn, target, buildCfg)
		resultCh <- buildResult{stack, snap, buildErr}
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

		// PoolKey should match what the stack builder computed.
		wantKey := poolKeyForH2(target, buildCfg)
		if gotKey := stack.PoolKey(); gotKey != wantKey {
			t.Errorf("PoolKey = %+v, want %+v", gotKey, wantKey)
		}

		// TLSSnapshot is populated and its ALPN is h2.
		if result.snap == nil {
			t.Fatal("expected non-nil TLSSnapshot")
		}
		if result.snap.ALPN != "h2" {
			t.Errorf("TLSSnapshot.ALPN = %q, want %q", result.snap.ALPN, "h2")
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

	k1 := poolKeyForH2(target, baseCfg)
	k2 := poolKeyForH2(target, baseCfg)
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
	altCfg := *baseCfg
	altCfg.InsecureSkipVerify = true
	kAlt := poolKeyForH2(target, &altCfg)
	if kAlt.TLSConfigHash == k1.TLSConfigHash {
		t.Error("InsecureSkipVerify change did not affect hash")
	}

	// Different TLSFingerprint -> different hash.
	altCfg2 := *baseCfg
	altCfg2.TLSFingerprint = "firefox"
	kAlt2 := poolKeyForH2(target, &altCfg2)
	if kAlt2.TLSConfigHash == k1.TLSConfigHash {
		t.Error("TLSFingerprint change did not affect hash")
	}

	// Different target -> different HostPort (hash may collide if canonical
	// bytes happen to match, but HostPort differs which is part of the key).
	kOther := poolKeyForH2("other.example.com:443", baseCfg)
	if kOther == k1 {
		t.Error("different target produced identical PoolKey")
	}
}

// TestPoolKeyForH2_NilCfg ensures the helper survives a nil BuildConfig
// (used by some tunnel paths that only carry an UpstreamProxy).
func TestPoolKeyForH2_NilCfg(t *testing.T) {
	k := poolKeyForH2("example.com:443", nil)
	if k.HostPort != "example.com:443" {
		t.Errorf("HostPort = %q, want %q", k.HostPort, "example.com:443")
	}
	if k.TLSConfigHash == "" {
		t.Error("empty TLSConfigHash for nil cfg")
	}
}
