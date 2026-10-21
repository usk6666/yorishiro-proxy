package connector

import (
	"context"
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

// USK-1315 tests: BuildConnectionStack takes an UpstreamTarget whose Dial and
// TLS halves are routed separately. Every test dials a local upstream at
// 127.0.0.1:P while naming the TLS authority a.example:P / b.example:P —
// names that do not resolve, so a build that succeeds proves the dial went
// to Dial rather than to the TLS host.

// sniRecordingUpstream is a local TLS upstream that records the SNI of every
// ClientHello it receives and keeps each accepted connection open until the
// test ends.
type sniRecordingUpstream struct {
	ln net.Listener

	mu      sync.Mutex
	snis    []string
	accepts int
}

// startSNIRecordingUpstream starts the upstream. nextProtos is its ALPN
// offer; when it contains "h2" each accepted connection runs a ServerRole
// http2.Layer so the proxy's ClientRole preface / SETTINGS exchange
// completes.
func startSNIRecordingUpstream(t *testing.T, nextProtos []string) *sniRecordingUpstream {
	t.Helper()
	base, err := newSelfSignedTLSConfig("upstream.test")
	if err != nil {
		t.Fatal(err)
	}
	u := &sniRecordingUpstream{}
	srvCfg := &tls.Config{
		Certificates: base.Certificates,
		NextProtos:   nextProtos,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			u.mu.Lock()
			u.snis = append(u.snis, hello.ServerName)
			u.mu.Unlock()
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	u.ln = ln

	var wg sync.WaitGroup
	var connsMu sync.Mutex
	var conns []net.Conn
	var layers []*http2.Layer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			u.mu.Lock()
			u.accepts++
			u.mu.Unlock()
			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				tc := c.(*tls.Conn)
				if herr := tc.Handshake(); herr != nil {
					return
				}
				if tc.ConnectionState().NegotiatedProtocol != "h2" {
					return // h1: hold the conn open; the test never sends a request.
				}
				l, lerr := http2.New(c, "test-upstream", http2.ServerRole, http2.WithScheme("https"))
				if lerr != nil {
					return
				}
				connsMu.Lock()
				layers = append(layers, l)
				connsMu.Unlock()
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		connsMu.Lock()
		for _, l := range layers {
			_ = l.Close()
		}
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
		wg.Wait()
	})
	return u
}

func (u *sniRecordingUpstream) port() string {
	_, p, _ := net.SplitHostPort(u.ln.Addr().String())
	return p
}

func (u *sniRecordingUpstream) dial() string { return u.ln.Addr().String() }

func (u *sniRecordingUpstream) recordedSNIs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.snis)
}

func (u *sniRecordingUpstream) acceptCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.accepts
}

// splitTarget returns UpstreamTarget{Dial: 127.0.0.1:P, TLS: tlsHost:P}.
func (u *sniRecordingUpstream) splitTarget(tlsHost string) UpstreamTarget {
	return UpstreamTarget{Dial: u.dial(), TLS: net.JoinHostPort(tlsHost, u.port())}
}

func newUpstreamTargetTestIssuer(t *testing.T) *cert.Issuer {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	return cert.NewIssuer(ca)
}

// builtStack is the outcome of buildThroughClient.
type builtStack struct {
	stack     *ConnectionStack
	clientTLS *tls.Conn
	err       error
}

// buildThroughClient runs BuildConnectionStack on the server side of a local
// TCP connection while a TLS client (offering clientALPN, SNI = the TLS
// authority's host) handshakes on the other side. On build failure the
// proxy-side conn is closed so the client handshake unblocks. Cleanup closes
// the stack and, when no pool owns it, the upstream h2 Layer.
func buildThroughClient(t *testing.T, ut UpstreamTarget, cfg *BuildConfig, clientALPN []string, peeked ClientHelloPeek) builtStack {
	t.Helper()
	return buildThroughClientCtx(t, context.Background(), ut, cfg, clientALPN, peeked)
}

func buildThroughClientCtx(t *testing.T, ctx context.Context, ut UpstreamTarget, cfg *BuildConfig, clientALPN []string, peeked ClientHelloPeek) builtStack {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		stack *ConnectionStack
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		sc, aerr := ln.Accept()
		if aerr != nil {
			resCh <- result{err: aerr}
			return
		}
		stack, _, _, berr := BuildConnectionStack(ctx, sc, ut, cfg, peeked)
		if berr != nil {
			_ = sc.Close()
		}
		resCh <- result{stack: stack, err: berr}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	clientTLS := tls.Client(cc, &tls.Config{
		ServerName:         extractHost(ut.TLS),
		NextProtos:         clientALPN,
		InsecureSkipVerify: true, //nolint:gosec // test: the MITM cert is inspected, not verified
	})
	hsCh := make(chan error, 1)
	go func() { hsCh <- clientTLS.Handshake() }()

	var res result
	select {
	case res = <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("BuildConnectionStack timed out")
	}
	if res.err != nil {
		<-hsCh
		return builtStack{err: res.err}
	}
	if hsErr := <-hsCh; hsErr != nil {
		_ = res.stack.Close()
		t.Fatalf("client TLS handshake: %v", hsErr)
	}
	stack := res.stack
	t.Cleanup(func() {
		if l := stack.UpstreamH2Layer(); l != nil && cfg.HTTP2Pool == nil {
			_ = l.Close()
		}
		_ = stack.Close()
	})
	return builtStack{stack: stack, clientTLS: clientTLS}
}

// buildH2ThroughClient is buildThroughClient for an h2 upstream: the client
// offers only h2 and drives its own preface so the proxy's ServerRole
// http2.New completes. A build error fails the test.
func buildH2ThroughClient(t *testing.T, ut UpstreamTarget, cfg *BuildConfig) *ConnectionStack {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		stack *ConnectionStack
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		sc, aerr := ln.Accept()
		if aerr != nil {
			resCh <- result{err: aerr}
			return
		}
		stack, _, _, berr := BuildConnectionStack(context.Background(), sc, ut, cfg, ClientHelloPeek{})
		if berr != nil {
			_ = sc.Close()
		}
		resCh <- result{stack: stack, err: berr}
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	clientTLS := tls.Client(cc, &tls.Config{
		ServerName:         extractHost(ut.TLS),
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true, //nolint:gosec // test
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	clientH2, err := http2.New(clientTLS, "test-client", http2.ClientRole, http2.WithScheme("https"))
	if err != nil {
		t.Fatalf("test-client http2.New: %v", err)
	}
	t.Cleanup(func() { _ = clientH2.Close() })
	var res result
	select {
	case res = <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("BuildConnectionStack timed out")
	}
	if res.err != nil {
		t.Fatalf("BuildConnectionStack(%+v): %v", ut, res.err)
	}
	t.Cleanup(func() { _ = res.stack.Close() })
	return res.stack
}

// Test plan #1: the upstream ClientHello carries the TLS authority's host as
// SNI, not the dial target.
func TestBuildConnectionStack_UpstreamTarget_UpstreamSNIIsTLSHost(t *testing.T) {
	up := startSNIRecordingUpstream(t, []string{"http/1.1"})
	cfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
	}
	got := buildThroughClient(t, up.splitTarget("a.example"), cfg, []string{"http/1.1"}, ClientHelloPeek{})
	if got.err != nil {
		t.Fatalf("BuildConnectionStack: %v", got.err)
	}
	if snis := up.recordedSNIs(); !slices.Equal(snis, []string{"a.example"}) {
		t.Errorf("upstream SNIs = %q, want [\"a.example\"] (the TLS authority's host)", snis)
	}
}

// Test plan #2: the client-facing MITM certificate names the TLS host.
func TestBuildConnectionStack_UpstreamTarget_MITMCertNamesTLSHost(t *testing.T) {
	up := startSNIRecordingUpstream(t, []string{"http/1.1"})
	cfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
	}
	got := buildThroughClient(t, up.splitTarget("a.example"), cfg, []string{"http/1.1"}, ClientHelloPeek{})
	if got.err != nil {
		t.Fatalf("BuildConnectionStack: %v", got.err)
	}
	leaf := got.clientTLS.ConnectionState().PeerCertificates[0]
	if !slices.Contains(leaf.DNSNames, "a.example") {
		t.Errorf("MITM cert DNSNames = %q, IPs = %v; want a DNS SAN for a.example", leaf.DNSNames, leaf.IPAddresses)
	}
}

// Test plan #3 (guard; passes on red): the TCP dial goes to Dial even though
// the TLS host does not resolve.
func TestBuildConnectionStack_UpstreamTarget_DialsDialTarget(t *testing.T) {
	up := startSNIRecordingUpstream(t, []string{"http/1.1"})
	cfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
	}
	got := buildThroughClient(t, up.splitTarget("a.example"), cfg, []string{"http/1.1"}, ClientHelloPeek{})
	if got.err != nil {
		t.Fatalf("BuildConnectionStack: %v (a.example is unresolvable — a dial of the TLS host would fail here)", got.err)
	}
	if n := up.acceptCount(); n != 1 {
		t.Errorf("upstream accepts = %d, want 1", n)
	}
}

// Test plan #4: same dial target + different TLS hosts → different h2 pool
// keys, each with HostPort == Dial.
func TestBuildConnectionStack_UpstreamTarget_H2PoolKeySplitsByTLSHost(t *testing.T) {
	up := startSNIRecordingUpstream(t, []string{"h2"})
	h2Pool := pool.New(pool.PoolOptions{})
	t.Cleanup(func() { _ = h2Pool.Close() })
	cfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
		HTTP2Pool:          h2Pool,
	}

	stackA := buildH2ThroughClient(t, up.splitTarget("a.example"), cfg)
	keyA := stackA.PoolKey()
	h2Pool.Put(keyA, stackA.UpstreamH2Layer())

	stackB := buildH2ThroughClient(t, up.splitTarget("b.example"), cfg)
	keyB := stackB.PoolKey()
	h2Pool.Put(keyB, stackB.UpstreamH2Layer())

	if keyA == keyB {
		t.Errorf("pool keys for a.example and b.example on one dial target are equal (%s); vhosts would share an h2 connection", keyA)
	}
	if keyA.HostPort != up.dial() || keyB.HostPort != up.dial() {
		t.Errorf("pool key HostPorts = %q / %q, want both %q (the dial target)", keyA.HostPort, keyB.HostPort, up.dial())
	}
	if snis := up.recordedSNIs(); !slices.Equal(snis, []string{"a.example", "b.example"}) {
		t.Errorf("upstream SNIs = %q, want [a.example b.example] (b must not ride a's pooled connection)", snis)
	}
}

// Test plan #5: same dial target + different TLS hosts → separate ALPN cache
// entries, on the legacy fallback path and on the sniff-first path.
func TestBuildConnectionStack_UpstreamTarget_ALPNCacheSplitsByTLSHost(t *testing.T) {
	tests := []struct {
		name   string
		peeked ClientHelloPeek
	}{
		{name: "legacy", peeked: ClientHelloPeek{}},
		{name: "sniff-first", peeked: ClientHelloPeek{ALPN: []string{"http/1.1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := startSNIRecordingUpstream(t, []string{"http/1.1"})
			cache := NewALPNCache(DefaultALPNCacheSize, DefaultALPNCacheTTL)
			cfg := &BuildConfig{
				ProxyConfig:        &config.ProxyConfig{},
				Issuer:             newUpstreamTargetTestIssuer(t),
				InsecureSkipVerify: true,
				ALPNCache:          cache,
			}
			for _, host := range []string{"a.example", "b.example"} {
				peeked := tt.peeked
				peeked.SNI = host
				if got := buildThroughClient(t, up.splitTarget(host), cfg, []string{"http/1.1"}, peeked); got.err != nil {
					t.Fatalf("BuildConnectionStack(%s): %v", host, got.err)
				}
			}
			if n := cache.Len(); n != 2 {
				t.Errorf("ALPN cache Len = %d, want 2 (one entry per TLS host)", n)
			}
			key := ALPNCacheKey{HostPort: up.dial(), ServerName: "a.example", Fingerprint: cfg.EffectiveUTLSProfile()}
			if entry, ok := cache.Get(key); !ok || entry.Protocol != "http/1.1" {
				t.Errorf("cache.Get(%+v) = %+v, %v; want http/1.1, true", key, entry, ok)
			}
		})
	}
}

// Test plan #6: per-host TLS settings are looked up by the TLS host.
// Verification is enforced globally and the upstream cert is self-signed,
// so only a per-host tls_verify=false entry lets the build succeed.
func TestBuildConnectionStack_UpstreamTarget_PerHostTLSByTLSHost(t *testing.T) {
	skip := false
	tests := []struct {
		name      string
		entryHost string
		tlsHost   string
		wantErr   bool
	}{
		{name: "entry for the TLS host applies", entryHost: "a.example", tlsHost: "a.example", wantErr: false},
		{name: "entry for the dial host does not", entryHost: "127.0.0.1", tlsHost: "b.example", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := startSNIRecordingUpstream(t, []string{"http/1.1"})
			reg := transport.NewHostTLSRegistry()
			reg.Set(tt.entryHost, &transport.HostTLSConfig{TLSVerify: &skip})
			cfg := &BuildConfig{
				ProxyConfig:     &config.ProxyConfig{},
				Issuer:          newUpstreamTargetTestIssuer(t),
				HostTLSRegistry: reg,
			}
			got := buildThroughClient(t, up.splitTarget(tt.tlsHost), cfg, []string{"http/1.1"}, ClientHelloPeek{})
			if tt.wantErr {
				if got.err == nil {
					t.Fatal("BuildConnectionStack succeeded; want an x509 verification error (the dial host's entry must not apply)")
				}
				return
			}
			if got.err != nil {
				t.Fatalf("BuildConnectionStack: %v (the %s entry should have disabled verification)", got.err, tt.entryHost)
			}
		})
	}
}

// Test plan #7: raw_passthrough_hosts is matched against the TLS authority,
// and inside the raw-passthrough stack the cert / SNI / dial follow #1–#3.
func TestBuildConnectionStack_UpstreamTarget_RawPassthroughByTLSAuthority(t *testing.T) {
	up := startSNIRecordingUpstream(t, []string{"http/1.1"})
	cfg := &BuildConfig{
		ProxyConfig: &config.ProxyConfig{
			RawPassthroughHosts: []string{net.JoinHostPort("a.example", up.port())},
		},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
	}

	gotA := buildThroughClient(t, up.splitTarget("a.example"), cfg, nil, ClientHelloPeek{})
	if gotA.err != nil {
		t.Fatalf("BuildConnectionStack(a.example): %v", gotA.err)
	}
	if _, ok := gotA.stack.ClientTopmost().(*bytechunk.Layer); !ok {
		t.Errorf("a.example ClientTopmost = %T, want *bytechunk.Layer (listed in raw_passthrough_hosts)", gotA.stack.ClientTopmost())
	}
	leaf := gotA.clientTLS.ConnectionState().PeerCertificates[0]
	if !slices.Contains(leaf.DNSNames, "a.example") {
		t.Errorf("raw-passthrough MITM cert DNSNames = %q, want a.example", leaf.DNSNames)
	}

	gotB := buildThroughClient(t, up.splitTarget("b.example"), cfg, []string{"http/1.1"}, ClientHelloPeek{})
	if gotB.err != nil {
		t.Fatalf("BuildConnectionStack(b.example): %v", gotB.err)
	}
	if _, ok := gotB.stack.ClientTopmost().(*http1.Layer); !ok {
		t.Errorf("b.example ClientTopmost = %T, want *http1.Layer (not listed)", gotB.stack.ClientTopmost())
	}

	if snis := up.recordedSNIs(); !slices.Equal(snis, []string{"a.example", "b.example"}) {
		t.Errorf("upstream SNIs = %q, want [a.example b.example]", snis)
	}
	if n := up.acceptCount(); n != 2 {
		t.Errorf("upstream accepts = %d, want 2 (both dials to the dial target)", n)
	}
}

// Test plan #8 (guard; passes on red): EnvelopeContext.TargetHost is the dial
// target on both legs.
func TestBuildConnectionStack_UpstreamTarget_TargetHostIsDial(t *testing.T) {
	up := startSNIRecordingUpstream(t, []string{"http/1.1"})
	cfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
	}
	got := buildThroughClient(t, up.splitTarget("a.example"), cfg, []string{"http/1.1"}, ClientHelloPeek{})
	if got.err != nil {
		t.Fatalf("BuildConnectionStack: %v", got.err)
	}
	clientL, ok := got.stack.ClientTopmost().(*http1.Layer)
	if !ok {
		t.Fatalf("ClientTopmost = %T, want *http1.Layer", got.stack.ClientTopmost())
	}
	upstreamL, ok := got.stack.UpstreamTopmost().(*http1.Layer)
	if !ok {
		t.Fatalf("UpstreamTopmost = %T, want *http1.Layer", got.stack.UpstreamTopmost())
	}
	if th := clientL.EnvelopeContextTemplate().TargetHost; th != up.dial() {
		t.Errorf("client TargetHost = %q, want %q", th, up.dial())
	}
	if th := upstreamL.EnvelopeContextTemplate().TargetHost; th != up.dial() {
		t.Errorf("upstream TargetHost = %q, want %q", th, up.dial())
	}
}

// Test plan #9 (guard; passes on red): the per_target_host rotation slot is
// keyed by the dial target (ContextWithDialTarget gets Dial).
func TestBuildConnectionStack_UpstreamTarget_RotationKeyedByDial(t *testing.T) {
	// A closed local port as the upstream proxy: the rotation resolver is
	// consulted (and caches its pick) before the proxy dial fails.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := closed.Addr().String()
	_ = closed.Close()

	resolver := NewRotationResolver(RotationConfig{
		Template:     "http://user-§__nonce§:pass@" + proxyAddr,
		Policy:       RotationPerTargetHost,
		ListenerName: "L1",
	}, 0, 0)
	cfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
	}
	cfg.SetRotationForListener("L1", resolver)

	ut := UpstreamTarget{Dial: "127.0.0.1:9", TLS: "a.example:9"}
	ctx := ContextWithListenerName(context.Background(), "L1")
	got := buildThroughClientCtx(t, ctx, ut, cfg, []string{"http/1.1"}, ClientHelloPeek{})
	if got.err == nil {
		t.Fatal("BuildConnectionStack succeeded through a closed upstream proxy; want a dial error")
	}
	if _, ok := resolver.perTargetHost.get(ut.Dial); !ok {
		t.Errorf("rotation slot for dial target %q missing", ut.Dial)
	}
	if _, ok := resolver.perTargetHost.get(ut.TLS); ok {
		t.Errorf("rotation slot keyed by TLS authority %q; want dial-target keying", ut.TLS)
	}
}

// UpstreamTargetOf returns the split for a stack BuildConnectionStack built
// and falls back to the callback target for any other stack.
func TestUpstreamTargetOf(t *testing.T) {
	if got := UpstreamTargetOf(NewConnectionStack("x"), "h:1"); got != SameUpstreamTarget("h:1") {
		t.Errorf("UpstreamTargetOf(unbuilt) = %+v, want SameUpstreamTarget(h:1)", got)
	}
	if got := UpstreamTargetOf(nil, "h:1"); got != SameUpstreamTarget("h:1") {
		t.Errorf("UpstreamTargetOf(nil) = %+v, want SameUpstreamTarget(h:1)", got)
	}

	up := startSNIRecordingUpstream(t, []string{"http/1.1"})
	cfg := &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             newUpstreamTargetTestIssuer(t),
		InsecureSkipVerify: true,
	}
	ut := up.splitTarget("a.example")
	got := buildThroughClient(t, ut, cfg, []string{"http/1.1"}, ClientHelloPeek{})
	if got.err != nil {
		t.Fatalf("BuildConnectionStack: %v", got.err)
	}
	if of := UpstreamTargetOf(got.stack, ut.Dial); of != ut {
		t.Errorf("UpstreamTargetOf(built) = %+v, want %+v", of, ut)
	}
}

// BuildConnectionStack fails closed on a malformed TLS authority rather than
// falling back to the dial target.
func TestBuildConnectionStack_UpstreamTarget_InvalidTLSAuthority(t *testing.T) {
	// A closed local port: should validation ever let the build through,
	// the upstream dial fails fast instead of reaching a live service.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dial := closed.Addr().String()
	_ = closed.Close()

	cfg := &BuildConfig{
		ProxyConfig: &config.ProxyConfig{},
		Issuer:      newUpstreamTargetTestIssuer(t),
	}
	for _, tlsAuth := range []string{"", "a.example"} {
		c1, c2 := net.Pipe()
		_, _, _, err := BuildConnectionStack(context.Background(), c1, UpstreamTarget{Dial: dial, TLS: tlsAuth}, cfg, ClientHelloPeek{})
		_ = c1.Close()
		_ = c2.Close()
		if err == nil || !strings.Contains(err.Error(), "invalid TLS authority") {
			t.Errorf("TLS=%q: err = %v, want invalid TLS authority", tlsAuth, err)
		}
	}
}

// Test plan #10 (connector half): a redial on a stack built with distinct
// Dial / TLS dials Dial and sends SNI = TLS host, for h1 and h2.
func TestRedialUpstream_UpstreamTargetSplit(t *testing.T) {
	t.Run("h1", func(t *testing.T) {
		up := startSNIRecordingUpstream(t, []string{"http/1.1"})
		cfg := &BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             newUpstreamTargetTestIssuer(t),
			InsecureSkipVerify: true,
		}
		ut := up.splitTarget("a.example")
		got := buildThroughClient(t, ut, cfg, []string{"http/1.1"}, ClientHelloPeek{})
		if got.err != nil {
			t.Fatalf("BuildConnectionStack: %v", got.err)
		}
		stale, ok := got.stack.UpstreamTopmost().(*http1.Layer)
		if !ok {
			t.Fatalf("UpstreamTopmost = %T, want *http1.Layer", got.stack.UpstreamTopmost())
		}
		fresh, err := RedialUpstreamH1(context.Background(), UpstreamTargetOf(got.stack, ut.Dial), stale, cfg, 1)
		if err != nil {
			t.Fatalf("RedialUpstreamH1: %v", err)
		}
		t.Cleanup(func() { _ = fresh.Close() })
		if snis := up.recordedSNIs(); !slices.Equal(snis, []string{"a.example", "a.example"}) {
			t.Errorf("upstream SNIs = %q, want the redial to send a.example too", snis)
		}
		if n := up.acceptCount(); n != 2 {
			t.Errorf("upstream accepts = %d, want 2 (the redial dials the dial target)", n)
		}
	})
	t.Run("h2", func(t *testing.T) {
		up := startSNIRecordingUpstream(t, []string{"h2"})
		cfg := &BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             newUpstreamTargetTestIssuer(t),
			InsecureSkipVerify: true,
		}
		ut := up.splitTarget("a.example")
		stack := buildH2ThroughClient(t, ut, cfg)
		stale := stack.UpstreamH2Layer()
		if stale == nil {
			t.Fatal("UpstreamH2Layer is nil")
		}
		t.Cleanup(func() { _ = stale.Close() })
		fresh, err := RedialUpstreamH2(context.Background(), UpstreamTargetOf(stack, ut.Dial), stale, cfg, 1, nil)
		if err != nil {
			t.Fatalf("RedialUpstreamH2: %v", err)
		}
		t.Cleanup(func() { _ = fresh.Close() })
		if snis := up.recordedSNIs(); !slices.Equal(snis, []string{"a.example", "a.example"}) {
			t.Errorf("upstream SNIs = %q, want the redial to send a.example too", snis)
		}
		if n := up.acceptCount(); n != 2 {
			t.Errorf("upstream accepts = %d, want 2 (the redial dials the dial target)", n)
		}
	})
}
