package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// TestMITMServerConfig_HostnameCaseInsensitive asserts that mixed-case
// hostnames map to a single cache entry. Without this, an attacker (or just
// a long-running proxy) issuing CONNECT requests for "Example.com",
// "EXAMPLE.com", etc. could grow the Config cache and cert LRU per casing
// (CWE-770). It also ensures the cert presented for any casing is the same
// underlying *tls.Certificate so session resumption is not split per casing.
func TestMITMServerConfig_HostnameCaseInsensitive(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cLower := iss.MITMServerConfig("example.com", []string{"h2"})
	cUpper := iss.MITMServerConfig("EXAMPLE.COM", []string{"h2"})
	cMixed := iss.MITMServerConfig("Example.Com", []string{"h2"})

	if cLower != cUpper || cLower != cMixed {
		t.Errorf("mixed-case hostnames produced distinct *tls.Config pointers; want single entry: lower=%p upper=%p mixed=%p",
			cLower, cUpper, cMixed)
	}
	if got := iss.serverCfgs.Len(); got != 1 {
		t.Errorf("Config cache Len = %d, want 1 (single entry across casings)", got)
	}

	// And the cert LRU should also collapse to a single entry — otherwise
	// the closure's iss.GetCertificate(host) would issue a fresh cert per
	// casing variant, defeating the resumption fix.
	certLower, err := iss.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate(example.com): %v", err)
	}
	certUpper, err := iss.GetCertificate("EXAMPLE.COM")
	if err != nil {
		t.Fatalf("GetCertificate(EXAMPLE.COM): %v", err)
	}
	if certLower != certUpper {
		t.Errorf("cert LRU returned different *tls.Certificate for different casings; want pointer-identical")
	}
	if got := iss.CacheLen(); got != 1 {
		t.Errorf("cert cache Len = %d, want 1 (single entry across casings)", got)
	}
}

// TestMITMServerConfig_BoundedEviction verifies the Config cache enforces a
// size bound and evicts the LRU entry when full (CWE-770). Without bounding,
// a long-lived proxy seeing many distinct CONNECT targets would grow memory
// without bound.
func TestMITMServerConfig_BoundedEviction(t *testing.T) {
	ca := newTestCA(t)
	const cap = 3
	iss := NewIssuer(ca, WithMaxCacheSize(cap))

	// Fill to capacity with distinct hostnames.
	cfgs := make([]*tls.Config, cap)
	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	for i, h := range hosts {
		cfgs[i] = iss.MITMServerConfig(h, []string{"h2"})
	}
	if got := iss.serverCfgs.Len(); got != cap {
		t.Fatalf("Config cache Len = %d, want %d", got, cap)
	}

	// Insert one more — should evict the LRU (a.example.com) and stay at cap.
	cfgD := iss.MITMServerConfig("d.example.com", []string{"h2"})
	if cfgD == nil {
		t.Fatal("MITMServerConfig returned nil after eviction")
	}
	if got := iss.serverCfgs.Len(); got != cap {
		t.Errorf("Config cache Len after over-fill = %d, want %d", got, cap)
	}

	// Re-requesting the evicted host must produce a NEW *tls.Config pointer.
	cfgA2 := iss.MITMServerConfig("a.example.com", []string{"h2"})
	if cfgA2 == cfgs[0] {
		t.Errorf("evicted hostname returned the same *tls.Config pointer; want fresh instance")
	}

	// Stress: insert 10x capacity and confirm size never exceeds cap.
	for i := 0; i < cap*10; i++ {
		_ = iss.MITMServerConfig(fmt.Sprintf("stress-%d.example.com", i), []string{"h2"})
		if got := iss.serverCfgs.Len(); got > cap {
			t.Fatalf("Config cache Len = %d at iteration %d, exceeds cap %d", got, i, cap)
		}
	}
}

// TestMITMServerConfig_MinVersionTLS12 asserts the cached MITM Config sets
// MinVersion >= TLS 1.2. crypto/tls's default is TLS 1.0, which would be the
// inconsistent outlier vs the rest of the proxy's TLS surface (client.go and
// tlstransport.go both set tls.VersionTLS12). CWE-757.
func TestMITMServerConfig_MinVersionTLS12(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cases := []struct {
		name       string
		host       string
		alpnOffers []string
	}{
		{name: "h2 ALPN", host: "example.com", alpnOffers: []string{"h2"}},
		{name: "http/1.1 ALPN", host: "example.com", alpnOffers: []string{"http/1.1"}},
		{name: "h2,http/1.1 ALPN", host: "example.com", alpnOffers: []string{"h2", "http/1.1"}},
		{name: "no ALPN", host: "example.com", alpnOffers: nil},
		{name: "different host", host: "other.example.com", alpnOffers: []string{"h2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := iss.MITMServerConfig(tc.host, tc.alpnOffers)
			if cfg.MinVersion < tls.VersionTLS12 {
				t.Errorf("MinVersion = 0x%04x, want >= 0x%04x (TLS 1.2)",
					cfg.MinVersion, tls.VersionTLS12)
			}
			// Do NOT assert MaxVersion: leaving it 0 lets crypto/tls pick
			// the highest mutually supported version (TLS 1.3 today).
			if cfg.MaxVersion != 0 {
				t.Errorf("MaxVersion = 0x%04x, want 0 (let crypto/tls pick)", cfg.MaxVersion)
			}
		})
	}
}

// TestMITMServerConfig_StableInstance asserts MITMServerConfig returns the
// SAME *tls.Config pointer for the same (host, alpnOffer) key. This is the
// invariant that allows crypto/tls's lazily-generated session ticket
// encryption key to persist across MITM connections — the key lives inside
// the Config and a fresh Config means a fresh random key (USK-795).
func TestMITMServerConfig_StableInstance(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	c1 := iss.MITMServerConfig("nghttp2.org", []string{"h2"})
	c2 := iss.MITMServerConfig("nghttp2.org", []string{"h2"})
	if c1 != c2 {
		t.Fatalf("MITMServerConfig returned different *tls.Config pointers for the same key; want stable instance reuse")
	}
}

// TestMITMServerConfig_KeyDimensions asserts that the cache key includes both
// hostname and ALPN offer list (including order). Different keys MUST yield
// different Configs because crypto/tls reads NextProtos at handshake time and
// the server picks the first NextProtos entry the client also offered;
// sharing across ALPN offer lists would corrupt negotiation.
func TestMITMServerConfig_KeyDimensions(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cH2 := iss.MITMServerConfig("example.com", []string{"h2"})
	cH1 := iss.MITMServerConfig("example.com", []string{"http/1.1"})
	cBoth := iss.MITMServerConfig("example.com", []string{"h2", "http/1.1"})
	cBothReversed := iss.MITMServerConfig("example.com", []string{"http/1.1", "h2"})
	cEmpty := iss.MITMServerConfig("example.com", nil)
	cOtherHost := iss.MITMServerConfig("other.example.com", []string{"h2"})

	for _, pair := range []struct {
		name   string
		a, b   *tls.Config
		want   bool // true = want different pointers
		reason string
	}{
		{"h2 vs http/1.1", cH2, cH1, true, "ALPN offer differs"},
		{"h2 vs empty", cH2, cEmpty, true, "ALPN offer differs (empty)"},
		{"http/1.1 vs empty", cH1, cEmpty, true, "ALPN offer differs (empty)"},
		{"h2 vs h2,http/1.1", cH2, cBoth, true, "single vs multi offer"},
		{"h2,http/1.1 vs http/1.1,h2", cBoth, cBothReversed, true, "ALPN order is wire-observable"},
		{"h2 vs other host", cH2, cOtherHost, true, "hostname differs"},
	} {
		gotDifferent := pair.a != pair.b
		if gotDifferent != pair.want {
			t.Errorf("%s: pointer-different=%v, want %v (reason: %s)",
				pair.name, gotDifferent, pair.want, pair.reason)
		}
	}

	// And the negotiation-relevant fields actually differ.
	if len(cH2.NextProtos) != 1 || cH2.NextProtos[0] != "h2" {
		t.Errorf("h2 config NextProtos = %v, want [h2]", cH2.NextProtos)
	}
	if len(cH1.NextProtos) != 1 || cH1.NextProtos[0] != "http/1.1" {
		t.Errorf("http/1.1 config NextProtos = %v, want [http/1.1]", cH1.NextProtos)
	}
	if len(cBoth.NextProtos) != 2 || cBoth.NextProtos[0] != "h2" || cBoth.NextProtos[1] != "http/1.1" {
		t.Errorf("h2,http/1.1 config NextProtos = %v, want [h2 http/1.1]", cBoth.NextProtos)
	}
	if len(cEmpty.NextProtos) != 0 {
		t.Errorf("empty-ALPN config NextProtos = %v, want empty", cEmpty.NextProtos)
	}
}

// TestMITMServerConfig_CertStableAcrossCalls verifies that two distinct calls
// to GetCertificate (and therefore two consecutive MITM handshakes) present
// the byte-identical leaf cert for the same hostname. This locks in the
// existing per-host cert stability that the (host, alpn) Config cache
// implicitly depends on — if a future change reintroduced per-call cert
// generation, browsers would also reject session resumption.
func TestMITMServerConfig_CertStableAcrossCalls(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	c1, err := iss.GetCertificate("nghttp2.org")
	if err != nil {
		t.Fatalf("GetCertificate #1: %v", err)
	}
	c2, err := iss.GetCertificate("nghttp2.org")
	if err != nil {
		t.Fatalf("GetCertificate #2: %v", err)
	}

	// Pointer identity: cache hit returns the same struct.
	if c1 != c2 {
		t.Errorf("GetCertificate returned different *tls.Certificate pointers for same host; want pointer-identical (cache hit)")
	}

	// Belt-and-suspenders: byte-identical DER on the leaf.
	if len(c1.Certificate) == 0 || len(c2.Certificate) == 0 {
		t.Fatalf("certificate chain empty: c1=%d c2=%d", len(c1.Certificate), len(c2.Certificate))
	}
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Errorf("leaf cert DER differs across calls; want byte-identical")
	}
}

// TestMITMServerConfig_GetCertificateCallback verifies the cached Config's
// GetCertificate callback returns the live cert from the LRU. This is what
// makes ClearCache + future GetCertificate observe the new CA without
// rebuilding the Config.
func TestMITMServerConfig_GetCertificateCallback(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cfg := iss.MITMServerConfig("example.com", []string{"h2"})
	if cfg.GetCertificate == nil {
		t.Fatal("MITMServerConfig: GetCertificate callback is nil")
	}

	// Drive the callback as crypto/tls would.
	helloCert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate callback: %v", err)
	}
	directCert, err := iss.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("Issuer.GetCertificate: %v", err)
	}
	if helloCert != directCert {
		t.Errorf("callback returned different *tls.Certificate than direct GetCertificate")
	}
}

// TestMITMServerConfig_ClearCacheEvictsConfigs ensures ClearCache evicts both
// the cert cache and the Config cache; otherwise a stale Config would still
// hold a closure that resolves to the freshly-issued cert (correct), but the
// session ticket key would persist across CA regen — letting a new client
// resume a session sealed under the old CA chain.
func TestMITMServerConfig_ClearCacheEvictsConfigs(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	c1 := iss.MITMServerConfig("example.com", []string{"h2"})
	iss.ClearCache()
	c2 := iss.MITMServerConfig("example.com", []string{"h2"})
	if c1 == c2 {
		t.Errorf("ClearCache did not evict cached *tls.Config; want fresh instance after Clear")
	}
}

// TestMITMServerConfig_Concurrent verifies concurrent first-time callers
// converge on a single Config instance (LoadOrStore semantics) and the
// returned Config is safe to read concurrently. Run with -race.
func TestMITMServerConfig_Concurrent(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	const goroutines = 32
	results := make([]*tls.Config, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = iss.MITMServerConfig("nghttp2.org", []string{"h2"})
		}(i)
	}
	wg.Wait()

	first := results[0]
	for i, got := range results {
		if got != first {
			t.Errorf("goroutine %d got different *tls.Config; want all callers to converge on a single instance", i)
		}
	}
}

// TestMITMServerConfig_FreshConfigBreaksResumption documents the bug shape
// that USK-795 fixed: when each MITM connection uses a freshly-allocated
// *tls.Config (the pre-fix code path on main HEAD 62cf2da), crypto/tls
// generates a different random session ticket encryption key per Config and
// the second connection cannot resume. This test runs that pre-fix shape
// inline so the regression test below has an explicit counterexample.
func TestMITMServerConfig_FreshConfigBreaksResumption(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	caCert, _ := ca.SigningPair()
	if caCert == nil {
		t.Fatal("CA SigningPair returned nil cert")
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	const host = "nghttp2.test"
	mitmCert, err := iss.GetCertificate(host)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	// Build a per-connection Config-factory that mirrors pre-fix
	// performClientMITM: a fresh tls.Config every call.
	freshConfig := func() *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{*mitmCert},
			NextProtos:   []string{"h2"},
		}
	}

	// One listener whose Listener.Accept hands the freshly-built Config
	// directly to tls.Server; this simulates "fresh Config per accept".
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer rawLn.Close()

	const n = 2
	done := make(chan struct{}, n)
	go func() {
		for i := 0; i < n; i++ {
			conn, err := rawLn.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, freshConfig()) // <-- key: fresh Config
			if err := tlsConn.HandshakeContext(context.Background()); err != nil {
				tlsConn.Close()
				done <- struct{}{}
				continue
			}
			buf := make([]byte, 1)
			_, _ = tlsConn.Read(buf)
			tlsConn.Close()
			done <- struct{}{}
		}
	}()

	clientCfg := &tls.Config{
		ServerName:         host,
		RootCAs:            pool,
		NextProtos:         []string{"h2"},
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		MinVersion:         tls.VersionTLS12,
	}

	dialOnce := func(t *testing.T, label string) tls.ConnectionState {
		t.Helper()
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		raw, err := dialer.Dial("tcp", rawLn.Addr().String())
		if err != nil {
			t.Fatalf("%s dial: %v", label, err)
		}
		conn := tls.Client(raw, clientCfg)
		if err := conn.HandshakeContext(context.Background()); err != nil {
			t.Fatalf("%s handshake: %v", label, err)
		}
		_, _ = conn.Write([]byte{0})
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		state := conn.ConnectionState()
		conn.Close()
		return state
	}

	_ = dialOnce(t, "conn#1")
	state2 := dialOnce(t, "conn#2")

	// With fresh Configs per accept, conn#2 MUST NOT resume — because the
	// new Config has a different lazy session ticket key. If this ever
	// starts resuming, Go's crypto/tls behaviour has changed and the
	// USK-795 mitigation may need re-evaluating.
	if state2.DidResume {
		t.Fatalf("counterexample assertion failed: conn#2 resumed under fresh-Config-per-accept; "+
			"this contradicts the USK-795 root-cause hypothesis (Go version=0x%04x)", state2.Version)
	}

	for i := 0; i < n; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("server goroutine did not complete connection %d", i+1)
		}
	}
}

// TestMITMServerConfig_SessionResumption is the regression test for USK-795.
// It runs a real tls.Listener using the cert package's MITM cert path and
// connects twice from the SAME *crypto/tls client with a ClientSessionCache.
// On main HEAD 62cf2da this fails: the second connection reports
// DidResume=false because performClientMITM/buildRawPassthroughStack hand
// tlslayer.Server a fresh *tls.Config per call, so crypto/tls generates a
// random session ticket key per Config and connection #2's ticket cannot be
// decrypted. With MITMServerConfig caching, DidResume=true.
//
// This test runs Go-against-Go: it proves the ticket-key inconsistency is
// gone. Chrome-side certificate_unknown alert reproduction is deferred to
// manual verification on nghttp2.org per USK-795 PR description.
func TestMITMServerConfig_SessionResumption(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	// Build a CA pool the test client trusts.
	caCert, _ := ca.SigningPair()
	if caCert == nil {
		t.Fatal("CA SigningPair returned nil cert")
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Listener using the cached MITM Config.
	const host = "nghttp2.test"
	serverCfg := iss.MITMServerConfig(host, []string{"h2"})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Server goroutine: accept N connections and complete handshakes.
	const n = 2
	done := make(chan struct{}, n)
	go func() {
		for i := 0; i < n; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.HandshakeContext(context.Background()); err != nil {
				tlsConn.Close()
				done <- struct{}{}
				continue
			}
			// Drain anything written by the client so the server side
			// completes a normal session — this is when the server
			// sends its NewSessionTicket on TLS 1.3.
			buf := make([]byte, 1)
			_, _ = tlsConn.Read(buf)
			tlsConn.Close()
			done <- struct{}{}
		}
	}()

	clientCfg := &tls.Config{
		ServerName:         host,
		RootCAs:            pool,
		NextProtos:         []string{"h2"},
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		MinVersion:         tls.VersionTLS12,
	}

	dialAndProbe := func(t *testing.T, label string) tls.ConnectionState {
		t.Helper()
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		raw, err := dialer.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("%s dial: %v", label, err)
		}
		conn := tls.Client(raw, clientCfg)
		if err := conn.HandshakeContext(context.Background()); err != nil {
			t.Fatalf("%s handshake: %v", label, err)
		}
		// Write a byte to ensure the server-side Read returns and the
		// post-handshake NewSessionTicket flight has been consumed; without
		// at least one Read on the client, the ticket may not yet be in
		// the ClientSessionCache by the time we close.
		if _, err := conn.Write([]byte{0}); err != nil {
			t.Fatalf("%s write: %v", label, err)
		}
		// Trigger a Read so we process the server's post-handshake
		// records (including NewSessionTicket on TLS 1.3) before close.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		state := conn.ConnectionState()
		conn.Close()
		return state
	}

	state1 := dialAndProbe(t, "conn#1")
	if state1.DidResume {
		t.Fatalf("conn#1 unexpectedly resumed; want fresh handshake on first connection")
	}

	// Brief settle: the client must process the server's
	// NewSessionTicket frame for the resumption ticket to land in the
	// ClientSessionCache before conn#2 starts.
	state2 := dialAndProbe(t, "conn#2")

	// On TLS 1.3 (Go's default), DidResume=true is the success signal.
	// On TLS 1.2 fallback, the same signal applies via session tickets.
	if !state2.DidResume {
		t.Fatalf("conn#2 did not resume: DidResume=false (version=0x%04x). "+
			"This indicates the per-connection tls.Config is generating a "+
			"new session ticket encryption key (USK-795 regression).",
			state2.Version)
	}

	// Drain the server-side completions so the goroutine doesn't outlive
	// the test (with a generous timeout).
	for i := 0; i < n; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("server goroutine did not complete connection %d", i+1)
		}
	}
}
