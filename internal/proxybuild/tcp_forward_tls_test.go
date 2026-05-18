package proxybuild

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// parseLeafCert parses the leaf x509 certificate from a *tls.Certificate.
// cert.Issuer.generate populates Certificate[0] but leaves Leaf nil; we
// parse on demand here so the test can inspect DNSNames / IPAddresses /
// SerialNumber. Returns nil + a fail t.Fatal when parsing fails.
func parseLeafCert(t *testing.T, tc *tls.Certificate) *x509.Certificate {
	t.Helper()
	if tc == nil || len(tc.Certificate) == 0 {
		t.Fatal("nil cert or empty Certificate slice")
	}
	parsed, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return parsed
}

// TestAlpnOffersForForwardProtocol pins the operator-declared ALPN advertise
// list for every supported ForwardConfig.Protocol value. The mapping is
// observable by clients (the wire ALPN extension reflects the offered list
// verbatim) and by the post-handshake dispatch arm — any drift here surfaces
// as a wire-visible regression or as a misrouted forward dispatch.
func TestAlpnOffersForForwardProtocol(t *testing.T) {
	cases := []struct {
		protocol string
		want     []string
	}{
		{"", []string{"h2", "http/1.1"}},
		{"auto", []string{"h2", "http/1.1"}},
		{"http", []string{"http/1.1"}},
		{"websocket", []string{"http/1.1"}},
		{"sse", []string{"http/1.1"}},
		{"http2", []string{"h2"}},
		{"grpc", []string{"h2"}},
		{"raw", nil},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			got := alpnOffersForForwardProtocol(tc.protocol)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("alpnOffersForForwardProtocol(%q) = %v, want %v", tc.protocol, got, tc.want)
			}
		})
	}
}

// TestAlpnOffersForForwardProtocol_UnknownReturnsNil documents the defensive
// fallback for values that somehow reach this helper without going through
// config.ValidateForwardConfig. nil keeps the handshake working (no ALPN
// extension on the wire) while downstream dispatch will route the result
// based on the negotiated ALPN (which will be empty → http/1.1 fallback).
func TestAlpnOffersForForwardProtocol_UnknownReturnsNil(t *testing.T) {
	if got := alpnOffersForForwardProtocol("invalid-zzz"); got != nil {
		t.Errorf("alpnOffersForForwardProtocol(invalid) = %v, want nil", got)
	}
}

// TestMitmServerConfigForForward_HonorsWireSNI verifies the GetCertificate
// callback issues a cert for the wire-observed SNI when one is present
// (USK-915 Decision U1).
func TestMitmServerConfigForForward_HonorsWireSNI(t *testing.T) {
	issuer := newTestIssuer(t)

	cfg := mitmServerConfigForForward(issuer, "fallback.example.test", []string{"h2", "http/1.1"})
	if cfg == nil {
		t.Fatal("mitmServerConfigForForward returned nil cfg")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(cfg.NextProtos, want) {
		t.Errorf("NextProtos = %v, want %v", cfg.NextProtos, want)
	}

	hello := &tls.ClientHelloInfo{ServerName: "wire-observed.example.test"}
	got, err := cfg.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	leaf := parseLeafCert(t, got)
	// The issued cert must include the wire SNI in its DNS SAN list.
	var hasSNI bool
	for _, name := range leaf.DNSNames {
		if name == "wire-observed.example.test" {
			hasSNI = true
			break
		}
	}
	if !hasSNI {
		t.Errorf("cert DNSNames = %v, want to include wire SNI %q", leaf.DNSNames, "wire-observed.example.test")
	}
}

// TestMitmServerConfigForForward_FallsBackToTarget verifies that when the
// ClientHello carries no SNI the GetCertificate callback issues a cert for
// the operator-declared Target hostname instead. Clients connecting by IP
// literal (Chromium does this for raw-IP URIs) still receive a usable cert
// even though the cert's CN/SAN cannot match the literal IP.
func TestMitmServerConfigForForward_FallsBackToTarget(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := mitmServerConfigForForward(issuer, "fallback.example.test", []string{"http/1.1"})

	hello := &tls.ClientHelloInfo{ServerName: ""}
	got, err := cfg.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate (no SNI) returned error: %v", err)
	}
	leaf := parseLeafCert(t, got)
	var hasFallback bool
	for _, name := range leaf.DNSNames {
		if name == "fallback.example.test" {
			hasFallback = true
			break
		}
	}
	if !hasFallback {
		t.Errorf("cert DNSNames = %v, want to include fallback target %q", leaf.DNSNames, "fallback.example.test")
	}
}

// TestMitmServerConfigForForward_SNILowercased verifies that mixed-case SNI
// values normalise to a single cert cache entry. This matches
// cert.Issuer.MITMServerConfig behaviour (which lowercases internally).
func TestMitmServerConfigForForward_SNILowercased(t *testing.T) {
	issuer := newTestIssuer(t)
	cfg := mitmServerConfigForForward(issuer, "fallback.example.test", nil)

	mixedHello := &tls.ClientHelloInfo{ServerName: "MIXED.Example.TEST"}
	mixedCert, err := cfg.GetCertificate(mixedHello)
	if err != nil {
		t.Fatalf("GetCertificate (mixed-case SNI) returned error: %v", err)
	}
	lowerHello := &tls.ClientHelloInfo{ServerName: "mixed.example.test"}
	lowerCert, err := cfg.GetCertificate(lowerHello)
	if err != nil {
		t.Fatalf("GetCertificate (lowercase SNI) returned error: %v", err)
	}
	// The mixed-case lookup must return the same underlying cert as the
	// lowercase lookup — proves the normalisation reaches the Issuer cache
	// key. The Issuer hands back the same *tls.Certificate pointer for
	// repeat lookups on the same hostname (its LRU caches the value), so
	// pointer equality is the strongest test.
	if mixedCert != lowerCert {
		t.Errorf("mixed-case SNI returned %p; lowercase returned %p; LRU cache key normalisation broken (issuer should return identical *tls.Certificate)", mixedCert, lowerCert)
	}
}

// TestMitmServerConfigForForward_NextProtosCopied verifies the
// defensive-copy contract: mutating the alpnOffers slice after the call
// must not perturb the cached *tls.Config.NextProtos. tls.Config retains
// the reference, so any drift here would corrupt the live handshake's
// observed list.
func TestMitmServerConfigForForward_NextProtosCopied(t *testing.T) {
	issuer := newTestIssuer(t)
	offers := []string{"h2", "http/1.1"}
	cfg := mitmServerConfigForForward(issuer, "fallback.example.test", offers)

	offers[0] = "MUTATED"
	if cfg.NextProtos[0] != "h2" {
		t.Errorf("NextProtos[0] = %q, want %q (defensive copy expected)", cfg.NextProtos[0], "h2")
	}
}

// TestTargetHostOnly_StripsPort confirms the host:port → host derivation
// used by the forward TLS handler when building the SNI fallback.
func TestTargetHostOnly_StripsPort(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com:443", "example.com"},
		{"127.0.0.1:8443", "127.0.0.1"},
		{"[::1]:443", "::1"},
		{"no-port", "no-port"}, // falls back verbatim
		{"", ""},
	}
	for _, tc := range cases {
		got := targetHostOnly(tc.in)
		if got != tc.want {
			t.Errorf("targetHostOnly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// newTestIssuer constructs a freshly-generated CA + Issuer suitable for
// the per-test handshake assertions. Centralised so the test surface
// reads as a single setup line per case.
func newTestIssuer(t *testing.T) *cert.Issuer {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	return cert.NewIssuer(ca)
}

// TestStartTCPForwardListener_TLSWithoutIssuer_Rejected pins the
// defensive listener-start guard introduced by USK-915: declaring tls=true
// when the Manager has no CA Issuer configured must fail fast with a clear
// error rather than silently accepting connections and failing per-handshake.
//
// This is the operator-visible failure path; the per-connection handler
// additionally fails-soft (see handleTCPForwardTLSConn) for the CA regen
// race window between listener start and the first accept.
func TestStartTCPForwardListener_TLSWithoutIssuer_Rejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Construct a Manager with NO BuildConfig (so m.buildCfg.Issuer is
	// nil). This is the misconfiguration the guard exists for.
	mgr, err := NewManager(ManagerConfig{
		Logger: silentLogger(),
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	startErr := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "http", TLS: true},
		},
	})
	if startErr == nil {
		t.Fatal("expected error from StartTCPForwards with tls=true and nil Issuer, got nil")
	}
	if !strings.Contains(startErr.Error(), "tls=true requires a configured CA Issuer") {
		t.Errorf("error %q does not surface the CA-missing reason; got %v", startErr.Error(), startErr)
	}
}

// TestStartTCPForwardListener_TLSWithIssuer_BuildsTLSCfg pins the
// happy-path setup: when tls=true and the Manager has an Issuer wired,
// the per-entry *tls.Config is built once at listener start so crypto/tls's
// lazy session-ticket key persists across every accepted conn. Without
// this caching, every handshake would rotate the ticket key — invalidating
// browser-held tickets and forcing full handshakes.
func TestStartTCPForwardListener_TLSWithIssuer_BuildsTLSCfg(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	mgr, err := NewManager(ManagerConfig{
		Logger:      silentLogger(),
		BuildConfig: buildCfg,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			d.BuildConfig = buildCfg
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	if err := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "http", TLS: true},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	// The forward entry is private; we can still observe success by the
	// absence of an error and the fact that StopAll exits cleanly. The
	// per-entry tls.Config is exercised end-to-end by the e2e tier.
}

// TestConfigureForwardTLS_NilIssuer pins the configureForwardTLS error path
// independently of the manager-level guard so the function is a stand-alone
// safe building block.
func TestConfigureForwardTLS_NilIssuer(t *testing.T) {
	entry := &tcpForwardEntry{port: "0", target: "127.0.0.1:1"}
	fc := &config.ForwardConfig{Target: "127.0.0.1:1", Protocol: "http", TLS: true}
	if err := configureForwardTLS(entry, fc, nil); err == nil {
		t.Fatal("configureForwardTLS(nil issuer) = nil, want error")
	}
	if entry.tlsServerCfg != nil {
		t.Errorf("entry.tlsServerCfg = %v, want nil after error", entry.tlsServerCfg)
	}
}

// TestConfigureForwardTLS_Happy verifies the happy-path output: a non-nil
// *tls.Config with the expected NextProtos derived from fc.Protocol, cached
// on the entry for reuse across handshakes.
func TestConfigureForwardTLS_Happy(t *testing.T) {
	entry := &tcpForwardEntry{port: "0", target: "127.0.0.1:1"}
	fc := &config.ForwardConfig{Target: "127.0.0.1:1", Protocol: "http2", TLS: true}
	issuer := newTestIssuer(t)
	if err := configureForwardTLS(entry, fc, issuer); err != nil {
		t.Fatalf("configureForwardTLS: %v", err)
	}
	if entry.tlsServerCfg == nil {
		t.Fatal("entry.tlsServerCfg is nil")
	}
	if got, want := entry.tlsServerCfg.NextProtos, []string{"h2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("NextProtos = %v, want %v (http2 → h2 only)", got, want)
	}
}

// TestUpstreamALPNOffersForForward pins the USK-916 ALPN propagation
// policy. Three branches:
//
//  1. Explicit Protocol → derive from declaration (delegates to
//     alpnOffersForForwardProtocol).
//  2. "auto" + client TLS terminated + client negotiated ALPN →
//     propagate the client's choice as a single-element list.
//  3. "auto" + plaintext client (or no client ALPN) → safe default
//     ["http/1.1"] only (NOT ["h2","http/1.1"] — see helper godoc /
//     Decision #5).
func TestUpstreamALPNOffersForForward(t *testing.T) {
	clientH2 := &forwardConnOverride{
		tlsTerminated:     true,
		clientTLSSnapshot: &envelope.TLSSnapshot{ALPN: "h2"},
	}
	clientH1 := &forwardConnOverride{
		tlsTerminated:     true,
		clientTLSSnapshot: &envelope.TLSSnapshot{ALPN: "http/1.1"},
	}
	clientTLSNoALPN := &forwardConnOverride{
		tlsTerminated:     true,
		clientTLSSnapshot: &envelope.TLSSnapshot{ALPN: ""},
	}
	plainClient := (*forwardConnOverride)(nil)

	cases := []struct {
		name     string
		protocol string
		override *forwardConnOverride
		want     []string
	}{
		// Branch 1: explicit protocol → delegated to
		// alpnOffersForForwardProtocol, independent of override.
		{"http_explicit_plain", "http", plainClient, []string{"http/1.1"}},
		{"http_explicit_clientH2", "http", clientH2, []string{"http/1.1"}},
		{"http2_explicit_plain", "http2", plainClient, []string{"h2"}},
		{"http2_explicit_clientH1", "http2", clientH1, []string{"h2"}},
		{"grpc_explicit", "grpc", plainClient, []string{"h2"}},
		{"websocket_explicit", "websocket", plainClient, []string{"http/1.1"}},
		{"sse_explicit", "sse", plainClient, []string{"http/1.1"}},
		{"raw_explicit", "raw", plainClient, nil},
		// Branch 2: auto + client TLS terminated + client ALPN known →
		// propagate single-element list.
		{"auto_clientH2", "auto", clientH2, []string{"h2"}},
		{"auto_clientH1", "auto", clientH1, []string{"http/1.1"}},
		{"empty_clientH2", "", clientH2, []string{"h2"}},
		// Branch 3: auto + plaintext client (or TLS client with no
		// negotiated ALPN) → safe default http/1.1.
		{"auto_plaintext", "auto", plainClient, []string{"http/1.1"}},
		{"empty_plaintext", "", plainClient, []string{"http/1.1"}},
		{"auto_clientTLSNoALPN", "auto", clientTLSNoALPN, []string{"http/1.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := upstreamALPNOffersForForward(tc.protocol, tc.override)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("upstreamALPNOffersForForward(%q, %v) = %v, want %v",
					tc.protocol, tc.override, got, tc.want)
			}
		})
	}
}

// TestUpstreamALPNOffersForForward_AutoOverrideNilSnapshot covers the
// override-non-nil-but-snapshot-nil edge case so the helper does not panic
// when a malformed override reaches it.
func TestUpstreamALPNOffersForForward_AutoOverrideNilSnapshot(t *testing.T) {
	override := &forwardConnOverride{tlsTerminated: true, clientTLSSnapshot: nil}
	if got, want := upstreamALPNOffersForForward("auto", override), []string{"http/1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("upstreamALPNOffersForForward(auto, nil-snapshot) = %v, want %v", got, want)
	}
}

// TestResolveUpstreamInsecureSkipVerify pins the USK-918 tri-state
// precedence: per-entry *bool override > global BuildConfig flag > false.
// Verifies the eight cross-product cases of (per-entry value × global flag).
func TestResolveUpstreamInsecureSkipVerify(t *testing.T) {
	skip := true
	enforce := false
	makeStack := func(globalSkip bool) *Stack {
		return &Stack{BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			InsecureSkipVerify: globalSkip,
		}}
	}
	cases := []struct {
		name        string
		fc          *config.ForwardConfig
		parentStack *Stack
		want        bool
	}{
		{
			// Per-entry &true overrides global=false (the moul/grpcbin
			// motivating case for USK-918).
			name:        "per-entry true overrides global false → true (skip)",
			fc:          &config.ForwardConfig{UpstreamInsecureSkipVerify: &skip},
			parentStack: makeStack(false),
			want:        true,
		},
		{
			// Per-entry &false overrides global=true (operator forces
			// enforce for one entry while leaving the global insecure).
			name:        "per-entry false overrides global true → false (enforce)",
			fc:          &config.ForwardConfig{UpstreamInsecureSkipVerify: &enforce},
			parentStack: makeStack(true),
			want:        false,
		},
		{
			// Per-entry &true matches global=true (idempotent).
			name:        "per-entry true with global true → true",
			fc:          &config.ForwardConfig{UpstreamInsecureSkipVerify: &skip},
			parentStack: makeStack(true),
			want:        true,
		},
		{
			// Per-entry &false matches global=false (idempotent).
			name:        "per-entry false with global false → false",
			fc:          &config.ForwardConfig{UpstreamInsecureSkipVerify: &enforce},
			parentStack: makeStack(false),
			want:        false,
		},
		{
			// nil per-entry inherits global=true.
			name:        "nil per-entry inherits global true → true",
			fc:          &config.ForwardConfig{},
			parentStack: makeStack(true),
			want:        true,
		},
		{
			// nil per-entry inherits global=false.
			name:        "nil per-entry inherits global false → false",
			fc:          &config.ForwardConfig{},
			parentStack: makeStack(false),
			want:        false,
		},
		{
			// nil fc + nil parentStack → defensive default false.
			name: "nil fc + nil parentStack → false",
			want: false,
		},
		{
			// non-nil fc with nil ptr + nil parentStack → false.
			name: "nil per-entry + nil parentStack → false",
			fc:   &config.ForwardConfig{},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveUpstreamInsecureSkipVerify(tc.fc, tc.parentStack)
			if got != tc.want {
				t.Errorf("resolveUpstreamInsecureSkipVerify(fc=%+v, parent=%v) = %v, want %v",
					tc.fc, tc.parentStack != nil, got, tc.want)
			}
		})
	}
}
