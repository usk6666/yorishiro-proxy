package connector

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// USK-1384: the startup-time HostTLSResolver compares host_tls patterns and
// targets in the dial-equivalent host form (hostcanon.FoldDialEquivalent),
// the same grammar as transport.HostTLSRegistry. Only the comparison key is
// folded: the dial target, the TLS ServerName and the recorded data stay as
// written.

// TestHostTLSResolver_Resolve_DialEquivalentSpellings covers both sides of
// the fold: a respelled target finds the entry, and a respelled pattern
// matches the canonical target. Targets are passed as host:port, the shape
// resolvePerHostTLS hands the resolver (UpstreamTarget.TLS), and as a bare
// host.
func TestHostTLSResolver_Resolve_DialEquivalentSpellings(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		target  string
	}{
		{"trailing dot target", "localhost", "localhost.:443"},
		{"upper case trailing dot target", "localhost", "LOCALHOST.:443"},
		{"IPv4-mapped IPv6 target", "127.0.0.1", "[::ffff:127.0.0.1]:443"},
		{"IPv4-mapped IPv6 hex target", "127.0.0.1", "[0:0::ffff:7f00:1]:443"},
		{"IPv4-mapped IPv6 with zone", "127.0.0.1", "[::ffff:127.0.0.1%lo]:443"},
		{"IPv4-mapped IPv6 bare", "127.0.0.1", "::ffff:127.0.0.1"},
		{"IPv6 non-canonical text", "::1", "[0:0::1]:443"},
		{"bracketed IPv6 bare", "::1", "[::1]"},
		{"wildcard trailing dot target", "*.example.com", "api.example.com.:443"},
		{"pattern case and trailing dot", "LocalHost.", "localhost:443"},
		{"bracketed IPv6 pattern", "[::1]", "[::1]:443"},
		{"IPv4-mapped IPv6 pattern", "::ffff:10.0.0.5", "10.0.0.5:443"},
		{"wildcard pattern case and trailing dot", "*.Example.COM.", "api.example.com:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verify := false
			r := NewHostTLSResolver(map[string]*config.HostTLSEntry{tt.pattern: {TLSVerify: &verify}})
			got, err := r.Resolve(tt.target)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tt.target, err)
			}
			if got == nil {
				t.Fatalf("Resolve(%q) with entry %q = nil, want the entry (dial-equivalent spelling)", tt.target, tt.pattern)
			}
		})
	}
}

// TestHostTLSResolver_Resolve_NonEquivalentSpellingsMiss is the negative
// control: legacy inet_aton IPv4 spellings, two trailing dots,
// IPv4-compatible IPv6 and wildcard depths outside the one-level grammar
// stay unmatched. A bracketed IPv4 authority "[127.0.0.1]:443" is not here:
// net.SplitHostPort strips the brackets and the dial reaches 127.0.0.1, so
// it matches the entry today and keeps doing so.
func TestHostTLSResolver_Resolve_NonEquivalentSpellingsMiss(t *testing.T) {
	verify := false
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"127.0.0.1":     {TLSVerify: &verify},
		"localhost":     {TLSVerify: &verify},
		"*.example.com": {TLSVerify: &verify},
	})
	for _, target := range []string{
		"127.1:443",
		"0x7f.0.0.1:443",
		"2130706433:443",
		"0177.0.0.1:443",
		"127.0.0.1.:443",
		"[127.0.0.1]",
		"[::127.0.0.1]:443",
		"localhost..:443",
		"a.b.example.com:443",
		"example.com:443",
	} {
		t.Run(target, func(t *testing.T) {
			got, err := r.Resolve(target)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", target, err)
			}
			if got != nil {
				t.Errorf("Resolve(%q) = %+v, want nil (not a dial-equivalent spelling of any entry)", target, got)
			}
		})
	}
}

// respelledLoopbackTLSHosts are TLS hosts that dial the loopback upstream
// but spell it differently from the "localhost" / "127.0.0.1" entries.
var respelledLoopbackTLSHosts = []string{"localhost.", "::ffff:127.0.0.1"}

// perHostTLSSource builds a BuildConfig that carries entries for localhost
// and 127.0.0.1 through either the startup-time resolver or the runtime
// registry.
type perHostTLSSource struct {
	name  string
	apply func(cfg *BuildConfig, verify bool)
}

var perHostTLSSources = []perHostTLSSource{
	{"resolver", func(cfg *BuildConfig, verify bool) {
		cfg.HostTLSResolver = NewHostTLSResolver(map[string]*config.HostTLSEntry{
			"localhost": {TLSVerify: &verify},
			"127.0.0.1": {TLSVerify: &verify},
		})
	}},
	{"registry", func(cfg *BuildConfig, verify bool) {
		reg := transport.NewHostTLSRegistry()
		reg.Set("localhost", &transport.HostTLSConfig{TLSVerify: &verify})
		reg.Set("127.0.0.1", &transport.HostTLSConfig{TLSVerify: &verify})
		cfg.HostTLSRegistry = reg
	}},
}

// TestBuildConnectionStack_PerHostTLSVerifyForRespelledHost_FailsClosed: the
// upstream cert is self-signed and verification is skipped globally, but the
// per-host entry enforces it (tls_verify: true). A respelled TLS host must
// get the entry, so the build fails verification instead of silently
// skipping it.
func TestBuildConnectionStack_PerHostTLSVerifyForRespelledHost_FailsClosed(t *testing.T) {
	for _, src := range perHostTLSSources {
		for _, host := range append([]string{"localhost"}, respelledLoopbackTLSHosts...) {
			t.Run(src.name+"/"+host, func(t *testing.T) {
				up := startSNIRecordingUpstream(t, []string{"http/1.1"})
				cfg := &BuildConfig{
					ProxyConfig:        &config.ProxyConfig{},
					Issuer:             newUpstreamTargetTestIssuer(t),
					InsecureSkipVerify: true,
				}
				src.apply(cfg, true)
				got := buildThroughClient(t, up.splitTarget(host), cfg, []string{"http/1.1"}, ClientHelloPeek{})
				if got.err == nil {
					t.Fatalf("BuildConnectionStack(TLS %s) succeeded; want an x509 verification error (the per-host tls_verify: true must apply)", host)
				}
				var verr *tls.CertificateVerificationError
				if !errors.As(got.err, &verr) {
					t.Fatalf("BuildConnectionStack(TLS %s): %v (%T); want a *tls.CertificateVerificationError (the per-host tls_verify: true must apply)", host, got.err, got.err)
				}
			})
		}
	}
}

// TestBuildConnectionStack_PerHostTLSSkipForRespelledHost_KeepsTargetVerbatim:
// verification is enforced globally and a per-host entry disables it, so a
// respelled TLS host builds only if it gets the entry. The fold is
// comparison-only: the stack's UpstreamTarget and the layers' TargetHost
// stay exactly as written.
func TestBuildConnectionStack_PerHostTLSSkipForRespelledHost_KeepsTargetVerbatim(t *testing.T) {
	for _, src := range perHostTLSSources {
		for _, host := range respelledLoopbackTLSHosts {
			t.Run(src.name+"/"+host, func(t *testing.T) {
				up := startSNIRecordingUpstream(t, []string{"http/1.1"})
				cfg := &BuildConfig{
					ProxyConfig: &config.ProxyConfig{},
					Issuer:      newUpstreamTargetTestIssuer(t),
				}
				src.apply(cfg, false)
				ut := up.splitTarget(host)
				got := buildThroughClient(t, ut, cfg, []string{"http/1.1"}, ClientHelloPeek{})
				if got.err != nil {
					t.Fatalf("BuildConnectionStack(TLS %s): %v (the per-host tls_verify: false must apply)", host, got.err)
				}
				if gotUT, ok := got.stack.UpstreamTarget(); !ok || gotUT != ut {
					t.Errorf("stack UpstreamTarget = %+v (ok=%v), want %+v verbatim", gotUT, ok, ut)
				}
				if want := net.JoinHostPort(host, up.port()); ut.TLS != want {
					t.Fatalf("test setup: TLS authority %q, want %q", ut.TLS, want)
				}
				for side, l := range map[string]any{"client": got.stack.ClientTopmost(), "upstream": got.stack.UpstreamTopmost()} {
					h1, ok := l.(*http1.Layer)
					if !ok {
						t.Fatalf("%s topmost = %T, want *http1.Layer", side, l)
					}
					if th := h1.EnvelopeContextTemplate().TargetHost; th != up.dial() {
						t.Errorf("%s TargetHost = %q, want the dial target %q verbatim", side, th, up.dial())
					}
				}
			})
		}
	}
}
