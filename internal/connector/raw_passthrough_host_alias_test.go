package connector

import (
	"net/netip"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// USK-1385: raw_passthrough_hosts is matched against the TLS authority in
// the dial-equivalent form, so a respelled destination takes the raw route
// at every routing seam (CONNECT / SOCKS5 classifyTunnelRoute, transparent
// TLS) — and legacy IPv4 spellings still do not.

func rawPassthroughBuildConfig(entries ...string) *BuildConfig {
	return &BuildConfig{ProxyConfig: &config.ProxyConfig{RawPassthroughHosts: entries}}
}

// T5 (unit half): the CONNECT / SOCKS5 opaque-route wiring sees a
// respelled target as raw passthrough.
func TestTunnelRouteOpaque_RawPassthroughHostAliases(t *testing.T) {
	tests := []struct {
		entry, target string
	}{
		{"localhost:8443", "localhost.:8443"},
		{"localhost:8443", "LOCALHOST.:8443"},
		{"localhost:8443", "localhost:08443"},
		{"127.0.0.1:8443", "[::ffff:127.0.0.1]:8443"},
		{"[::1]:8443", "[0:0::1]:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			cfg := rawPassthroughBuildConfig(tc.entry)
			if !TunnelRouteOpaque(nil, cfg, tc.target) {
				t.Errorf("entry %q: TunnelRouteOpaque(%q) = false, want true (raw passthrough)", tc.entry, tc.target)
			}
			if r := classifyTunnelRoute(nil, cfg, SameUpstreamTarget(tc.target)); !r.rawPassthrough {
				t.Errorf("entry %q: classifyTunnelRoute(%q).rawPassthrough = false, want true", tc.entry, tc.target)
			}
		})
	}
}

// T6: a transparent TLS connection whose SNI carries a trailing dot
// selects the raw-passthrough stack for an entry written without it.
func TestTransparentUpstreamTarget_RawPassthroughTrailingDotSNI(t *testing.T) {
	cfg := rawPassthroughBuildConfig("a.example:443")
	ut := transparentUpstreamTarget(netip.MustParseAddrPort("10.0.0.5:443"), "a.example.")
	if !ut.isRawPassthrough(cfg) {
		t.Errorf("isRawPassthrough(TLS=%q) = false, want true (entry a.example:443)", ut.TLS)
	}
	if !classifyTunnelRoute(nil, cfg, ut).rawPassthrough {
		t.Errorf("classifyTunnelRoute(TLS=%q).rawPassthrough = false, want true", ut.TLS)
	}
	// The fold is comparison-only: the TLS authority keeps the SNI as sent.
	if ut.TLS != "a.example.:443" {
		t.Errorf("TLS authority = %q, want verbatim %q", ut.TLS, "a.example.:443")
	}
}

// T7: negative control at the routing seam — legacy IPv4 spellings of an
// entry's address are not raw-passthrough'd (allow-like list).
func TestTunnelRouteOpaque_RawPassthroughLegacyIPv4NotFolded(t *testing.T) {
	cfg := rawPassthroughBuildConfig("127.0.0.1:8443")
	for _, target := range []string{"127.1:8443", "2130706433:8443", "0x7f.0.0.1:8443", "127.0.0.1.:8443"} {
		if TunnelRouteOpaque(nil, cfg, target) {
			t.Errorf("TunnelRouteOpaque(%q) = true, want false (legacy IPv4 spelling is not dial-equivalent)", target)
		}
	}
}
