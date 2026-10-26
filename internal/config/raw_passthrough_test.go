package config

import "testing"

func TestProxyConfig_IsRawPassthrough(t *testing.T) {
	cfg := &ProxyConfig{
		RawPassthroughHosts: []string{
			"target.example.com:443",
			"OTHER.EXAMPLE.COM:8443",
		},
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"target.example.com:443", true},
		{"TARGET.EXAMPLE.COM:443", true},   // case-insensitive
		{"other.example.com:8443", true},   // stored uppercase, queried lowercase
		{"target.example.com:8080", false}, // different port
		{"unknown.com:443", false},
		{"", false},
		{"  target.example.com:443  ", true}, // trimmed
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			got := cfg.IsRawPassthrough(tt.target)
			if got != tt.want {
				t.Errorf("IsRawPassthrough(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestProxyConfig_IsRawPassthrough_Empty(t *testing.T) {
	cfg := &ProxyConfig{}
	if cfg.IsRawPassthrough("anything:443") {
		t.Error("expected false for empty RawPassthroughHosts")
	}
}

// USK-1385: raw_passthrough_hosts compares host:port in the dial-equivalent
// form (hostcanon.FoldDialEquivalent), on both the entry and the target
// side, so a spelling verified to dial the same destination is relayed raw
// whichever way the client wrote it. The port is compared as an integer.
func TestProxyConfig_IsRawPassthrough_DialEquivalentSpellings(t *testing.T) {
	tests := []struct {
		entry, target string
	}{
		{"localhost:443", "localhost.:443"},
		{"localhost:443", "LOCALHOST.:443"},
		{"localhost.:443", "localhost:443"},
		{"127.0.0.1:443", "[::ffff:127.0.0.1]:443"},
		{"127.0.0.1:443", "[::ffff:7f00:1]:443"},
		{"[::ffff:127.0.0.1]:443", "127.0.0.1:443"},
		{"[::ffff:10.0.0.5]:443", "10.0.0.5:443"},
		// net.SplitHostPort strips the brackets of an authority exactly as
		// the dialer does, so "[127.0.0.1]:443" dials 127.0.0.1:443.
		{"127.0.0.1:443", "[127.0.0.1]:443"},
		{"[::1]:443", "[0:0::1]:443"},
		{"[::1]:443", "[::1%lo]:443"},
		{"[0:0::1]:443", "[::1]:443"},
		{"a.example:443", "a.example:0443"},
		{"a.example:0443", "a.example:443"},
		{"A.Example.:443", "a.example:443"},
		{" localhost:443 ", "  localhost.:443  "},
	}
	for _, tc := range tests {
		t.Run(tc.entry+"_vs_"+tc.target, func(t *testing.T) {
			cfg := &ProxyConfig{RawPassthroughHosts: []string{tc.entry}}
			if !cfg.IsRawPassthrough(tc.target) {
				t.Errorf("entry %q: IsRawPassthrough(%q) = false, want true (dials the same destination)", tc.entry, tc.target)
			}
		})
	}
}

// USK-1385 negative control: raw passthrough is allow-like (no Safety /
// Intercept / Transform on the raw route), so spellings that are not
// verified to dial the entry's destination must not match — in particular
// legacy inet_aton IPv4 spellings, which Go's pure resolver rejects or
// sends to DNS.
func TestProxyConfig_IsRawPassthrough_NonEquivalentSpellingsDoNotMatch(t *testing.T) {
	tests := []struct {
		entry, target string
	}{
		{"127.0.0.1:443", "127.1:443"},
		{"127.0.0.1:443", "2130706433:443"},
		{"127.0.0.1:443", "0x7f.0.0.1:443"},
		{"127.0.0.1:443", "0177.0.0.1:443"},
		{"127.0.0.1:443", "127.0.0.01:443"},
		{"127.0.0.1:443", "127.0.0.1.:443"},
		{"0x7f.0.0.1:443", "127.0.0.1:443"},
		{"2130706433:443", "127.0.0.1:443"},
		{"localhost:443", "localhost..:443"},
		{"127.0.0.1:443", "[::127.0.0.1]:443"},
		{"127.0.0.1:443", "127.0.0.1:8443"},
		{"localhost:443", "127.0.0.1:443"},
		{"a.example:443", "a.example:+443"},
		{"a.example:443", "a.example:https"},
	}
	for _, tc := range tests {
		t.Run(tc.entry+"_vs_"+tc.target, func(t *testing.T) {
			cfg := &ProxyConfig{RawPassthroughHosts: []string{tc.entry}}
			if cfg.IsRawPassthrough(tc.target) {
				t.Errorf("entry %q: IsRawPassthrough(%q) = true, want false (not a verified same-destination spelling)", tc.entry, tc.target)
			}
		})
	}
}

// USK-1385 (Principle 5): malformed authorities never panic and never
// match a well-formed entry. An unparsable entry still matches its own
// literal spelling, as before.
func TestProxyConfig_IsRawPassthrough_MalformedAuthorities(t *testing.T) {
	malformed := []string{
		"[", "]", "[]", "[]:443", ":443", "[::1", "a:b:c", "host:99999999999",
		"host:0", "host:65536", "host:", "host:+443", "host:https", "", " ", "\x00",
		"[::1]]:443", "[[::1]]:443", "host:-1", "host:443\x00",
	}
	cfg := &ProxyConfig{RawPassthroughHosts: []string{
		"host:443", "127.0.0.1:443", "[::1]:443", "localhost:443",
	}}
	for _, in := range malformed {
		if cfg.IsRawPassthrough(in) {
			t.Errorf("IsRawPassthrough(%q) = true, want false (malformed authority)", in)
		}
	}
	// Malformed entries do not panic either, and a literal match still works.
	odd := &ProxyConfig{RawPassthroughHosts: append([]string{"Opaque-Entry"}, malformed...)}
	for _, in := range malformed {
		_ = odd.IsRawPassthrough(in)
	}
	if !odd.IsRawPassthrough("opaque-entry") {
		t.Error(`IsRawPassthrough("opaque-entry") = false, want true (unparsable entry keeps literal case-insensitive match)`)
	}
}
