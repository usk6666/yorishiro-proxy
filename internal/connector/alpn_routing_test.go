package connector

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestAlpnRoute_HTTP11(t *testing.T) {
	route, err := alpnRoute("http/1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route != "http1" {
		t.Errorf("route = %q, want %q", route, "http1")
	}
}

func TestAlpnRoute_Empty(t *testing.T) {
	route, err := alpnRoute("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route != "http1" {
		t.Errorf("route = %q, want %q for empty ALPN", route, "http1")
	}
}

func TestAlpnRoute_H2(t *testing.T) {
	route, err := alpnRoute("h2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route != "h2" {
		t.Errorf("route = %q, want %q", route, "h2")
	}
}

func TestAlpnRoute_Unknown(t *testing.T) {
	route, err := alpnRoute("spdy/3.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if route != "bytechunk" {
		t.Errorf("route = %q, want %q for unknown ALPN", route, "bytechunk")
	}
}

func TestALPNCacheKeyFromConfig_NoClientCert(t *testing.T) {
	cfg := &BuildConfig{
		TLSFingerprint: "chrome",
	}
	key := ALPNCacheKeyFromConfig("example.com:443", cfg)
	if key.HostPort != "example.com:443" {
		t.Errorf("HostPort = %q, want %q", key.HostPort, "example.com:443")
	}
	if key.Fingerprint != "chrome" {
		t.Errorf("Fingerprint = %q, want %q", key.Fingerprint, "chrome")
	}
	if key.ClientCertHash != "" {
		t.Errorf("ClientCertHash = %q, want empty", key.ClientCertHash)
	}
}

func TestALPNCacheKeyFromConfig_WithClientCert(t *testing.T) {
	// Use a minimal cert with at least one DER-encoded certificate
	cfg := &BuildConfig{
		TLSFingerprint: "firefox",
		ClientCert: &tls.Certificate{
			Certificate: [][]byte{{0x30, 0x82, 0x01, 0x00}},
		},
	}
	key := ALPNCacheKeyFromConfig("api.example.com:443", cfg)
	if key.ClientCertHash == "" {
		t.Error("expected non-empty ClientCertHash when cert is present")
	}
}

func TestALPNCacheKeyFromConfig_StableHash(t *testing.T) {
	cert := &tls.Certificate{
		Certificate: [][]byte{{0x30, 0x82, 0x01, 0x00}},
	}
	cfg := &BuildConfig{ClientCert: cert}

	key1 := ALPNCacheKeyFromConfig("host:443", cfg)
	key2 := ALPNCacheKeyFromConfig("host:443", cfg)

	if key1.ClientCertHash != key2.ClientCertHash {
		t.Error("expected stable hash for same cert")
	}
}

func TestHashCert_Nil(t *testing.T) {
	if h := hashCert(nil); h != "" {
		t.Errorf("hashCert(nil) = %q, want empty", h)
	}
}

func TestHashCert_EmptyCertList(t *testing.T) {
	cert := &tls.Certificate{}
	if h := hashCert(cert); h != "" {
		t.Errorf("hashCert(empty) = %q, want empty", h)
	}
}

// TestClientALPNOffersForUpstream_LegacyBehavior verifies the function's
// pre-USK-808 behaviour is unchanged when no enabled-protocols filter is
// supplied (nil or empty).
func TestClientALPNOffersForUpstream_LegacyBehavior(t *testing.T) {
	tests := []struct {
		name        string
		upstream    string
		enabled     []string
		wantOffers  []string
		description string
	}{
		{
			name:       "h2 upstream, nil filter",
			upstream:   ALPNProtocolH2,
			enabled:    nil,
			wantOffers: []string{ALPNProtocolH2, ALPNProtocolHTTP11},
		},
		{
			name:       "h2 upstream, empty filter",
			upstream:   ALPNProtocolH2,
			enabled:    []string{},
			wantOffers: []string{ALPNProtocolH2, ALPNProtocolHTTP11},
		},
		{
			name:       "http/1.1 upstream, nil filter",
			upstream:   ALPNProtocolHTTP11,
			enabled:    nil,
			wantOffers: []string{ALPNProtocolHTTP11},
		},
		{
			name:       "empty upstream ALPN, nil filter",
			upstream:   "",
			enabled:    nil,
			wantOffers: []string{ALPNProtocolHTTP11},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientALPNOffersForUpstream(tt.upstream, tt.enabled)
			if !reflect.DeepEqual(got, tt.wantOffers) {
				t.Errorf("clientALPNOffersForUpstream(%q, %v) = %v, want %v",
					tt.upstream, tt.enabled, got, tt.wantOffers)
			}
		})
	}
}

// TestClientALPNOffersForUpstream_FilteredByEnabledProtocols verifies the
// USK-808 behaviour: the returned ALPN offers respect the operator's
// enabled-protocols allow-list.
func TestClientALPNOffersForUpstream_FilteredByEnabledProtocols(t *testing.T) {
	tests := []struct {
		name       string
		upstream   string
		enabled    []string
		wantOffers []string
	}{
		{
			name:       "h2 upstream, only HTTP/1.x+HTTPS enabled drops h2",
			upstream:   ALPNProtocolH2,
			enabled:    []string{"HTTP/1.x", "HTTPS"},
			wantOffers: []string{ALPNProtocolHTTP11},
		},
		{
			name:       "h2 upstream, HTTP/2+HTTPS enabled keeps h2 only (no inner h1)",
			upstream:   ALPNProtocolH2,
			enabled:    []string{"HTTP/2", "HTTPS"},
			wantOffers: []string{ALPNProtocolH2},
		},
		{
			name:       "h2 upstream, HTTP/1.x+HTTP/2+HTTPS enabled keeps both",
			upstream:   ALPNProtocolH2,
			enabled:    []string{"HTTP/1.x", "HTTPS", "HTTP/2"},
			wantOffers: []string{ALPNProtocolH2, ALPNProtocolHTTP11},
		},
		{
			name:       "h2 upstream, only HTTPS enabled falls back to http/1.1",
			upstream:   ALPNProtocolH2,
			enabled:    []string{"HTTPS"},
			wantOffers: []string{ALPNProtocolHTTP11},
		},
		{
			name:       "h2 upstream, gRPC enables h2",
			upstream:   ALPNProtocolH2,
			enabled:    []string{"gRPC", "HTTPS"},
			wantOffers: []string{ALPNProtocolH2},
		},
		{
			name:       "h2 upstream, WebSocket enables http/1.1",
			upstream:   ALPNProtocolH2,
			enabled:    []string{"WebSocket", "HTTPS"},
			wantOffers: []string{ALPNProtocolHTTP11},
		},
		{
			name:       "http/1.1 upstream, only HTTP/2 enabled falls back to http/1.1",
			upstream:   ALPNProtocolHTTP11,
			enabled:    []string{"HTTP/2", "HTTPS"},
			wantOffers: []string{ALPNProtocolHTTP11},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientALPNOffersForUpstream(tt.upstream, tt.enabled)
			if !reflect.DeepEqual(got, tt.wantOffers) {
				t.Errorf("got %v, want %v", got, tt.wantOffers)
			}
		})
	}
}

// TestAlpnOffersAllowedByEnabledProtocols_OrderPreserved verifies the
// helper preserves the order of `base` (crypto/tls picks the first
// NextProtos entry that the client offered, so the upstream-preferred
// order from clientALPNOffersForUpstream must survive the filter).
func TestAlpnOffersAllowedByEnabledProtocols_OrderPreserved(t *testing.T) {
	base := []string{ALPNProtocolH2, ALPNProtocolHTTP11}
	enabled := []string{"HTTP/1.x", "HTTP/2"}
	got := alpnOffersAllowedByEnabledProtocols(base, enabled)
	want := []string{ALPNProtocolH2, ALPNProtocolHTTP11}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (order should follow base, not enabled)", got, want)
	}

	// Reversing `base` reverses the result.
	baseRev := []string{ALPNProtocolHTTP11, ALPNProtocolH2}
	got = alpnOffersAllowedByEnabledProtocols(baseRev, enabled)
	want = []string{ALPNProtocolHTTP11, ALPNProtocolH2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (order should follow base, not enabled)", got, want)
	}
}

// TestAlpnOffersAllowedByEnabledProtocols_UnknownPassthrough verifies
// the helper passes through ALPN ids it doesn't know how to gate
// (forward-compatibility — the filter constrains only h2/http1).
func TestAlpnOffersAllowedByEnabledProtocols_UnknownPassthrough(t *testing.T) {
	base := []string{ALPNProtocolH2, "spdy/3.1", ALPNProtocolHTTP11}
	enabled := []string{"HTTP/1.x", "HTTP/2"}
	got := alpnOffersAllowedByEnabledProtocols(base, enabled)
	want := []string{ALPNProtocolH2, "spdy/3.1", ALPNProtocolHTTP11}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (unknown ALPN ids must be passed through)", got, want)
	}
}

// TestAlpnOffersAllowedByEnabledProtocols_HTTPSAlone verifies the
// HTTPS-only fallback rule (USK-808 design decision #7): leaving
// NextProtos empty on a TLS 1.3 server can trigger
// no_application_protocol alerts on strict clients, so when the filter
// would empty the list we return ["http/1.1"] as the conservative
// HTTPS-with-HTTP/1.1 default.
func TestAlpnOffersAllowedByEnabledProtocols_HTTPSAlone(t *testing.T) {
	base := []string{ALPNProtocolH2, ALPNProtocolHTTP11}
	enabled := []string{"HTTPS"}
	got := alpnOffersAllowedByEnabledProtocols(base, enabled)
	want := []string{ALPNProtocolHTTP11}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (HTTPS-only must fall back to http/1.1)", got, want)
	}
}

// TestBuildConfig_EnabledProtocols_Roundtrip verifies the
// Set/EffectiveEnabledProtocols pair on BuildConfig. nil/empty inputs
// produce the legacy "all-allowed" identity (nil out); non-empty
// inputs round-trip with a defensive copy.
func TestBuildConfig_EnabledProtocols_Roundtrip(t *testing.T) {
	cfg := &BuildConfig{}
	if got := cfg.EffectiveEnabledProtocols(); got != nil {
		t.Errorf("default EffectiveEnabledProtocols = %v, want nil", got)
	}

	cfg.SetEnabledProtocols(nil)
	if got := cfg.EffectiveEnabledProtocols(); got != nil {
		t.Errorf("after SetEnabledProtocols(nil): %v, want nil", got)
	}

	cfg.SetEnabledProtocols([]string{})
	if got := cfg.EffectiveEnabledProtocols(); got != nil {
		t.Errorf("after SetEnabledProtocols(empty): %v, want nil", got)
	}

	cfg.SetEnabledProtocols([]string{"HTTP/1.x", "HTTPS"})
	got := cfg.EffectiveEnabledProtocols()
	want := []string{"HTTP/1.x", "HTTPS"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EffectiveEnabledProtocols = %v, want %v", got, want)
	}

	// Clear by passing nil.
	cfg.SetEnabledProtocols(nil)
	if got := cfg.EffectiveEnabledProtocols(); got != nil {
		t.Errorf("after clear: %v, want nil", got)
	}
}

// TestBuildConfig_EnabledProtocols_DefensiveCopy verifies neither the
// caller's input slice nor the returned slice can mutate the stored
// snapshot — a defensive copy is taken on both Set and Get.
func TestBuildConfig_EnabledProtocols_DefensiveCopy(t *testing.T) {
	cfg := &BuildConfig{}
	input := []string{"HTTP/1.x", "HTTPS"}
	cfg.SetEnabledProtocols(input)

	// Mutate caller's input — stored snapshot must be unaffected.
	input[0] = "MUTATED"
	got := cfg.EffectiveEnabledProtocols()
	if got[0] == "MUTATED" {
		t.Errorf("Set did not take a defensive copy: stored = %v", got)
	}

	// Mutate returned slice — second Get must be unaffected.
	got[1] = "ALSO_MUTATED"
	got2 := cfg.EffectiveEnabledProtocols()
	if got2[1] == "ALSO_MUTATED" {
		t.Errorf("Effective did not return a defensive copy: stored = %v", got2)
	}
}

// TestBuildConfig_EnabledProtocols_NilReceiver verifies the accessors
// tolerate a nil BuildConfig receiver (matches the SetUpstreamProxy
// nil-tolerance pattern).
func TestBuildConfig_EnabledProtocols_NilReceiver(t *testing.T) {
	var cfg *BuildConfig
	cfg.SetEnabledProtocols([]string{"HTTP/1.x"}) // must not panic
	if got := cfg.EffectiveEnabledProtocols(); got != nil {
		t.Errorf("nil cfg EffectiveEnabledProtocols = %v, want nil", got)
	}
}
