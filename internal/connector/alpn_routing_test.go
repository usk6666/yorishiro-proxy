package connector

import (
	"crypto/tls"
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
	_, err := alpnRoute("h2")
	if err == nil {
		t.Fatal("expected error for h2")
	}
	if err != ErrHTTP2LayerNotImplemented {
		t.Errorf("error = %v, want ErrHTTP2LayerNotImplemented", err)
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
