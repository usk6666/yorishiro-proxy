package mcptest

import (
	"crypto/tls"
	"sync"
)

// FingerprintObserver records the most recent TLS ClientHello observed by
// the upstream test server. Tests use it to assert that the proxy's
// configured TLS fingerprint profile (e.g. uTLS Chrome) actually shaped
// the ClientHello on the wire — not just that the configuration value
// was stored. It is the regression hook for USK-727 (boot-order
// `tls_fingerprint` honored by `resend_http` even before `proxy_start`
// runs).
//
// Detection strategy: GREASE values (RFC 8701) of the form 0x?A?A —
// browsers like Chrome/Firefox/Edge insert these into ClientHello
// cipher_suites and other lists at random positions to keep middleboxes
// from ossifying on a fixed list. Go's crypto/tls library does NOT emit
// GREASE. Any GREASE value in the observed cipher_suites therefore
// proves a uTLS-style client was used. We do not attempt to distinguish
// Chrome vs Firefox vs Edge here — the test only needs to confirm
// "uTLS-flavored ClientHello ran"; checking the proxy_start config
// surface separately confirms the configured profile.
//
// Concurrency: Observe is invoked from inside crypto/tls's
// GetConfigForClient callback, which may run on the listener's accept
// goroutine. We protect last with a mutex so LastObservedFingerprint
// reads are safe regardless of where they fire.
type FingerprintObserver struct {
	mu   sync.Mutex
	last string
}

// LastObservedFingerprint returns one of:
//
//   - "utls"   — at least one GREASE value was present in the observed
//     ClientHello cipher_suites, indicating a uTLS-style client.
//   - "standard" — no GREASE present; the standard Go crypto/tls client
//     (or any non-uTLS client without GREASE) was used.
//   - ""       — no ClientHello has been observed yet.
//
// The terminology "utls" is intentional: the observer cannot tell
// Chrome from Firefox from Edge. Callers that want the configured
// profile name should consult the proxy_start config surface instead;
// this method only proves the proxy actually used uTLS at handshake time.
func (o *FingerprintObserver) LastObservedFingerprint() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.last
}

// observe inspects a ClientHelloInfo and records "utls" or "standard"
// based on GREASE presence. Multiple calls are tolerated; the latest
// observation wins.
func (o *FingerprintObserver) observe(hello *tls.ClientHelloInfo) {
	verdict := "standard"
	for _, suite := range hello.CipherSuites {
		if isGREASE(suite) {
			verdict = "utls"
			break
		}
	}
	o.mu.Lock()
	o.last = verdict
	o.mu.Unlock()
}

// isGREASE reports whether v is one of the 16 GREASE values defined by
// RFC 8701. GREASE values follow the pattern 0x?A?A where both nibbles
// match — the high byte equals the low byte and each is a 0x?A pattern.
func isGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	if hi != lo {
		return false
	}
	// 0x0A, 0x1A, 0x2A, ..., 0xFA — low nibble must be 0xA.
	return hi&0x0F == 0x0A
}

// installFingerprintObserver returns a *tls.Config derived from base
// whose GetConfigForClient callback notifies the returned observer of
// every observed ClientHello. The returned config preserves all of
// base's fields (Certificates, ClientAuth, ClientCAs, MinVersion, …) by
// shallow-copying base inside the callback before returning it to the
// TLS handshake. base may be nil — in which case a minimal config with
// MinVersion=TLS1.2 is used, sufficient for httptest's auto-issued leaf
// cert path.
//
// The returned config's GetConfigForClient takes precedence over the
// shallow copy's own GetConfigForClient (which we do not set) so the
// crypto/tls handshake uses the cloned config directly.
func installFingerprintObserver(base *tls.Config) (*tls.Config, *FingerprintObserver) {
	obs := &FingerprintObserver{}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if base != nil {
		// Clone base so we can layer GetConfigForClient on top without
		// mutating the caller's config.
		cfg = base.Clone()
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
	}
	// crypto/tls calls GetConfigForClient once per handshake, after it
	// has parsed the ClientHello. We snapshot the hello and return the
	// already-prepared config (httptest.Server populates Certificates
	// during StartTLS).
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		obs.observe(hello)
		return nil, nil // nil means "use the listener's config as-is"
	}
	return cfg, obs
}
