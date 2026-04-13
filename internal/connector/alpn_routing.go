package connector

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
)

// ALPN protocol constants for routing decisions.
const (
	ALPNProtocolHTTP11 = "http/1.1"
	ALPNProtocolH2     = "h2"
)

// ErrHTTP2LayerNotImplemented is returned when upstream negotiates h2 but the
// HTTP/2 Layer is not yet available (deferred to N6).
var ErrHTTP2LayerNotImplemented = fmt.Errorf("connector: HTTP/2 Layer not implemented (deferred to N6)")

// alpnRoute determines which Layer type to build based on the negotiated ALPN.
//
// Returns:
//   - "http1" for "http/1.1" or "" (empty = no ALPN negotiated, assume HTTP/1.1)
//   - "bytechunk" for unknown/unrecognized ALPN protocols
//   - error for "h2" (HTTP/2 Layer deferred to N6)
func alpnRoute(negotiatedALPN string) (string, error) {
	switch negotiatedALPN {
	case ALPNProtocolHTTP11, "":
		return "http1", nil
	case ALPNProtocolH2:
		return "", ErrHTTP2LayerNotImplemented
	default:
		// Unknown protocol: raw passthrough with MITM for observability
		return "bytechunk", nil
	}
}

// defaultALPNOffer is the ALPN list offered to upstream on cache miss.
// We offer both h2 and http/1.1 to learn the server's preference.
// On cache hit, only the cached ALPN is offered.
var defaultALPNOffer = []string{ALPNProtocolH2, ALPNProtocolHTTP11}

// ALPNCacheKeyFromConfig constructs an ALPNCacheKey for the given target
// using the TLS configuration from BuildConfig.
func ALPNCacheKeyFromConfig(target string, cfg *BuildConfig) ALPNCacheKey {
	key := ALPNCacheKey{
		HostPort:    target,
		Fingerprint: cfg.TLSFingerprint,
	}
	if cfg.ClientCert != nil {
		key.ClientCertHash = hashCert(cfg.ClientCert)
	}
	return key
}

// hashCert produces a short hex hash of a TLS certificate for use as a
// cache key component. Returns empty string for nil cert.
func hashCert(cert *tls.Certificate) string {
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	h := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(h[:8]) // 16 hex chars is sufficient for keying
}
