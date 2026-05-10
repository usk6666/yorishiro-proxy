package connector

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
)

// ALPN protocol constants for routing decisions.
const (
	ALPNProtocolHTTP11 = "http/1.1"
	ALPNProtocolH2     = "h2"
)

// alpnRoute determines which Layer type to build based on the negotiated ALPN.
//
// Returns:
//   - "http1" for "http/1.1" or "" (empty = no ALPN negotiated, assume HTTP/1.1)
//   - "h2" for "h2" (HTTP/2 Layer, wired in USK-612)
//   - "bytechunk" for unknown/unrecognized ALPN protocols
func alpnRoute(negotiatedALPN string) (string, error) {
	switch negotiatedALPN {
	case ALPNProtocolHTTP11, "":
		return "http1", nil
	case ALPNProtocolH2:
		return "h2", nil
	default:
		// Unknown protocol: raw passthrough with MITM for observability
		return "bytechunk", nil
	}
}

// defaultALPNOffer is the ALPN list offered to upstream on cache miss.
// We offer both h2 and http/1.1 to learn the server's preference.
// On cache hit, only the cached ALPN is offered.
var defaultALPNOffer = []string{ALPNProtocolH2, ALPNProtocolHTTP11}

// clientALPNOffersForUpstream returns the ALPN list the proxy should
// advertise to the client during MITM TLS handshake, given what we know
// about the upstream's selected ALPN.
//
// USK-793: the proxy MUST offer a superset of what the client might want,
// not only the upstream's choice. Otherwise a client that only speaks
// http/1.1 hitting an upstream that supports h2 sees a server-Hello with
// no overlapping ALPN, completes TLS with NegotiatedProtocol="" (Go's
// crypto/tls behaviour — silent fallback rather than no_application_protocol
// alert in many code paths), then speaks HTTP/1.x on a connection the proxy
// would otherwise route through the HTTP/2 stack — yielding "invalid client
// preface" errors and 0-byte timeouts.
//
// Order matters: the proxy advertises the upstream-preferred protocol
// first, so a client that supports both still ends up on h2.
//
// upstreamALPN values:
//   - "h2": offer ["h2", "http/1.1"]
//   - "http/1.1": offer ["http/1.1"]
//   - "" (no upstream ALPN): offer ["http/1.1"]
//   - anything else (unrecognised): offer ["http/1.1"] — alpnRoute would
//     fall through to bytechunk anyway, and we don't want to mislead the
//     client into thinking we speak the unknown protocol.
//
// USK-808: the result is then filtered through the operator's
// enabled-protocols allow-list (when non-empty) so the proxy never
// advertises a protocol the operator disabled via proxy_start `protocols`.
// Pass nil/empty enabled to keep the legacy unfiltered behaviour.
func clientALPNOffersForUpstream(upstreamALPN string, enabled []string) []string {
	var base []string
	switch upstreamALPN {
	case ALPNProtocolH2:
		base = []string{ALPNProtocolH2, ALPNProtocolHTTP11}
	default:
		base = []string{ALPNProtocolHTTP11}
	}
	return alpnOffersAllowedByEnabledProtocols(base, enabled)
}

// alpnOffersAllowedByEnabledProtocols filters the supplied client-facing
// ALPN offer list to the protocols permitted by the operator's
// enabled_protocols allow-list (USK-808).
//
// Mapping rule:
//   - "h2" is allowed iff any of {"HTTP/2", "gRPC"} appears in enabled.
//     (gRPC requires HTTP/2 framing; advertising h2 is therefore implied
//     when gRPC is enabled.)
//   - "http/1.1" is allowed iff any of {"HTTP/1.x", "WebSocket"} appears
//     in enabled. (RFC 6455 WebSocket runs on HTTP/1.1 at this layer.)
//
// Order is preserved from `base`. crypto/tls picks the first NextProtos
// entry the client also offered, so the upstream-preferred ordering
// established by clientALPNOffersForUpstream survives the filter.
//
// Special cases:
//   - enabled is nil or empty → return base unchanged (legacy
//     "all-allowed" semantic per USK-808 design decision #5).
//   - filter strips every entry — e.g. operator enabled only "HTTPS"
//     with no inner protocol — return ["http/1.1"]. Leaving NextProtos
//     unset would cause `no_application_protocol` alerts on strict TLS
//     1.3 clients; HTTPS-with-HTTP/1.1 is the safe conservative default
//     when the operator did not name an inner protocol (USK-808 design
//     decision #7).
//
// "HTTPS", "SOCKS5", "TCP" are listener-level pre-conditions only
// (matched at peek time by kindMatchesEnabledNames); they have no
// effect on the ALPN filter beyond the fallback rule above.
func alpnOffersAllowedByEnabledProtocols(base, enabled []string) []string {
	if len(enabled) == 0 {
		return base
	}
	allowH2 := false
	allowH1 := false
	for _, name := range enabled {
		switch name {
		case "HTTP/2", "gRPC":
			allowH2 = true
		case "HTTP/1.x", "WebSocket":
			allowH1 = true
		}
	}

	out := make([]string, 0, len(base))
	for _, proto := range base {
		switch proto {
		case ALPNProtocolH2:
			if allowH2 {
				out = append(out, proto)
			}
		case ALPNProtocolHTTP11:
			if allowH1 {
				out = append(out, proto)
			}
		default:
			// Unknown ids in `base` are passed through — the filter only
			// constrains protocols it knows how to gate. Keeps the helper
			// future-proof if a new ALPN id is added to the offer list.
			out = append(out, proto)
		}
	}
	if len(out) == 0 {
		// Filter excluded everything. HTTPS-only (operator named
		// "HTTPS" but no inner protocol) lands here; fall back to
		// http/1.1 rather than leaving NextProtos unset.
		return []string{ALPNProtocolHTTP11}
	}
	return out
}

// clientALPNMatchesUpstream reports whether a client-negotiated ALPN
// produces the same dispatch route as upstream's. Used by
// buildCacheMissPath / buildCacheHitPath to decide whether to re-dial
// upstream so the inner stack stays single-protocol end-to-end.
//
// An empty client ALPN matches an empty or "http/1.1" upstream ALPN
// because alpnRoute collapses both to "http1".
func clientALPNMatchesUpstream(clientALPN, upstreamALPN string) bool {
	clientRoute, _ := alpnRoute(clientALPN)
	upstreamRoute, _ := alpnRoute(upstreamALPN)
	return clientRoute == upstreamRoute
}

// canonicalRedialALPNOffer returns the ALPN list to offer upstream when
// re-dialing after a client/upstream mismatch. It collapses the empty
// client ALPN (no offer / no overlap) to ["http/1.1"] because that is
// the protocol Go's TLS server falls back to when no overlap exists,
// and the only protocol the proxy can actually serve in that mode.
func canonicalRedialALPNOffer(clientALPN string) []string {
	if clientALPN == "" {
		return []string{ALPNProtocolHTTP11}
	}
	return []string{clientALPN}
}

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
