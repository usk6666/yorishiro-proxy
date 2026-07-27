// ALPN routing helpers.
//
// Two flows coexist after USK-997:
//
//	Sniff-first MITM (primary, USK-997)
//	  client ClientHello peek → forward client ALPN list verbatim to
//	  upstream → upstream picks → MITM advertise = [upstream pick]
//	  → client necessarily picks the same → end-to-end single ALPN.
//	  mitmAdvertiseFromUpstreamPick builds the single-element list.
//
//	Legacy speculate-then-redial (fallback only)
//	  Used when the ClientHello peek fails (timeout, non-TLS, ECH,
//	  > 4 KiB CH, or test opt-out via BuildConfig.DisableClientHelloPeek):
//	    cache hit → MITM offer HTTP-family superset → upstream
//	      offered the client's pick → mismatch refresh
//	    cache miss → upstream offer [h2, http/1.1] → MITM offer
//	      client-supportable widening → mismatch redial
//	  defaultALPNOffer / clientALPNOffersForUpstream /
//	  canonicalRedialALPNOffer / clientALPNMatchesUpstream are reachable
//	  only in this fallback path; their USK-793 / USK-884 history is
//	  orthogonal to the sniff-first flow (which never widens past
//	  upstream's authoritative pick).
//
// MITM Principle #1 (CLAUDE.md): the ALPN list is forwarded to upstream
// in the client's wire order, byte-identical. Do not sort, dedup, or
// case-normalise — upstream selection depends on the offer list being
// the exact bytes the client sent.

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

// defaultALPNOffer is the ALPN list offered to upstream on cache miss
// in the legacy fallback path. We offer both h2 and http/1.1 to learn
// the server's preference; on cache hit, only the cached ALPN is offered.
//
// USK-997: reached only when the client's ClientHello peek failed
// (timeout / non-TLS / > 4 KiB / ECH / test opt-out via
// BuildConfig.DisableClientHelloPeek). The sniff-first primary path
// forwards the client's offered ALPN list verbatim instead.
var defaultALPNOffer = []string{ALPNProtocolH2, ALPNProtocolHTTP11}

// mitmAdvertiseFromUpstreamPick builds the ALPN list the MITM
// (client-facing) TLS server should advertise after upstream's
// authoritative pick has been learned by the sniff-first flow
// (USK-997). The returned slice has at most one element:
//
//   - upstreamALPN == "": returns nil. Go's crypto/tls then omits the
//     ALPN extension entirely from the ServerHello, matching the
//     observed upstream reality (servers that did not negotiate ALPN
//     must not be impersonated as having done so).
//   - upstreamALPN non-empty: returns []string{upstreamALPN}. The
//     client can only pick this single value, so the post-handshake
//     client ALPN equals upstream's pick by construction — no
//     mismatch-redial dance.
//
// This is the sniff-first-only sibling of clientALPNOffersForUpstream
// (the legacy widening helper retained for the fallback path).
func mitmAdvertiseFromUpstreamPick(upstreamALPN string) []string {
	if upstreamALPN == "" {
		return nil
	}
	return []string{upstreamALPN}
}

// alpnListContains reports whether protocol appears anywhere in offers,
// using byte-exact comparison. Used by the sniff-first H2 pool fast path
// to decide whether the client's offered list permits the cached h2
// Layer (USK-997). nil/empty offers return false.
func alpnListContains(offers []string, protocol string) bool {
	for _, o := range offers {
		if o == protocol {
			return true
		}
	}
	return false
}

// clientALPNOffersForUpstream returns the ALPN list the proxy should
// advertise to the client during MITM TLS handshake, given what we know
// about the upstream's selected ALPN.
//
// USK-997: reachable only via the legacy fallback path (cache hit /
// cache miss / pool fast-path branches in buildALPNRoutedStack when the
// ClientHello peek did not return an ALPN list — see the file-level
// flow diagram). The sniff-first primary path advertises a single
// element list via mitmAdvertiseFromUpstreamPick instead and never
// invokes this helper.
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
// USK-884: the cache value is a hint about upstream preference, not a
// contract about client capability. When the cached ALPN is "http/1.1",
// previously the proxy advertised ["http/1.1"] only — a one-way ratchet
// that pinned every subsequent h2-capable client to HTTP/1.1 for the cache
// TTL window. The proxy now advertises the full HTTP-family superset
// ["h2", "http/1.1"] whenever the cached upstream-negotiated ALPN is
// explicitly HTTP-family (h2 or http/1.1). The cache refresh-on-mismatch
// logic in buildCacheHitPath / buildCacheMissPath redials upstream with
// the client's choice and rewrites the cache entry if the negotiated
// values diverge.
//
// USK-884 follow-up: the empty-cache case ("") must NOT be widened.
// Go's crypto/tls completes a handshake with NegotiatedProtocol="" when
// the peer advertises no ALPN at all (e.g., the chained-MITM test rig
// upstream, plain HTTP/1.1 servers that omit ALPN, or proxies that
// strip the ALPN extension). Advertising ["h2", "http/1.1"] to a client
// whose upstream authoritatively negotiated empty ALPN forces an
// unnecessary refresh cycle on every subsequent connection — the client
// picks h2, the refresh-on-mismatch logic redials, learns "" again, and
// re-emits the same offer next time. This regressed
// TestPerListener_UpstreamProxy_ChainedMITM_NoSelfRecursion by
// canceling the inner TLS handshake mid-flight on rapid CONNECT cycles.
// When we know nothing about upstream (truly empty cache), the default
// flow goes through buildCacheMissPath which offers defaultALPNOffer
// upstream first; the value stored in the cache after that is the
// upstream's actual choice, not the proxy's offer.
//
// Order matters: the proxy advertises h2 first so a client that supports
// both still ends up on h2 (preserving upstream's likely preference for
// HTTP/2 capable hosts).
//
// upstreamALPN values:
//   - "h2": offer ["h2", "http/1.1"]
//   - "http/1.1": offer ["h2", "http/1.1"] (USK-884: was ["http/1.1"] only)
//   - "" (upstream negotiated no ALPN): offer ["http/1.1"] only — the
//     observed peer does not speak ALPN; offering h2 would force a
//     spurious refresh on every reuse.
//   - anything else (unrecognised): offer ["http/1.1"] — alpnRoute would
//     fall through to bytechunk anyway, and we don't want to mislead the
//     client into thinking we speak the unknown protocol.
func clientALPNOffersForUpstream(upstreamALPN string) []string {
	switch upstreamALPN {
	case ALPNProtocolH2, ALPNProtocolHTTP11:
		// HTTP-family upstream ALPN observed: advertise the full
		// superset so the client can pick the protocol it actually
		// speaks. Refresh-on-mismatch rewrites the cache when the
		// chosen ALPN differs from the seed.
		return []string{ALPNProtocolH2, ALPNProtocolHTTP11}
	default:
		// Empty (upstream negotiated no ALPN) or unrecognised — fall
		// back to http/1.1 only. We don't advertise a protocol the
		// observed upstream didn't agree to; doing so would force a
		// spurious refresh cycle on every subsequent connection (see
		// TestPerListener_UpstreamProxy_ChainedMITM_NoSelfRecursion).
		return []string{ALPNProtocolHTTP11}
	}
}

// clientALPNMatchesUpstream reports whether a client-negotiated ALPN
// produces the same dispatch route as upstream's. Used by the legacy
// fallback paths (buildCacheMissPath / buildCacheHitPath) to decide
// whether to re-dial upstream so the inner stack stays single-protocol
// end-to-end, and by the sniff-first defense-in-depth assert in
// buildSniffFirstStack (which should never fire on the happy path
// because mitmAdvertiseFromUpstreamPick narrows to a single element).
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
//
// USK-997: invoked by the legacy fallback paths (buildCacheMissPath
// mismatch branch, buildCacheHitPath redial setup) and by the
// sniff-first defense-in-depth assert in buildSniffFirstStack when the
// MITM somehow produced a client ALPN different from upstream's pick.
func canonicalRedialALPNOffer(clientALPN string) []string {
	if clientALPN == "" {
		return []string{ALPNProtocolHTTP11}
	}
	return []string{clientALPN}
}

// ALPNCacheKeyFromConfig constructs an ALPNCacheKey for the given target
// using the TLS configuration from BuildConfig. The fingerprint
// component reads via EffectiveUTLSProfile so a runtime
// proxy_start / configure fingerprint switch produces a distinct cache
// key — ALPN learned under the previous fingerprint is not reused for
// dials that should now use a different uTLS profile (USK-809). The
// resolved (dial-identity) form is used so a boot-time "none" and a
// runtime "none" share one keyspace, matching the handshakes they
// actually key (USK-1021).
func ALPNCacheKeyFromConfig(target string, cfg *BuildConfig) ALPNCacheKey {
	key := ALPNCacheKey{
		HostPort:    target,
		Fingerprint: cfg.EffectiveUTLSProfile(),
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
