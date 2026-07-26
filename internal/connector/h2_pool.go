package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

// poolKeyForH2 builds a pool.PoolKey for the given CONNECT target using the
// TLS-relevant knobs from cfg and the per-host overlay in hostTLS. The
// TLSConfigHash canonicalises a byte form covering:
//   - ServerName (host portion of the target)
//   - NextProtos ({"h2"}, since this is the h2-specific hash)
//   - InsecureSkipVerify (resolved per-host; falls back to cfg)
//   - ClientCert hash (first DER bytes via hashCert; resolved per-host)
//   - CA bundle hash (when a per-host CA bundle is in effect)
//   - UTLSProfile (TLSFingerprint)
//   - UpstreamProxy URL string (resolved per-listener via ctx; USK-826)
//
// Two connections with identical values above produce identical keys and
// therefore share a pooled upstream Layer. Callers MUST pass the
// resolvedTLS snapshot that was used for the upstream dial; diverging here
// would mint a different pool key than the one used at insertion and yield
// a silent cache miss. hostTLS may be nil — in that case the caller has
// no per-host overlay and the key falls back entirely to cfg fields.
//
// USK-737: hostTLS folds the runtime-mutable HostTLSRegistry overlay into
// the key so a `proxy_start(client_cert=...)` (or CA / TLS-verify swap)
// invalidates pooled H2 connections established under the prior overlay.
//
// USK-826: ctx is consulted via cfg.EffectiveUpstreamProxyForCtx so the
// per-listener upstream-proxy override participates in the pool key. Two
// listeners (A and B) with distinct upstream_proxy must NOT share pooled
// H2 connections — otherwise listener B's "send my traffic through A"
// dial would silently reuse a pool entry minted under listener A's own
// (no-proxy / different-proxy) dial state, defeating the per-listener fix.
func poolKeyForH2(ctx context.Context, target string, cfg *BuildConfig, hostTLS *resolvedTLS) pool.PoolKey {
	var buf bytes.Buffer

	// ServerName. Kept under a length prefix so "a"+"b" never collides with
	// "ab"+"".
	host, _, _ := splitHostOrSelf(target)
	writeField(&buf, "sn", host)

	// NextProtos — always {"h2"} for this helper.
	writeField(&buf, "np", "h2")

	// Resolve TLS knobs from the per-host overlay, falling back to cfg.
	insecureSkip := false
	var clientCert *tls.Certificate
	caHash := ""
	if hostTLS != nil {
		insecureSkip = hostTLS.insecureSkip
		clientCert = hostTLS.clientCert
		caHash = hostTLS.caBundleHash
	} else if cfg != nil {
		insecureSkip = cfg.InsecureSkipVerify
		clientCert = cfg.ClientCert
	}

	insec := "0"
	if insecureSkip {
		insec = "1"
	}
	writeField(&buf, "insecure", insec)

	writeField(&buf, "clientcert", hashCert(clientCert))

	writeField(&buf, "ca", caHash)

	// Use EffectiveUTLSProfile so a runtime proxy_start / configure
	// fingerprint switch produces a distinct pool key — pooled h2 Layers
	// established under the previous fingerprint must not be reused for
	// dials that should now use a different uTLS profile (USK-809). The
	// resolved (dial-identity) form is used so a boot-time "none" and a
	// runtime "none" share one keyspace, matching the connections they
	// actually key (USK-1021).
	profile := ""
	if cfg != nil {
		profile = cfg.EffectiveUTLSProfile()
	}
	writeField(&buf, "utls", profile)

	// Use EffectiveUpstreamProxyForCtx so a runtime proxy_start / configure
	// URL switch produces a distinct pool key AND per-listener overrides
	// (USK-826) participate in keying. Pooled h2 Layers established under
	// the previous proxy must not be reused for dials that should now
	// transit a different upstream proxy (USK-734); pooled entries
	// established for listener A must not be reused for listener B
	// (USK-826).
	//
	// USK-959: For per_request rotation, every dial mints a fresh URL so
	// the pool key always differs — no pooling reuse, as intended (each
	// HTTP/2 outbound TCP dial gets its own URL → its own pooled Layer
	// keyspace). Resolver errors are swallowed here (key minted with
	// empty proxyURL); the live dial path catches the error via
	// EffectiveUpstreamProxyForCtxErr and fails closed there.
	proxyURL := ""
	if cfg != nil {
		if u := cfg.EffectiveUpstreamProxyForCtx(ctx); u != nil {
			proxyURL = u.String()
		}
	}
	writeField(&buf, "proxy", proxyURL)

	return pool.PoolKey{
		HostPort:      target,
		TLSConfigHash: pool.HashTLSConfig(buf.Bytes()),
	}
}

// writeField appends a length-prefixed key=value entry to buf. The length
// prefix ensures concatenation is injective: no two distinct (key,value)
// pairs can produce the same byte sequence.
func writeField(buf *bytes.Buffer, key, value string) {
	buf.WriteString(key)
	buf.WriteByte('=')
	buf.WriteString(strconv.Itoa(len(value)))
	buf.WriteByte(':')
	buf.WriteString(value)
	buf.WriteByte(0x00)
}

// splitHostOrSelf returns the host portion of target ("host:port"). If target
// is not a valid host:port, target itself is returned as the host with an
// empty port. Used only to derive the ServerName for pool keying — strict
// validation lives in upstream dialing code.
func splitHostOrSelf(target string) (host, port string, ok bool) {
	// We want the simple prefix before the last colon. Avoid importing
	// net.SplitHostPort because it rejects bracketed IPv6 without ports and
	// introduces error-handling noise we don't need here.
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == ':' {
			return target[:i], target[i+1:], true
		}
	}
	return target, "", false
}
