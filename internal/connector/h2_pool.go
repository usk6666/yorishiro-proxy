package connector

import (
	"bytes"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

// poolKeyForH2 builds a pool.PoolKey for the given CONNECT target using the
// TLS-relevant knobs from cfg. The TLSConfigHash canonicalises a byte form
// covering:
//   - ServerName (host portion of the target)
//   - NextProtos ({"h2"}, since this is the h2-specific hash)
//   - InsecureSkipVerify
//   - ClientCert hash (first DER bytes via hashCert)
//   - UTLSProfile (TLSFingerprint)
//   - UpstreamProxy URL string
//
// Two connections with identical values above produce identical keys and
// therefore share a pooled upstream Layer. Callers MUST pass the same cfg
// that was used for the upstream dial — diverging here yields a silent
// cache miss rather than a correctness issue, but is wasteful.
func poolKeyForH2(target string, cfg *BuildConfig) pool.PoolKey {
	var buf bytes.Buffer

	// ServerName. Kept under a length prefix so "a"+"b" never collides with
	// "ab"+"".
	host, _, _ := splitHostOrSelf(target)
	writeField(&buf, "sn", host)

	// NextProtos — always {"h2"} for this helper.
	writeField(&buf, "np", "h2")

	// TLS knobs.
	insec := "0"
	if cfg != nil && cfg.InsecureSkipVerify {
		insec = "1"
	}
	writeField(&buf, "insecure", insec)

	certHash := ""
	if cfg != nil {
		certHash = hashCert(cfg.ClientCert)
	}
	writeField(&buf, "clientcert", certHash)

	profile := ""
	if cfg != nil {
		profile = cfg.TLSFingerprint
	}
	writeField(&buf, "utls", profile)

	proxyURL := ""
	if cfg != nil && cfg.UpstreamProxy != nil {
		proxyURL = cfg.UpstreamProxy.String()
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
