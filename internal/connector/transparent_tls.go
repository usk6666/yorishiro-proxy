package connector

// transparentTLSClass is how the transparent listener handles a TLS
// connection, decided from its ClientHello (USK-1317).
type transparentTLSClass int

const (
	// transparentTLSPassthrough: metadata-only passthrough (no MITM).
	transparentTLSPassthrough transparentTLSClass = iota
	// transparentTLSMITM: the ALPN offer names an HTTP protocol; MITM
	// through BuildConnectionStack's sniff-first path.
	transparentTLSMITM
	// transparentTLSMITMNoALPN: no ALPN offered; MITM, then the decrypted
	// bytes decide HTTP/1 or raw.
	transparentTLSMITMNoALPN
)

// classifyTransparentTLS classifies a peeked ClientHello.
func classifyTransparentTLS(p ClientHelloPeek) transparentTLSClass {
	return transparentTLSPassthrough
}
