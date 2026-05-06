package connector

import "bytes"

// ProtocolKind identifies one of the protocols that the connector knows how
// to detect from the client's first bytes.
//
// The set of kinds is intentionally small: Detection happens at the TCP layer
// and can only tell protocols apart by their wire preface. Finer-grained
// protocol selection (e.g. gRPC vs plain HTTP/2) is performed later by the
// Codec itself once header parsing has occurred.
type ProtocolKind int

const (
	// ProtocolUnknown means Detection could not identify the protocol.
	// The connection should be closed by the caller.
	ProtocolUnknown ProtocolKind = iota

	// ProtocolSOCKS5 means the client sent a SOCKS5 version byte (0x05).
	// The connector dispatches the connection to a Negotiator so the
	// SOCKS5 handshake can be performed before the real protocol is
	// detected on the tunneled stream.
	ProtocolSOCKS5

	// ProtocolHTTPConnect means the client sent an HTTP CONNECT request.
	// Like SOCKS5, this is handled by a Negotiator that terminates the
	// tunnel and re-runs Detection on the inner stream.
	ProtocolHTTPConnect

	// ProtocolHTTP1 means the client sent a regular HTTP/1.x request
	// (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE).
	ProtocolHTTP1

	// ProtocolHTTP2 means the client sent the HTTP/2 connection preface
	// (also known as h2c — cleartext HTTP/2). The M39 connector only
	// detects this pattern; actual handling is added in M40 when the
	// HTTP/2 Codec is registered.
	ProtocolHTTP2

	// ProtocolTCP is the fall-through kind. When no other pattern matches,
	// the connector treats the connection as opaque bytes and dispatches
	// the TCP (identity) Codec.
	ProtocolTCP
)

// String returns a human-readable name for the ProtocolKind.
func (k ProtocolKind) String() string {
	switch k {
	case ProtocolSOCKS5:
		return "SOCKS5"
	case ProtocolHTTPConnect:
		return "HTTP/CONNECT"
	case ProtocolHTTP1:
		return "HTTP/1.x"
	case ProtocolHTTP2:
		return "HTTP/2 (h2c)"
	case ProtocolTCP:
		return "TCP"
	default:
		return "unknown"
	}
}

// UserName returns the canonical user-facing protocol name corresponding
// to this ProtocolKind. Used by the EnabledProtocols allow-list (USK-732)
// to compare detected kinds against names accepted by the proxy_start
// MCP tool ("HTTP/1.x", "HTTPS", "HTTP/2", "SOCKS5", "TCP").
//
// Note that the listener-level kind ProtocolHTTPConnect maps to the
// user-facing name "HTTPS" — clients reach the proxy with a CONNECT
// request when they intend to tunnel TLS, so HTTPS is the user-visible
// protocol of the connection from the operator's perspective. Kinds
// that have no user-facing equivalent return the empty string.
func (k ProtocolKind) UserName() string {
	switch k {
	case ProtocolSOCKS5:
		return "SOCKS5"
	case ProtocolHTTPConnect:
		return "HTTPS"
	case ProtocolHTTP1:
		return "HTTP/1.x"
	case ProtocolHTTP2:
		return "HTTP/2"
	case ProtocolTCP:
		return "TCP"
	default:
		return ""
	}
}

// kindMatchesEnabledNames reports whether the detected ProtocolKind is
// permitted under the user-facing allow-list. Recognises the canonical
// UserName() mapping plus the inner-protocol family names that ride on
// HTTPS ("HTTP/2", "WebSocket", "gRPC"): when the operator enabled any
// of these, HTTPS connections are accepted at the listener level so
// post-CONNECT ALPN can deliver the requested inner protocol.
//
// "HTTP/2" deserves a special note: at the listener level it covers
// cleartext h2c (ProtocolHTTP2). When the operator enables "HTTP/2" it
// also implies that h2 over TLS (an HTTPS connection followed by ALPN
// negotiation to "h2") should be allowed; we therefore accept
// ProtocolHTTPConnect as a precondition to HTTP/2-over-TLS.
//
// The inner-protocol set is anchored on the proxy_start MCP tool's
// validProtocols accept-list ("HTTP/2", "WebSocket", "gRPC"). gRPC-Web
// and SSE are deliberately omitted: they are not currently accepted as
// values for the proxy_start `protocols` argument, so a branch handling
// them here would be unreachable. Add them back here only if the MCP
// accept-list grows to include them.
func kindMatchesEnabledNames(kind ProtocolKind, names []string) bool {
	canonical := kind.UserName()
	if canonical == "" {
		return false
	}
	for _, n := range names {
		if n == canonical {
			return true
		}
		// HTTPS is the listener-level pre-condition for the protocols
		// that ride inside a TLS tunnel. When the operator enables any
		// of those names we must let CONNECT (HTTPS) through so the
		// tunnel can be established and ALPN/upgrade can deliver the
		// inner protocol.
		if kind == ProtocolHTTPConnect {
			switch n {
			case "HTTP/2", "WebSocket", "gRPC":
				return true
			}
		}
	}
	return false
}

// http2Preface is the HTTP/2 connection preface (RFC 9113 §3.4).
// Clients speaking h2c (cleartext HTTP/2) send this sequence before any frame.
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// PeekSize is the number of bytes used for the second Detection stage.
// It is large enough to disambiguate HTTP methods (longest: "OPTIONS" = 7)
// and to match the HTTP/2 preface's initial "PRI * HT" bytes.
const PeekSize = 16

// QuickPeekSize is the number of bytes used for the first Detection stage.
// SOCKS5 can be identified from a single byte (0x05), so the connector first
// peeks one byte to avoid blocking until PeekSize bytes arrive. A bufio
// reader's Peek(n) call blocks until n bytes are available — so a full peek
// on an idle SOCKS5 client would wait for the peek deadline even though the
// client only intends to send a 3-byte greeting.
const QuickPeekSize = 1

// DetectKind inspects the peeked bytes and returns the matching ProtocolKind.
//
// Returns ProtocolUnknown only when peek is empty. When peek contains at
// least one byte that does not match any other pattern, the fall-through is
// ProtocolTCP — the connector always has a handler for raw bytes.
//
// DetectKind is pure and safe for concurrent use; it does not consume the
// bytes it inspects.
func DetectKind(peek []byte) ProtocolKind {
	if len(peek) == 0 {
		return ProtocolUnknown
	}

	// 1. SOCKS5 is always the first byte 0x05.
	if peek[0] == 0x05 {
		return ProtocolSOCKS5
	}

	// 2. HTTP/2 preface must match exactly.
	//
	// Full preface length is 24 bytes, longer than PeekSize, so we confirm
	// HTTP/2 as soon as peek agrees with the preface on all bytes it has
	// and has at least 8 bytes ("PRI * HT") — enough to rule out any
	// regular HTTP/1.x method while still fitting inside PeekSize. This
	// prefix-tolerance is the standard h2c detection technique; a client
	// speaking anything else will diverge well before byte 8.
	if len(peek) >= 8 && bytes.Equal(peek[:8], http2Preface[:8]) {
		return ProtocolHTTP2
	}

	// 3. HTTP CONNECT — exact prefix match is required. "CONNECT " has the
	//    trailing space so we don't accidentally match something like
	//    "CONNECTED".
	if bytes.HasPrefix(peek, []byte("CONNECT ")) {
		return ProtocolHTTPConnect
	}

	// 4. Regular HTTP/1.x methods. All HTTP methods are followed by a space.
	if isHTTPMethodPrefix(peek) {
		return ProtocolHTTP1
	}

	// 5. Fall-through: opaque TCP stream.
	return ProtocolTCP
}

// httpMethodsWithSpace lists the HTTP/1.x methods the connector understands,
// each followed by the mandatory SP separator. Detection is anchored on the
// trailing space so "GETS" or "POSTURE" are not misidentified.
var httpMethodsWithSpace = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("TRACE "),
}

// isHTTPMethodPrefix reports whether peek begins with any known HTTP/1.x
// method followed by a space. It also returns true when peek is a strict
// prefix of one of the methods (e.g. peek=="GE"), so that the first
// Detection stage does not reject a short read; the second stage can then
// confirm the full pattern.
func isHTTPMethodPrefix(peek []byte) bool {
	for _, m := range httpMethodsWithSpace {
		if bytes.HasPrefix(peek, m) {
			return true
		}
		// Allow short reads: peek is a strict prefix of a method, and
		// the next byte could still match.
		if len(peek) < len(m) && bytes.HasPrefix(m, peek) {
			// Only accept the short-read match if peek is non-empty
			// (already checked by caller) and contains no SP — that
			// way "GET\n" is rejected as invalid but "GE" is allowed
			// through to the second peek stage.
			if bytes.IndexByte(peek, ' ') < 0 {
				return true
			}
		}
	}
	return false
}
