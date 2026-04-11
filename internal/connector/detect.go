package connector

import (
	"bytes"
	"sync"
)

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

// CodecFactory builds the client-side and upstream-side Codecs for a newly
// accepted connection. It is invoked by the listener once DetectKind has
// chosen a ProtocolKind and the peek deadline has been cleared.
//
// conn is the buffered connection — the bytes that Detection peeked at are
// still available to the first Codec.Next call. The factory may choose to
// wrap conn further (e.g. TLS termination) and is responsible for any error
// handling related to the protocol's own startup sequence.
//
// A factory that only produces a client-side Codec and defers upstream
// dialing to session.RunSession can return a nil upstream Codec; the caller
// must handle the nil case.
//
// Factories are intentionally decoupled from the session.DialFunc: the
// dialer and upstream Codec setup belong to USK-562 (DialUpstream), which
// runs in parallel with this Issue.
type CodecFactory interface {
	// Kind returns the ProtocolKind this factory handles.
	Kind() ProtocolKind
}

// Detector selects CodecFactories by ProtocolKind and exposes a
// registration API for protocol additions (M40 HTTP/2, etc.).
//
// A Detector is safe for concurrent use: Register may be called at start-up
// and Lookup/Detect may be called from listener goroutines simultaneously.
type Detector struct {
	mu        sync.RWMutex
	factories map[ProtocolKind]CodecFactory
}

// NewDetector creates a Detector with no factories registered.
//
// Callers should register at least the protocols they want to support via
// Register. The default wiring is performed by the binary's main.go (see
// cmd/yorishiro-proxy) — not by this package — so tests can swap in mocks.
func NewDetector() *Detector {
	return &Detector{
		factories: make(map[ProtocolKind]CodecFactory),
	}
}

// Register installs a CodecFactory for the given ProtocolKind. Registering
// the same kind twice overwrites the previous factory; this is deliberate
// so that tests can replace a production factory with a mock.
//
// Passing a nil factory clears the registration for that kind (useful for
// tests and for the M39-only state where HTTP/2 is detected but not yet
// handled).
func (d *Detector) Register(kind ProtocolKind, factory CodecFactory) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if factory == nil {
		delete(d.factories, kind)
		return
	}
	d.factories[kind] = factory
}

// Lookup returns the registered factory for the given kind, or nil if none
// has been registered.
func (d *Detector) Lookup(kind ProtocolKind) CodecFactory {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.factories[kind]
}

// Detect is a convenience wrapper that runs DetectKind on peek and then
// Lookup on the result. It returns both the kind (so callers can log it
// even when no factory is registered) and the factory (which may be nil).
func (d *Detector) Detect(peek []byte) (ProtocolKind, CodecFactory) {
	kind := DetectKind(peek)
	return kind, d.Lookup(kind)
}
