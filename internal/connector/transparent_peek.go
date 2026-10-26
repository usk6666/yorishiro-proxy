package connector

import (
	"bytes"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// transparentHTTPMethods are the request methods that route a transparent
// connection to the L7 HTTP/1 path — only on a complete "METHOD SP"
// match (decision R5). A strict prefix ("G") keeps peeking within the
// same deadline; anything else, including lowercase or unknown methods,
// is passed through as opaque bytes rather than forced into the HTTP
// parser.
var transparentHTTPMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("TRACE "),
	[]byte("CONNECT "),
}

// transparentH2CPreface is the HTTP/2 prior-knowledge client preface
// (RFC 9113 §3.4).
var transparentH2CPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// classifyTransparentBytes classifies the client's first bytes. decided
// is false while b is still a strict prefix of an HTTP method or of the
// h2c preface.
func classifyTransparentBytes(b []byte) (route TransparentRoute, decided bool) {
	if len(b) == 0 {
		return "", false
	}
	if b[0] == tlsContentTypeHandshake {
		return TransparentRouteTLS, true
	}
	if bytes.HasPrefix(b, transparentH2CPreface) {
		return TransparentRouteH2C, true
	}
	pending := len(b) < len(transparentH2CPreface) && bytes.HasPrefix(transparentH2CPreface, b)
	for _, m := range transparentHTTPMethods {
		if bytes.HasPrefix(b, m) {
			return TransparentRouteHTTP, true
		}
		if len(b) < len(m) && bytes.HasPrefix(m, b) {
			pending = true
		}
	}
	if pending {
		return "", false
	}
	return TransparentRouteOpaque, true
}

// peekTransparentRoute peeks pc's first bytes until they decide the route
// or timeout elapses. No byte before the deadline (or a client that
// closed without sending) is a server-first connection; an undecided
// prefix at the deadline is opaque. The read deadline is cleared before
// returning; no byte is consumed.
func peekTransparentRoute(pc *PeekConn, timeout time.Duration) TransparentRoute {
	_ = pc.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = pc.SetReadDeadline(time.Time{}) }()
	for {
		n := pc.Buffered()
		if n > 0 {
			b, _ := pc.Peek(n)
			if route, ok := classifyTransparentBytes(b); ok {
				return route
			}
		}
		if _, err := pc.Peek(n + 1); err != nil {
			if pc.Buffered() == 0 {
				return TransparentRouteServerFirst
			}
			b, _ := pc.Peek(pc.Buffered())
			if route, ok := classifyTransparentBytes(b); ok {
				return route
			}
			return TransparentRouteOpaque
		}
	}
}

// transparentRequestHead is what the HTTP route's gate reads from the
// first request head when a name must admit the connection.
type transparentRequestHead struct {
	// hostValues are the Host header values (envelope.HostHeaderValues).
	hostValues []string
	// absoluteAuthority is the authority of an absolute-form
	// request-target, empty for origin-form.
	absoluteAuthority string
	// path is the request path without the query.
	path string
	// complete reports that the whole head (through CRLF CRLF) was read
	// within the size and time bounds.
	complete bool
}

// names returns every name value the head carries.
func (h transparentRequestHead) names() []string {
	out := append([]string(nil), h.hostValues...)
	if h.absoluteAuthority != "" {
		out = append(out, h.absoluteAuthority)
	}
	return out
}

// readTransparentRequestHead peeks the first request head (bounded by
// peekHeaderSize and timeout; a non-positive timeout arms no deadline,
// USK-1185) without consuming it and extracts its names. Parsing is
// tolerant like the HTTP/1 Layer's: no net/url, no
// rejection of escapes or control bytes — a head that cannot be read
// simply yields no names (and so no admitting name).
func readTransparentRequestHead(pc *PeekConn, timeout time.Duration) transparentRequestHead {
	if timeout > 0 {
		_ = pc.SetReadDeadline(time.Now().Add(timeout))
	}
	buf, _ := peekUntilHeadersEnd(pc, peekHeaderSize)
	if timeout > 0 {
		_ = pc.SetReadDeadline(time.Time{})
	}
	var head transparentRequestHead
	if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
		buf = buf[:idx]
		head.complete = true
	}
	lines := bytes.Split(buf, []byte("\r\n"))
	if len(lines) == 0 {
		return head
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) >= 2 {
		target := string(parts[1])
		lower := strings.ToLower(target)
		for _, scheme := range []string{"http://", "https://"} {
			if strings.HasPrefix(lower, scheme) {
				rest := target[len(scheme):]
				end := strings.IndexAny(rest, "/?#")
				if end < 0 {
					head.absoluteAuthority, target = rest, "/"
				} else {
					head.absoluteAuthority, target = rest[:end], rest[end:]
				}
				break
			}
		}
		if q := strings.IndexAny(target, "?#"); q >= 0 {
			target = target[:q]
		}
		head.path = target
	}
	var kvs []envelope.KeyValue
	for _, line := range lines[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		kvs = append(kvs, envelope.KeyValue{Name: string(line[:colon]), Value: string(line[colon+1:])})
	}
	head.hostValues = envelope.HostHeaderValues(kvs)
	return head
}
