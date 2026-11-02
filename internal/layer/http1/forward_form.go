package http1

import (
	"bytes"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// Plain-HTTP forward-proxy egress form (USK-1117).
//
// A client talking to an explicit forward proxy sends an absolute-form
// request-target and may add Proxy-Connection / Proxy-Authorization. Those
// exist only because the client is talking to a proxy; a client speaking
// to the origin directly would send origin-form and neither header. On the
// forward proxy path the upstream request therefore drops them, so what
// the origin receives looks like a direct client's request. Everything
// else — the Host header, the other headers' order, casing and OWS, the
// body — is relayed byte-for-byte.
//
// A request with no Host header (legal in HTTP/1.0) carries its authority
// only in the absolute-form target, so that target is kept as received
// (no Host is synthesised); Proxy-* headers are still dropped.
//
// This is egress only. Envelope.Raw (the recording), the L7 Message and
// every Pipeline Step see the request as received (MITM Principle 1
// applies to the recording). Plaintext inside a CONNECT / SOCKS5 tunnel,
// transparent mode, tcp_forwards and TLS MITM never set the option: there
// the request form is the client's own choice and is relayed verbatim.

// WithForwardProxyOriginForm marks a Send-direction (client-facing) Layer
// as the ingress of the explicit plain-HTTP forward proxy. Requests it
// parses are sent upstream in origin-form (RFC 9112 §3.2.1; asterisk-form
// for an OPTIONS with an empty path and no query, §3.2.4) without
// Proxy-Connection / Proxy-Authorization headers. A request without a
// Host header keeps its absolute-form target. The flag rides on the
// request envelope's Opaque, so it survives an upstream redial and the
// modified variant EncodeWireBytes records equals the bytes sent. A raw
// authoritative send (plugin msg["raw"]) and synthetic sends (resend /
// fuzz) are unaffected. Ignored on Receive-direction Layers.
func WithForwardProxyOriginForm() Option {
	return func(o *options) { o.forwardOriginForm = true }
}

// setForwardOriginForm records the forward-proxy egress decision on a
// request opaque at parse time. forwardTarget is set for an absolute-form
// target that is sent in origin-form: only when the request has a Host
// header (any casing, matched on the name exactly as parsed), since
// without one the target is the only carrier of the authority and is
// kept as received. forwardRewrite is precomputed so the opaque send path
// keeps its zero-copy fast path for requests that need no conversion
// (no target conversion and no Proxy-* headers). Must run after
// snapshotRequestLine (it reads targetPrefix).
func (o *opaqueHTTP1) setForwardOriginForm(enabled bool) {
	o.forwardOriginForm = enabled
	o.forwardTarget = enabled && o.targetPrefix != "" && hasHostHeader(o.rawReq.Headers)
	o.forwardRewrite = o.forwardTarget || (enabled && hasForwardProxyHeader(o.rawReq.Headers))
}

// hasHostHeader reports whether headers carry a Host field, by the same
// case-insensitive name match RawHeaders.Get uses. A name with whitespace
// before the colon ("Host :") is not Host.
func hasHostHeader(headers parser.RawHeaders) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Host") {
			return true
		}
	}
	return false
}

// isForwardProxyHeader reports whether a header name, exactly as parsed
// (line[:colon], no trimming), is one the forward proxy removes. A name
// with whitespace before the colon ("Proxy-Connection :") does not match:
// that is the client's anomaly and is forwarded as received.
func isForwardProxyHeader(name string) bool {
	return strings.EqualFold(name, "Proxy-Connection") || strings.EqualFold(name, "Proxy-Authorization")
}

func hasForwardProxyHeader(headers parser.RawHeaders) bool {
	for _, h := range headers {
		if isForwardProxyHeader(h.Name) {
			return true
		}
	}
	return false
}

// delForwardProxyHeaders removes every forward-proxy header from headers
// (all occurrences, any casing).
func delForwardProxyHeaders(headers *parser.RawHeaders) {
	headers.Del("Proxy-Connection")
	headers.Del("Proxy-Authorization")
}

// originFormTarget converts an absolute-form request-target to the
// origin-form a direct client would send, by slicing the wire bytes after
// prefix (the wire "scheme://authority", userinfo included): no
// re-encoding. An empty remainder is "/" — or "*" for OPTIONS, the
// asterisk-form a last proxy sends for a server-wide OPTIONS (RFC 9112
// §3.2.4) — and a bare query gets "/" in front of it.
func originFormTarget(method, requestURI, prefix string) string {
	rest := requestURI[len(prefix):]
	switch {
	case rest == "":
		if method == "OPTIONS" {
			return "*"
		}
		return "/"
	case rest[0] == '?':
		return "/" + rest
	default:
		return rest
	}
}

// stripForwardProxyHeaders returns tail — a header section as captured on
// the wire, after the start line — without the forward-proxy headers and
// their obs-fold continuation lines. Every other line is kept
// byte-for-byte, its own terminator (CRLF or bare LF) included.
//
// The line walk mirrors parser.parseHeaderLines so the filter removes
// exactly what the parser recorded as those headers: lines are split on
// LF, one trailing CRLF or LF is the terminator, an empty line ends the
// section (it and anything after it are copied verbatim), a line led by
// SP / HT is a continuation of the previous header (an orphan
// continuation with no previous header is kept), and a header's name is
// the bytes before the first colon (the whole line when there is none). A
// last line without a terminator is treated like any other line.
func stripForwardProxyHeaders(tail []byte) []byte {
	out := make([]byte, 0, len(tail))
	dropping := false
	rest := tail
	for len(rest) > 0 {
		var line []byte
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			line, rest = rest, nil
		}
		content := line
		if n := len(content); n > 0 && content[n-1] == '\n' {
			content = content[:n-1]
			if n := len(content); n > 0 && content[n-1] == '\r' {
				content = content[:n-1]
			}
		}
		if len(content) == 0 {
			out = append(out, line...)
			out = append(out, rest...)
			break
		}
		if content[0] == ' ' || content[0] == '\t' {
			if !dropping {
				out = append(out, line...)
			}
			continue
		}
		name := content
		if i := bytes.IndexByte(content, ':'); i >= 0 {
			name = content[:i]
		}
		dropping = isForwardProxyHeader(string(name))
		if !dropping {
			out = append(out, line...)
		}
	}
	return out
}
