package connector

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// resolveForwardTarget returns the upstream host:port an explicit
// plain-HTTP forward-proxy request names. It is the single routing rule of
// the forward proxy (USK-1410): peekForwardTarget applies it to the first
// request before any Layer exists, and the client-facing http1 Layer
// applies it to every request it parses (WithForwardTargetResolver), so
// each keep-alive request reaches the upstream it names.
//
// Resolution order (RFC 9112 §3.2.2): an absolute-form "http://"
// request-target's authority wins; otherwise the first Host header (by
// the parser's case-insensitive match on the name exactly as parsed —
// "Host :" is not Host). The default port is 80. The result must pass
// SplitTargetHostPort (USK-1249): a port the dialer would read differently
// from TargetScope is an error. The target is never rewritten beyond
// adding the default port. CONNECT is refused: CONNECT requests belong to
// the CONNECT handler.
func resolveForwardTarget(method, requestURI string, headers parser.RawHeaders) (string, error) {
	if strings.EqualFold(method, "CONNECT") {
		return "", fmt.Errorf("connector: CONNECT method routed to plain-HTTP handler")
	}

	// Absolute-form URI takes precedence (RFC 9112 §3.2.2).
	if strings.HasPrefix(strings.ToLower(requestURI), "http://") {
		u, err := url.Parse(requestURI)
		if err != nil {
			return "", fmt.Errorf("connector: parse absolute URI: %w", err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("connector: absolute URI missing authority")
		}
		return validForwardTarget(JoinDefaultPort(u.Host, "80"))
	}

	// Origin-form: Host header is mandatory in HTTP/1.1.
	host := headers.Get("Host")
	if host == "" {
		return "", fmt.Errorf("connector: missing Host header in origin-form request")
	}
	return validForwardTarget(JoinDefaultPort(host, "80"))
}

// forwardTargetRefusal is the response the forward proxy answers a request
// whose target cannot be resolved with — the first-request gate's 400, and
// the client http1 Layer's for a later keep-alive request (USK-1410).
func forwardTargetRefusal() []byte {
	return forwardErrorResponse(400, "Bad Request", "yorishiro-proxy: could not parse request target")
}

// SameForwardTarget reports whether two resolved forward targets name the
// same upstream: exact host:port, host compared case-insensitively. It
// decides only whether the current upstream connection is reused; the
// target is never written anywhere in this form (USK-1410).
func SameForwardTarget(a, b string) bool {
	return strings.EqualFold(a, b)
}
