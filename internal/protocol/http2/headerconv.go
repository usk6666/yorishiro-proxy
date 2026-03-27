package http2

import (
	gohttp "net/http"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// httpHeaderToRawHeaders converts net/http.Header to parser.RawHeaders.
// This is a temporary bridge until USK-494 removes net/http from the handler.
func httpHeaderToRawHeaders(h gohttp.Header) parser.RawHeaders {
	return httputil.HTTPHeaderToRawHeaders(h)
}

// rawHeadersToHTTPHeader converts parser.RawHeaders back to net/http.Header.
// This is a temporary bridge until USK-494 removes net/http from the handler.
func rawHeadersToHTTPHeader(rh parser.RawHeaders) gohttp.Header {
	return httputil.RawHeadersToHTTPHeader(rh)
}
