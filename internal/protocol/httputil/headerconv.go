package httputil

import (
	gohttp "net/http"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// HTTPHeaderToRawHeaders converts net/http.Header to parser.RawHeaders.
// This is a temporary bridge used by handlers that still operate on
// *net/http.Request and *net/http.Response until USK-494 removes net/http
// from the handler pipeline entirely.
func HTTPHeaderToRawHeaders(h gohttp.Header) parser.RawHeaders {
	if h == nil {
		return nil
	}
	var rh parser.RawHeaders
	for name, vals := range h {
		for _, v := range vals {
			rh = append(rh, parser.RawHeader{Name: name, Value: v})
		}
	}
	return rh
}

// RawHeadersToHTTPHeader converts parser.RawHeaders back to net/http.Header.
// This is a temporary bridge used by handlers that still operate on
// *net/http.Request and *net/http.Response until USK-494 removes net/http
// from the handler pipeline entirely.
func RawHeadersToHTTPHeader(rh parser.RawHeaders) gohttp.Header {
	if rh == nil {
		return make(gohttp.Header)
	}
	h := make(gohttp.Header, len(rh))
	for _, hdr := range rh {
		h.Add(hdr.Name, hdr.Value)
	}
	return h
}
