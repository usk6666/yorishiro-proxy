package http2

import (
	gohttp "net/http"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
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

// hpackGetHeader returns the first value for the given header name from hpack
// fields, performing a case-insensitive comparison. Returns "" if not found.
func hpackGetHeader(fields []hpack.HeaderField, name string) string {
	lower := strings.ToLower(name)
	for _, hf := range fields {
		if strings.ToLower(hf.Name) == lower {
			return hf.Value
		}
	}
	return ""
}

// hpackToGoHTTPHeader converts hpack header fields to gohttp.Header,
// skipping pseudo-headers. This is a bridge for subsystems that still
// require net/http types.
func hpackToGoHTTPHeader(fields []hpack.HeaderField) gohttp.Header {
	h := make(gohttp.Header)
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		h.Add(hf.Name, hf.Value)
	}
	return h
}

// hpackToRawHeaders converts hpack header fields to parser.RawHeaders,
// skipping pseudo-headers. This allows subsystems to work with hpack
// headers without going through gohttp.Header.
func hpackToRawHeaders(fields []hpack.HeaderField) parser.RawHeaders {
	var rh parser.RawHeaders
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		rh = append(rh, parser.RawHeader{Name: hf.Name, Value: hf.Value})
	}
	return rh
}

// hpackToGoHTTPHeaderMap converts hpack header fields to a map[string][]string
// (same as gohttp.Header / http.Header), skipping pseudo-headers.
func hpackToGoHTTPHeaderMap(fields []hpack.HeaderField) map[string][]string {
	m := make(map[string][]string)
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		m[hf.Name] = append(m[hf.Name], hf.Value)
	}
	return m
}

// hpackHeadersToPluginMap converts hpack header fields to the map format
// expected by the plugin system, skipping pseudo-headers.
func hpackHeadersToPluginMap(fields []hpack.HeaderField) map[string]any {
	m := make(map[string]any)
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		if existing, ok := m[hf.Name]; ok {
			if list, ok := existing.([]any); ok {
				m[hf.Name] = append(list, hf.Value)
			}
		} else {
			m[hf.Name] = []any{hf.Value}
		}
	}
	return m
}
