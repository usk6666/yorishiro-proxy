package http2

import (
	gohttp "net/http"
	"net/textproto"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// httpHeaderToRawHeaders converts net/http.Header to parser.RawHeaders.
// Header name casing is preserved as-is.
func httpHeaderToRawHeaders(h gohttp.Header) parser.RawHeaders {
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

// rawHeadersToHTTPHeader converts parser.RawHeaders back to net/http.Header.
func rawHeadersToHTTPHeader(rh parser.RawHeaders) gohttp.Header {
	if rh == nil {
		return make(gohttp.Header)
	}
	h := make(gohttp.Header, len(rh))
	for _, hdr := range rh {
		h.Add(hdr.Name, hdr.Value)
	}
	return h
}

// hpackGetHeader returns the first value for the given header name from hpack
// fields, performing a case-insensitive comparison. Returns "" if not found.
func hpackGetHeader(fields []hpack.HeaderField, name string) string {
	for _, hf := range fields {
		if strings.EqualFold(hf.Name, name) {
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
		key := textproto.CanonicalMIMEHeaderKey(hf.Name)
		m[key] = append(m[key], hf.Value)
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
		key := textproto.CanonicalMIMEHeaderKey(hf.Name)
		if existing, ok := m[key]; ok {
			if list, ok := existing.([]any); ok {
				m[key] = append(list, hf.Value)
			}
		} else {
			m[key] = []any{hf.Value}
		}
	}
	return m
}
