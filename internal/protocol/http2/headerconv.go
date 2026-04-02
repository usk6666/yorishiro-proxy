package http2

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// hpackGetPseudo returns the value of the first pseudo-header with the given
// name (e.g., ":method") from hpack fields. Returns "" if not found.
func hpackGetPseudo(fields []hpack.HeaderField, name string) string {
	for _, hf := range fields {
		if hf.Name == name {
			return hf.Value
		}
	}
	return ""
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

// rawHeadersToHpack converts parser.RawHeaders to hpack header fields.
// No pseudo-headers are added; call buildPseudoHeaders separately if needed.
func rawHeadersToHpack(rh parser.RawHeaders) []hpack.HeaderField {
	fields := make([]hpack.HeaderField, 0, len(rh))
	for _, h := range rh {
		fields = append(fields, hpack.HeaderField{Name: h.Name, Value: h.Value})
	}
	return fields
}

// hpackToHeaderMap converts hpack header fields to a map[string][]string,
// skipping pseudo-headers. Header name casing is preserved as-is (no
// canonicalization). This is used for flow recording where map[string][]string
// is the required type.
func hpackToHeaderMap(fields []hpack.HeaderField) map[string][]string {
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
// expected by the plugin system, skipping pseudo-headers. Header name casing
// is preserved as-is (no canonicalization).
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

// hpackDelHeader removes all hpack fields matching the given name
// (case-insensitive comparison). Returns a new slice.
func hpackDelHeader(fields []hpack.HeaderField, name string) []hpack.HeaderField {
	result := make([]hpack.HeaderField, 0, len(fields))
	for _, hf := range fields {
		if !strings.EqualFold(hf.Name, name) {
			result = append(result, hf)
		}
	}
	return result
}

// cloneHpackHeaders creates a deep copy of an hpack header field slice.
func cloneHpackHeaders(fields []hpack.HeaderField) []hpack.HeaderField {
	if fields == nil {
		return nil
	}
	clone := make([]hpack.HeaderField, len(fields))
	copy(clone, fields)
	return clone
}
