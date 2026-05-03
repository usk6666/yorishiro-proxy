package http2

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// hpackToKV converts hpack header fields to []exchange.KeyValue for the
// intercept engine/queue API, skipping pseudo-headers.
func hpackToKV(fields []hpack.HeaderField) []exchange.KeyValue {
	var kv []exchange.KeyValue
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		kv = append(kv, exchange.KeyValue{Name: hf.Name, Value: hf.Value})
	}
	return kv
}

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

// hpackToRawHeadersWithHost converts hpack header fields to parser.RawHeaders,
// skipping pseudo-headers and inserting a Host header derived from the :authority
// pseudo-header or the provided host value. HTTP/2 hop-by-hop headers
// (Connection, Keep-Alive, Proxy-Connection, Transfer-Encoding, Upgrade) are
// also removed since they are not valid in HTTP/1.1 proxied requests converted
// from HTTP/2.
func hpackToRawHeadersWithHost(fields []hpack.HeaderField, host string) parser.RawHeaders {
	var rh parser.RawHeaders
	// Add Host header first, as HTTP/1.1 convention expects it early.
	if host != "" {
		rh = append(rh, parser.RawHeader{Name: "Host", Value: host})
	}
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		// Skip HTTP/2 hop-by-hop headers that should not be forwarded to HTTP/1.1.
		switch strings.ToLower(hf.Name) {
		case "host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			continue
		case "te":
			if !strings.EqualFold(hf.Value, "trailers") {
				continue
			}
		}
		rh = append(rh, parser.RawHeader{Name: hf.Name, Value: hf.Value})
	}
	return rh
}

// rawHeadersToHpackLower converts parser.RawHeaders to hpack header fields,
// lowercasing header names per RFC 9113 (HTTP/2 headers must be lowercase).
// Used when converting HTTP/1.1 response headers for relay to an HTTP/2 client.
func rawHeadersToHpackLower(rh parser.RawHeaders) []hpack.HeaderField {
	fields := make([]hpack.HeaderField, 0, len(rh))
	for _, h := range rh {
		fields = append(fields, hpack.HeaderField{Name: strings.ToLower(h.Name), Value: h.Value})
	}
	return fields
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

// setRawHeader replaces the first occurrence of name (case-insensitive) with
// the given value, or appends a new header if none exists. Returns the
// modified slice.
func setRawHeader(rh parser.RawHeaders, name, value string) parser.RawHeaders {
	for i, h := range rh {
		if strings.EqualFold(h.Name, name) {
			rh[i].Value = value
			return rh
		}
	}
	return append(rh, parser.RawHeader{Name: name, Value: value})
}

// hpackToKeyValues converts hpack header fields to []exchange.KeyValue,
// skipping pseudo-headers. This is used by the safety engine API.
func hpackToKeyValues(fields []hpack.HeaderField) []exchange.KeyValue {
	var kvs []exchange.KeyValue
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		kvs = append(kvs, exchange.KeyValue{Name: hf.Name, Value: hf.Value})
	}
	return kvs
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

// keyValuesToHpack converts []exchange.KeyValue to hpack header fields.
// No pseudo-headers are added.
func keyValuesToHpack(kv []exchange.KeyValue) []hpack.HeaderField {
	fields := make([]hpack.HeaderField, 0, len(kv))
	for _, h := range kv {
		fields = append(fields, hpack.HeaderField{Name: h.Name, Value: h.Value})
	}
	return fields
}
