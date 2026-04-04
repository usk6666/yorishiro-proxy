package exchange

import "strings"

// headerValue returns the value of the first entry in headers whose name
// matches the given name case-insensitively. Returns "" if not found.
func headerValue(headers []KeyValue, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// setHeader updates the value of the first entry in headers whose name matches
// case-insensitively. If no match is found, a new entry is appended. The
// original name casing of the matched entry is preserved; for new entries the
// provided name is used as-is.
func setHeader(headers []KeyValue, name, value string) []KeyValue {
	for i, h := range headers {
		if strings.EqualFold(h.Name, name) {
			headers[i].Value = value
			return headers
		}
	}
	return append(headers, KeyValue{Name: name, Value: value})
}

// delHeader removes all entries from headers whose name matches
// case-insensitively. It returns the resulting slice.
func delHeader(headers []KeyValue, name string) []KeyValue {
	n := 0
	for _, h := range headers {
		if !strings.EqualFold(h.Name, name) {
			headers[n] = h
			n++
		}
	}
	// Clear trailing references to allow GC.
	for i := n; i < len(headers); i++ {
		headers[i] = KeyValue{}
	}
	return headers[:n]
}
