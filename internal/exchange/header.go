package exchange

import "strings"

// headerValues returns the values of all entries in headers whose name
// matches the given name case-insensitively. Returns nil if none found.
func headerValues(headers []KeyValue, name string) []string {
	var vals []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			vals = append(vals, h.Value)
		}
	}
	return vals
}

// HeaderGet returns the value of the first header matching name
// (case-insensitive). Returns empty string if not found.
func HeaderGet(headers []KeyValue, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// HeaderSet sets the first header matching name to value (case-insensitive),
// or appends a new entry if not found. The original or provided name case is
// preserved.
func HeaderSet(headers []KeyValue, name, value string) []KeyValue {
	for i, h := range headers {
		if strings.EqualFold(h.Name, name) {
			headers[i].Value = value
			return headers
		}
	}
	return append(headers, KeyValue{Name: name, Value: value})
}

// HeaderDel removes all headers matching name (case-insensitive).
func HeaderDel(headers []KeyValue, name string) []KeyValue {
	n := 0
	for _, h := range headers {
		if !strings.EqualFold(h.Name, name) {
			headers[n] = h
			n++
		}
	}
	// Clear removed entries to avoid dangling references.
	for i := n; i < len(headers); i++ {
		headers[i] = KeyValue{}
	}
	return headers[:n]
}
