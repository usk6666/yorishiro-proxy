package http

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// headerGet returns the value of the first header matching name (case-insensitive).
func headerGet(headers []envelope.KeyValue, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// headerDel removes all headers matching name (case-insensitive).
func headerDel(headers []envelope.KeyValue, name string) []envelope.KeyValue {
	n := 0
	for _, h := range headers {
		if !strings.EqualFold(h.Name, name) {
			headers[n] = h
			n++
		}
	}
	for i := n; i < len(headers); i++ {
		headers[i] = envelope.KeyValue{}
	}
	return headers[:n]
}

// headerAdd appends a header (allows duplicates).
func headerAdd(headers []envelope.KeyValue, name, value string) []envelope.KeyValue {
	return append(headers, envelope.KeyValue{Name: name, Value: value})
}

// reconstructURL builds a full URL string from HTTPMessage fields.
// Used for TargetURL safety matching. No net/url dependency.
func reconstructURL(msg *envelope.HTTPMessage) string {
	var b strings.Builder
	if msg.Scheme != "" {
		b.WriteString(msg.Scheme)
		b.WriteString("://")
	}
	b.WriteString(msg.Authority)
	b.WriteString(msg.Path)
	if msg.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(msg.RawQuery)
	}
	return b.String()
}

// allHeadersString concatenates all headers in wire order for TargetHeaders matching.
// No normalization — wire casing and order preserved.
func allHeadersString(headers []envelope.KeyValue) string {
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	return b.String()
}

// containsCRLF checks if a string contains CR or LF characters.
// Used for CWE-113 CRLF injection prevention in header actions.
func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}
