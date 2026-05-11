package http

import (
	"context"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// materializeBody returns the body bytes for msg, reading from the in-memory
// Body slice if present, or materializing via BodyBuffer.Bytes(ctx) otherwise.
// Returns (nil, nil) when msg has neither a Body slice nor a BodyBuffer.
//
// Ownership note: when the result is sourced from BodyBuffer, the returned
// slice is a defensive copy (bodybuf.BodyBuffer.Bytes) — callers may mutate
// it freely. materializeBody does not touch the refcount.
func materializeBody(ctx context.Context, msg *envelope.HTTPMessage) ([]byte, error) {
	if msg == nil {
		return nil, nil
	}
	if msg.Body != nil {
		return msg.Body, nil
	}
	if msg.BodyBuffer != nil {
		return msg.BodyBuffer.Bytes(ctx)
	}
	return nil, nil
}

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

// effectivePathAndMethod returns the path and method to evaluate against
// rule conditions for the given envelope direction. For Send (request),
// it returns the wire-observed fields from msg. For Receive (response),
// it returns the paired request's fields recorded on env.Context by the
// producing Layer (HTTP/1.x channel or HTTP/2 aggregator) — if those
// fields are empty (no paired request data available, e.g. for a
// direction:"response" rule fired on an unpaired response or when the
// producing Layer pre-dates USK-833), knowable is false and the caller
// must skip request-only condition checks.
//
// USK-833: this helper replaces the per-call `dir == envelope.Send` skip
// in intercept/transform engines so direction:"both" rules with
// path_pattern or methods conditions correctly gate on the paired
// request's identity at response phase, matching user expectations
// documented in help_configure.md.
func effectivePathAndMethod(env *envelope.Envelope, msg *envelope.HTTPMessage, dir envelope.Direction) (path, method string, knowable bool) {
	if dir == envelope.Send {
		return msg.Path, msg.Method, true
	}
	// dir == envelope.Receive: read from EnvelopeContext.
	if env.Context.RequestPath == "" && env.Context.RequestMethod == "" {
		return "", "", false
	}
	return env.Context.RequestPath, env.Context.RequestMethod, true
}
