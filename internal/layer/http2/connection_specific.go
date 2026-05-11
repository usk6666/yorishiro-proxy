package http2

import "strings"

// connectionSpecificHeaders is the RFC 7540 §8.1.2.2 / RFC 9113 §8.2.2 set of
// HTTP/1.x connection-management headers that MUST NOT appear over HTTP/2.
// The set is owned here and shared between the receive-side anomaly check
// (assembler.go regularHeaderAnomalies) and the send-side wire encoder
// (channel.go BuildHeaderFieldsFromEvent) — DRY.
//
// Receive side (USK-pre-historic): wire-fidelity rules — we do NOT strip on
// receive; we attach an envelope.H2ConnectionSpecificHeader anomaly and keep
// the header so analysts can see the upstream non-conformance.
//
// Send side (USK-840): we MUST strip because emitting any of these names
// produces an invalid HEADERS frame and peers reject the entire frame with a
// PROTOCOL_ERROR. The strip is therefore a wire-format necessity, not a
// fidelity choice. To keep the diagnostic visible we attach an
// envelope.H2ConnectionSpecificHeaderStrippedOnSend anomaly to the
// HTTPMessage so the recorded flow still surfaces the original header that
// the producer attempted to emit.
//
// "TE: trailers" is the documented exception (RFC 9113 §8.2.2) — `te` itself
// is permitted iff the value is exactly "trailers". TEAllowedValue handles
// the value check; IsConnectionSpecificHeader handles the name set.
var connectionSpecificHeaders = map[string]struct{}{
	"connection":        {},
	"keep-alive":        {},
	"proxy-connection":  {},
	"transfer-encoding": {},
	"upgrade":           {},
}

// IsConnectionSpecificHeader reports whether name (case-insensitive) is one
// of the RFC 7540 §8.1.2.2 / RFC 9113 §8.2.2 forbidden-on-HTTP/2 connection-
// management headers. The `te` header is NOT included — its handling
// requires inspecting the value via TEAllowedValue.
func IsConnectionSpecificHeader(name string) bool {
	_, ok := connectionSpecificHeaders[strings.ToLower(name)]
	return ok
}

// TEAllowedValue reports whether a `te` header value is permitted over
// HTTP/2 per RFC 9113 §8.2.2. Only the exact value "trailers" is allowed;
// every other value (including comma-lists that contain trailers among
// other tokens) is forbidden. Value comparison is case-insensitive — the
// RFC defines "trailers" as a registered keyword without explicit case
// rules but peers in practice accept either casing.
func TEAllowedValue(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "trailers")
}
