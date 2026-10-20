package grpcweb

import "github.com/usk6666/yorishiro-proxy/internal/envelope"

// RawWinsSupported reports whether this Layer's Send can write a plugin's
// msg["raw"] on env verbatim (RFC-001 §9.3 D4 "Raw wins"). The Pipeline
// consults it through the route's WireEncoderRegistry before RecordStep,
// so a refused raw write never becomes a recorded modified variant that
// the wire did not carry.
//
//   - GRPCStartMessage → false, unless the Start carries a malformed-body
//     anomaly. A regular Start's Raw is a header snapshot that
//     sendStartLocked never writes (the HTTP request/response head is
//     rebuilt from the struct fields on both HTTP/1.x and HTTP/2
//     transports). The malformed-body passthrough Start is the exception:
//     its Raw is the forwarded body, which sendEndLocked writes verbatim
//     (mirrors the sendStartLocked condition).
//   - GRPCDataMessage / GRPCEndMessage → true. Both are LPM frames inside
//     the body that the Layer appends verbatim when Raw is non-empty.
//
// A nil env (or nil Message) has nothing to refuse and reports true.
func RawWinsSupported(env *envelope.Envelope) bool {
	if env == nil {
		return true
	}
	if m, ok := env.Message.(*envelope.GRPCStartMessage); ok {
		return m != nil && hasMalformedBodyAnomaly(m.Anomalies)
	}
	return true
}
