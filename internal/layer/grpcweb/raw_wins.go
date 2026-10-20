package grpcweb

import "github.com/usk6666/yorishiro-proxy/internal/envelope"

// RawWinsSupported reports whether this Layer's Send can write a plugin's
// msg["raw"] on env verbatim (RFC-001 §9.3 D4).
func RawWinsSupported(env *envelope.Envelope) bool {
	return true
}
