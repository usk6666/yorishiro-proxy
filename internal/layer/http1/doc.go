// Package http1 implements an HTTP/1.x Layer and Channel for the RFC-001
// Envelope + Layered Connection Model.
//
// The Layer wraps a net.Conn and yields a single Channel. The Channel
// produces HTTPMessage envelopes for each HTTP request or response,
// preserving wire fidelity (header case, order, OWS, anomalies).
//
// The Channel supports two Send() paths:
//   - Opaque-based: raw-first patching with OWS preservation (normal flow)
//   - Opaque-less: synthetic serialization (for Resend/Job in N5)
package http1
