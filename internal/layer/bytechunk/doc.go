// Package bytechunk implements a single-channel Layer that wraps a net.Conn
// and yields [envelope.RawMessage] envelopes for each Read() call.
//
// This is the identity layer for raw TCP passthrough and TLS-terminate-only
// diagnostic mode (HTTP request smuggling). See RFC-001 section 3.3.1.
//
// Each Read() from the underlying connection produces exactly one Envelope.
// No accumulation or framing is applied — chunk boundaries are determined
// by the OS TCP stack. This is intentional: the proxy observes wire reality
// without imposing its own segmentation.
//
// The Layer owns the connection passed at construction time. Close() closes
// the underlying connection.
package bytechunk
