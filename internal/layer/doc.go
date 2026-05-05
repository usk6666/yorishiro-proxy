// Package layer defines the Layer and Channel abstractions for
// yorishiro-proxy's Envelope + Layered Connection Model (RFC-001).
//
// A [Layer] is a connection-level component that consumes a lower layer
// and produces one or more [Channel]s upward. Byte-stream layers (TCP, TLS)
// transform a net.Conn into another net.Conn; message-stream layers
// (HTTP/1.x, HTTP/2, WebSocket, gRPC, SSE) yield Channels.
//
// A [Channel] is the Pipeline's input/output surface. One Channel drives
// one session.RunSession invocation.
//
// # Ownership Convention
//
// By default, a Layer owns the resources it receives at construction time.
// When Close() is called, it cascades to owned lower layers and connections.
//
// When a Layer borrows resources (e.g., a WebSocket layer receiving a
// detached byte stream from an HTTP/1 layer via DetachStream), its Close()
// does NOT close the borrowed resources. Ownership is established at
// construction time and documented per-constructor.
package layer
