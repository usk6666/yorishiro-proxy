// Package http2 implements the HTTP/2 Layer for RFC-001.
//
// One Layer corresponds to one TCP connection (or one TLS session over one
// TCP connection). One Channel corresponds to one HTTP/2 stream — including
// server-pushed streams.
//
// # Architecture
//
// The Layer owns a frame.Reader and a frame.Writer. A single reader goroutine
// reads frames sequentially and dispatches them to per-stream assembler state
// stored in a connection-scoped map. A single writer goroutine reads write
// requests from a queue and serializes them to the wire. This single-writer
// design satisfies the HPACK encoder's sequential-encoding requirement (RFC
// 7541 §4.1) and avoids mid-frame interleaving.
//
// HPACK decoding happens in the reader goroutine; HPACK encoding happens in
// the writer goroutine. Neither codec is shared between goroutines.
//
// # Channel semantics
//
// A Channel does NOT assume request/response pairing. Sequence is event-order,
// numbered from 0. For client-initiated streams the typical event order is
// (Send request, Receive response). For server-pushed streams the first event
// is a Receive (no client-side request — the synthetic request that triggered
// the push is delivered as a separate envelope on the original stream's
// Channel, carrying the H2PushPromise anomaly).
//
// # Endpoints model
//
// The Layer treats each side as an independent endpoint. Settings sent by
// the peer are applied locally but never forwarded; settings we send to the
// peer reflect our local configuration only. PING/PRIORITY/PUSH_PROMISE are
// handled locally — no upper layer sees these as control envelopes
// (PUSH_PROMISE is exposed as new Channels and a synthetic envelope, but the
// raw PUSH_PROMISE frame is not propagated as an envelope on its own).
//
// # Wire fidelity
//
// All wire bytes are preserved in Envelope.Raw. Cookie headers are recorded
// as separate KeyValue entries (no folding). HTTP/1-only headers (Connection,
// Keep-Alive, Proxy-Connection, Transfer-Encoding, Upgrade, TE other than
// "te: trailers") are kept on the message with an H2ConnectionSpecificHeader
// anomaly attached. Uppercase header names are kept verbatim with an
// H2UppercaseHeaderName anomaly. Pseudo-header order anomalies and duplicates
// are flagged via H2PseudoHeaderAfterRegular and H2DuplicatePseudoHeader.
//
// # Body buffering and passthrough
//
// Bodies are buffered up to passthroughThreshold (10 MiB) before the
// envelope is yielded to the consumer. When a stream's body exceeds that
// threshold, the assembler switches to passthrough mode: it yields the
// envelope immediately with HTTPMessage.BodyStream set to a pipe reader,
// and subsequent DATA frames are written into the pipe writer. END_STREAM
// closes the pipe writer.
//
// Trailers are not supported in passthrough mode — they are dropped. A
// counter is incremented on the Layer for diagnostic purposes; consumers
// that hold the already-yielded envelope will not see the trailers.
//
// # Flow control
//
// WINDOW_UPDATE frames are sent eagerly during body assembly: when the
// stream-level recv window has been consumed by ≥50% of the local
// InitialWindowSize, or when the connection-level recv window has been
// consumed by ≥50% of the initial 65535. This keeps backpressure in lock-
// step with consumer drain rate without holding excessive bytes in memory.
//
// # Server push send-side
//
// Channels representing server-pushed streams accept only RST_STREAM (with
// CANCEL or REFUSED_STREAM) on Send. We are never the pusher; we can only
// accept or refuse incoming pushes.
package http2
