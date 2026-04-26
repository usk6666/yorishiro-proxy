// Package ws provides the WebSocket Layer + Channel implementing
// RFC-001 §3.3.2 on top of the byte-level frame codec (RFC 6455) and
// per-message-deflate (RFC 7692) primitives.
//
// # Layer construction
//
// A WSLayer is built on a (reader, writer, closer) triple — typically the
// triple returned by [internal/layer/http1.Layer.DetachStream] after a
// successful HTTP/1.1 Upgrade — together with a streamID, a Role, and
// optional configuration. The reader is usually a *bufio.Reader so that
// any post-CRLFCRLF bytes the HTTP/1 parser already buffered are visible
// to the WS frame parser.
//
// # Frame-per-Envelope
//
// Each parsed wire frame produces exactly one Envelope. Control frames
// (Ping/Pong/Close) and continuation frames are NOT coalesced; the
// Pipeline observes them individually. The Layer never auto-responds to
// Ping (MITM transparency).
//
// # Wire fidelity
//
// Envelope.Raw carries the verbatim wire bytes (header + extended
// length + mask key + masked payload exactly as observed) via
// [ReadFrameRaw]. RSV2/RSV3 bits are observable only on Envelope.Raw —
// the WSMessage struct does not surface them as fields. On Send the
// Layer always emits RSV2=RSV3=0; only RSV1 is set, when permessage-
// deflate compression is applied.
//
// # Compression (RFC 7692)
//
// permessage-deflate is opt-in via [WithDeflateEnabled] + per-direction
// [WithClientDeflate] / [WithServerDeflate]. The master switch
// WithDeflateEnabled(false) overrides per-direction options.
//
// Fragmented compressed messages follow RFC 7692 §6.1: the start frame
// carries RSV1=1; continuation frames carry RSV1=0 but inherit the
// compression flag. The Layer surfaces this as follows:
//
//   - Continuation envelopes (Compressed=true, Fin=false): Payload is the
//     verbatim compressed bytes for that fragment. The application can
//     observe the raw wire shape but should not attempt to decompress
//     these bytes alone — a single fragment is rarely a complete deflate
//     stream.
//
//   - The FIN frame envelope (Compressed=true, Fin=true): Payload is the
//     decompressed bytes of the entire reassembled message.
//
// Single-frame compressed messages (Fin=true on the start frame) carry
// the decompressed Payload directly.
//
// # Limitations
//
//   - No background watcher goroutine for post-EOF RST observation. If
//     the wire is closed by the peer between Next calls, the next Next
//     observes either io.EOF (graceful) or *layer.StreamError{Code:
//     ErrorAborted}. Late-RST detection across an idle Channel is owned
//     by USK-643 (Session-level RST handling).
//
//   - Send-side fragmentation is the caller's responsibility. The Layer
//     emits exactly one wire frame per Send call.
//
//   - On Send, the WSMessage.Mask field is informational. The Layer
//     regenerates the 4-byte mask key from crypto/rand for every
//     RoleClient frame per RFC 6455 §5.3 strong-entropy requirement.
//
// # Sibling files
//
//   - [frame.go]: low-level WebSocket frame codec (Read/Write).
//   - [deflate.go]: per-message-deflate state machine.
//
// Note: a parallel copy of frame.go and deflate.go exists in
// internal/protocol/ws/ during the RFC-001 transition. The legacy copy
// is consumed by internal/protocol/ws/handler.go and the existing
// resend code path; both are scheduled for removal in N9 once feature
// parity is reached.
package ws
