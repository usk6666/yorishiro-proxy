// Package grpc implements the gRPC application Layer for RFC-001. It is a
// wrapper Layer that consumes the event-granular HTTP/2 stream Channel
// produced by internal/layer/http2 (N6.7) and emits one Envelope per gRPC
// event:
//
//   - *envelope.GRPCStartMessage  — translated from H2HeadersEvent (initial
//     HEADERS frame on either direction).
//   - *envelope.GRPCDataMessage   — produced by length-prefixed-message
//     (LPM) reassembly across one or more H2DataEvent payloads.
//   - *envelope.GRPCEndMessage    — translated from H2TrailersEvent or, in
//     the trailers-only response case, synthesized from the same
//     END_STREAM HEADERS frame that produced the GRPCStartMessage.
//
// Boundary:
//
//   - Wrap consumes a layer.Channel that yields HTTP/2 events and the
//     pre-peeked first H2HeadersEvent envelope (typically obtained by the
//     connector's gRPC content-type detection). The wrapper is a strict
//     upper-layer boundary: Pipeline never sees the raw H2*Event types
//     through the wrapped Channel.
//   - Detection of "this stream is gRPC" is owned by the connector's
//     dispatchH2Stream helper (internal/connector/h2_dispatch.go). This
//     package contains no detection logic.
//
// LPM reassembly:
//
//   - The 5-byte gRPC LPM prefix (1 compressed byte + 4-byte big-endian
//     length) is parsed across H2DataEvent boundaries. A single LPM may
//     span many DATA events; one DATA event may carry many LPMs.
//   - Per-channel reassembly buffer is bounded by config.MaxGRPCMessageSize
//     (254 MiB). Exceeding the cap yields *layer.StreamError{
//     Code: ErrorInternalError} and marks the wrapper terminated.
//
// Compression policy (D2 — strict):
//
//   - v1 supports only "identity" (no-op) and "gzip" (compress/gzip).
//   - Any other grpc-encoding on a Compressed=true LPM returns
//     *layer.StreamError{Code: ErrorProtocol} from Next or Send.
//
// Path parsing (D1 — tolerant):
//
//   - Service / Method are extracted from :path with the scheme
//     "/Service/Method". Malformed :path values (missing, empty, no
//     leading slash, no separator, single segment) yield Service="" and
//     Method="" together with a Warn log. The malformed path is surfaced
//     to Pipeline rather than hidden, for diagnostic purposes — the
//     Envelope.Raw still contains the original wire bytes.
//
// Sequence numbering (D3):
//
//   - Per-channel monotonic counter starting at 0; incremented on every
//     emitted Envelope regardless of direction. This is correct for
//     bidirectional streams; the issue spec's unary-only "Start=0,
//     Data=1..N, Start(resp)=N+1, ..." scheme is intentionally rejected.
//
// Trailers-only response (D4):
//
//   - When a Receive-side H2HeadersEvent arrives with EndStream=true and
//     Headers carry "grpc-status", the wrapper emits BOTH a
//     GRPCStartMessage envelope (sequence N) AND a synthetic
//     GRPCEndMessage envelope (sequence N+1) parsed from the same
//     headers. The synthetic End envelope has Envelope.Raw=nil.
//
// Synthetic firstHeaders (D5):
//
//   - Wrap callers on the upstream side may pass a synthetic startup
//     signal as firstHeaders. When firstHeaders.Raw is nil or empty the
//     wrapper discards it; the first Next call reads a real envelope
//     from the inner Channel. When firstHeaders.Raw is non-empty, it is
//     replayed as the first emitted envelope.
//
// Metadata strip (D7):
//
//   - GRPCStartMessage.Metadata excludes pseudo-headers (any name
//     starting with ':'), content-type, grpc-encoding,
//     grpc-accept-encoding, and grpc-timeout — those values surface on
//     dedicated GRPCStartMessage fields. Order and case of remaining
//     metadata are preserved.
//   - GRPCEndMessage.Trailers excludes grpc-status, grpc-message, and
//     grpc-status-details-bin. Order and case are preserved.
//
// Send direction:
//
//   - GRPCStartMessage / GRPCEndMessage envelopes always rebuild the
//     HPACK header field list from struct fields; Envelope.Raw on
//     headers is informational only.
//   - GRPCDataMessage envelopes prefer Envelope.Raw verbatim when
//     non-empty (5-byte LPM prefix + payload). Otherwise the wrapper
//     re-encodes Payload using Compressed + the negotiated grpc-encoding
//     (must be identity or gzip per D2).
//
// Concurrency:
//
//   - Single-reader / single-writer per Channel contract. One mutex
//     protects the reassembly buffer, encoding cache, sequence counter,
//     and terminated flag. Close uses sync.Once to cascade inner.Close.
//
// References:
//
//   - RFC-001 §3.2.3 (gRPC Message types), §3.3.2 (Layer/Channel),
//     §9.2 (gRPC granularity resolution).
//   - RFC-001 implementation guide §7 Friction 4-A (peek before wrap),
//     4-B (envelope granularity), 4-D (HTTP/2 split aftermath).
//   - gRPC HTTP/2 spec — https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
package grpc
