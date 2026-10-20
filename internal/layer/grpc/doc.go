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
//   - The cap applies BOTH to the wire LPM length (the 4-byte length
//     prefix) AND to the decompressed length after gunzip — the latter
//     is enforced via io.LimitReader inside gunzip to mitigate
//     CWE-409 / CWE-400 (decompression bomb).
//   - END_STREAM while an LPM is still incomplete yields
//     *layer.StreamError{Code: ErrorProtocol}.
//   - In both failure cases the observed bytes of the incomplete LPM are
//     handed to the WithLPMFrameRecordCallback hook as a
//     wire_level=grpc-lpm-frame row carrying AnomalyGRPCLPMTooLarge or
//     AnomalyGRPCLPMTruncated (USK-1254). Recording only — the stream
//     terminates exactly as it did before, and nothing is forwarded.
//   - A bidirectional gRPC stream holds two reassembler buffers (one
//     per direction), so worst-case in-flight memory per stream is
//     2 * MaxGRPCMessageSize (CWE-770; same envelope as the body limits
//     documented in internal/config/limits.go).
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
//     Method="" together with a Debug log — Debug rather than Warn since
//     USK-1075, because the trigger is client-controlled and fires once
//     per stream with no dedup. The malformed path is surfaced to
//     Pipeline rather than hidden, for diagnostic purposes — the
//     Envelope.Raw still contains the original wire bytes.
//
// Sequence numbering (D3):
//
//   - Per-channel monotonic counter starting at 0; incremented on every
//     emitted Envelope regardless of direction. This is correct for
//     bidirectional streams; the issue spec's unary-only "Start=0,
//     Data=1..N, Start(resp)=N+1, ..." scheme is intentionally rejected.
//
// Response ending on its HEADERS frame (D4, USK-1251):
//
//   - When a Receive-side H2HeadersEvent arrives with EndStream=true, the
//     wrapper emits BOTH a GRPCStartMessage envelope (sequence N) AND a
//     synthetic GRPCEndMessage envelope (sequence N+1, Envelope.Raw=nil).
//     For a trailers-only response (Headers carry "grpc-status") the End
//     is parsed from the same headers; its Trailers list the frame's
//     other entries, content-type included, because in this form the
//     HEADERS frame is the trailer block. Without any grpc-status (e.g.
//     a load balancer's bare 503) the End is a Status=0 placeholder
//     stamped AnomalyGRPCMissingStatus.
//   - The opposite-side Send defers that Start's HEADERS and writes it
//     with the End as ONE HEADERS frame with END_STREAM: the observed
//     header list, no fabricated content-type or grpc-status. An End
//     status / message / details edit (detected against a snapshot of the
//     emitted End kept on the Opaque) is written into the matching
//     entries in place; a Start-side edit is relayed as edited; an End
//     Trailers edit falls back to HEADERS + TRAILERS rebuilt from the End.
//     A Data Send in between flushes the HEADERS first without
//     END_STREAM. When the Start was Clone()d (no Opaque, not deferred),
//     an untouched placeholder End is sent as an empty END_STREAM DATA
//     frame instead of a fabricated grpc-status trailer.
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
//   - The stripped control entries' observed names, raw values and
//     positions (anchored among the retained Metadata) are recorded on the
//     Start envelope's Opaque together with a snapshot of the parsed
//     fields (USK-1251, mirroring the gRPC-Web Layer's USK-1219 layout).
//
// Send direction:
//
//   - GRPCStartMessage / GRPCEndMessage envelopes rebuild the HPACK
//     header field list from struct fields; Envelope.Raw on headers is
//     informational only.
//   - A Start carrying this Layer's Opaque gets its observed control
//     header layout back: verbatim while the structured field is
//     unchanged (duplicates and unparseable values survive), value
//     rewritten in place when edited, dropped when cleared, synthesized at
//     the front only when never observed. No default content-type and no
//     "te: trailers" is added on this path (the client's omission is not
//     repaired). A Start without the Opaque (Envelope.Clone — intercept
//     modify_and_forward — or synthetic producers: resend_grpc, fuzz_grpc,
//     RESPOND_GRPC) keeps the synthesized layout: content-type (default
//     application/grpc), grpc-encoding, grpc-accept-encoding,
//     grpc-timeout, "te: trailers" on requests, then Metadata.
//   - A Receive Start's :status is GRPCStartMessage.HTTPStatus, the
//     upstream's observed status (USK-1251); 200 when it is zero.
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
