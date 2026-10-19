// Package grpcweb implements the GRPCWebLayer wrapper Channel.
//
// GRPCWebLayer consumes a lower [layer.Channel] that yields aggregated
// [envelope.HTTPMessage] envelopes (either an HTTP/1.x Channel or an
// HTTPAggregator-wrapped HTTP/2 Channel — see Friction 4-C in
// docs/rfc/envelope-implementation.md) and surfaces gRPC-Web traffic as
// [envelope.GRPCStartMessage] / [envelope.GRPCDataMessage] /
// [envelope.GRPCEndMessage] envelopes per RFC-001 §3.2.3 and §3.3.2.
//
// # Channel-type-agnostic
//
// Wrap accepts any [layer.Channel] whose Next produces *envelope.HTTPMessage
// envelopes. It does not type-assert on the inner Channel implementation
// (Friction 4-C). HTTP/1.x bodies arrive fully buffered (Body or BodyBuffer
// non-nil); HTTP/2 bodies arrive aggregated by httpaggregator.
//
// # Wire formats
//
// gRPC-Web supports two wire formats discriminated by Content-Type:
//
//   - application/grpc-web[+proto|+json]      — binary LPM frames
//   - application/grpc-web-text[+proto|+json] — base64-encoded LPM frames
//
// On Receive, this Layer detects the encoding from the inbound HTTPMessage's
// content-type header and parses LPM (Length-Prefixed Message) frames out
// of the body. For binary wire, Envelope.Raw on emitted GRPCDataMessage /
// GRPCEndMessage envelopes carries the raw 5-byte prefix + payload bytes.
// For base64 wire, Envelope.Raw is kept in its base64-encoded form (issue
// USK-641 spec: "base64 の場合は base64 encoded のまま、binary はそのまま").
//
// # Send-side flush convention (D6)
//
// On the Send-side request path the caller must push a
// *envelope.GRPCEndMessage envelope (Status: 0, Trailers: nil) with
// Direction=Send to signal end-of-direction. This is a Layer-INTERNAL flush
// marker, NOT a wire trailer: gRPC-Web requests do not carry an embedded
// trailer frame. Receiving this sentinel triggers HTTPMessage assembly and
// inner.Send of the assembled HTTP request.
//
// RoleServer.Next emits the sentinel itself (USK-780): when an inbound
// request HTTPMessage has been split into Start + Data*, the Layer appends
// a synthetic Send-direction GRPCEndMessage{Status: 0, Raw: nil} so the
// session loop forwards it to the upstream-side RoleClient.Send via the
// Pipeline. Without this synthesis the upstream Send buffer never flushes
// and well-formed unary RPCs hang at the upstream wire. The lifecycle
// (grpc-web, on_end) hook is suppressed on this path — request-side Ends
// have no grpc-status to observe.
//
// On the Receive-side response path (RoleServer responding), the caller's
// final Send is a *envelope.GRPCEndMessage with Direction=Receive; this
// Layer encodes an embedded gRPC-Web trailer LPM frame (flags MSB=1) into
// the outbound HTTPMessage body, alongside any prior GRPCDataMessage
// payloads. A Receive End stamped AnomalyMissingGRPCWebTrailer is the
// placeholder for a trailer the upstream never sent, so no trailer frame is
// synthesized for it.
//
// A Receive HTTPMessage with an empty body still yields Start + End
// (USK-1219): the End carries the grpc-status / grpc-message of a
// trailers-only response read from the HTTP headers, or the
// AnomalyMissingGRPCWebTrailer placeholder when there is none (e.g. a bare
// 503). The opposite-side Send writes such a response with an empty body —
// a trailers-only status already travels in the headers, so no trailer
// frame is added; an edit to that End is written back into those header
// entries in place. A 1xx informational response (100, 103) is not final:
// it yields only a Start and no End.
//
// # Status, path and query (USK-1219, USK-1069 / USK-1110)
//
// The response status and reason are projected onto
// GRPCStartMessage.HTTPStatus / HTTPStatusReason and relayed by the
// opposite-side Send; a Start without one (synthetic producers, or a live
// response whose status line / :status the inner Layer could not parse and
// left at 0) is written as 200 OK. On the request side Path / RawQuery are projected from the
// inner HTTPMessage and the Send side resolves the path with pathForStart
// (the observed path wins when parseServiceMethod cannot represent it) and
// forwards RawQuery for the inner HTTP Layer to rejoin.
//
// # Malformed bodies, request trailers and framing headers (USK-1203)
//
// A body that fails to parse (malformed base64 / LPM / trailer) is emitted
// as a Start carrying the anomaly and the whole observed body on
// Envelope.Raw, followed by a sentinel End stamped with the same anomaly
// (no trailer observed; never re-encoded into a trailer frame) — in both
// directions. The opposite-side Send treats the Raw of a Start carrying a
// malformed-body anomaly as a passthrough body and forwards it verbatim, so
// the anomaly is recorded AND the observed bytes reach the next hop; Raw on
// any other Start is ignored. Start Transform rules and intercept overrides
// keep that Raw (envelope.IsGRPCWebPassthroughStart), and the Input
// SafetyFilter's payload/body rules are evaluated against it, since no
// GRPCDataMessage is emitted for an unparsed body. An observed request
// trailer frame
// (AnomalyUnexpectedGRPCWebRequestTrailer) is likewise forwarded, not
// stripped.
//
// The assembled HTTPMessage carries the observed Content-Length /
// Transfer-Encoding headers reconciled with the re-assembled body: a
// Content-Length that no longer matches is rewritten in place, and
// Transfer-Encoding is dropped in favour of Content-Length (the chunk
// boundaries are not reproduced on the next hop). See reconcileBodyFraming.
//
// # Metadata strip set (D7)
//
// On Receive, GRPCStartMessage.Metadata excludes the following entries
// (case-insensitive comparison): pseudo-headers (any name beginning with
// ':' — defensive against H2-aggregator inputs), content-type,
// grpc-encoding, grpc-accept-encoding, grpc-timeout. The stripped values
// populate ContentType, Encoding, AcceptEncoding, Timeout respectively.
// Order and casing of remaining Metadata entries are preserved.
//
// The stripped entries' observed names, raw values and positions are
// recorded on the per-RPC Opaque, and the opposite-side Send restores them
// (rebuildStartHeaders): verbatim while the structured field is unchanged,
// rewritten in place when edited, dropped when cleared, synthesized
// lowercase at the front only when never observed. An Envelope that lost
// its Opaque (Envelope.Clone) gets the synthesized layout.
//
// On Receive, GRPCEndMessage.Trailers excludes grpc-status, grpc-message,
// and grpc-status-details-bin per RFC §3.2.3; those values populate Status,
// Message, StatusDetails respectively.
//
// # Envelope.Protocol asymmetry (D8)
//
// Emitted envelopes have Envelope.Protocol = [envelope.ProtocolGRPCWeb] —
// this tags the actual transport. Note that the Message types' Protocol()
// method returns ProtocolGRPC because GRPCStart/Data/End are shared with
// the native gRPC layer (USK-640) by type-system identity. Pipeline Steps
// that care about transport (HTTP/1 vs HTTP/2 framing, base64 vs binary)
// inspect env.Protocol; Steps that type-switch on Message see GRPC* and
// share intercept rules with native gRPC.
//
// # Compression
//
// Identity (passthrough) and gzip are supported. Other grpc-encoding values
// produce a [layer.StreamError] with Code=ErrorInternalError on both Send
// and Receive paths.
//
// # Concurrency
//
// One Channel per RPC. Internal mutex serializes Next emission cursor
// (one inbound HTTPMessage produces N+1 emitted envelopes) and Send-side
// assembly buffer.
package grpcweb
