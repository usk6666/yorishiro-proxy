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
// On the Receive-side response path (RoleServer responding), the caller's
// final Send is a *envelope.GRPCEndMessage with Direction=Receive; this
// Layer encodes an embedded gRPC-Web trailer LPM frame (flags MSB=1) into
// the outbound HTTPMessage body, alongside any prior GRPCDataMessage
// payloads.
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
