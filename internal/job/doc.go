// Package job collects the per-protocol [EnvelopeSource] implementations
// and byte-patch utilities consumed by the resend / fuzz MCP tool helpers
// in internal/mcp/ (resend_http / resend_ws / resend_grpc / resend_raw /
// fuzz_http / fuzz_raw).
//
// # Sources
//
// Each Source rebuilds the send-direction Envelope for a recorded stream
// (optionally with overrides applied) and yields it via [EnvelopeSource.Next].
// MCP helpers drive the Source from their own send/receive loops; this
// package does not provide its own run loop.
//
//   - HTTPResendSource (http_source.go)
//   - WSResendSource   (ws_source.go)
//   - GRPCResendSource (grpc_source.go)
//   - RawResendSource  (raw_source.go)
//   - FuzzHTTPSource   (fuzz_http_source.go)
//   - FuzzRawSource    (fuzz_raw_source.go)
//
// # Byte patching
//
// [BytePatch] / [ApplyPatches] (byte_patch.go) provide a single-byte / byte-range
// patch primitive used by fuzz_raw and resend_raw to apply offset-anchored
// edits on top of a recorded raw payload.
//
// # Template expansion
//
// [ExpandEnvelopeTemplates] (template.go) applies §variable§ template
// expansion to an Envelope's Message fields using a KV store. Used by the
// fuzz Sources to inject per-iteration macro state into reconstructed
// requests.
package job
