// Package job collects the per-protocol [EnvelopeSource] implementations
// and byte-patch utilities. The resend_raw / fuzz_raw MCP tool helpers in
// internal/mcp/ consume [RawResendSource], [BytePatch] and [ApplyPatches].
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
//
// # Byte patching
//
// [BytePatch] / [ApplyPatches] (byte_patch.go) provide a single-byte / byte-range
// patch primitive used by fuzz_raw and resend_raw to apply offset-anchored
// edits on top of a recorded raw payload.
package job
