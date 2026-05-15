// Package flow wire_level constants (USK-889, USK-895).
//
// wire_level discriminates between the canonical L7 "semantic" envelope view
// (HTTPMessage / WSMessage / SSEMessage / GRPCStartMessage / ...) and a
// frame-level envelope produced by a per-stream sub-stack overlay (RFC-001
// §3.4.1). The v1 set covers the immediate need from USK-889: H2 DATA
// frames recorded under the WS-over-h2 / SSE-over-h2 detach paths. USK-895
// extends the discriminator to HTTP/1.x Transfer-Encoding chunk boundaries
// (h1-chunk) on the SSE-over-h1-chunked path so the chunk-size line,
// chunk-extension, and trailing CRLF are observable as independent
// envelopes — closing the live diagnostic gap that hid USK-883's hex-prefix
// bug. USK-896 extends the discriminator to gRPC LPM (Length-Prefixed
// Message) frames so the per-message wire bytes (5-byte prefix +
// payload, before decompression) are observable as independent envelopes
// — closing the diagnostic gap that hid LPM length-prefix smuggling and
// compressed-flag anomalies. USK-898 extends the discriminator to
// gRPC-Web text variants (application/grpc-web-text[+proto]) so the
// pre-decode base64 wire bytes are observable as independent envelopes —
// closing the diagnostic gap that base64 padding anomalies / illegal
// characters / encoding bombs would otherwise hide behind the in-place
// decode performed by the grpcweb Layer. Future wire_level values
// (ws-frame, ...) are scoped to follow-up Issues; the schema-level column
// is open enough to admit them without another migration.
//
// Storage: persisted in the flows.wire_level column added by schemaV14, with
// DEFAULT 'semantic'. The flows UNIQUE constraint is widened to
// (stream_id, sequence, direction, variant, wire_level) so a frame envelope
// can coexist with the semantic envelope it overlays under the same
// stream_id (AC literal "同一 StreamID") without colliding on the sequence
// space.

package flow

// Canonical wire_level values stamped on Flow.WireLevel and persisted in
// the flows.wire_level column (USK-889 / USK-895). Producers must use these
// constants rather than string literals so a future renaming surfaces at
// compile time across every call site.
const (
	// WireLevelSemantic marks the canonical L7 envelope view recorded by
	// RecordStep on the main Pipeline: HTTPMessage, WSMessage, SSEMessage,
	// GRPCStartMessage, GRPCDataMessage, GRPCEndMessage, RawMessage,
	// TLSHandshakeMessage. This is the default value applied by
	// envelopeToFlow and the schemaV14 column default for backfilled rows.
	WireLevelSemantic = "semantic"

	// WireLevelH2Frame marks an H2 DATA frame envelope recorded as a
	// per-stream sub-stack overlay (RFC-001 §3.4.1) on the WS-over-h2 /
	// SSE-over-h2 detach paths. Stamped by the orchestrator-owned
	// frame-record callback wired into http2.Layer.DetachStream via
	// WithFrameRecordCallback. The Envelope.Raw on these rows is the DATA
	// frame payload only — the 9-byte frame header is reconstructable from
	// the typed *H2DataEvent EndStream field + payload length, and is
	// omitted to match the existing assembler.go semantics.
	WireLevelH2Frame = "h2-frame"

	// WireLevelHTTP1Chunk marks an HTTP/1.x Transfer-Encoding chunk-boundary
	// envelope recorded on the SSE-over-h1-chunked streaming detach path
	// (USK-895). The Envelope.Raw on these rows is the full on-wire chunk
	// syntax — chunk-size line (including any chunk-extension) + chunk-data
	// + trailing CRLF — exactly as it appeared on the wire. The terminal
	// zero-size chunk + trailer section is recorded as its own envelope.
	// Naming follows the agreed `<protocol>-<unit>` flat scheme (USK-893):
	// the chunk mechanism is HTTP/1.x's, not SSE's, so the discriminator is
	// per-protocol rather than per-payload (no `sse-chunk`).
	WireLevelHTTP1Chunk = "h1-chunk"

	// WireLevelGRPCLPMFrame marks a gRPC LPM (Length-Prefixed Message)
	// envelope recorded on the gRPC data path (USK-896). The Envelope.Raw
	// on these rows is the full on-wire LPM bytes:
	//
	//   [compressed_flag (1 byte)] [length (4 bytes BE)] [payload (length bytes)]
	//
	// Captured BEFORE decompression — the semantic GRPCDataMessage envelope
	// already exposes the decompressed payload; the LPM wire envelope is
	// the canonical record for length-prefix / compressed-flag / payload
	// boundary anomalies (LPM smuggling, compressed-flag ≠ 0/1, multi-LPM
	// packing inside one h2 DATA frame). Naming follows the agreed
	// `<protocol>-<unit>` flat scheme (USK-893): the LPM unit is gRPC's
	// own framing (distinct from h2 DATA — multiple LPMs can be packed
	// into a single h2 DATA payload), so the discriminator is per-protocol
	// rather than reusing `h2-frame`.
	WireLevelGRPCLPMFrame = "grpc-lpm-frame"

	// WireLevelGRPCWebBase64 marks a gRPC-Web text-variant body envelope
	// recorded on the gRPC-Web data path (USK-898). The Envelope.Raw on
	// these rows is the on-the-wire base64-encoded body bytes — captured
	// BEFORE base64-decode and BEFORE LPM frame parsing. The semantic
	// GRPCStartMessage / GRPCDataMessage / GRPCEndMessage envelopes
	// already expose the decoded LPM payload; the base64 wire envelope is
	// the canonical record for base64 padding anomalies, illegal
	// characters, and encoding-side smuggling that the in-place decode
	// would otherwise destroy.
	//
	// Naming follows the agreed `<protocol>-<unit>` flat scheme (USK-893
	// Q12): "grpcweb-base64" identifies both the protocol (gRPC-Web) and
	// the wire unit (the base64 text body). The choice is forward-
	// compatible: a future gRPC-Web text encoding other than base64 would
	// land on its own discriminator rather than overloading this one.
	//
	// Fired only on text variants (application/grpc-web-text[+proto] —
	// IsBase64Encoded matches both). Binary variants
	// (application/grpc-web[+proto]) do NOT fire because they never pass
	// through the base64 decode branch.
	WireLevelGRPCWebBase64 = "grpcweb-base64"
)
