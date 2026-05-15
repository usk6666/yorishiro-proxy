// Package flow wire_level constants (USK-889).
//
// wire_level discriminates between the canonical L7 "semantic" envelope view
// (HTTPMessage / WSMessage / SSEMessage / GRPCStartMessage / ...) and a
// frame-level envelope produced by a per-stream sub-stack overlay (RFC-001
// §3.4.1). The v1 set covers the immediate need from USK-889: H2 DATA
// frames recorded under the WS-over-h2 / SSE-over-h2 detach paths. Future
// wire_level values (ws-frame, sse-chunk, grpc-lpm-frame, ...) are scoped
// to follow-up Issues; the schema-level column is open enough to admit them
// without another migration.
//
// Storage: persisted in the flows.wire_level column added by schemaV14, with
// DEFAULT 'semantic'. The flows UNIQUE constraint is widened to
// (stream_id, sequence, direction, variant, wire_level) so a frame envelope
// can coexist with the semantic envelope it overlays under the same
// stream_id (AC literal "同一 StreamID") without colliding on the sequence
// space.

package flow

// Canonical wire_level values stamped on Flow.WireLevel and persisted in
// the flows.wire_level column (USK-889). Producers must use these constants
// rather than string literals so a future renaming surfaces at compile time
// across every call site.
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
)
