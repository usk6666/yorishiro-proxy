package config

// Body and message size limits for protocol handlers and MCP tools.
//
// These constants were previously scattered across individual protocol handlers.
// They are centralized here to ensure consistency and simplify future adjustments.
//
// The primary limit (MaxBodySize) is set to 254 MB, which is one-quarter of
// SQLite's default BLOB maximum (1 GB). This allows recording full response
// bodies while staying well within the database engine's capabilities.
//
// CWE-770 note: these limits serve as a defense against resource exhaustion.
// Each concurrent connection may buffer up to MaxBodySize for both the request
// and response body, so the worst-case memory usage is:
//
//	MaxBodySize × 2 (req + resp) × MaxConnections
//	= 254 MB × 2 × 128 = ~63.5 GB
//
// The default MaxConnections (128, internal/proxy/listener.go) is chosen to
// keep this theoretical maximum manageable. Operators should consider total
// memory capacity and adjust MaxConnections via the proxy_start MCP tool or
// configure_limits when running under heavy load.

var (
	// MaxBodySize is the unified maximum size for both reading upstream
	// response bodies into memory and recording bodies to the flow store.
	// Previously two separate limits (maxResponseBodySize=64MB and
	// maxBodyRecordSize=1MB), now unified at 254 MB so that entire
	// responses can be captured and stored.
	// Declared as var (not const) to allow test overrides in resource-
	// constrained environments.
	MaxBodySize int64 = 254 << 20 // 254 MB
)

const (
	// MaxGRPCMessageSize limits the maximum gRPC Length-Prefixed Message
	// payload size. This prevents memory exhaustion from malicious or
	// malformed gRPC messages.
	MaxGRPCMessageSize uint32 = 254 << 20 // 254 MB

	// MaxWebSocketMessageSize limits the total assembled size of a
	// fragmented WebSocket message. This prevents unbounded memory growth
	// from continuation frame accumulation (CWE-400).
	MaxWebSocketMessageSize int64 = 254 << 20 // 254 MB

	// MaxWebSocketRecordPayloadSize limits the payload size recorded per
	// WebSocket message. Payloads exceeding this size are truncated in the
	// flow store.
	MaxWebSocketRecordPayloadSize = 254 << 20 // 254 MB

	// MaxReplayResponseSize limits the response body size for MCP replay
	// (resend / resend_raw / tcp_replay) operations.
	MaxReplayResponseSize int64 = 254 << 20 // 254 MB

	// MaxTCPPluginChunkSize limits the size of a TCP chunk after plugin
	// modification. The relay buffer is 32 KB, so this allows a maximum
	// 32× expansion by plugins (CWE-400 mitigation).
	MaxTCPPluginChunkSize int64 = 1 << 20 // 1 MB

	// MaxImportScannerBuffer is the maximum per-line buffer size for the
	// JSONL import scanner. A 254 MB body base64-encodes to ~339 MB, so
	// 350 MB provides adequate headroom for a full JSONL line.
	MaxImportScannerBuffer = 350 * 1024 * 1024 // 350 MB

	// MaxSSEEventSize limits the maximum raw byte size of a single SSE event.
	// This prevents memory exhaustion from maliciously large events (CWE-400).
	MaxSSEEventSize = 1 << 20 // 1 MB

	// MaxSSEEventsPerStream limits the number of SSE events recorded per
	// stream. Once exceeded, events are still forwarded to the client but
	// no longer recorded to the flow store. This prevents unbounded DB growth
	// from very long-lived SSE streams.
	MaxSSEEventsPerStream = 10000

	// MaxSSERecordPayloadSize limits the body size recorded per SSE event
	// message. Events exceeding this size are truncated in the flow store.
	MaxSSERecordPayloadSize = 254 << 20 // 254 MB

	// MaxGRPCMessagesPerStream limits the number of gRPC messages recorded
	// per stream. Once exceeded, messages are still forwarded to the client
	// but no longer recorded to the flow store. This prevents unbounded DB
	// growth from very long-lived gRPC streams.
	MaxGRPCMessagesPerStream = 10000
)
