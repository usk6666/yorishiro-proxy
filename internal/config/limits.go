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

const (
	// MaxBodySize is the unified maximum size for both reading upstream
	// response bodies into memory and recording bodies to the session store.
	// Previously two separate limits (maxResponseBodySize=64MB and
	// maxBodyRecordSize=1MB), now unified at 254 MB so that entire
	// responses can be captured and stored.
	MaxBodySize int64 = 254 << 20 // 254 MB

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
	// session store.
	MaxWebSocketRecordPayloadSize = 254 << 20 // 254 MB

	// MaxReplayResponseSize limits the response body size for MCP replay
	// (resend / resend_raw / tcp_replay) operations.
	MaxReplayResponseSize int64 = 254 << 20 // 254 MB

	// MaxImportScannerBuffer is the maximum per-line buffer size for the
	// JSONL import scanner. A 254 MB body base64-encodes to ~339 MB, so
	// 350 MB provides adequate headroom for a full JSONL line.
	MaxImportScannerBuffer = 350 * 1024 * 1024 // 350 MB
)
