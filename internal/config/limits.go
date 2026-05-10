package config

// Body and message size limits for protocol handlers and MCP tools.
//
// These constants were previously scattered across individual protocol handlers.
// They are centralized here to ensure consistency and simplify future adjustments.
//
// MaxBodySize (254 MB) is the disk-persistence cap: it bounds the largest
// single body that may be written as one SQLite BLOB row, set to one-quarter
// of SQLite's default BLOB maximum (1 GB) to stay well within the database
// engine's capabilities. It is NOT the per-connection RAM cap. Bodies larger
// than DefaultBodySpillThreshold (10 MiB, see internal/config/body_spill.go)
// spill to disk via the bodybuf memory-then-spill BodyBuffer introduced in
// USK-630, so the in-memory footprint of a single body is bounded by
// BodySpillThreshold rather than by MaxBodySize.
//
// CWE-770 note: these limits serve as a defense against resource exhaustion.
// The per-connection RAM worst case (request + response in flight) is bounded
// by:
//
//	BodySpillThreshold × 2 (req + resp) × MaxConnections
//	= 10 MiB × 2 × 128 ≈ 2.5 GiB
//
// The default MaxConnections (DefaultMaxConnections = 128 in
// internal/connector/listener_common.go) is chosen with this RAM ceiling in
// mind. Operators should consider total memory capacity and adjust
// MaxConnections via the proxy_start MCP tool or configure_limits when
// running under heavy load.

const (
	// MaxBodySize is the unified maximum size for both reading upstream
	// response bodies into memory and recording bodies to the flow store.
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

	// MaxTCPPluginChunkSize limits the size of a TCP chunk after plugin
	// modification. The relay buffer is 32 KB, so this allows a maximum
	// 32× expansion by plugins (CWE-400 mitigation).
	MaxTCPPluginChunkSize int64 = 1 << 20 // 1 MB

	// MaxSSEEventSize limits the maximum raw byte size of a single SSE event.
	// This prevents memory exhaustion from maliciously large events (CWE-400).
	MaxSSEEventSize = 1 << 20 // 1 MB

	// MaxSSEEventsPerStream limits the number of SSE events recorded per
	// stream. Once exceeded, events are still forwarded to the client but
	// no longer recorded to the flow store. This prevents unbounded DB growth
	// from very long-lived SSE streams (CWE-400 against the SQLite flow
	// store).
	//
	// The default is intentionally larger than MaxGRPCMessagesPerStream
	// because AI streaming token-event endpoints (e.g. OpenAI / Anthropic
	// completion streams) routinely exceed 10000 events per stream while
	// remaining a single logical interaction worth fully recording.
	//
	// Wired via internal/pipeline/RecordStep.WithSSEMaxEventsPerStream and
	// connector.BuildConfig.SSEMaxEventsPerStream (USK-802).
	MaxSSEEventsPerStream = 100000

	// MaxGRPCMessagesPerStream limits the number of gRPC GRPCDataMessage
	// envelopes recorded per stream. Once exceeded, messages are still
	// forwarded upstream / to the client but no longer recorded to the flow
	// store. This prevents unbounded DB growth from very long-lived gRPC
	// streams (CWE-400 against the SQLite flow store).
	//
	// GRPCStartMessage and GRPCEndMessage envelopes are bounded (≤2 per
	// stream) and always recorded; only the per-data envelopes are gated by
	// this cap.
	//
	// Wired via internal/pipeline/RecordStep.WithGRPCMaxMessagesPerStream and
	// connector.BuildConfig.GRPCMaxMessagesPerStream (USK-802).
	MaxGRPCMessagesPerStream = 10000

	// MaxWebSocketFrameSize limits the maximum payload size of a single
	// WebSocket frame. WebSocket frames can theoretically be up to 2^63
	// bytes per RFC 6455; this constant caps them at 16 MiB to prevent
	// memory exhaustion (CWE-400). It is the default for the
	// WSLayer.WithMaxFrameSize Option and the wire-side validation cap
	// applied by the WebSocket frame parser.
	MaxWebSocketFrameSize int64 = 16 << 20 // 16 MiB

	// DefaultMaxRawCaptureSize is the default cap on per-message HTTP/1.x
	// raw-bytes capture (header section + memory-mode body capture) when
	// Config.MaxRawCaptureSize is zero. It mirrors the
	// internal/layer/http1/parser.MaxRawCaptureSize package constant; the
	// values are kept in sync via TestLimits_MaxRawCaptureSize_MirrorsParser
	// so that ResolveMaxRawCaptureSize need not import the parser package
	// (config does not depend on internal/layer/...).
	//
	// Memory-mode only: when body spill is configured (see USK-769 /
	// USK-772), the body sink switches to a disk-backed BodyBuffer bounded
	// by MaxBodySize and this cap no longer applies to body bytes.
	DefaultMaxRawCaptureSize int64 = 2 << 20 // 2 MiB
)
