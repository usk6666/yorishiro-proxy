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
//
// MaxConnections (default DefaultMaxConnections below) is a concurrency cap
// — it bounds file descriptors and per-connection goroutines — not a RAM
// ceiling. It applies per listener (SOCKS5 shares the listener's cap) and
// separately per TCP forward entry. A nominal "every connection is moving a
// spill-threshold body in each direction" figure is:
//
//	BodySpillThreshold × 2 (req + resp) × MaxConnections
//	= 10 MiB × 2 × 512 ≈ 10 GiB
//
// That formula was never a true bound and is not one now: an HTTP/2
// connection carries up to SETTINGS_MAX_CONCURRENT_STREAMS streams, each
// with its own spill budget (see below), and WebSocket / gRPC messages are
// assembled in memory up to MaxWebSocketMessageSize / MaxGRPCMessageSize.
// Conversely, most connections a browser holds are idle keep-alive
// connections or CONNECT tunnels, which hold no body buffers at all, so the
// typical footprint is far below the nominal figure.
//
// The default is sized for a single proxied browser rather than for that
// nominal figure. Browsers pool well past the old default of 128: Chromium
// (net/socket/client_socket_pool_manager.cc) allows
// g_max_sockets_per_proxy_chain = 128 normal + 128 WebSocket sockets per
// proxy chain with g_socket_soft_cap_per_pool = 256, and Firefox
// (modules/libpref/init/all.js) sets network.http.max-connections = 900 on
// desktop. One ad-heavy page was enough to exceed 128 (USK-1141). Operators
// with tighter memory or FD budgets lower MaxConnections via the
// proxy_start / configure MCP tools.
//
// HTTP/2 stream fan-out (USK-862): the per-connection stream worst case is
// bounded by the advertised SETTINGS_MAX_CONCURRENT_STREAMS. The H2 Layer
// default (internal/layer/http2/connstate.go defaultMaxConcurrentStreams)
// was raised from 100 to 500 to support high-multiplexing pages, so the
// per-listener worst-case stream count is:
//
//	defaultMaxConcurrentStreams × MaxConnections
//	= 500 × 512 = 256,000 streams
//
// Each H2 stream's BodyBuffer obeys BodySpillThreshold individually, which
// is why the nominal RAM figure above understates a fully loaded H2
// connection. Operators concerned about goroutine or memory pressure can
// re-tighten this cap via Config.MaxConcurrentStreams (CLI
// -max-concurrent-streams / YP_MAX_CONCURRENT_STREAMS) which threads through
// connector.BuildConfig.MaxConcurrentStreams to the client-facing Layer.

// DefaultMaxConnections is the default concurrent-connection cap per
// listener and per TCP forward entry. It is the single definition: config
// seeds Config.MaxConnections from it, connector.DefaultMaxConnections
// aliases it (connector imports config, so the constant cannot live there),
// and the proxy_start MCP tool resets to it when max_connections is omitted
// (USK-407). See the CWE-770 note above for how the value was chosen.
const DefaultMaxConnections = 512

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

	// MaxHTTP2FrameRecordsPerStream limits the number of frame-level
	// envelopes (wire_level="h2-frame", typed *envelope.H2DataEvent)
	// recorded per stream on the WS-over-h2 / SSE-over-h2 detach paths
	// (USK-889). Once exceeded, the frame-record callback is suppressed
	// for further DATA frames on the affected (stream_id, direction);
	// wire forwarding is unaffected because the callback runs inside
	// runDetachDrain BEFORE pipe.Write and the suppression skips only the
	// RecordStep dispatch, not the io.Pipe relay.
	//
	// Default matches MaxGRPCMessagesPerStream so the operator's mental
	// model "long-running streaming protocols cap at ~10k events" stays
	// uniform across gRPC, SSE, and frame-level recording.
	//
	// Wired via internal/pipeline/RecordStep.WithHTTP2FrameMaxPerStream
	// (USK-889).
	MaxHTTP2FrameRecordsPerStream = 10000

	// MaxHTTP1ChunkRecordsPerStream limits the number of HTTP/1.x chunk-
	// boundary envelopes (wire_level="h1-chunk") recorded per stream on the
	// SSE-over-h1-chunked streaming detach path (USK-895). Once exceeded,
	// the per-chunk record callback is suppressed for further chunks on the
	// affected stream; wire forwarding is unaffected because the suppression
	// skips only the RecordStep dispatch, not the streaming body relay to
	// the SSE event-boundary reader.
	//
	// Default matches MaxGRPCMessagesPerStream / MaxHTTP2FrameRecordsPerStream
	// so the operator's mental model "long-running streaming protocols cap
	// at ~10k events" stays uniform across gRPC, SSE, and frame-level /
	// chunk-level recording.
	//
	// Wired via internal/pipeline/RecordStep.WithHTTP1ChunkMaxPerStream
	// (USK-895).
	MaxHTTP1ChunkRecordsPerStream = 10000

	// MaxGRPCLPMFrameRecordsPerStream limits the number of gRPC LPM
	// (Length-Prefixed Message) envelopes (wire_level="grpc-lpm-frame")
	// recorded per stream on the gRPC data path (USK-896). Once exceeded,
	// the per-LPM record callback is suppressed for further LPMs on the
	// affected stream; wire forwarding is unaffected because the
	// suppression skips only the RecordStep dispatch, not the LPM
	// reassembly + semantic envelope emission carrying the decoded payload
	// to consumers.
	//
	// Default matches MaxGRPCMessagesPerStream so a single RPC that
	// exhausts the per-stream gRPC semantic budget also exhausts the
	// per-stream LPM wire budget at the same threshold — operator mental
	// model "long-running gRPC streams cap at ~10k messages" applies
	// uniformly to both views.
	//
	// Wired via internal/pipeline/RecordStep.WithGRPCLPMFrameMaxPerStream
	// (USK-896).
	MaxGRPCLPMFrameRecordsPerStream = 10000

	// MaxGRPCWebBase64RecordsPerStream limits the number of gRPC-Web
	// text-variant body envelopes (wire_level="grpcweb-base64") recorded
	// per stream on the gRPC-Web data path (USK-898). Once exceeded, the
	// per-body record callback is suppressed for further inbound text
	// bodies on the affected stream; wire forwarding is unaffected
	// because the suppression skips only the RecordStep dispatch, not
	// the base64 decode + LPM parse that produces the semantic envelopes
	// the consumer observes.
	//
	// Default matches MaxGRPCMessagesPerStream so a single RPC that
	// exhausts the per-stream gRPC semantic budget also exhausts the
	// per-stream base64 wire budget at the same threshold — operator
	// mental model "long-running gRPC streams cap at ~10k messages"
	// applies uniformly across semantic and wire views.
	//
	// Wired via internal/pipeline/RecordStep.WithGRPCWebBase64MaxPerStream
	// (USK-898).
	MaxGRPCWebBase64RecordsPerStream = 10000

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
