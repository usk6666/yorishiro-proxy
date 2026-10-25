package flow

import (
	"net/url"
	"time"
)

// Origin classifies how a Stream came into existence so consumers can
// distinguish proxy-recorded traffic from operator-initiated resends or
// fuzzing campaigns. The set is closed: only the three constants below are
// canonical. Import is treated as a path attribute (the imported value is
// inherited as-is); it is not its own Origin value.
//
// Storage shape: the value is persisted as a TEXT column on the streams
// table (schemaV12) with DEFAULT 'proxy'. Existing rows from earlier
// schema versions migrate to OriginProxy via that default.
type Origin string

const (
	// OriginProxy marks streams recorded from live MITM proxy traffic.
	// This is the default value applied by RecordStep and the schemaV12
	// column default for backfilled rows.
	OriginProxy Origin = "proxy"
	// OriginResend marks streams created by the resend_* MCP tools
	// (resend_http / resend_ws / resend_grpc / resend_raw).
	OriginResend Origin = "resend"
	// OriginFuzz marks streams created by the fuzz_* MCP tools
	// (fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw), including the
	// blocked_by="budget" audit Streams of over-budget trials.
	OriginFuzz Origin = "fuzz"
)

// Stream represents a recorded proxy stream (connection/RPC-level grouping).
// A stream contains one or more flows: for HTTP unary, there is exactly
// one send + one receive flow. For streaming protocols, there may be many.
type Stream struct {
	// ID is the unique identifier of the stream.
	ID string
	// ConnID is the connection ID for log correlation.
	ConnID string
	// Protocol is the canonical Envelope Protocol value assigned to the
	// stream — one of the lowercase constants defined in
	// internal/envelope/envelope.go: "http", "ws", "grpc", "grpc-web",
	// "sse", "raw", "tls-handshake". Stamped by RecordStep.createStream
	// / maybeRetagProtocol via string(env.Protocol).
	//
	// Legacy rows recorded before the SOCKS5 path was canonicalized may
	// still carry composite spellings like "SOCKS5+HTTPS"; readers that
	// need to handle both should compare via envelope.Protocol(st.Protocol)
	// against the canonical constants.
	Protocol string
	// Scheme is the wire-observed handshake transport indicator
	// (canonical live values: "https", "http", "tcp"). Per USK-848,
	// Stream.Scheme records the handshake transport only — application-
	// level URL schemes such as "ws"/"wss" are NOT recorded on the live
	// path. WebSocket Streams retain the handshake transport ("http" or
	// "https") across the WS Protocol retag, so WS-over-TLS flows carry
	// Scheme="https". The MCP query/manage filter surfaces hard-reject
	// "ws"/"wss" filter values at the enum boundary (USK-864). Note: the
	// Store layer is protocol-neutral and accepts any string for
	// round-trip / import compatibility; validation is enforced at the
	// MCP boundary, not here.
	Scheme string
	// State indicates the stream lifecycle state:
	// "active" (in progress), "complete" (finished), or "error" (failed).
	State string
	// FailureReason classifies the stream-level error for diagnostic use.
	// Empty when State != "error" or when no classified error was surfaced.
	// Canonical values come from layer.ErrorCode.String(): "refused",
	// "canceled", "aborted", "internal_error", "protocol_error".
	// Analysts use this to distinguish GOAWAY-refused streams from
	// cancelled streams and protocol errors without inspecting raw bytes.
	FailureReason string
	// Timestamp is the time the stream was initiated.
	Timestamp time.Time
	// Duration is the total duration of the stream.
	Duration time.Duration
	// Tags holds optional key-value metadata for the stream.
	// Examples include security flags such as smuggling detection results.
	// A nil map indicates no tags are present.
	Tags map[string]string
	// ConnInfo holds network and TLS connection metadata.
	// May be nil for streams recorded without connection information.
	ConnInfo *ConnectionInfo
	// BlockedBy indicates which subsystem blocked this request.
	// Empty string means the request was not blocked. The canonical
	// vocabulary lives in internal/pipeline/blocked_by.go: "target_scope",
	// "safety_filter", "intercept_drop", "intercept_cancelled",
	// "rate_limit" (reserved), "budget", and "capacity" (written by the
	// connection-rejection recorder rather than a Pipeline Step).
	BlockedBy string
	// Origin classifies how the Stream came into existence (USK-785).
	// OriginProxy for live MITM-recorded traffic, OriginResend for streams
	// created by the resend_* MCP tools, OriginFuzz for streams created by
	// the fuzz_* MCP tools. Empty string
	// is treated as OriginProxy by readers that want backward compatibility
	// with pre-schemaV12 rows; the SQLite column itself defaults to 'proxy'.
	Origin Origin
	// ListenerName is the operator-configured name of the proxy listener
	// that accepted the connection this Stream was recorded on (the
	// proxy_start "name", or "default"). On live Streams it comes from
	// configuration, never from the wire, so traffic cannot alter it.
	// JSONL import preserves whatever the imported file contains, so the
	// value is only as trustworthy as its source on imported rows.
	// tcp_forwards inherit their parent listener's name. Empty
	// for Streams that did not arrive through a listener (resend / fuzz /
	// budget audit) and for rows recorded before schemaV19.
	ListenerName string
	// SendMs is the time in milliseconds to send the request (headers + body).
	// Nil when not measured (e.g., Raw TCP, or legacy streams before this feature).
	SendMs *int64 `json:"send_ms,omitempty"`
	// WaitMs is the server processing time in milliseconds (TTFB).
	// Nil when not measured.
	WaitMs *int64 `json:"wait_ms,omitempty"`
	// ReceiveMs is the time in milliseconds to receive the response body.
	// Nil when not measured.
	ReceiveMs *int64 `json:"receive_ms,omitempty"`
}

// ConnectionInfo holds network-level and TLS metadata for a proxy stream.
type ConnectionInfo struct {
	// ClientAddr is the remote address of the client (e.g., "192.168.1.100:54321").
	ClientAddr string
	// ServerAddr is the wire-observed TCP peer of the upstream socket
	// (e.g., "93.184.216.34:443"). When the proxy reached the upstream
	// through an upstream proxy this is the upstream proxy's address, not
	// the final destination — see UpstreamProxy. Live streams fill it from
	// the first upstream Receive envelope, so a stream that never received
	// anything from upstream leaves it empty. It never holds a requested
	// hostname: audit / error rows that had no upstream socket (TLS
	// stack-build errors, proxy-closed request heads, capacity
	// rejections) leave it empty and carry the requested destination in
	// Stream.Tags["target"], which the Host list filter also matches.
	ServerAddr string
	// UpstreamProxy is the upstream proxy the upstream socket was dialed
	// through, as "scheme://host:port" with any userinfo stripped so no
	// credential is ever persisted. Empty for a direct dial.
	UpstreamProxy string
	// TLSVersion is the negotiated TLS version (e.g., "TLS 1.3").
	// Empty for non-TLS connections.
	TLSVersion string
	// TLSCipher is the negotiated TLS cipher suite name (e.g., "TLS_AES_128_GCM_SHA256").
	// Empty for non-TLS connections.
	TLSCipher string
	// TLSALPN is the negotiated Application-Layer Protocol (e.g., "h2", "http/1.1").
	// Empty if ALPN was not negotiated or for non-TLS connections.
	TLSALPN string
	// TLSServerCertSubject is the subject DN of the upstream server's TLS certificate.
	// Empty for non-TLS connections.
	TLSServerCertSubject string
	// TLSClientJA3 is the JA3 (MD5) fingerprint of the client's TLS
	// ClientHello, captured by the MITM ClientHello peek (USK-1015). Empty
	// for non-TLS connections or when the ClientHello could not be observed
	// / parsed (e.g. it exceeded the peek cap).
	TLSClientJA3 string
	// TLSClientJA4 is the JA4 (TLS client) fingerprint of the client's TLS
	// ClientHello. Same population/empty semantics as TLSClientJA3.
	TLSClientJA4 string
}

// Flow represents a single directional message within a stream.
// For HTTP unary streams, there are exactly two flows: one send (request)
// and one receive (response). For streaming protocols, there may be many.
type Flow struct {
	// ID is the unique identifier of the flow.
	ID string
	// StreamID is the ID of the stream this flow belongs to.
	StreamID string
	// Sequence is the order of this flow within the stream (0-based).
	Sequence int
	// Direction indicates the flow direction: "send" (client to server)
	// or "receive" (server to client).
	Direction string
	// Timestamp is the time this flow was captured.
	Timestamp time.Time
	// Headers holds HTTP-style headers. May be nil for non-HTTP protocols.
	Headers map[string][]string
	// Trailers holds HTTP message trailers (HTTP/2 trailer-HEADERS and
	// HTTP/1.1 chunked trailer lines). Nil for non-HTTP protocols and for
	// messages without trailers. Storage shape mirrors Headers; wire-level
	// ordering and case of duplicate names live in RawBytes.
	Trailers map[string][]string
	// Body holds the flow body content.
	Body []byte
	// RawBytes holds the original raw bytes as captured on the wire.
	// This preserves header ordering, whitespace, and protocol version
	// exactly as sent, enabling smuggling analysis and byte-faithful replay.
	// May be nil if raw capture was not performed.
	RawBytes []byte
	// BodyTruncated indicates whether the body was truncated during recording.
	BodyTruncated bool
	// Method is the HTTP request method (e.g., "GET", "POST").
	// Only set for HTTP send flows.
	Method string
	// URL is the HTTP request URL. Only set for HTTP send flows.
	URL *url.URL
	// StatusCode is the HTTP response status code.
	// Only set for HTTP receive flows.
	StatusCode int
	// HTTPVersion is the wire-observed HTTP protocol version (USK-788).
	// Canonical lowercased values: "http/1.0", "http/1.1", "h2", "h2c".
	// Empty for non-HTTP protocols and for any pre-USK-788 row stored
	// before schemaV13 added the column. Mirrors the source-of-truth
	// envelope.HTTPMessage.HTTPVersion field set by the producing Layer
	// (HTTP/1.x parser → http/1.0 / http/1.1; HTTP/2 aggregator → h2 / h2c
	// based on the Layer scheme). Downstream filters (USK-792 manage
	// export_flows / delete_flows) read this column directly.
	HTTPVersion string
	// WireLevel discriminates the envelope's recording layer (USK-889):
	// WireLevelSemantic for canonical L7 message envelopes recorded by
	// RecordStep on the main Pipeline; WireLevelH2Frame for H2 DATA frame
	// envelopes recorded as a per-stream sub-stack overlay (RFC-001
	// §3.4.1) under the WS-over-h2 / SSE-over-h2 detach paths. Empty
	// string is treated as WireLevelSemantic by readers for backward
	// compatibility with pre-schemaV14 rows; the SQLite column default
	// is 'semantic' so backfilled rows always read as semantic.
	WireLevel string
	// Metadata holds protocol-specific key-value metadata for this flow.
	Metadata map[string]string
}

// StreamUpdate holds the fields that can be updated on an existing stream.
// Only non-zero/non-nil fields are applied.
type StreamUpdate struct {
	// Protocol overrides the stream's recorded protocol name. Used by
	// the wss-over-h2 swap path (USK-781) to retag a Stream that was
	// initially created from the pre-swap CONNECT request envelope
	// (Protocol="http") to the post-swap value (Protocol="websocket")
	// once the upgrade fires. Only applied when non-empty.
	Protocol string
	// Scheme backfills the stream's recorded scheme (USK-1197). It exists
	// for the overlay-first createStream path: when a wire-level overlay
	// envelope (h2-frame / grpcweb-base64) wins the USK-908 first-write-
	// wins race it carries no Message, so the Stream row is created with
	// an empty Scheme; RecordStep then copies the scheme the following
	// semantic message carries. It is not a TLS / handshake oracle — the
	// value is whatever the semantic message records (see USK-1067).
	// Only applied when non-empty.
	Scheme string
	// State sets the stream state (e.g., "complete", "error").
	State string
	// FailureReason sets the classification label for an errored stream.
	// Only applied when non-empty. See Stream.FailureReason for valid values.
	FailureReason string
	// BlockedBy sets the audit attribution label for a blocked stream
	// (USK-782 mid-stream Drop path). Canonical values mirror
	// Stream.BlockedBy — see internal/pipeline/blocked_by.go for the
	// Pipeline-emitted set ("target_scope", "safety_filter",
	// "intercept_drop", "intercept_cancelled", "rate_limit"). Only applied
	// when non-empty.
	BlockedBy string
	// Duration sets the stream duration.
	Duration time.Duration
	// Tags replaces the stream tags. Mutually exclusive with AppendTags;
	// callers must pick one or the other in a single update.
	Tags map[string]string
	// AppendTags merges the supplied entries into the stream's existing
	// tags column without clobbering keys that are not present in the
	// map. Used by the live OnComplete recorder (USK-797) so the
	// classification "error" tag does not erase tags written earlier in
	// the stream's lifetime (e.g. TLS metadata, USK-790 tls-handshake
	// meta tags).
	//
	// Concurrency: the merge is performed inside the SQLiteStore's
	// single-writer goroutine, so it is atomic with respect to other
	// UpdateStream / SaveStream calls. Mutually exclusive with Tags;
	// implementations reject updates that set both.
	AppendTags map[string]string
	// ServerAddr sets the upstream server address in ConnInfo.
	// Only applied when non-empty.
	ServerAddr string
	// UpstreamProxy sets ConnInfo.UpstreamProxy (redacted proxy URL).
	// Only applied when non-empty.
	UpstreamProxy string
	// TLSVersion sets the negotiated TLS version in ConnInfo
	// (e.g., "TLS 1.3"). Only applied when non-empty.
	TLSVersion string
	// TLSCipher sets the negotiated TLS cipher suite name in ConnInfo
	// (e.g., "TLS_AES_128_GCM_SHA256"). Only applied when non-empty.
	TLSCipher string
	// TLSALPN sets the negotiated ALPN protocol in ConnInfo
	// (e.g., "h2", "http/1.1"). Only applied when non-empty.
	TLSALPN string
	// TLSServerCertSubject sets the upstream server TLS certificate subject in ConnInfo.
	// Only applied when non-empty.
	TLSServerCertSubject string
	// TLSClientJA3 sets the client ClientHello JA3 fingerprint in ConnInfo
	// (USK-1015). Only applied when non-empty.
	TLSClientJA3 string
	// TLSClientJA4 sets the client ClientHello JA4 fingerprint in ConnInfo
	// (USK-1015). Only applied when non-empty.
	TLSClientJA4 string
	// SendMs sets the request send time in milliseconds.
	// Only applied when non-nil.
	SendMs *int64
	// WaitMs sets the server processing (TTFB) time in milliseconds.
	// Only applied when non-nil.
	WaitMs *int64
	// ReceiveMs sets the response receive time in milliseconds.
	// Only applied when non-nil.
	ReceiveMs *int64
}
