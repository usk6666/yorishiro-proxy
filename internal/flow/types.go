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
	// OriginFuzz is reserved for streams created by fuzz campaigns. It
	// is enumerated for forward compatibility but no production write
	// path stamps this value yet — that wiring lives in a follow-up
	// Issue. Existing fuzz streams continue to record as OriginProxy
	// until the fuzz path is updated.
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
	// Scheme is the URL scheme or transport indicator
	// (e.g., "https", "http", "wss", "ws", "tcp").
	// It separates TLS/transport information from Protocol, so that
	// filter={scheme: "https"} returns HTTP/1.x, HTTP/2, gRPC streams over TLS.
	// WebSocket over TLS uses scheme="wss", not "https".
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
	// Empty string means the request was not blocked.
	// "target_scope" means it was blocked by the target scope rules.
	BlockedBy string
	// Origin classifies how the Stream came into existence (USK-785).
	// OriginProxy for live MITM-recorded traffic, OriginResend for streams
	// created by the resend_* MCP tools, OriginFuzz reserved for fuzz
	// campaigns (not yet written from any production path). Empty string
	// is treated as OriginProxy by readers that want backward compatibility
	// with pre-schemaV12 rows; the SQLite column itself defaults to 'proxy'.
	Origin Origin
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
	// ServerAddr is the resolved address of the upstream server (e.g., "93.184.216.34:443").
	ServerAddr string
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
	// State sets the stream state (e.g., "complete", "error").
	State string
	// FailureReason sets the classification label for an errored stream.
	// Only applied when non-empty. See Stream.FailureReason for valid values.
	FailureReason string
	// BlockedBy sets the audit attribution label for a blocked stream
	// (USK-782 mid-stream Drop path). Canonical values mirror
	// Stream.BlockedBy — see internal/pipeline/blocked_by.go for the
	// Pipeline-emitted set ("target_scope", "safety_filter",
	// "intercept_drop", "rate_limit"). Only applied when non-empty.
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
