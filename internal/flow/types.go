package flow

import (
	"net/url"
	"time"
)

// Stream represents a recorded proxy stream (connection/RPC-level grouping).
// A stream contains one or more flows: for HTTP unary, there is exactly
// one send + one receive flow. For streaming protocols, there may be many.
type Stream struct {
	// ID is the unique identifier of the stream.
	ID string
	// ConnID is the connection ID for log correlation.
	ConnID string
	// Protocol is the protocol label assigned to the stream
	// (e.g., "HTTP/1.x", "HTTPS", "HTTP/2", "gRPC", "WebSocket", "TCP",
	// "SOCKS5+HTTPS", "SOCKS5+HTTP").
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
	// Metadata holds protocol-specific key-value metadata for this flow.
	Metadata map[string]string
}

// StreamUpdate holds the fields that can be updated on an existing stream.
// Only non-zero/non-nil fields are applied.
type StreamUpdate struct {
	// State sets the stream state (e.g., "complete", "error").
	State string
	// Duration sets the stream duration.
	Duration time.Duration
	// Tags replaces the stream tags.
	Tags map[string]string
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
