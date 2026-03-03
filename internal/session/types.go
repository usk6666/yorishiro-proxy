package session

import (
	"net/url"
	"time"
)

// Session represents a recorded proxy session (connection-level metadata).
// A session contains one or more messages depending on the session type:
// unary sessions have exactly one send + one receive message,
// stream/bidirectional sessions have multiple messages.
type Session struct {
	// ID is the unique identifier of the session.
	ID string
	// ConnID is the connection ID for log correlation.
	ConnID string
	// Protocol is the detected protocol (e.g., "HTTP/1.x", "HTTPS").
	Protocol string
	// SessionType indicates the communication pattern:
	// "unary" (single request-response), "stream", or "bidirectional".
	SessionType string
	// State indicates the session lifecycle state:
	// "active" (in progress), "complete" (finished), or "error" (failed).
	State string
	// Timestamp is the time the session was initiated.
	Timestamp time.Time
	// Duration is the total duration of the session.
	Duration time.Duration
	// Tags holds optional key-value metadata for the session.
	// Examples include security flags such as smuggling detection results.
	// A nil map indicates no tags are present.
	Tags map[string]string
	// ConnInfo holds network and TLS connection metadata.
	// May be nil for sessions recorded without connection information.
	ConnInfo *ConnectionInfo
	// BlockedBy indicates which subsystem blocked this request.
	// Empty string means the request was not blocked.
	// "target_scope" means it was blocked by the target scope rules.
	BlockedBy string
}

// ConnectionInfo holds network-level and TLS metadata for a proxy session.
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

// Message represents a single directional message within a session.
// For HTTP unary sessions, there are exactly two messages: one send (request)
// and one receive (response). For streaming protocols, there may be many.
type Message struct {
	// ID is the unique identifier of the message.
	ID string
	// SessionID is the ID of the session this message belongs to.
	SessionID string
	// Sequence is the order of this message within the session (0-based).
	Sequence int
	// Direction indicates the message flow: "send" (client to server)
	// or "receive" (server to client).
	Direction string
	// Timestamp is the time this message was captured.
	Timestamp time.Time
	// Headers holds HTTP-style headers. May be nil for non-HTTP protocols.
	Headers map[string][]string
	// Body holds the message body content.
	Body []byte
	// RawBytes holds the original raw bytes as captured on the wire.
	// This preserves header ordering, whitespace, and protocol version
	// exactly as sent, enabling smuggling analysis and byte-faithful replay.
	// May be nil if raw capture was not performed.
	RawBytes []byte
	// BodyTruncated indicates whether the body was truncated during recording.
	BodyTruncated bool
	// Method is the HTTP request method (e.g., "GET", "POST").
	// Only set for HTTP send messages.
	Method string
	// URL is the HTTP request URL. Only set for HTTP send messages.
	URL *url.URL
	// StatusCode is the HTTP response status code.
	// Only set for HTTP receive messages.
	StatusCode int
	// Metadata holds protocol-specific key-value metadata for this message.
	Metadata map[string]string
}

// SessionUpdate holds the fields that can be updated on an existing session.
// Only non-zero/non-nil fields are applied.
type SessionUpdate struct {
	// State sets the session state (e.g., "complete", "error").
	State string
	// Duration sets the session duration.
	Duration time.Duration
	// Tags replaces the session tags.
	Tags map[string]string
	// ServerAddr sets the upstream server address in ConnInfo.
	// Only applied when non-empty.
	ServerAddr string
	// TLSServerCertSubject sets the upstream server TLS certificate subject in ConnInfo.
	// Only applied when non-empty.
	TLSServerCertSubject string
}
