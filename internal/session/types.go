package session

import (
	"net/url"
	"time"
)

// Entry represents a single recorded proxy session entry.
type Entry struct {
	ID        string
	ConnID    string // connection ID for log correlation
	Protocol  string
	Request   RecordedRequest
	Response  RecordedResponse
	Timestamp time.Time
	Duration  time.Duration
	// Tags holds optional key-value metadata for the session entry.
	// Examples include security flags such as smuggling detection results.
	// A nil map indicates no tags are present.
	Tags map[string]string
	// RawRequest holds the original raw HTTP request bytes as received on the wire.
	// This preserves header ordering, whitespace, and HTTP version exactly as sent
	// by the client, enabling smuggling analysis and byte-faithful replay.
	// May be nil if raw capture was not performed.
	RawRequest []byte
	// RawResponse holds the original raw HTTP response bytes as received from
	// the upstream server. This preserves the exact wire format for analysis.
	// May be nil if raw capture was not performed.
	RawResponse []byte
	// ConnInfo holds network and TLS connection metadata.
	// May be nil for sessions recorded without connection information.
	ConnInfo *ConnectionInfo
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

// RecordedRequest holds the captured request data.
type RecordedRequest struct {
	Method        string
	URL           *url.URL
	Headers       map[string][]string
	Body          []byte
	BodyTruncated bool
}

// RecordedResponse holds the captured response data.
type RecordedResponse struct {
	StatusCode    int
	Headers       map[string][]string
	Body          []byte
	BodyTruncated bool
}
