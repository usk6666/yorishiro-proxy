package connector

import "time"

// RejectInfo describes one connection refused because max_connections was
// already saturated (USK-1142). It is the payload of
// FullListenerConfig.OnReject and of the TCP forward accept loop's direct
// call into the same aggregator.
type RejectInfo struct {
	// Listener is the listener name the connection arrived on.
	Listener string
	// ForwardPort is the TCP forward port for rejections on a tcp_forwards
	// listener; empty for the main FullListener.
	ForwardPort string
	// RemoteAddr is the client's address.
	RemoteAddr string
	// DetectedKind is the protocol detected from the first bytes, or
	// ProtocolUnknown when the peek failed or timed out.
	DetectedKind ProtocolKind
	// Method is the request-line method (HTTP/1.x and CONNECT only).
	Method string
	// Target is the request-target exactly as observed on the wire
	// (HTTP/1.x and CONNECT), or the configured forward target (TCP forward).
	Target string
	// TargetTruncated reports that Target was cut at MaxRejectTargetLen.
	TargetTruncated bool
	// WroteResponse reports that the 503 response reached the socket.
	WroteResponse bool
	// MaxConnections is the cap in force when the connection was refused.
	MaxConnections int
	// At is the rejection time.
	At time.Time
}

// MaxRejectTargetLen caps the request-target kept for a rejected
// connection. Longer targets are cut and RejectInfo.TargetTruncated is set.
const MaxRejectTargetLen = 512

// rejectWarnWindow is the minimum interval between two capacity-rejection
// Warn logs on one listener; rejections in between are logged at Debug and
// counted in the next Warn's "suppressed" attribute.
const rejectWarnWindow = 10 * time.Second
