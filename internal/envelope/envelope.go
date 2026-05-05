package envelope

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrPartialWireBytes is returned by a per-protocol wire-encode helper to
// signal that only a fragment of the post-mutation message (typically
// headers, not body) could be re-encoded. Callers such as
// pipeline.RecordStep use this sentinel to tag the recorded modified
// variant's metadata as "partial" while still storing the returned header-
// only bytes.
//
// It lives on internal/envelope (a leaf package) rather than on
// internal/pipeline because per-Layer encoders must import the sentinel
// without creating an import cycle through pipeline's dependency on
// internal/connector.
var ErrPartialWireBytes = errors.New("envelope: partial wire bytes")

// Direction indicates whether an envelope was observed traveling from
// client to server (Send) or server to client (Receive).
type Direction int

const (
	// Send indicates a client-to-server direction.
	Send Direction = iota
	// Receive indicates a server-to-client direction.
	Receive
)

// String returns a human-readable label for the direction.
func (d Direction) String() string {
	switch d {
	case Send:
		return "send"
	case Receive:
		return "receive"
	default:
		return "unknown"
	}
}

// Protocol identifies which layer produced an envelope.
type Protocol string

const (
	ProtocolHTTP         Protocol = "http"
	ProtocolWebSocket    Protocol = "ws"
	ProtocolGRPC         Protocol = "grpc"
	ProtocolGRPCWeb      Protocol = "grpc-web"
	ProtocolSSE          Protocol = "sse"
	ProtocolRaw          Protocol = "raw"
	ProtocolTLSHandshake Protocol = "tls-handshake"
)

// Envelope is the protocol-agnostic outer container that flows through the
// Pipeline. See RFC-001 section 3.1.
type Envelope struct {
	// --- Identity (shared across all protocols) ---

	// StreamID is a connection/RPC-level grouping identifier.
	StreamID string

	// FlowID is a unique identifier for this individual message.
	FlowID string

	// Sequence is the order within the stream (0-origin).
	Sequence int

	// Direction indicates Send (client->server) or Receive (server->client).
	Direction Direction

	// --- Provenance ---

	// Protocol identifies which layer produced this envelope.
	Protocol Protocol

	// --- Wire fidelity (read-only view for Pipeline; authoritative bytes) ---

	// Raw contains the wire-observed bytes exactly as captured.
	Raw []byte

	// --- Protocol-specific structured view ---

	// Message is the typed protocol-specific payload.
	Message Message

	// --- Connection-scoped context accessible to any Step ---

	// Context holds cross-layer metadata for the connection.
	Context EnvelopeContext

	// --- Layer-internal state; Pipeline must not type-assert ---

	// Opaque is layer-internal state. Pipeline Steps must not type-assert
	// on this field; it is owned exclusively by the producing Layer.
	Opaque any
}

// Clone returns a deep copy of the envelope suitable for variant snapshotting.
// Opaque is not cloned — that is the Layer's responsibility.
func (e *Envelope) Clone() *Envelope {
	clone := &Envelope{
		StreamID:  e.StreamID,
		FlowID:    e.FlowID,
		Sequence:  e.Sequence,
		Direction: e.Direction,
		Protocol:  e.Protocol,
		Raw:       cloneBytes(e.Raw),
		Context:   e.Context, // shallow copy; TLS is a pointer (shared, immutable)
		// Opaque intentionally not cloned
	}
	if e.Message != nil {
		clone.Message = e.Message.CloneMessage()
	}
	return clone
}

// cloneBytes returns a copy of b, or nil if b is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// EnvelopeContext holds connection-scoped metadata accessible to any
// Pipeline Step. See RFC-001 section 3.1.
type EnvelopeContext struct {
	// ConnID is unique per client TCP connection.
	ConnID string

	// ClientAddr is the original client address.
	ClientAddr net.Addr

	// TargetHost is the CONNECT destination or SOCKS5 target.
	TargetHost string

	// TLS is non-nil if a TLS layer is in the stack.
	TLS *TLSSnapshot

	// ReceivedAt is the wall-clock time at Next() invocation.
	ReceivedAt time.Time

	// UpgradePath is the URL path observed on the HTTP Upgrade request that
	// initiated a non-HTTP protocol (WebSocket via HTTP/1.1 Upgrade, or HTTP/2
	// CONNECT with :protocol). Populated by the Layer that consumes the Upgrade
	// (WSLayer at construction in USK-642). Empty for non-upgraded protocols.
	UpgradePath string

	// UpgradeQuery is the URL query string observed on the HTTP Upgrade
	// request. Same semantics as UpgradePath. Empty for non-upgraded protocols.
	UpgradeQuery string
}

// TLSSnapshot captures TLS connection metadata observed during handshake.
// It is immutable after construction and safe to share across envelopes
// on the same connection.
type TLSSnapshot struct {
	SNI               string
	ALPN              string
	PeerCertificate   *x509.Certificate
	ClientFingerprint string // JA3 or JA4 hash of the client's ClientHello
	Version           uint16
	CipherSuite       uint16
}

// VersionName returns a human-readable TLS version string
// ("TLS 1.2", "TLS 1.3", ...). Unknown versions are formatted
// as "unknown (0xNNNN)".
func (s *TLSSnapshot) VersionName() string {
	if s == nil {
		return ""
	}
	switch s.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0:
		return ""
	default:
		return fmt.Sprintf("unknown (0x%04x)", s.Version)
	}
}

// CipherName returns the standard name of the negotiated cipher suite,
// or a hex-encoded identifier for unknown suites. Returns the empty
// string when the snapshot is nil or CipherSuite is zero.
func (s *TLSSnapshot) CipherName() string {
	if s == nil || s.CipherSuite == 0 {
		return ""
	}
	return tls.CipherSuiteName(s.CipherSuite)
}

// PeerCertSubject returns the Subject DN of PeerCertificate, or the
// empty string when no peer certificate was observed.
func (s *TLSSnapshot) PeerCertSubject() string {
	if s == nil || s.PeerCertificate == nil {
		return ""
	}
	return s.PeerCertificate.Subject.String()
}
