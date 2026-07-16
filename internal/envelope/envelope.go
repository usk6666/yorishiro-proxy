package envelope

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
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

	// Raw contains the complete wire-observed bytes for this Envelope as
	// captured during parsing — header section concatenated with the on-wire
	// body section. For HTTP/1.x with chunked Transfer-Encoding, Raw includes
	// chunk-size lines, chunk extensions, optional trailers, and the
	// terminating "0\r\n\r\n" exactly as observed on the wire. For identity
	// bodies (Content-Length / EOF-delimited) Raw includes the verbatim body
	// bytes after the header CRLFCRLF terminator. For bodyless messages
	// (HEAD response, 204, 304) Raw contains the header section only.
	//
	// Body capture is bounded by parser.MaxRawCaptureSize. On cap breach the
	// HTTP/1.x parser surfaces AnomalyRawBodyTruncated on the message and Raw
	// holds the truncated header+body prefix.
	//
	// Memory profile on the variant-record path: Clone deep-copies these
	// bytes via cloneBytes, so an intercept that produces both an original
	// and a modified variant peaks at roughly 2 × len(Raw) per flow on top of
	// the existing HTTPMessage.Body deep-copy. With Raw promoted to full wire
	// bytes (header + body, up to MaxRawCaptureSize), peak residency on
	// intercept-heavy sessions is appreciably higher than under the
	// pre-USK-773 header-only semantics; size session limits accordingly.
	//
	// USK-773: prior to this Issue Raw held only the header section for
	// HTTP/1.x; the on-wire body section was reconstructed at re-encode time.
	// Raw is now the complete wire snapshot so Flow Store BLOB columns,
	// `query` MCP tool, and WebUI hex viewers see the full wire bytes
	// (RFC-001 §3.1).
	//
	// USK-772: when the on-wire body crosses the parser disk-spill threshold,
	// Raw holds only the header section bytes and RawBuffer holds the body
	// section. Consumers should call WireBytes(ctx) for the full wire snapshot
	// instead of reading Raw directly when the spill path may be active.
	Raw []byte

	// RawBuffer optionally carries the disk-backed body portion of the wire
	// snapshot when the on-wire body crossed the disk-spill threshold during
	// parsing. When non-nil, the Raw field holds the header section bytes
	// only (memory) and RawBuffer holds the body section bytes (disk-backed
	// via bodybuf.BodyBuffer). Consumers must call WireBytes to read the
	// complete wire snapshot — it stitches header (Raw) + body (RawBuffer)
	// transparently.
	//
	// USK-773 introduced the field with a memory-only path (RawBuffer is
	// left nil; Raw holds the full wire bytes). USK-772 populates RawBuffer
	// when the HTTP/1.x parser disk-spills a chunked or identity body so
	// multi-MiB bodies do not double up in memory and survive past the
	// MaxRawCaptureSize cap.
	RawBuffer *bodybuf.BodyBuffer

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
//
// RawBuffer is shared via Retain (when non-nil) so variant snapshots see the
// same disk-backed wire snapshot; the session OnComplete backstop releases
// the terminal reference (see bodyBufRegistry.trackEnvelope in
// internal/session/session.go which tracks env.RawBuffer alongside
// HTTPMessage.BodyBuffer). USK-772 populates RawBuffer when the HTTP/1.x
// parser disk-spills a chunked or identity body.
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
	if e.RawBuffer != nil {
		// USK-772: Retain is symmetric with HTTPMessage.BodyBuffer's Retain
		// in HTTPMessage.CloneMessage. The corresponding terminal Release
		// lives in internal/session/session.go bodyBufRegistry.trackEnvelope
		// which now also tracks env.RawBuffer.
		e.RawBuffer.Retain()
		clone.RawBuffer = e.RawBuffer
	}
	if e.Message != nil {
		clone.Message = e.Message.CloneMessage()
	}
	return clone
}

// WireBytes returns the complete wire bytes for this Envelope. When
// RawBuffer is non-nil, the body section is materialized via
// BodyBuffer.Bytes(ctx) and concatenated after the header section in Raw;
// otherwise Raw is returned directly.
//
// USK-773 memory path: RawBuffer is nil and WireBytes returns Raw verbatim.
// USK-772 disk-spill path: Raw holds the header section bytes (captured in
// memory by the parser, capped at MaxRawCaptureSize) and RawBuffer holds the
// disk-backed body bytes; WireBytes stitches them so callers do not need to
// know which storage path produced the envelope.
//
// Errors are surfaced from BodyBuffer.Bytes only (e.g. read errors on a
// disk-backed buffer or ctx cancellation). When RawBuffer is nil the call
// cannot fail.
func (e *Envelope) WireBytes(ctx context.Context) ([]byte, error) {
	if e == nil {
		return nil, nil
	}
	if e.RawBuffer != nil {
		body, err := e.RawBuffer.Bytes(ctx)
		if err != nil {
			return nil, fmt.Errorf("envelope: read RawBuffer: %w", err)
		}
		if len(e.Raw) == 0 {
			return body, nil
		}
		// Bound the stitched size to a safe constant (1 GiB) before
		// allocating. Header is bounded by MaxRawCaptureSize and body by
		// MaxBodySize, so the sum cannot reach the cap under current caps.
		// The explicit constant cap satisfies CodeQL
		// (go/allocation-size-overflow) which cannot infer the parser-side
		// caps statically.
		const maxStitchedWireBytes = 1 << 30 // 1 GiB sanity cap
		if len(e.Raw) > maxStitchedWireBytes-len(body) {
			return nil, fmt.Errorf("envelope: WireBytes stitched size exceeds %d (header=%d body=%d)", maxStitchedWireBytes, len(e.Raw), len(body))
		}
		out := append(append(make([]byte, 0, len(e.Raw)), e.Raw...), body...)
		return out, nil
	}
	return e.Raw, nil
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

	// RequestPath, RequestMethod, RequestRawQuery carry the wire-observed
	// request line fields onto subsequent envelopes for the same HTTP
	// transaction so response-phase rule matching (direction:"both" with
	// path_pattern or methods conditions) can evaluate against the paired
	// request. Populated by HTTP-producing Layers (HTTP/1.x channel via
	// ctxTmpl; HTTP/2 aggregator via per-stream inflight state). Empty when
	// the envelope is not HTTP, or when no paired request is available (the
	// legitimate direction:"response" no-data case).
	//
	// USK-833: prior to this Issue, response-phase matching for
	// direction:"both" silently permitted any path because the request-side
	// fields were not threaded forward; rules with host_pattern + path_pattern
	// held every paired response regardless of path.
	RequestPath     string
	RequestMethod   string
	RequestRawQuery string

	// Synthetic is true when this Envelope was synthesized by the proxy
	// (not observed on the wire). The first and currently only producer is
	// the USK-854 WS hold-window keepalive injection path in
	// internal/session/session.go, which synthesizes WS Ping frames toward
	// the upstream while a frame is held in the intercept queue so the
	// upstream's idle timer does not expire.
	//
	// Pipeline Steps that mutate wire observation MUST NOT re-trigger on a
	// Synthetic Envelope:
	//   - InterceptStep early-returns Result{} (a synthetic Ping must not
	//     trigger another hold).
	//   - SafetyStep early-returns Result{} (Synthetic Pings carry no
	//     attacker-influenced payload).
	//
	// PluginPre / PluginPost / RecordStep / wire-forwarding Steps pass
	// through unchanged so the operator-visible observation surface still
	// records the synthetic frame as part of the wire conversation. The
	// flag itself is provenance metadata; the wire bytes the analyst sees
	// on `Envelope.Raw` and `query` MCP tool exposures are the actual frame
	// bytes the proxy wrote.
	//
	// Defaults to false (zero value). Synthetic is propagated by the
	// shallow Context-copy inside Envelope.Clone, matching every other
	// EnvelopeContext field.
	Synthetic bool

	// WireLevel discriminates the envelope's recording layer (USK-889).
	// Empty string means the canonical L7 "semantic" view (RecordStep
	// projects this as flow.WireLevelSemantic when persisting). A
	// non-empty value marks a frame-level overlay envelope produced by
	// a per-stream sub-stack (RFC-001 §3.4.1); the v1 implementation
	// only emits "h2-frame" (flow.WireLevelH2Frame) for H2 DATA frames
	// recorded under the WS-over-h2 / SSE-over-h2 detach paths.
	//
	// RecordStep reads this field to (a) project it into Flow.WireLevel
	// before persisting and (b) gate the frame-only per-stream record
	// cap (WithHTTP2FrameMaxPerStream). Plugin / Intercept / Transform
	// Steps do NOT inspect this field — the record-only Pipeline that
	// the orchestrator constructs via p.Without(...) excludes those
	// Steps entirely, so the gating happens at the chain composition
	// layer, not via runtime branching.
	//
	// Propagated by the shallow Context-copy inside Envelope.Clone like
	// every other EnvelopeContext field; defaults to the empty string
	// (zero value).
	WireLevel string
}

// TLSSnapshot captures TLS connection metadata observed during handshake.
// It is immutable after construction and safe to share across envelopes
// on the same connection.
type TLSSnapshot struct {
	SNI             string
	ALPN            string
	PeerCertificate *x509.Certificate
	// ClientFingerprint is the client's ClientHello fingerprint exposed to
	// plugins via the legacy `client_fingerprint` dict key. It is set to
	// ClientJA4 for back-compat; prefer ClientJA3 / ClientJA4 for the
	// explicit forms (USK-1015).
	ClientFingerprint string
	// ClientJA3 is the MD5 JA3 fingerprint of the client's ClientHello, or
	// empty when the proxy did not observe / could not parse it (e.g. no
	// ClientHello peek, malformed hello, or a ClientHello larger than the
	// peek cap). Populated only on the CLIENT-facing MITM snapshot; the
	// proxy's own outbound (upstream) ClientHello is never fingerprinted
	// into this field (USK-1015).
	ClientJA3 string
	// ClientJA4 is the JA4 (TLS client) fingerprint of the client's
	// ClientHello. Same population/empty semantics as ClientJA3.
	ClientJA4   string
	Version     uint16
	CipherSuite uint16
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
