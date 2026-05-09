package envelope

import (
	"io"

	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// HTTPMessage represents one HTTP request or response. Used by both HTTP/1.x
// and HTTP/2 layers. See RFC-001 section 3.2.1.
//
// Request-side fields (Method, Scheme, Authority, Path, RawQuery) are valid
// when Envelope.Direction == Send.
// Response-side fields (Status, StatusReason) are valid when
// Envelope.Direction == Receive.

// HTTP wire-version canonical values (USK-788).
//
// HTTPMessage.HTTPVersion carries the wire-observed HTTP protocol version
// for the request/response. Values are lowercase and align with the ALPN
// token registry (RFC 7301 / IANA "TLS Application-Layer Protocol
// Negotiation (ALPN) Protocol IDs") so a flow's HTTPVersion can be
// compared directly against ConnectionInfo.TLSALPN without case-folding
// or slash-form normalization.
//
// The canonical set is closed: producers that cannot determine the
// version (or write before this field is wired up) leave HTTPVersion
// empty. Empty is treated as "unknown" by readers and is the persisted
// shape for any pre-USK-788 row in the SQLite store.
const (
	// HTTPVersion10 is the HTTP/1.0 wire version (RFC 1945).
	HTTPVersion10 = "http/1.0"
	// HTTPVersion11 is the HTTP/1.1 wire version (RFC 9112). Default for
	// most HTTP/1.x deployments.
	HTTPVersion11 = "http/1.1"
	// HTTPVersionH2 is HTTP/2 over TLS (RFC 9113), matching the ALPN
	// token "h2".
	HTTPVersionH2 = "h2"
	// HTTPVersionH2C is HTTP/2 over cleartext TCP (RFC 9113 §3.1).
	// Matches the ALPN token "h2c" even though h2c is not negotiated via
	// ALPN in production deployments — keeping the same string lets
	// downstream filters reuse a single value space.
	HTTPVersionH2C = "h2c"
)

// AnomalyType classifies the kind of HTTP anomaly detected during parsing.
// Anomaly types are defined as strings matching the parser's type constants.
type AnomalyType string

const (
	AnomalyCLTE                  AnomalyType = "CLTE"
	AnomalyDuplicateCL           AnomalyType = "DuplicateCL"
	AnomalyInvalidTE             AnomalyType = "InvalidTE"
	AnomalyHeaderInjection       AnomalyType = "HeaderInjection"
	AnomalyAmbiguousTE           AnomalyType = "AmbiguousTE"
	AnomalyObsFold               AnomalyType = "ObsFold"
	AnomalyTrailerPseudoHeader   AnomalyType = "TrailerPseudoHeader"
	AnomalyTrailerForbidden      AnomalyType = "TrailerForbidden"
	AnomalyTrailersInPassthrough AnomalyType = "TrailersInPassthrough"
	// AnomalyRawBodyTruncated indicates that the on-wire raw body bytes
	// exceeded MaxRawCaptureSize; the captured RawBody is a prefix only.
	// The semantic body (HTTPMessage.Body / BodyBuffer) is not affected by
	// this cap (it is bounded independently by spillThreshold / MaxBodySize).
	AnomalyRawBodyTruncated AnomalyType = "RawBodyTruncated"

	// HTTP/2 specific anomalies.
	H2DuplicatePseudoHeader    AnomalyType = "H2DuplicatePseudoHeader"
	H2PseudoHeaderAfterRegular AnomalyType = "H2PseudoHeaderAfterRegular"
	H2InvalidPseudoHeader      AnomalyType = "H2InvalidPseudoHeader"
	H2UppercaseHeaderName      AnomalyType = "H2UppercaseHeaderName"
	H2ConnectionSpecificHeader AnomalyType = "H2ConnectionSpecificHeader"
	H2TrailersAfterPassthrough AnomalyType = "H2TrailersAfterPassthrough"
	H2PushPromise              AnomalyType = "H2PushPromise"
	// H2UnsupportedConnectProtocol marks an extended CONNECT request
	// (RFC 8441 §4) that carries a :protocol value other than "websocket".
	// The proxy currently only swaps WebSocket streams (USK-765); other
	// :protocol values fall back to standard HTTP/2 framing without a
	// per-stream sub-stack swap. The anomaly Detail carries the verbatim
	// wire :protocol value so analysts can identify forward-compat
	// candidates (h2c, webtransport, …) in recorded flows. The connection
	// itself stays alive — this is a forward-compat advisory, not a
	// fatal protocol error.
	H2UnsupportedConnectProtocol AnomalyType = "H2UnsupportedConnectProtocol"
)

// Anomaly records a single protocol-level anomaly found during parsing.
// HTTP-specific; lives on HTTPMessage, not Envelope (RFC-001 §3.1 rule).
type Anomaly struct {
	Type   AnomalyType
	Detail string
}

type HTTPMessage struct {
	// --- Request-side fields ---

	// Method is the HTTP verb (GET, POST, etc.).
	Method string

	// Scheme is "http" or "https".
	Scheme string

	// Authority is the Host header or :authority pseudo-header.
	Authority string

	// Path is the request path.
	Path string

	// RawQuery is the raw query string (without leading '?').
	RawQuery string

	// ConnectProtocol carries the value of the HTTP/2 :protocol
	// pseudo-header from RFC 8441 extended CONNECT requests (e.g.
	// "websocket"). Empty for normal HTTP requests, classic CONNECT
	// requests, all responses, and all HTTP/1.x messages. Session-level
	// code uses Method=="CONNECT" + ConnectProtocol!="" to recognise
	// that the stream is bootstrapping a non-HTTP protocol over HTTP/2;
	// the actual layer swap to the tunnelled protocol is handled by the
	// connector orchestrator (USK-765), not the parsing path.
	//
	// Named ConnectProtocol (not Protocol) to avoid colliding with the
	// Message-interface Protocol() method (which returns ProtocolHTTP
	// for this type).
	ConnectProtocol string

	// HTTPVersion is the wire-observed HTTP protocol version (USK-788).
	// Canonical values are HTTPVersion10 / HTTPVersion11 / HTTPVersionH2 /
	// HTTPVersionH2C ("http/1.0" / "http/1.1" / "h2" / "h2c") — see the
	// constants above for the full canonical set and rationale.
	//
	// Set by the producing Layer:
	//   - HTTP/1.x channel translates parser.RawRequest.Proto /
	//     parser.RawResponse.Proto ("HTTP/1.0" / "HTTP/1.1") to the
	//     lowercased canonical form.
	//   - HTTP/2 aggregator stamps HTTPVersionH2 when evt.Scheme=="https"
	//     and HTTPVersionH2C when evt.Scheme=="http" (the h2c handler in
	//     internal/connector/h2c_handler.go is the sole producer of the
	//     latter — it constructs the HTTP/2 Layer with WithScheme("http")).
	//
	// The field is informational; the wire-format encoding of an
	// outgoing request/response is not driven from HTTPVersion. The
	// HTTP/1.x re-encode path uses opaque rawReq/rawResp.Proto, and the
	// HTTP/2 re-encode runs through HPACK regardless of HTTPVersion.
	// Downstream filters (e.g. USK-792 manage export_flows / delete_flows)
	// filter on HTTPVersion as recorded; they do not infer it from the
	// scheme or ALPN.
	//
	// Empty for non-HTTP messages and for any pre-USK-788 stored row.
	HTTPVersion string

	// --- Response-side fields ---

	// Status is the HTTP status code.
	Status int

	// StatusReason is the reason phrase (e.g., "OK", "Not Found").
	// Relevant for HTTP/1.x wire fidelity; HTTP/2 does not have reason phrases.
	StatusReason string

	// --- Both directions ---

	// Headers is an order-preserved, case-preserved list of headers.
	Headers []KeyValue

	// Trailers is an order-preserved, case-preserved list of trailers.
	Trailers []KeyValue

	// Body is the message body. Nil when BodyStream is used instead.
	Body []byte

	// BodyStream is reserved for future streaming protocols (SSE, WebSocket).
	// HTTP/1.x and HTTP/2 layers populate BodyBuffer instead.
	BodyStream io.Reader

	// BodyBuffer holds the body when it exceeds BodySpillThreshold and is
	// backed by a temp file (memory mode for smaller bodies is represented
	// via Body []byte). At most one of Body/BodyBuffer is non-nil for HTTP/1.x
	// and HTTP/2 envelopes.
	BodyBuffer *bodybuf.BodyBuffer

	// Anomalies records parser-detected protocol anomalies (CL/TE conflict,
	// duplicate CL, obs-fold, etc.). HTTP-specific; not on Envelope because
	// not meaningful for all protocols.
	Anomalies []Anomaly
}

// Protocol returns ProtocolHTTP.
func (m *HTTPMessage) Protocol() Protocol { return ProtocolHTTP }

// CloneMessage returns a deep copy of the HTTPMessage.
// BodyStream is not cloned — it is a one-shot reader owned by the Layer.
// BodyBuffer is shared (pointer-copied) via Retain so variant snapshots
// see the same underlying buffer; the session OnComplete backstop releases
// the terminal reference.
func (m *HTTPMessage) CloneMessage() Message {
	clone := &HTTPMessage{
		Method:          m.Method,
		Scheme:          m.Scheme,
		Authority:       m.Authority,
		Path:            m.Path,
		RawQuery:        m.RawQuery,
		ConnectProtocol: m.ConnectProtocol,
		HTTPVersion:     m.HTTPVersion,
		Status:          m.Status,
		StatusReason:    m.StatusReason,
		Headers:         cloneKeyValues(m.Headers),
		Trailers:        cloneKeyValues(m.Trailers),
		Body:            cloneBytes(m.Body),
		Anomalies:       cloneAnomalies(m.Anomalies),
		// BodyStream intentionally not cloned (one-shot reader).
	}
	if m.BodyBuffer != nil {
		m.BodyBuffer.Retain()
		clone.BodyBuffer = m.BodyBuffer
	}
	return clone
}

// HasPushPromiseAnomaly reports whether m carries an H2PushPromise anomaly.
// Used to classify a synthetic envelope the HTTP/2 layer delivers upon
// receiving a PUSH_PROMISE: such envelopes are for recording only and must
// not be forwarded back down as a response frame (they have no :status).
func HasPushPromiseAnomaly(m *HTTPMessage) bool {
	if m == nil {
		return false
	}
	for _, a := range m.Anomalies {
		if a.Type == H2PushPromise {
			return true
		}
	}
	return false
}

// HTTPVersionFromProto translates an HTTP/1.x parser proto string
// ("HTTP/1.0" / "HTTP/1.1") to the canonical lowercased HTTPVersion form
// (USK-788). Unknown values fall through unchanged so downstream readers
// can surface oddities (e.g. a "HTTP/0.9" appearance) verbatim instead of
// silently masking them.
func HTTPVersionFromProto(proto string) string {
	switch proto {
	case "HTTP/1.0":
		return HTTPVersion10
	case "HTTP/1.1":
		return HTTPVersion11
	default:
		return proto
	}
}

// HTTPVersionFromH2Scheme returns the canonical HTTP/2 wire-version
// constant for a given scheme stamped on an HTTP/2 Layer (USK-788). The
// h2c handler in internal/connector/h2c_handler.go is the sole producer
// of scheme="http"; every other HTTP/2 path uses scheme="https". Unknown
// values yield HTTPVersionH2 since the HTTP/2 wire format itself is
// identical regardless of transport.
func HTTPVersionFromH2Scheme(scheme string) string {
	if scheme == "http" {
		return HTTPVersionH2C
	}
	return HTTPVersionH2
}

// cloneAnomalies returns a deep copy of an Anomaly slice.
func cloneAnomalies(a []Anomaly) []Anomaly {
	if a == nil {
		return nil
	}
	c := make([]Anomaly, len(a))
	copy(c, a)
	return c
}
