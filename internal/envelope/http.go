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

	// HTTP/2 specific anomalies.
	H2DuplicatePseudoHeader    AnomalyType = "H2DuplicatePseudoHeader"
	H2PseudoHeaderAfterRegular AnomalyType = "H2PseudoHeaderAfterRegular"
	H2InvalidPseudoHeader      AnomalyType = "H2InvalidPseudoHeader"
	H2UppercaseHeaderName      AnomalyType = "H2UppercaseHeaderName"
	H2ConnectionSpecificHeader AnomalyType = "H2ConnectionSpecificHeader"
	H2TrailersAfterPassthrough AnomalyType = "H2TrailersAfterPassthrough"
	H2PushPromise              AnomalyType = "H2PushPromise"
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
		Method:       m.Method,
		Scheme:       m.Scheme,
		Authority:    m.Authority,
		Path:         m.Path,
		RawQuery:     m.RawQuery,
		Status:       m.Status,
		StatusReason: m.StatusReason,
		Headers:      cloneKeyValues(m.Headers),
		Trailers:     cloneKeyValues(m.Trailers),
		Body:         cloneBytes(m.Body),
		Anomalies:    cloneAnomalies(m.Anomalies),
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

// cloneAnomalies returns a deep copy of an Anomaly slice.
func cloneAnomalies(a []Anomaly) []Anomaly {
	if a == nil {
		return nil
	}
	c := make([]Anomaly, len(a))
	copy(c, a)
	return c
}
