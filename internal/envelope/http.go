package envelope

import "io"

// HTTPMessage represents one HTTP request or response. Used by both HTTP/1.x
// and HTTP/2 layers. See RFC-001 section 3.2.1.
//
// Request-side fields (Method, Scheme, Authority, Path, RawQuery) are valid
// when Envelope.Direction == Send.
// Response-side fields (Status, StatusReason) are valid when
// Envelope.Direction == Receive.
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

	// BodyStream is a streaming body reader for passthrough mode.
	// Non-nil only when Body is nil.
	BodyStream io.Reader
}

// Protocol returns ProtocolHTTP.
func (m *HTTPMessage) Protocol() Protocol { return ProtocolHTTP }

// CloneMessage returns a deep copy of the HTTPMessage.
// BodyStream is not cloned — it is a one-shot reader owned by the Layer.
func (m *HTTPMessage) CloneMessage() Message {
	return &HTTPMessage{
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
		// BodyStream intentionally not cloned
	}
}
