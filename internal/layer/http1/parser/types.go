package parser

import (
	"io"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// hasConnectionToken reports whether any Connection header value contains the
// given token as an exact, case-insensitive, comma-separated token.
func hasConnectionToken(headers RawHeaders, want string) bool {
	for _, val := range headers.Values("Connection") {
		for _, token := range strings.Split(val, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

// AnomalyType classifies the kind of HTTP anomaly detected during parsing.
type AnomalyType string

const (
	// AnomalyCLTE indicates both Content-Length and Transfer-Encoding are present.
	AnomalyCLTE AnomalyType = "CLTE"
	// AnomalyDuplicateCL indicates multiple Content-Length headers with different values.
	AnomalyDuplicateCL AnomalyType = "DuplicateCL"
	// AnomalyInvalidTE indicates a non-standard Transfer-Encoding value.
	AnomalyInvalidTE AnomalyType = "InvalidTE"
	// AnomalyHeaderInjection indicates suspected HTTP header injection or malformed
	// header syntax (for example, embedded CR/LF characters or illegal whitespace
	// around the header name/colon).
	AnomalyHeaderInjection AnomalyType = "HeaderInjection"
	// AnomalyAmbiguousTE indicates obfuscated Transfer-Encoding (e.g., trailing whitespace).
	AnomalyAmbiguousTE AnomalyType = "AmbiguousTE"
	// AnomalyObsFold indicates an obsolete line folding (RFC 7230 Section 3.2.4).
	AnomalyObsFold AnomalyType = "ObsFold"
	// AnomalyTrailerPseudoHeader indicates a pseudo-header name (":"-prefix) in
	// a chunked trailer. HTTP/1.x has no pseudo-header concept, so its appearance
	// in a trailer is a smuggling/injection indicator. The header is preserved
	// in Trailers for wire fidelity.
	AnomalyTrailerPseudoHeader AnomalyType = "TrailerPseudoHeader"
	// AnomalyTrailerForbidden indicates a framing/routing header appeared in a
	// chunked trailer, which RFC 7230 §4.1.2 prohibits (Transfer-Encoding,
	// Content-Length, Host, Trailer). The header is preserved in Trailers for
	// wire fidelity.
	AnomalyTrailerForbidden AnomalyType = "TrailerForbidden"
	// AnomalyTrailersInPassthrough indicates that a chunked body exceeded the
	// passthrough threshold before trailers could be captured on the Envelope.
	// Trailer values are drained by the downstream writer but are not surfaced
	// on HTTPMessage.Trailers. Parallels H2TrailersAfterPassthrough for HTTP/2.
	AnomalyTrailersInPassthrough AnomalyType = "TrailersInPassthrough"
	// AnomalyRawBodyTruncated indicates that the on-wire raw body bytes
	// exceeded MaxRawCaptureSize and the captured RawBody is a prefix only.
	// The semantic body (Body / BodyBuffer) is unaffected and capped by the
	// independent body-spill / MaxBodySize policies.
	AnomalyRawBodyTruncated AnomalyType = "RawBodyTruncated"
)

// TrailerProvider is implemented by body readers that parse chunked trailers
// after the terminal chunk. Callers may type-assert a RawRequest.Body or
// RawResponse.Body to TrailerProvider after the body has been fully drained
// (io.EOF) to retrieve parsed trailers. Before full drain the methods return
// empty results.
type TrailerProvider interface {
	// Trailers returns the parsed chunked trailers in wire order, preserving
	// original header name case and OWS (same rules as parseHeaders).
	Trailers() RawHeaders
	// TrailerAnomalies returns anomalies detected during trailer parsing
	// (pseudo-header, forbidden header, obs-fold, header injection).
	TrailerAnomalies() []Anomaly
}

// RawBodyProvider is implemented by body readers that capture the on-wire
// body bytes verbatim (chunk framing for chunked Transfer-Encoding, raw
// content bytes for Content-Length / EOF-delimited bodies). Callers may
// type-assert a RawRequest.Body or RawResponse.Body to RawBodyProvider after
// the body has been fully drained to retrieve the captured bytes.
//
// RawBody preserves chunk-size hex, chunk extensions, optional trailers, and
// the terminating "0\r\n\r\n" exactly as observed on the wire — opaque
// pass-through send paths re-emit these bytes verbatim, satisfying
// RFC-001 §3.1 (wire-observed raw bytes must not be destroyed or modified).
//
// Memory vs disk-backed (USK-772): the body capture sink supports two
// storage modes. Below the configured spill threshold, RawBody returns the
// captured bytes from memory and RawBodyBuffer returns nil. Above the
// threshold the sink promotes to a disk-backed bodybuf.BodyBuffer; RawBody
// then returns nil and RawBodyBuffer returns the populated buffer. Callers
// check both. Truncation at the absolute cap (MaxRawCaptureSize for memory,
// the configured maxSize for spill) is signalled via RawBodyTruncated().
type RawBodyProvider interface {
	// RawBody returns the on-wire body bytes captured during parsing when the
	// body fit in memory. Nil when capture spilled to disk (consult
	// RawBodyBuffer instead) or for messages with no body.
	RawBody() []byte
	// RawBodyBuffer returns the disk-backed bodybuf when the captured body
	// crossed the spill threshold. Nil when capture stayed in memory. The
	// returned buffer carries one outstanding Retain; the caller assumes
	// ownership and must arrange for a matching Release.
	RawBodyBuffer() *bodybuf.BodyBuffer
	// RawBodyTruncated reports whether RawBody / RawBodyBuffer was capped at
	// the absolute byte cap and is a prefix of the actual on-wire bytes. The
	// semantic body (Body / BodyBuffer) is unaffected by this cap.
	RawBodyTruncated() bool
}

// Anomaly records a single protocol-level anomaly found during parsing.
type Anomaly struct {
	Type   AnomalyType
	Detail string
}

// RawHeader represents a single HTTP header with original case preserved.
type RawHeader struct {
	Name     string // original case preserved
	Value    string // OWS-trimmed value
	RawValue string // value before OWS trimming (empty if same as Value)
}

// RawHeaders is an ordered list of HTTP headers preserving wire order and case.
type RawHeaders []RawHeader

// Get returns the value of the first header matching name (case-insensitive).
// Returns empty string if not found.
func (h RawHeaders) Get(name string) string {
	for _, hdr := range h {
		if strings.EqualFold(hdr.Name, name) {
			return hdr.Value
		}
	}
	return ""
}

// Values returns all values for headers matching name (case-insensitive).
func (h RawHeaders) Values(name string) []string {
	var vals []string
	for _, hdr := range h {
		if strings.EqualFold(hdr.Name, name) {
			vals = append(vals, hdr.Value)
		}
	}
	return vals
}

// Set sets the first header matching name to value, or appends if not found.
// Matching is case-insensitive but the original or provided name case is preserved.
func (h *RawHeaders) Set(name, value string) {
	for i, hdr := range *h {
		if strings.EqualFold(hdr.Name, name) {
			(*h)[i].Value = value
			(*h)[i].RawValue = ""
			return
		}
	}
	*h = append(*h, RawHeader{Name: name, Value: value})
}

// Del removes all headers matching name (case-insensitive).
func (h *RawHeaders) Del(name string) {
	n := 0
	for _, hdr := range *h {
		if !strings.EqualFold(hdr.Name, name) {
			(*h)[n] = hdr
			n++
		}
	}
	// Clear removed entries to avoid dangling references.
	for i := n; i < len(*h); i++ {
		(*h)[i] = RawHeader{}
	}
	*h = (*h)[:n]
}

// Clone returns a deep copy of the headers.
func (h RawHeaders) Clone() RawHeaders {
	if h == nil {
		return nil
	}
	out := make(RawHeaders, len(h))
	copy(out, h)
	return out
}

// RawRequest represents a parsed HTTP/1.x request.
type RawRequest struct {
	Method     string
	RequestURI string
	Proto      string // "HTTP/1.0" or "HTTP/1.1"
	Headers    RawHeaders
	Body       io.Reader
	RawBytes   []byte // complete raw bytes of the header section (request-line + headers + CRLF CRLF)
	// RawBody is the on-wire body bytes captured during parsing. For chunked
	// Transfer-Encoding it preserves the chunk framing (chunk-size hex,
	// extensions, trailing CRLF after each chunk, the terminal "0" chunk, and
	// any trailer headers + final CRLF). For Content-Length / EOF-delimited
	// bodies it is identical to the dechunked semantic body. Empty for
	// bodyless messages (HEAD / 204 / 304 / no body).
	//
	// RawBody is populated by the consumer of Body after the io.Reader has
	// been fully drained, by type-asserting Body to RawBodyProvider. The
	// parser itself returns RawBody == nil; the field is filled in by
	// internal/layer/http1/channel.go after readBodyWithThreshold.
	//
	// USK-772: RawBody is nil when the captured body crossed the spill
	// threshold; in that case RawBodyBuffer holds the disk-backed bytes.
	RawBody []byte
	// RawBodyBuffer is the disk-backed body capture buffer populated when the
	// on-wire body crossed the spill threshold. Nil when capture stayed in
	// memory (use RawBody instead). The buffer carries one outstanding Retain
	// — the channel layer transfers ownership to Envelope.RawBuffer; the
	// terminal Release is the session bodyBufRegistry's responsibility.
	//
	// USK-772: introduced so multi-MiB chunked bodies can be re-emitted
	// byte-for-byte through the opaque passthrough send path without
	// hitting the MaxRawCaptureSize memory cap.
	RawBodyBuffer *bodybuf.BodyBuffer
	// RawBodyTruncated is true when RawBody / RawBodyBuffer was capped at
	// the absolute byte cap (MaxRawCaptureSize for memory mode, MaxBodySize
	// for spill mode).
	RawBodyTruncated bool
	Anomalies        []Anomaly
	Close            bool // true if Connection: close or HTTP/1.0 default

	// Truncated is true when RawBytes was capped at MaxRawCaptureSize.
	Truncated bool
}

// RawResponse represents a parsed HTTP/1.x response.
type RawResponse struct {
	Proto      string
	StatusCode int
	Status     string // e.g. "200 OK"
	Headers    RawHeaders
	Body       io.Reader
	RawBytes   []byte
	// RawBody is the on-wire body bytes captured during parsing. See
	// RawRequest.RawBody for semantics.
	RawBody []byte
	// RawBodyBuffer is the disk-backed body capture buffer (USK-772). See
	// RawRequest.RawBodyBuffer for semantics.
	RawBodyBuffer *bodybuf.BodyBuffer
	// RawBodyTruncated is true when RawBody / RawBodyBuffer was capped at
	// the absolute byte cap.
	RawBodyTruncated bool
	Anomalies        []Anomaly

	// Truncated is true when RawBytes was capped at MaxRawCaptureSize.
	Truncated bool
}
