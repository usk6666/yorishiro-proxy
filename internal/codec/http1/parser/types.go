package parser

import (
	"io"
	"strings"
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
)

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
	Anomalies  []Anomaly
	Close      bool // true if Connection: close or HTTP/1.0 default

	// Truncated is true when RawBytes was capped at maxRawCaptureSize.
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
	Anomalies  []Anomaly

	// Truncated is true when RawBytes was capped at maxRawCaptureSize.
	Truncated bool
}
