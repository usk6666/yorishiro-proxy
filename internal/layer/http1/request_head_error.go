package http1

import (
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// RequestHeadReason classifies why the client-facing Layer closed a
// connection before a request Envelope existed (USK-1181). The values are
// the Stream.FailureReason labels the proxy records.
type RequestHeadReason string

const (
	// RequestHeadTimeout: the request line + header deadline
	// (request_timeout_ms, USK-1162) expired after at least one byte of
	// the request arrived.
	RequestHeadTimeout RequestHeadReason = "request_head_timeout"
	// RequestHeadLineTooLong: the request line exceeded the parser limit
	// and the Layer answered 414 URI Too Long.
	RequestHeadLineTooLong RequestHeadReason = "request_line_too_long"
	// RequestHeadHeaderTooLarge: the header section exceeded a parser
	// limit and the Layer answered 431 Request Header Fields Too Large.
	RequestHeadHeaderTooLarge RequestHeadReason = "request_header_too_large"
	// RequestHeadCONNECTTimeout: the request_timeout_ms deadline expired
	// while the connector was reading a CONNECT request, after at least
	// one byte of it arrived (USK-1189).
	RequestHeadCONNECTTimeout RequestHeadReason = "connect_request_timeout"
)

// Request-head phases reported in RequestHeadError.Phase.
const (
	RequestHeadPhaseRequestLine = "request_line"
	RequestHeadPhaseHeaders     = "headers"
	// RequestHeadPhaseCONNECTRequest marks a CONNECT request read by the
	// connector before any Layer existed (USK-1189).
	RequestHeadPhaseCONNECTRequest = "connect_request"
)

// RequestHeadError is the terminal error a Send-direction Channel's Next
// returns when the Layer itself closed the connection while reading a
// request head (USK-1181): the header deadline expired with bytes already
// received, or the request line / header section exceeded a parser limit.
// It carries what the wire showed so the caller can record the event even
// though no Envelope was built. The Layer has no flow concerns; recording
// is the consumer's job.
//
// A keep-alive idle expiry with zero bytes of the next request, a peer
// close, and a Layer shutdown never produce a RequestHeadError.
//
// errors.Is / errors.As see through it to Err.
type RequestHeadError struct {
	// Reason classifies the failure.
	Reason RequestHeadReason
	// Phase is RequestHeadPhaseRequestLine when the request line was not
	// complete, RequestHeadPhaseHeaders otherwise.
	Phase string
	// Scheme is the Layer's scheme ("http" / "https").
	Scheme string
	// Raw holds the request-head bytes received, capped at the Layer's
	// max raw capture size. Authoritative over the parsed fields below.
	Raw []byte
	// RawTruncated reports that Raw was cut at the capture cap.
	RawTruncated bool
	// Method, RequestTarget and Proto are the request-line fields, set
	// only when the request line was complete.
	Method        string
	RequestTarget string
	Proto         string
	// Path, RawQuery and Authority split RequestTarget exactly as a parsed
	// request's HTTPMessage would (Authority falls back to the Host
	// header). Empty when the request line was not complete.
	Path      string
	RawQuery  string
	Authority string
	// Headers holds the header lines fully received, in wire order.
	Headers parser.RawHeaders
	// Timeout is the request-head deadline that was armed, zero when none.
	Timeout time.Duration
	// Status is the status code of the proxy-generated response (414 /
	// 431), zero when none is sent.
	Status int
	// Response holds the exact bytes of the proxy-generated response.
	Response []byte
	// ResponseWritten reports that Response was written to the client.
	ResponseWritten bool
	// Started is when the first byte of the request head was available.
	Started time.Time
	// Err is the underlying error.
	Err error
}

// ApplyPartialRequest copies what perr observed into e: the received bytes
// (Raw / RawTruncated) and, when the request line was complete, the
// request-line fields, the complete header lines and the Path / RawQuery /
// Authority split a parsed request's HTTPMessage would carry. Phase is set
// to RequestHeadPhaseHeaders when the request line was complete and
// RequestHeadPhaseRequestLine otherwise. A nil perr leaves e unchanged.
func (e *RequestHeadError) ApplyPartialRequest(perr *parser.PartialRequestError) {
	if e == nil || perr == nil {
		return
	}
	e.Raw = perr.Raw
	e.RawTruncated = perr.Truncated
	e.Phase = RequestHeadPhaseRequestLine
	if !perr.RequestLineComplete {
		return
	}
	e.Phase = RequestHeadPhaseHeaders
	e.Method = perr.Method
	e.RequestTarget = perr.RequestURI
	e.Proto = perr.Proto
	e.Headers = perr.Headers
	e.Path, e.RawQuery, e.Authority = parseRequestURI(perr.RequestURI, perr.Headers)
}

// Error returns the underlying error's message.
func (e *RequestHeadError) Error() string {
	if e == nil || e.Err == nil {
		return "http1: request head failed: " + string(e.reason())
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *RequestHeadError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *RequestHeadError) reason() RequestHeadReason {
	if e == nil {
		return ""
	}
	return e.Reason
}
