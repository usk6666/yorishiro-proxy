package layer

import (
	"errors"
	"fmt"
)

// ErrorCode categorizes stream-level errors. Values correspond to
// HTTP/2 error codes (RFC 7540 section 7) but are used generically
// across all protocols that support stream-level error signaling.
type ErrorCode uint32

const (
	// ErrorCanceled indicates the stream was canceled by the local side
	// (e.g., context cancellation, user abort). HTTP/2: CANCEL (0x8).
	ErrorCanceled ErrorCode = 0x8

	// ErrorAborted indicates the stream was aborted by the remote side
	// or due to a protocol violation detected locally. HTTP/2: N/A
	// (application-level abort, mapped from RST_STREAM with various codes).
	ErrorAborted ErrorCode = 0x100

	// ErrorInternalError indicates an internal processing error.
	// HTTP/2: INTERNAL_ERROR (0x2).
	ErrorInternalError ErrorCode = 0x2

	// ErrorRefused indicates the stream was refused before any processing
	// occurred. HTTP/2: REFUSED_STREAM (0x7).
	ErrorRefused ErrorCode = 0x7

	// ErrorProtocol indicates a protocol-level error (e.g., malformed frame,
	// invalid state transition). HTTP/2: PROTOCOL_ERROR (0x1).
	ErrorProtocol ErrorCode = 0x1
)

// String returns a human-readable label for the error code.
func (c ErrorCode) String() string {
	switch c {
	case ErrorCanceled:
		return "canceled"
	case ErrorAborted:
		return "aborted"
	case ErrorInternalError:
		return "internal_error"
	case ErrorRefused:
		return "refused"
	case ErrorProtocol:
		return "protocol_error"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}

// StreamError represents a stream-level error that occurred in a Layer or
// Channel. It carries an error code for classification and a human-readable
// reason. Pipeline Steps (especially RecordStep) use the code to distinguish
// cancellation from actual errors.
//
// See RFC-001 implementation guide, Friction 3-D.
type StreamError struct {
	Code   ErrorCode
	Reason string

	// PeerWireCode is the protocol-native error code the peer itself put on
	// the wire (HTTP/2: the RST_STREAM error code, RFC 9113 §7), verbatim.
	// Code is a lossy classification of it; PeerWireCode is what a MITM
	// relays to the other leg. Valid only when HasPeerWireCode is true:
	// proxy-synthesized terminations (local resets, GOAWAY refusals,
	// wrapper-local failures) never set it. USK-1269.
	PeerWireCode uint32
	// HasPeerWireCode reports whether PeerWireCode was observed on the wire.
	HasPeerWireCode bool
}

// Error implements the error interface.
func (e *StreamError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("stream error %s: %s", e.Code, e.Reason)
	}
	return fmt.Sprintf("stream error %s", e.Code)
}

// Is supports errors.Is matching by comparing error codes.
func (e *StreamError) Is(target error) bool {
	if t, ok := target.(*StreamError); ok {
		return e.Code == t.Code
	}
	return false
}

// ErrUpstreamStoppedReadingBody reports that the upstream peer stopped
// reading a request body the proxy was still writing: a write of body bytes,
// after the request head was written, failed because the peer closed or
// reset the connection (EPIPE / ECONNRESET). The upstream may already have
// answered — an early final response such as 413 — and that response is
// still read and delivered: a Channel whose Send returns an error matching
// this sentinel ends only the request direction. The session treats it like
// a clean client end (no cascade close of the upstream Channel), so the
// response keeps flowing and the Stream ends complete when one arrives, or
// in error when the upstream closed without answering.
//
// The HTTP/1.x Layer composes it with its *StaleUpstreamError (stage
// "body"), so errors.Is(err, ErrUpstreamStoppedReadingBody) and errors.As
// to the stale error both hold.
var ErrUpstreamStoppedReadingBody = errors.New("upstream stopped reading the request body")
