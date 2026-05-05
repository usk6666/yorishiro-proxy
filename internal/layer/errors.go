package layer

import "fmt"

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
