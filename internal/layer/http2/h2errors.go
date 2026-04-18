package http2

import "fmt"

// HTTP/2 error codes as defined in RFC 9113 Section 7.
const (
	// ErrCodeNo indicates no error (used in GOAWAY for graceful shutdown).
	ErrCodeNo uint32 = 0x00
	// ErrCodeProtocol indicates a generic protocol error.
	ErrCodeProtocol uint32 = 0x01
	// ErrCodeInternal indicates an internal error.
	ErrCodeInternal uint32 = 0x02
	// ErrCodeFlowControl indicates a flow control error.
	ErrCodeFlowControl uint32 = 0x03
	// ErrCodeSettingsTimeout indicates SETTINGS was not acknowledged in time.
	ErrCodeSettingsTimeout uint32 = 0x04
	// ErrCodeStreamClosed indicates a frame was received on a closed stream.
	ErrCodeStreamClosed uint32 = 0x05
	// ErrCodeFrameSize indicates a frame size error.
	ErrCodeFrameSize uint32 = 0x06
	// ErrCodeRefusedStream indicates the stream was refused before processing.
	ErrCodeRefusedStream uint32 = 0x07
	// ErrCodeCancel indicates the stream is no longer needed.
	ErrCodeCancel uint32 = 0x08
	// ErrCodeCompression indicates a compression state error (HPACK).
	ErrCodeCompression uint32 = 0x09
	// ErrCodeConnect indicates a CONNECT request error.
	ErrCodeConnect uint32 = 0x0a
	// ErrCodeEnhanceYourCalm indicates the peer is generating excessive load.
	ErrCodeEnhanceYourCalm uint32 = 0x0b
	// ErrCodeInadequateSecurity indicates the transport does not meet minimum security requirements.
	ErrCodeInadequateSecurity uint32 = 0x0c
	// ErrCodeHTTP11Required indicates HTTP/1.1 must be used.
	ErrCodeHTTP11Required uint32 = 0x0d
)

// errCodeNames maps error codes to human-readable names.
var errCodeNames = map[uint32]string{
	ErrCodeNo:                 "NO_ERROR",
	ErrCodeProtocol:           "PROTOCOL_ERROR",
	ErrCodeInternal:           "INTERNAL_ERROR",
	ErrCodeFlowControl:        "FLOW_CONTROL_ERROR",
	ErrCodeSettingsTimeout:    "SETTINGS_TIMEOUT",
	ErrCodeStreamClosed:       "STREAM_CLOSED",
	ErrCodeFrameSize:          "FRAME_SIZE_ERROR",
	ErrCodeRefusedStream:      "REFUSED_STREAM",
	ErrCodeCancel:             "CANCEL",
	ErrCodeCompression:        "COMPRESSION_ERROR",
	ErrCodeConnect:            "CONNECT_ERROR",
	ErrCodeEnhanceYourCalm:    "ENHANCE_YOUR_CALM",
	ErrCodeInadequateSecurity: "INADEQUATE_SECURITY",
	ErrCodeHTTP11Required:     "HTTP_1_1_REQUIRED",
}

// ErrCodeString returns the human-readable name of an HTTP/2 error code.
func ErrCodeString(code uint32) string {
	if name, ok := errCodeNames[code]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_ERROR(0x%02x)", code)
}

// ConnError represents an HTTP/2 connection error as described in
// RFC 9113 Section 5.4.1. A connection error signals that the entire
// connection is no longer usable. The endpoint should send a GOAWAY
// frame and close the connection.
type ConnError struct {
	// Code is the HTTP/2 error code to include in the GOAWAY frame.
	Code uint32
	// Reason provides additional context for logging/debugging.
	Reason string
}

// Error returns the string representation of the connection error.
func (e *ConnError) Error() string {
	return fmt.Sprintf("connection error: %s: %s", ErrCodeString(e.Code), e.Reason)
}

// StreamError represents an HTTP/2 stream error as described in
// RFC 9113 Section 5.4.2. A stream error signals that only the
// specific stream is in error; the connection may continue. The
// endpoint should send a RST_STREAM frame for the affected stream.
type StreamError struct {
	// StreamID is the stream that encountered the error.
	StreamID uint32
	// Code is the HTTP/2 error code to include in the RST_STREAM frame.
	Code uint32
	// Reason provides additional context for logging/debugging.
	Reason string
}

// Error returns the string representation of the stream error.
func (e *StreamError) Error() string {
	return fmt.Sprintf("stream error (stream %d): %s: %s", e.StreamID, ErrCodeString(e.Code), e.Reason)
}
