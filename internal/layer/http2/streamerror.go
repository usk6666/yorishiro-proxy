package http2

import "github.com/usk6666/yorishiro-proxy/internal/layer"

// translateH2StreamError converts an HTTP/2 stream error code (RFC 9113 §7)
// to a layer.ErrorCode for surfacing to the Pipeline.
//
// Codes that map to a Pipeline-meaningful classification (CANCEL, PROTOCOL_ERROR,
// REFUSED_STREAM, INTERNAL_ERROR) are translated directly. Anything else (e.g.
// FLOW_CONTROL_ERROR, COMPRESSION_ERROR, application-defined codes) is mapped
// to ErrorAborted.
func translateH2StreamError(code uint32) layer.ErrorCode {
	switch code {
	case ErrCodeCancel:
		return layer.ErrorCanceled
	case ErrCodeProtocol:
		return layer.ErrorProtocol
	case ErrCodeRefusedStream:
		return layer.ErrorRefused
	case ErrCodeInternal:
		return layer.ErrorInternalError
	default:
		return layer.ErrorAborted
	}
}
