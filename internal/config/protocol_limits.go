package config

import "fmt"

// WebSocketLimits holds runtime limits for the WebSocket Layer
// (internal/layer/ws). Fields are pointers/values designed for "nil = use
// default, zero = use default, positive = use the supplied value" so the
// JSON shape is fully backward-compatible: a config that does not mention
// "web_socket" at all behaves identically to a config that omits all
// fields inside it.
type WebSocketLimits struct {
	// MaxFrameSize caps the per-frame payload byte count. The cap applies
	// to both Receive (pre-decompression) and Send (pre-mask). Zero
	// (or omitted) selects MaxWebSocketFrameSize (16 MiB).
	MaxFrameSize int64 `json:"max_frame_size,omitempty"`

	// DeflateEnabled toggles the permessage-deflate (RFC 7692) feature on
	// the Layer. The pointer shape is required because the spec default is
	// true: a plain bool would silently disable deflate on any config that
	// omits the field. Nil = use default (true).
	DeflateEnabled *bool `json:"deflate_enabled,omitempty"`
}

// GRPCLimits holds runtime limits shared by the gRPC and gRPC-Web Layers
// (internal/layer/grpc, internal/layer/grpcweb). Both packages enforce the
// same Length-Prefixed-Message wire cap (CWE-400 mitigation), so a single
// substruct configures both.
type GRPCLimits struct {
	// MaxMessageSize caps the declared LPM length on Receive (and the
	// gunzip-decoded length when grpc-encoding=gzip). Frames over the cap
	// trigger *layer.StreamError{Code: ErrorInternalError} and an
	// RST_STREAM. Zero (or omitted) selects MaxGRPCMessageSize (254 MiB).
	MaxMessageSize uint32 `json:"max_message_size,omitempty"`
}

// SSELimits holds runtime limits for the SSE Layer (internal/layer/sse).
type SSELimits struct {
	// MaxEventSize caps the raw byte size of a single SSE event accumulated
	// across event lines (data:, event:, id:, retry:, comment :). Frames
	// over the cap trigger *layer.StreamError. Zero (or omitted) selects
	// MaxSSEEventSize (1 MiB).
	MaxEventSize int `json:"max_event_size,omitempty"`
}

// ResolveWSMaxFrameSize returns ws.MaxFrameSize when positive, else the
// default MaxWebSocketFrameSize. Nil ws is treated as "use default" (the
// project convention; matches BodySpillThreshold's resolver).
func ResolveWSMaxFrameSize(ws *WebSocketLimits) int64 {
	if ws != nil && ws.MaxFrameSize > 0 {
		return ws.MaxFrameSize
	}
	return MaxWebSocketFrameSize
}

// ResolveWSDeflateEnabled returns the configured DeflateEnabled value, or
// the default true when ws is nil or the field is unset.
func ResolveWSDeflateEnabled(ws *WebSocketLimits) bool {
	if ws == nil || ws.DeflateEnabled == nil {
		return true
	}
	return *ws.DeflateEnabled
}

// ResolveGRPCMaxMessageSize returns g.MaxMessageSize when positive, else
// the default MaxGRPCMessageSize.
func ResolveGRPCMaxMessageSize(g *GRPCLimits) uint32 {
	if g != nil && g.MaxMessageSize > 0 {
		return g.MaxMessageSize
	}
	return MaxGRPCMessageSize
}

// ResolveSSEMaxEventSize returns s.MaxEventSize when positive, else the
// default MaxSSEEventSize.
func ResolveSSEMaxEventSize(s *SSELimits) int {
	if s != nil && s.MaxEventSize > 0 {
		return s.MaxEventSize
	}
	return MaxSSEEventSize
}

// ValidateProtocolLimits validates the per-protocol limit substructs. It
// rejects only negative values; zero means "use default" per project
// convention (see DefaultBodySpillThreshold's resolver). Nil substructs
// are treated as fully-default and cause no error. The function is the
// per-protocol-limits sibling of ValidateSafetyFilterConfig.
func ValidateProtocolLimits(ws *WebSocketLimits, grpc *GRPCLimits, sse *SSELimits) error {
	if ws != nil {
		if ws.MaxFrameSize < 0 {
			return fmt.Errorf("web_socket.max_frame_size must be >= 0, got %d", ws.MaxFrameSize)
		}
		// MaxFrameSize is int64; the WebSocket Layer Option signature is
		// also int64 (WithMaxFrameSize). No upper-bound check here — the
		// CWE-400 cap is the operator's responsibility.
	}
	// grpc.MaxMessageSize is uint32 so it cannot be negative; nothing to
	// reject syntactically. Resolve* applies the default for zero.
	_ = grpc
	if sse != nil {
		if sse.MaxEventSize < 0 {
			return fmt.Errorf("sse.max_event_size must be >= 0, got %d", sse.MaxEventSize)
		}
	}
	return nil
}
