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

	// MaxMessagesPerStream caps the number of gRPC GRPCDataMessage envelopes
	// recorded per stream. Once exceeded, messages are still forwarded
	// upstream / to the client but no longer persisted to the flow store
	// (CWE-400 against the SQLite flow store). Start/End envelopes are
	// always recorded. Zero (or omitted) selects MaxGRPCMessagesPerStream
	// (10000). The cap is enforced inside internal/pipeline/RecordStep
	// (USK-802) — Channels are untouched so wire forwarding is preserved.
	MaxMessagesPerStream int `json:"max_messages_per_stream,omitempty"`
}

// SSELimits holds runtime limits for the SSE Layer (internal/layer/sse).
type SSELimits struct {
	// MaxEventSize caps the raw byte size of a single SSE event accumulated
	// across event lines (data:, event:, id:, retry:, comment :). Frames
	// over the cap trigger *layer.StreamError. Zero (or omitted) selects
	// MaxSSEEventSize (1 MiB).
	MaxEventSize int `json:"max_event_size,omitempty"`

	// MaxEventsPerStream caps the number of SSEMessage envelopes recorded
	// per stream. Once exceeded, events are still forwarded to the client
	// but no longer persisted to the flow store (CWE-400 against the SQLite
	// flow store). Zero (or omitted) selects MaxSSEEventsPerStream
	// (100000 — raised for AI streaming token-event use cases). The cap is
	// enforced inside internal/pipeline/RecordStep (USK-802); Channels are
	// untouched so the SSE TeeReader continues to relay every event byte.
	MaxEventsPerStream int `json:"max_events_per_stream,omitempty"`
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

// ResolveGRPCMaxMessagesPerStream returns g.MaxMessagesPerStream when
// positive, else the default MaxGRPCMessagesPerStream. The pipeline
// RecordStep treats the resolved value as "0 = unlimited" only via the
// explicit Option escape hatch; the proxy_start MCP tool path always
// resolves to a positive default through this helper.
func ResolveGRPCMaxMessagesPerStream(g *GRPCLimits) int {
	if g != nil && g.MaxMessagesPerStream > 0 {
		return g.MaxMessagesPerStream
	}
	return MaxGRPCMessagesPerStream
}

// ResolveSSEMaxEventsPerStream returns s.MaxEventsPerStream when positive,
// else the default MaxSSEEventsPerStream. See
// ResolveGRPCMaxMessagesPerStream for the "0 = default" convention.
func ResolveSSEMaxEventsPerStream(s *SSELimits) int {
	if s != nil && s.MaxEventsPerStream > 0 {
		return s.MaxEventsPerStream
	}
	return MaxSSEEventsPerStream
}

// ResolveMaxBodySize returns c.MaxBodySize when positive, else the package
// default MaxBodySize constant. Nil c is treated as "use default", matching
// the WS / gRPC / SSE resolver convention.
func ResolveMaxBodySize(c *ProxyConfig) int64 {
	if c != nil && c.MaxBodySize > 0 {
		return c.MaxBodySize
	}
	return MaxBodySize
}

// MaxBodySizeUpperBound is the inclusive upper bound on a configured
// max_body_size value. It matches SQLite's default BLOB length cap (1 GiB),
// since MaxBodySize is the disk-persistence cap on a single SQLite row.
const MaxBodySizeUpperBound int64 = 1 << 30

// ValidateProtocolLimits validates the per-protocol limit substructs on
// ProxyConfig. It rejects negative values and (for max_body_size) values
// above MaxBodySizeUpperBound; zero means "use default" per project
// convention (see DefaultBodySpillThreshold's resolver). A nil c is
// treated as fully-default and causes no error.
func ValidateProtocolLimits(c *ProxyConfig) error {
	if c == nil {
		return nil
	}
	if c.WebSocket != nil {
		if c.WebSocket.MaxFrameSize < 0 {
			return fmt.Errorf("web_socket.max_frame_size must be >= 0, got %d", c.WebSocket.MaxFrameSize)
		}
		// MaxFrameSize is int64; the WebSocket Layer Option signature is
		// also int64 (WithMaxFrameSize). No upper-bound check here — the
		// CWE-400 cap is the operator's responsibility.
	}
	// grpc.MaxMessageSize is uint32 so it cannot be negative; only the
	// MaxMessagesPerStream (int) needs a syntactic check. Resolve* applies
	// the default for zero.
	if c.GRPC != nil {
		if c.GRPC.MaxMessagesPerStream < 0 {
			return fmt.Errorf("grpc.max_messages_per_stream must be >= 0, got %d", c.GRPC.MaxMessagesPerStream)
		}
	}
	if c.SSE != nil {
		if c.SSE.MaxEventSize < 0 {
			return fmt.Errorf("sse.max_event_size must be >= 0, got %d", c.SSE.MaxEventSize)
		}
		if c.SSE.MaxEventsPerStream < 0 {
			return fmt.Errorf("sse.max_events_per_stream must be >= 0, got %d", c.SSE.MaxEventsPerStream)
		}
	}
	if c.MaxBodySize < 0 {
		return fmt.Errorf("max_body_size must be >= 0, got %d", c.MaxBodySize)
	}
	if c.MaxBodySize > MaxBodySizeUpperBound {
		return fmt.Errorf("max_body_size must be <= %d (SQLite BLOB limit), got %d", MaxBodySizeUpperBound, c.MaxBodySize)
	}
	return nil
}
