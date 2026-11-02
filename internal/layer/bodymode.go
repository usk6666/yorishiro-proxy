package layer

import (
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// BodyModeKind selects how a Layer delivers an HTTP message body to the
// Pipeline (RFC-001 §3.2.1 "HTTP body streaming").
type BodyModeKind int

const (
	// BodyBuffer reads the whole body before the Envelope is emitted
	// (HTTPMessage.Body / BodyBuffer). The zero value.
	BodyBuffer BodyModeKind = iota
	// BodyStream emits the Envelope after the header section and forwards
	// the body while it is read (HTTPMessage.BodyStream).
	BodyStream
	// BodyBufferUpTo buffers the body when it is at most BodyMode.Limit
	// bytes and streams it otherwise.
	BodyBufferUpTo
)

// BodyMode is the decision a [BodyModeFunc] returns for one message.
type BodyMode struct {
	Kind BodyModeKind
	// Limit is the buffering bound for BodyBufferUpTo (semantic bytes).
	Limit int64
}

// Buffer returns the BodyBuffer mode.
func Buffer() BodyMode { return BodyMode{Kind: BodyBuffer} }

// Stream returns the BodyStream mode.
func Stream() BodyMode { return BodyMode{Kind: BodyStream} }

// BufferUpTo returns the BodyBufferUpTo mode bounded by limit.
func BufferUpTo(limit int64) BodyMode { return BodyMode{Kind: BodyBufferUpTo, Limit: limit} }

// String renders the mode for logs and test failures.
func (m BodyMode) String() string {
	switch m.Kind {
	case BodyBuffer:
		return "buffer"
	case BodyStream:
		return "stream"
	case BodyBufferUpTo:
		return fmt.Sprintf("buffer_up_to(%d)", m.Limit)
	default:
		return fmt.Sprintf("body_mode(%d)", int(m.Kind))
	}
}

// BodyModeFunc decides, from the header section alone, whether the body of
// msg is buffered or streamed. env is the Envelope the Layer is about to
// emit (Direction, Context — including the paired request's method and path
// for a response); its Message is msg with no body yet. A nil BodyModeFunc
// means BodyBuffer for every message.
type BodyModeFunc func(env *envelope.Envelope, msg *envelope.HTTPMessage) BodyMode
