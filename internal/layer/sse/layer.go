package sse

import (
	"errors"
	"io"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// DefaultMaxEventSize is the default per-event byte cap applied when no
// WithMaxEventSize Option is supplied. Matches the parser's own legacy
// default (1 MiB).
const DefaultMaxEventSize = 1 << 20

// ErrSendUnsupported is returned by the SSE Channel's Send method. SSE is
// half-duplex (server → client only) per RFC 8895 and RFC-001 N7 D23, so
// Send is a programmer error rather than a stream-level abort. Match with
// errors.Is.
var ErrSendUnsupported = errors.New("sse: Send not supported (half-duplex Receive-only)")

// config holds the resolved options for a Wrap call. Zero-value fields
// fall back to package defaults.
type config struct {
	maxEventSize  int
	skipFirstEmit bool
}

// Option tunes the SSE wrapper.
type Option func(*config)

// WithMaxEventSize caps the maximum byte size of a single SSE event. A
// non-positive n leaves the default in place. The cap also bounds memory
// usage of the underlying scanner buffer.
func WithMaxEventSize(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxEventSize = n
		}
	}
}

// WithSkipFirstEmit causes the wrapped Channel to skip emitting the
// firstResponse envelope on its first Next() call and jump straight to
// driving the parser. Used by the production HTTP/1.x → SSE swap path
// (session.runUpgradeSSE) where the response envelope was already
// recorded by the pre-swap Pipeline run; re-emitting would project a
// duplicate Receive flow. firstResponse is still required for streamID,
// sequence, and Context derivation on the SSE event envelopes.
func WithSkipFirstEmit() Option {
	return func(c *config) { c.skipFirstEmit = true }
}

// Wrap consumes an HTTP/1.x Channel that has just produced firstResponse
// and an io.Reader carrying the response body bytes, and returns a
// Receive-only layer.Channel that emits one envelope.SSEMessage per parsed
// event.
//
// firstResponse must have Direction=Receive, Protocol=ProtocolHTTP, and
// status 200 with a Content-Type of text/event-stream. The wrapper does
// not re-validate; detection and swap orchestration is owned by USK-643.
//
// body is the post-headers byte stream from the upstream connection.
// HTTP/1.x's HTTPMessage.Body is fully drained by the http1 layer and
// HTTPMessage.BodyStream is unpopulated, so the SSE byte source must be
// supplied explicitly by the swap orchestrator.
//
// Close on the returned Channel cascades to body (if it implements
// io.Closer) and then to inner.
func Wrap(inner layer.Channel, firstResponse *envelope.Envelope, body io.Reader, opts ...Option) layer.Channel {
	cfg := &config{maxEventSize: DefaultMaxEventSize}
	for _, o := range opts {
		o(cfg)
	}

	// Pre-shape the first envelope: clone the supplied response, but
	// override Protocol to ProtocolSSE and force Direction=Receive.
	first := &envelope.Envelope{
		StreamID:  firstResponse.StreamID,
		FlowID:    firstResponse.FlowID,
		Sequence:  firstResponse.Sequence,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolSSE,
		Raw:       cloneBytes(firstResponse.Raw),
		Context:   firstResponse.Context,
	}
	if firstResponse.Message != nil {
		first.Message = firstResponse.Message.CloneMessage()
	}

	return &sseChannel{
		inner:     inner,
		body:      body,
		firstEnv:  first,
		streamID:  inner.StreamID(),
		nextSeq:   firstResponse.Sequence + 1,
		maxEvent:  cfg.maxEventSize,
		recvDone:  make(chan struct{}),
		skipFirst: cfg.skipFirstEmit,
	}
}
