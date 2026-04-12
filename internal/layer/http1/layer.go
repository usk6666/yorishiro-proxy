package http1

import (
	"bufio"
	"errors"
	"io"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// Layer wraps a net.Conn in an HTTP/1.x Layer. It yields exactly one Channel
// that produces HTTPMessage envelopes for each request or response in
// keep-alive order.
//
// The Layer owns the connection and closes it on Close().
type Layer struct {
	conn    net.Conn
	ch      chan layer.Channel
	channel *channel
	opts    options
}

// options holds Layer configuration.
type options struct {
	scheme  string
	ctx     envelope.EnvelopeContext
	bufSize int
}

// Option configures a Layer.
type Option func(*options)

// WithScheme sets the HTTP scheme ("http" or "https") for envelopes.
func WithScheme(scheme string) Option {
	return func(o *options) { o.scheme = scheme }
}

// WithEnvelopeContext sets the template EnvelopeContext stamped onto every
// envelope produced by this Layer's Channel. ReceivedAt is overwritten
// per-envelope.
func WithEnvelopeContext(ctx envelope.EnvelopeContext) Option {
	return func(o *options) { o.ctx = ctx }
}

// WithBufioSize sets the bufio.Reader buffer size. Default is 4096.
func WithBufioSize(size int) Option {
	return func(o *options) { o.bufSize = size }
}

// New creates an HTTP/1.x Layer wrapping conn.
//
// direction determines what the Channel parses:
//   - envelope.Send: parses requests (server-facing / client-side layer)
//   - envelope.Receive: parses responses (client-facing / upstream-side layer)
//
// streamID is the connection-level identifier returned by Channel.StreamID().
func New(conn net.Conn, streamID string, direction envelope.Direction, opts ...Option) *Layer {
	o := options{
		scheme:  "http",
		bufSize: 4096,
	}
	for _, opt := range opts {
		opt(&o)
	}

	l := &Layer{
		conn: conn,
		ch:   make(chan layer.Channel, 1),
		opts: o,
	}

	reader := bufio.NewReaderSize(conn, o.bufSize)

	l.channel = &channel{
		reader:    reader,
		writer:    conn,
		streamID:  streamID,
		direction: direction,
		scheme:    o.scheme,
		ctxTmpl:   o.ctx,
	}
	l.ch <- l.channel
	close(l.ch)
	return l
}

// Channels returns a channel that yields exactly one Channel, then closes.
func (l *Layer) Channels() <-chan layer.Channel { return l.ch }

// Close closes the underlying connection. The Layer owns the connection.
func (l *Layer) Close() error { return l.conn.Close() }

// DetachStream tears down the HTTP/1 layer after an Upgrade response and
// returns the buffered reader, writer, and underlying closer so that the
// next layer (WebSocket) can be constructed on top of the same wire.
// The caller takes ownership of these resources; the Layer becomes unusable.
//
// Not implemented until N7 (WebSocket Upgrade).
func (l *Layer) DetachStream() (io.Reader, io.Writer, io.Closer, error) {
	return nil, nil, nil, errors.New("http1: DetachStream not implemented (deferred to N7)")
}
